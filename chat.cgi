#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ドパ描き用 チャットCGI (SSE)

  GET  chat.cgi?a=stream&from=<最後に受け取ったid>   SSEで新着メッセージを配信
  POST chat.cgi  a=post&name=<名前>&text=<本文>       メッセージ投稿

place.cgi と同じディレクトリに置いて chmod 755。
同じディレクトリに chat_log.jsonl / chat_rate.json / chat_lock が作られるので、
ディレクトリはCGIの実行ユーザーが書き込める必要があります。
"""
import os
import sys
import json
import time
import fcntl
import hashlib
import unicodedata
from urllib.parse import parse_qs

# ---- 設定 ----------------------------------------------------------
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, 'chat_log.jsonl')
RATE = os.path.join(BASE, 'chat_rate.json')
LOCK = os.path.join(BASE, 'chat_lock')

MAX_NAME = 20        # 名前の最大文字数
MAX_TEXT = 200       # 本文の最大文字数
KEEP = 300           # 保持する最大メッセージ数
TRIM_AT = 400        # これを超えたら KEEP 件まで古いものを削除
HISTORY = 50         # 接続直後に送る過去ログ件数
RATE_SEC = 1.0       # 同一IPの最短投稿間隔(秒)

STREAM_SEC = 50      # 1接続あたりの最大維持時間(秒)。切れてもブラウザが自動再接続する
POLL_SEC = 0.5       # ログ更新の確認間隔
HEARTBEAT_SEC = 10   # 無通信時にコメント行を送る間隔

STRIP = set('\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e'
            '\u2066\u2067\u2068\u2069\ufeff')


# ---- 共通 ----------------------------------------------------------
def out(b):
    sys.stdout.buffer.write(b)
    sys.stdout.buffer.flush()


def header(lines):
    out(('\r\n'.join(lines) + '\r\n\r\n').encode('utf-8'))


CORS = 'Access-Control-Allow-Origin: *'


def json_response(obj, status=200):
    reason = {200: 'OK', 400: 'Bad Request', 405: 'Method Not Allowed',
              429: 'Too Many Requests', 500: 'Internal Server Error'}.get(status, 'OK')
    header([
        'Status: %d %s' % (status, reason),
        'Content-Type: application/json; charset=utf-8',
        'Cache-Control: no-store',
        CORS,
    ])
    out(json.dumps(obj, ensure_ascii=False).encode('utf-8'))


def clean(s, limit):
    """改行・制御文字・不可視/方向制御文字を除去し、空白を整えて切り詰める"""
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    s = ''.join(ch for ch in s
                if ch not in STRIP and unicodedata.category(ch) not in ('Cc', 'Cs', 'Co', 'Cn'))
    return ' '.join(s.split())[:limit]


def read_log():
    try:
        with open(LOG, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    msgs = []
    for ln in lines:
        try:
            m = json.loads(ln)
            if isinstance(m, dict) and 'id' in m:
                msgs.append(m)
        except ValueError:
            pass  # 書き込み途中の行などは無視
    return msgs


class Lock(object):
    def __enter__(self):
        self.f = open(LOCK, 'a')
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def first(params, key, default=''):
    v = params.get(key)
    return v[0] if v else default


# ---- 投稿 ----------------------------------------------------------
def post(params):
    name = clean(first(params, 'name'), MAX_NAME) or '名無し'
    text = clean(first(params, 'text'), MAX_TEXT)
    if not text:
        return json_response({'ok': False, 'error': 'メッセージが空です'}, 400)

    ip = os.environ.get('REMOTE_ADDR', '')
    key = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:16]
    now = time.time()

    with Lock():
        # 連投制限
        try:
            with open(RATE, 'r', encoding='utf-8') as f:
                rate = json.load(f)
        except (OSError, ValueError):
            rate = {}
        rate = {k: v for k, v in rate.items() if now - v < 60}
        if now - rate.get(key, 0) < RATE_SEC:
            return json_response({'ok': False, 'error': '連投しないでください'}, 429)
        rate[key] = now
        with open(RATE, 'w', encoding='utf-8') as f:
            json.dump(rate, f)

        # 追記
        msgs = read_log()
        nid = (msgs[-1]['id'] if msgs else 0) + 1
        msg = {'id': nid, 't': int(now), 'n': name, 'm': text}
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(msg, ensure_ascii=False) + '\n')

        # 古いログの切り詰め(一時ファイル→置換で読み手に中途半端な状態を見せない)
        if len(msgs) + 1 > TRIM_AT:
            keep = (msgs + [msg])[-KEEP:]
            tmp = LOG + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                for m in keep:
                    f.write(json.dumps(m, ensure_ascii=False) + '\n')
            os.replace(tmp, LOG)

    json_response({'ok': True, 'id': nid})


# ---- SSE -----------------------------------------------------------
def stream(params):
    # 自動再接続時はブラウザが Last-Event-ID ヘッダを付けるので、そちらを優先
    last = 0
    try:
        hdr = os.environ.get('HTTP_LAST_EVENT_ID', '')
        last = int(hdr) if hdr else int(first(params, 'from', '0') or 0)
    except ValueError:
        last = 0

    header([
        'Status: 200 OK',
        'Content-Type: text/event-stream; charset=utf-8',
        'Cache-Control: no-cache',
        'X-Accel-Buffering: no',
        CORS,
    ])

    # 初回(from=0)は直近 HISTORY 件だけ送る
    if last <= 0:
        msgs = read_log()
        newest = msgs[-1]['id'] if msgs else 0
        last = max(0, newest - HISTORY)

    try:
        out(b'retry: 2000\n\n')
        t0 = time.time()
        last_send = t0
        sig = object()       # 初回は必ずログを読む
        ready_sent = False

        while time.time() - t0 < STREAM_SEC:
            try:
                st = os.stat(LOG)
                cur = (st.st_mtime_ns, st.st_size)
            except OSError:
                cur = None

            if cur != sig:
                sig = cur
                for m in read_log():
                    if m['id'] > last:
                        out(('id: %d\ndata: %s\n\n' %
                             (m['id'], json.dumps(m, ensure_ascii=False))).encode('utf-8'))
                        last = m['id']
                        last_send = time.time()
                if not ready_sent:
                    # 過去ログ/取りこぼし分の送信が終わった合図
                    out(b'event: ready\ndata: 1\n\n')
                    ready_sent = True
                    last_send = time.time()

            if time.time() - last_send >= HEARTBEAT_SEC:
                out(b': ping\n\n')
                last_send = time.time()

            time.sleep(POLL_SEC)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass  # クライアント切断


# ---- エントリポイント ------------------------------------------------
def main():
    method = os.environ.get('REQUEST_METHOD', 'GET').upper()
    qs = parse_qs(os.environ.get('QUERY_STRING', ''), keep_blank_values=True)

    if method == 'OPTIONS':
        header(['Status: 204 No Content', CORS,
                'Access-Control-Allow-Methods: GET, POST, OPTIONS',
                'Access-Control-Allow-Headers: Content-Type, Last-Event-ID',
                'Access-Control-Max-Age: 86400'])
        return

    if method == 'POST':
        try:
            n = min(int(os.environ.get('CONTENT_LENGTH') or 0), 4096)
        except ValueError:
            n = 0
        body = sys.stdin.buffer.read(n).decode('utf-8', 'replace')
        params = parse_qs(body, keep_blank_values=True)
        action = first(params, 'a') or first(qs, 'a')
        if action == 'post':
            return post(params)
        return json_response({'ok': False, 'error': 'bad request'}, 400)

    if method == 'GET':
        if first(qs, 'a') == 'stream':
            return stream(qs)
        return json_response({'ok': False, 'error': 'bad request'}, 400)

    json_response({'ok': False, 'error': 'method not allowed'}, 405)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # ヘッダ送信前の例外のみ500を返す(送信後は黙って終了)
        try:
            json_response({'ok': False, 'error': 'server error'}, 500)
        except Exception:
            pass
