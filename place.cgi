#!/usr/bin/perl
# r/place風 キャンバス (Perl CGI + SSE) -- クールタイムなし
#
#   GET  place.cgi?a=board            現在のキャンバス(バイナリ) + X-Seq ヘッダ
#   POST place.cgi  a=place&x=&y=&c=  ピクセルを置く
#   GET  place.cgi?a=stream&from=N    SSE ストリーム (N以降の更新を配信)
#
# 状態はファイルで共有する(CGIはリクエストごとに別プロセスのため)
#   data/board.bin  W*H バイト (1ピクセル=色番号1バイト)
#   data/log5.bin   更新ログ (1件=5バイト x(16bit),y(16bit),c(8bit))。ログの件数がシーケンス番号

use strict;
use warnings;
use Fcntl qw(:flock SEEK_SET);

my ($W, $H, $NCOL) = (2000, 2000, 64);   # W,H は 65535 以下
my $DIR   = $ENV{PLACE_DATA} || './data';
my $BOARD = "$DIR/board.bin";
my $LOG   = "$DIR/log5.bin";
my $LOCK  = "$DIR/lock";
my $IP_LOG = "$DIR/ip_rate.dat";
my $REC   = 5;
my $MAX_LIFETIME = 300;                # 1接続の最大秒数(切れてもクライアントが自動再接続)
my $BLOCK_TIME = 10800;
# IPレート制限（制限時間と許容アクセス数）
my $LIMIT_WINDOW = 60;                 # 監視する秒数
my $MAX_REQUESTS = 120;                 # 上記時間内の最大リクエスト数

# ---------- 共通 ----------
sub parse_params {
    my $q = $ENV{QUERY_STRING} // '';
    if (($ENV{REQUEST_METHOD} // '') eq 'POST') {
        my $len = $ENV{CONTENT_LENGTH} || 0;
        $len = 1024 if $len > 1024;
        read(STDIN, my $body, $len);
        $q .= '&' . ($body // '');
    }
    my %p;
    for my $pair (split /&/, $q) {
        my ($k, $v) = split /=/, $pair, 2;
        next unless defined $k && length $k;
        $v //= '';
        for ($k, $v) { tr/+/ /; s/%([0-9A-Fa-f]{2})/chr hex $1/ge; }
        $p{$k} = $v;
    }
    return \%p;
}

sub init_storage {
    mkdir $DIR unless -d $DIR;
    open my $l, '>>', $LOCK or die "lock: $!";
    flock($l, LOCK_EX);
    unless (((-s $BOARD) // 0) == $W * $H) {
        open my $b, '>', $BOARD or die "board: $!";
        binmode $b;
        print $b "\0" x ($W * $H);
        close $b;
        unlink $LOG;
    }
    unless (-e $LOG) {
        open my $g, '>', $LOG or die "log: $!";
        close $g;
    }
    close $l;
}

sub fail {
    my ($status, $msg) = @_;
    print "Status: $status\nContent-Type: text/plain\n\n$msg\n";
    exit 0;
}

# ---------- IPごとのレート制限 ----------
sub check_ip_limit {
    my $ip  = $ENV{REMOTE_ADDR} // 'unknown';
    my $now = time;

    open my $l, '>>', $LOCK or fail(500, 'lock');
    flock($l, LOCK_EX);

    my %records;
    if (-e $IP_LOG) {
        open my $f, '<', $IP_LOG;
        while (<$f>) {
            chomp;
            my ($i, $t, $c, $b) = split /\t/;
            $b //= 0;
            # 監視期間内 または ブロック期限内のレコードを保持
            next unless defined $i && ($t > $now - $LIMIT_WINDOW || $b > $now);
            $records{$i} = { time => $t, count => $c, blocked_until => $b };
        }
        close $f;
    }

    my $rec = $records{$ip};

    # 既にブロック期間中の場合は弾く
    if ($rec && $rec->{blocked_until} > $now) {
        close $l;
        fail(429, 'Too Many Requests');
    }

    # カウント更新
    if (!$rec || $rec->{time} <= $now - $LIMIT_WINDOW) {
        $rec = { time => $now, count => 1, blocked_until => 0 };
    } else {
        $rec->{count}++;
    }

    # 制限を超えた場合、3時間ブロックをセット
    if ($rec->{count} > $MAX_REQUESTS) {
        $rec->{blocked_until} = $now + $BLOCK_TIME;
    }

    $records{$ip} = $rec;

    open my $out, '>', $IP_LOG or fail(500, 'ip_log');
    for my $i (keys %records) {
        print $out "$i\t$records{$i}{time}\t$records{$i}{count}\t$records{$i}{blocked_until}\n";
    }
    close $out;

    close $l;

    if ($rec->{blocked_until} > $now) {
        fail(429, 'Too Many Requests');
    }
}

# ---------- 現在のキャンバス ----------
sub do_board {
    open my $l, '>>', $LOCK or fail(500, 'lock');
    flock($l, LOCK_SH);
    open my $b, '<', $BOARD or fail(500, 'board');
    binmode $b;
    local $/;
    my $data = <$b>;
    close $b;
    my $seq = int(((-s $LOG) // 0) / $REC);
    close $l;

    $| = 1;
    binmode STDOUT;
    print "Content-Type: application/octet-stream\n",
          "Cache-Control: no-store\n",
          "X-Seq: $seq\n",
          "Content-Length: ", length($data), "\n\n";
    print $data;
}

# ---------- ピクセルを置く(クールタイムなし) ----------
sub do_place {
    fail(405, 'POST only') unless ($ENV{REQUEST_METHOD} // '') eq 'POST';
    my $p = shift;
    my ($x, $y, $c) = @{$p}{qw(x y c)};
    for ($x, $y, $c) { fail(400, 'bad params') unless defined && /^\d{1,4}$/; }
    fail(400, 'out of range') if $x >= $W || $y >= $H || $c >= $NCOL;

    open my $l, '>>', $LOCK or fail(500, 'lock');
    flock($l, LOCK_EX);

    open my $b, '+<', $BOARD or fail(500, 'board');
    binmode $b;
    seek $b, $y * $W + $x, SEEK_SET;
    print $b chr($c);
    close $b;

    open my $g, '>>', $LOG or fail(500, 'log');
    binmode $g;
    print $g pack('nnC', $x, $y, $c);
    close $g;

    close $l;
    print "Status: 204 No Content\n\n";
}

# ---------- SSE ----------
sub do_stream {
    my $p = shift;
    my $from = $ENV{HTTP_LAST_EVENT_ID};              # 自動再接続時はこちらが優先
    $from = $p->{from} unless defined $from && $from =~ /^\d+$/;
    $from = 0 unless defined $from && $from =~ /^\d+$/;

    $| = 1;
    binmode STDOUT;
    $SIG{PIPE} = sub { exit 0 };                      # クライアント切断で終了
    print "Content-Type: text/event-stream\n",
          "Cache-Control: no-cache\n",
          "X-Accel-Buffering: no\n\n",
          "retry: 1000\n\n";

    my $seq = $from + 0;
    my $avail0 = int(((-s $LOG) // 0) / $REC);
    $seq = $avail0 if $seq > $avail0;                 # ログが作り直された場合の保険

    my $start = time;
    my $last  = time;
    while (time - $start < $MAX_LIFETIME) {
        my $avail = int(((-s $LOG) // 0) / $REC);
        if ($avail > $seq) {
            my $n = $avail - $seq;
            $n = 2000 if $n > 2000;
            open my $f, '<', $LOG or last;
            binmode $f;
            seek $f, $seq * $REC, SEEK_SET;
            read $f, my $buf, $n * $REC;
            close $f;
            my @pts;
            for my $i (0 .. $n - 1) {
                my ($x, $y, $c) = unpack 'nnC', substr($buf, $i * $REC, $REC);
                push @pts, "$x,$y,$c";
            }
            $seq += $n;
            print "id: $seq\ndata: ", join(';', @pts), "\n\n";
            $last = time;
        } else {
            if (time - $last >= 15) {                 # プロキシに切られないためのハートビート
                print ": ping\n\n";
                $last = time;
            }
            select(undef, undef, undef, 0.1);
        }
    }
}

# ---------- ディスパッチ ----------
init_storage();
check_ip_limit();
my $p = parse_params();
my $a = $p->{a} // '';

if    ($a eq 'board')  { do_board() }
elsif ($a eq 'place')  { do_place($p) }
elsif ($a eq 'stream') { do_stream($p) }
else                   { fail(400, 'unknown action') }