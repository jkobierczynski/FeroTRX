#!/bin/sh
# Checks the traffic limits of a control server (`ferotrx serve
# --allow-iface/--allow-dst/--max-pps/--max-duration/--allow-unlimited`):
# starts beyond them are refused, and what is sent stays below --max-pps on
# a real veth, as counted at its other end.
#
#   namespace ftrx-lim-a                       namespace ftrx-lim-b
#   ferotrx serve, a0 10.9.7.1 --------------- b0 10.9.7.2 (counts frames)
#
# 1. Refusals: a profile at 5000 pps (--max-pps 1000), an interface not
#    allowed, a destination outside 10.9.7.0/24, top speed, a duration
#    beyond --max-duration; each names its limit, and the audit log has a
#    limit_refused record.
# 2. 800 pps for 3 s: about 2400 frames reach b0.
# 3. With --allow-unlimited, top speed for 3 s: no more than about 3000
#    frames (1000 pps) reach b0.
# 4. A run without a duration ends at --max-duration.
#
# Usage: sudo scripts/limits-netns.sh [path/to/ferotrx]
# Needs root and ip (iproute2). Removes the lab when done.
set -eu

if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    BIN=$1
    shift
else
    BIN=
    for b in ./target/debug/ferotrx ./target/release/ferotrx; do
        if [ -x "$b" ] && { [ -z "$BIN" ] || [ "$b" -nt "$BIN" ]; }; then BIN=$b; fi
    done
    [ -n "$BIN" ] || BIN=$(command -v ferotrx || true)
fi
if [ -z "$BIN" ] || ! [ -x "$BIN" ]; then
    echo "ferotrx not found${BIN:+ at $BIN}: build it first (cargo build -p ferotrx-cli)," >&2
    echo "or give its path: sudo $0 path/to/ferotrx" >&2
    exit 1
fi
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
echo "using $BIN"
A=ftrx-lim-a
B=ftrx-lim-b
WORK=
SERVER=

stop_server() {
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2>/dev/null || true
        wait "$SERVER" 2>/dev/null || true
        SERVER=
    fi
}
cleanup() {
    stop_server
    ip netns del $A 2>/dev/null || true
    ip netns del $B 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)
mkdir -p "$WORK/data"

ip netns add $A
ip netns add $B
ip link add a0 netns $A type veth peer name b0 netns $B
for s in a:1:$A b:2:$B; do
    n=${s%%:*}; rest=${s#*:}; k=${rest%%:*}; ns=${rest#*:}
    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.all.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set ${n}0 address 02:00:00:00:07:0$k
    ip netns exec "$ns" ip addr add 10.9.7.$k/24 dev ${n}0
    ip netns exec "$ns" ip link set ${n}0 up
done
INA="ip netns exec $A"
INB="ip netns exec $B"

fail=0
ok() { echo "ok: $1"; }
bad() { echo "FAILED: $1"; fail=1; }

eth="eth(src=02:00:00:00:07:01,dst=02:00:00:00:07:02)"
cat > "$WORK/data/flood.toml" <<EOF
[[stream]]
name = "flood"
packet = "$eth/ipv4(src=10.9.7.1,dst=10.9.7.2)/udp(sport=4000,dport=9)/raw(len=60)"
rate = "5000pps"
loops = 0
EOF
cat > "$WORK/data/away.toml" <<EOF
[[stream]]
name = "away"
packet = "$eth/ipv4(src=10.9.7.1,dst=10.9.8.9)/udp(sport=4000,dport=9)/raw(len=60)"
rate = "100pps"
loops = 0
EOF

ctl() { $INA "$BIN" ctl -c 127.0.0.1 "$@"; }

# serve [OPTIONS...]: a server in A with the limits and the options given.
serve() {
    stop_server
    $INA "$BIN" serve --listen 127.0.0.1:4510 --data-dir "$WORK/data" \
        --audit-log "$WORK/audit.log" \
        --allow-iface a0 --allow-dst 10.9.7.0/24 --max-pps 1000 --max-duration 4s \
        "$@" 2>"$WORK/serve.log" &
    SERVER=$!
    i=0
    until ctl info >/dev/null 2>&1; do
        i=$((i + 1))
        [ $i -lt 100 ] || { cat "$WORK/serve.log"; echo "the server does not answer" >&2; exit 1; }
        sleep 0.1
    done
    ctl load "$WORK/data/flood.toml" >/dev/null
    ctl load "$WORK/data/away.toml" >/dev/null
}

# refused WHAT FLAG ARGS...: `ctl start ARGS` fails, naming FLAG.
refused() {
    what=$1; flag=$2; shift 2
    if ctl start "$@" >"$WORK/out.txt" 2>&1; then
        bad "$what: the run started"
        cat "$WORK/out.txt"
    elif grep -q -- "$flag" "$WORK/out.txt"; then
        ok "$what: refused ($flag)"
    else
        bad "$what: refused without naming $flag"
        cat "$WORK/out.txt"
    fi
}

rx() { $INB cat /sys/class/net/b0/statistics/rx_packets; }

# sent RUN-ARGS...: frames b0 receives while `ctl start ARGS --watch` goes.
sent() {
    before=$(rx)
    ctl start "$@" --watch >"$WORK/run.txt" 2>&1 || { cat "$WORK/run.txt"; bad "the run failed"; }
    sleep 0.3
    echo $(($(rx) - before))
}

within() {
    what=$1; got=$2; lo=$3; hi=$4
    if [ "$got" -ge "$lo" ] && [ "$got" -le "$hi" ]; then
        ok "$what: $got frames (expected $lo-$hi)"
    else
        bad "$what: $got frames (expected $lo-$hi)"
    fi
}

echo "== 1. starts beyond the limits are refused"
serve
ctl info | grep -q "at most 1 kpps" && ok "ctl info shows the limits" || bad "ctl info shows no limits"
refused "5000 pps" --max-pps flood -i a0
refused "an interface not allowed" --allow-iface flood -i lo -r 100pps
refused "a destination outside the range" --allow-dst away -i a0
refused "top speed" --allow-unlimited flood -i a0 -r topspeed
refused "a duration beyond the limit" --max-duration flood -i a0 -r 100pps -d 10s
n=$(grep -c '"event":"limit_refused"' "$WORK/audit.log" || true)
if [ "$n" -ge 5 ]; then ok "the audit log has $n limit_refused records"; else bad "limit_refused records: $n"; fi

echo "== 2. a rate under the limit goes through"
within "800 pps for 3 s" "$(sent flood -i a0 -r 800pps -d 3s)" 2200 2500

echo "== 3. top speed is held to --max-pps"
serve --allow-unlimited
within "top speed for 3 s at 1000 pps" "$(sent flood -i a0 -r topspeed -d 3s)" 2600 3100

echo "== 4. a run without a duration ends at --max-duration"
began=$(date +%s)
ctl start flood -i a0 -r 200pps --watch >"$WORK/run.txt" 2>&1 || true
took=$(($(date +%s) - began))
if grep -q "finished" "$WORK/run.txt" && [ "$took" -ge 3 ] && [ "$took" -le 7 ]; then
    ok "it ended after ${took} s"
else
    bad "it ended after ${took} s:"
    cat "$WORK/run.txt"
fi

[ $fail -eq 0 ] && echo "all limit checks passed"
exit $fail
