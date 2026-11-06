#!/bin/sh
# Checks FeroTRX's own impairments, without netem: the two-port bridge
# (`ferotrx impair`) between two hosts in network namespaces, and a stream's
# `--impair` measured by a receiver on the far side.
#
#   namespace ftrx-imp-a                          namespace ftrx-imp-b
#   a0 10.9.3.1 ---- ia ==ferotrx impair== ib ---- b0 10.9.3.2
#
# 1. The hosts ping each other through the bridge with delay, jitter and
#    loss one way and delay the other: ping sees the round trip and the loss.
# 2. The bridge drops frames over an MTU and duplicates: large pings are
#    lost, small ones come back with duplicates.
# 3. `ferotrx run --impair` in a sends a stream with latency signatures, and
#    `ferotrx rx` in b measures the loss, delay and jitter it was given.
# 4. The bridge limits the rate: twice that rate in, about half lost, and
#    the queue's delay.
#
# Usage: sudo scripts/impair-netns.sh [path/to/ferotrx]
# Needs root, ip (iproute2), ping and jq. Removes the lab when done.
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
A=ftrx-imp-a
B=ftrx-imp-b
WORK=
BRIDGE=

cleanup() {
    [ -z "$BRIDGE" ] || kill "$BRIDGE" 2>/dev/null || true
    for l in ia ib; do ip link del $l 2>/dev/null || true; done
    ip netns del $A 2>/dev/null || true
    ip netns del $B 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

for side in a:1:$A b:2:$B; do
    n=${side%%:*}; rest=${side#*:}; k=${rest%%:*}; ns=${rest#*:}
    ip netns add "$ns"
    ip link add ${n}0 type veth peer name i$n
    ip link set ${n}0 netns "$ns"
    sysctl -qw "net.ipv6.conf.i$n.disable_ipv6=1" 2>/dev/null || true
    ip link set i$n up
    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.all.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set ${n}0 address 02:00:00:00:03:0$k
    ip netns exec "$ns" ip addr add 10.9.3.$k/24 dev ${n}0
    ip netns exec "$ns" ip link set ${n}0 up
    # Checksums in full: the bridge passes frames as they are, and offloaded
    # ones would arrive with partial checksums.
    ip netns exec "$ns" ethtool -K ${n}0 tx off >/dev/null 2>&1 || true
done
# Static neighbours, so that a lost ARP request does not cost a ping.
ip netns exec $A ip neigh replace 10.9.3.2 lladdr 02:00:00:00:03:02 dev a0 nud permanent
ip netns exec $B ip neigh replace 10.9.3.1 lladdr 02:00:00:00:03:01 dev b0 nud permanent

fail=0
ok() { echo "ok: $1"; }
bad() { echo "FAILED: $1"; fail=1; }
# check DESCRIPTION AWK-CONDITION: the condition over the numbers given after.
check() {
    what=$1; shift
    cond=$1; shift
    if awk -v a="${1:-}" -v b="${2:-}" -v c="${3:-}" "BEGIN { exit !($cond) }"; then
        ok "$what"
    else
        bad "$what (got ${*})"
    fi
}

bridge() {
    "$BIN" impair -i ia -o ib -q "$@" >"$WORK/bridge.txt" 2>&1 &
    BRIDGE=$!
    sleep 1
    if ! kill -0 $BRIDGE 2>/dev/null; then
        cat "$WORK/bridge.txt"
        echo "the bridge did not start" >&2
        exit 1
    fi
}
bridge_done() {
    wait $BRIDGE || { cat "$WORK/bridge.txt"; bad "the bridge failed"; }
    BRIDGE=
    sed 's/^/  bridge: /' "$WORK/bridge.txt"
}
# ping_stats NS ARGS: prints "loss% min avg max mdev duplicates".
ping_stats() {
    ns=$1; shift
    out=$(ip netns exec "$ns" ping -q "$@" 2>&1 || true)
    echo "$out" | sed 's/^/  ping: /' >&2
    loss=$(echo "$out" | sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p')
    dups=$(echo "$out" | sed -n 's/.*+\([0-9]*\) duplicates.*/\1/p')
    rtt=$(echo "$out" | sed -n 's|.*= \([0-9.]*\)/\([0-9.]*\)/\([0-9.]*\)/\([0-9.]*\) ms.*|\1 \2 \3 \4|p')
    echo "${loss:-100} ${rtt:-0 0 0 0} ${dups:-0}"
}

echo "== 1. delay, jitter and loss through the bridge"
bridge -d 9s --impair "delay=20ms jitter=2ms loss=5% seed=1" --impair-back "delay=10ms"
set -- $(ping_stats $A -c 400 -i 0.01 -W 1 10.9.3.2)
check "ping loss near 5% (one way only)" 'a >= 1.5 && a <= 10' "$1"
check "round trip at least 28 ms (20 +- 2 there, 10 back)" 'a >= 27.9' "$2"
# The average is not checked on ping: a VM's stalls add tens of ms to some
# round trips (ping's max). What the bridge held each frame is checked below.
echo "  round trip avg $3 ms, max $4 ms (a busy VM adds its own delay here)"
check "jitter shows (mdev over 0.4 ms)" 'a > 0.4' "$5"
bridge_done
lost=$(sed -n 's/.*ia -> ib: [0-9]* in, [0-9]* out, \([0-9]*\) lost.*/\1/p' "$WORK/bridge.txt")
check "the bridge counted what it lost" 'a > 0' "${lost:-0}"
held() { sed -n "s/.*$1: .* held ms avg \([0-9.]*\) min \([0-9.]*\) max \([0-9.]*\).*/\1 \2 \3/p" "$WORK/bridge.txt"; }
set -- $(held "ia -> ib")
check "the bridge held frames 20 ms +- 2 there" 'a >= 19.5 && a <= 20.5 && b >= 17.99 && c <= 22.01' "$1" "$2" "$3"
set -- $(held "ib -> ia")
check "and 10 ms back" 'a >= 9.99 && a <= 10.01' "$1"

echo "== 2. MTU and duplicates"
bridge -d 8s --impair "mtu=1000 duplicate=20% seed=5" --impair-back none
set -- $(ping_stats $A -c 10 -i 0.05 -W 1 -s 1200 10.9.3.2)
check "pings over the MTU are all lost" 'a == 100' "$1"
set -- $(ping_stats $A -c 200 -i 0.01 -W 1 -s 500 10.9.3.2)
check "pings under the MTU all come back" 'a == 0' "$1"
check "about 20% of them twice" 'a >= 15 && a <= 70' "$6"
bridge_done

echo "== 3. a stream's own impairments, measured by a receiver"
eth="eth(src=02:00:00:00:03:01,dst=02:00:00:00:03:02)"
cat > "$WORK/stream.toml" <<EOF
[[stream]]
name = "probe"
packet = "$eth/ipv4(src=10.9.3.1,dst=10.9.3.2)/udp(sport=4000,dport=9)/raw(len=100)"
interval = "1ms"
rate = "1000pps"
loops = 0
latency = true
impair = "delay=15ms jitter=3ms loss=2% seed=3"
EOF
bridge -d 9s --impair none --impair-back none
ip netns exec $B "$BIN" rx -i b0 -d 6s -q --report "$WORK/rx.json" >"$WORK/rx.txt" 2>&1 &
RX=$!
sleep 1
ip netns exec $A "$BIN" run "$WORK/stream.toml" -i a0 -d 4s -q 2>&1 | sed 's/^/  run: /'
wait $RX || { cat "$WORK/rx.txt"; bad "the receiver failed"; }
bridge_done
sed 's/^/  rx: /' "$WORK/rx.txt"
loss=$(jq '.flows[0].loss_pct' "$WORK/rx.json")
min=$(jq '.flows[0].latency.min_us' "$WORK/rx.json")
p50=$(jq '.flows[0].latency.p50_us' "$WORK/rx.json")
jit=$(jq '.flows[0].latency.jitter_us' "$WORK/rx.json")
check "receiver sees about 2% loss" 'a >= 1 && a <= 3.5' "$loss"
check "latency at least 12 ms (15 - 3)" 'a >= 12000' "$min"
# The median, not the mean: a VM's stalls make a few packets very late.
# (Percentiles are to within 12.5%.)
check "median latency about 15 ms" 'a >= 13000 && a <= 18500' "$p50"
check "jitter measured" 'a >= 300' "$jit"

echo "== 4. a rate limit"
cat > "$WORK/rate.toml" <<EOF
[[stream]]
name = "bulk"
packet = "$eth/ipv4(src=10.9.3.1,dst=10.9.3.2)/udp(sport=4001,dport=9)/raw(len=1000)"
interval = "1ms"
rate = "20mbps"
loops = 0
latency = true
EOF
# 1070-byte frames (signature included), 1094 on the wire: 0.875 ms each at
# 10 Mbit/s, so 50 queued wait up to 44 ms.
bridge -d 7s --impair "rate=10mbit limit=50" --impair-back none
ip netns exec $B "$BIN" rx -i b0 -d 5s -q --report "$WORK/rate.json" >"$WORK/rx.txt" 2>&1 &
RX=$!
sleep 1
ip netns exec $A "$BIN" run "$WORK/rate.toml" -i a0 -d 3s -q 2>&1 | sed 's/^/  run: /'
wait $RX || { cat "$WORK/rx.txt"; bad "the receiver failed"; }
bridge_done
sed 's/^/  rx: /' "$WORK/rx.txt"
loss=$(jq '.flows[0].loss_pct' "$WORK/rate.json")
p50=$(jq '.flows[0].latency.p50_us' "$WORK/rate.json")
check "about half lost at twice the rate" 'a >= 40 && a <= 60' "$loss"
check "the queue delays: about 44 ms when full (median)" 'a >= 30000 && a <= 55000' "$p50"
set -- $(held "ia -> ib")
check "and the bridge held no frame longer than the queue holds (44 ms)" 'c <= 44.5' "$1" "$2" "$3"
queue=$(sed -n 's/.*ia -> ib: .* \([0-9]*\) over the queue limit.*/\1/p' "$WORK/bridge.txt")
check "the bridge counted its tail drops" 'a > 0' "${queue:-0}"

exit $fail
