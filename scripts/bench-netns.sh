#!/bin/sh
# Builds a small lab in Linux network namespaces and benchmarks a router the
# RFC 2544 way: the kernel routes between two veth links and a token bucket
# (tc tbf) limits what it forwards to RATE, with a small queue, as a slow
# WAN link would. `ferotrx bench` then has to find that rate (throughput),
# the loss above it (frame loss), the queue (back-to-back) and the latency.
#
#   ferotrx (this namespace)            router (namespace ferotrx-bench)
#   c0 sends 10.9.1.2 -> 10.9.2.2 ----- rc 10.9.1.1/24
#                                       rs 10.9.2.1/24, tbf RATE, (netem DELAY)
#   s0 receives  <--------------------- rs
#
# Usage: sudo scripts/bench-netns.sh [path/to/ferotrx] [extra ferotrx bench options]
# Needs root, ip (iproute2), tc and jq. Removes the lab when done.
#
# RATE=20      what the router forwards, Mbit/s of frames (default 20)
# LINE=100     the line rate the benchmark assumes, Mbit/s (default 100)
# DELAY=2ms    delay added by the router (needs sch_netem; without it the
#              delay is left out and not checked)
# SIZES="1020 imix"  frame sizes to test
# TRIAL=1s     length of each trial
set -eu

if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    BIN=$1
    shift
else
    BIN=
    # The newest of the debug and release builds, else the one on the PATH.
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
echo "using $BIN"
NS=ferotrx-bench
RATE=${RATE:-20}
LINE=${LINE:-100}
DELAY=${DELAY:-2ms}
SIZES=${SIZES:-1020 imix}
TRIAL=${TRIAL:-1s}
WORK=

cleanup() {
    for l in c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
for side in c:1 s:2; do
    n=${side%%:*}; net=${side##*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    r sysctl -qw "net.ipv6.conf.r$n.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    r ip link set r$n address 02:00:00:00:0$net:01
    r ip addr add 10.9.$net.1/24 dev r$n
    r ip link set r$n up
done
# The receiving host is ferotrx in promiscuous mode on s0.
r ip neigh replace 10.9.2.2 lladdr 02:00:00:00:02:02 dev rs nud permanent
# Answers from the router (ICMP errors, redirects) would only add noise.
r sysctl -qw net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.rc.send_redirects=0

# The bottleneck: RATE Mbit/s, a 16 KB bucket and at most 25 ms of queue, so
# a sender that stalls for a few ms in a VM and then catches up does not
# overflow it at loads below RATE.
tbf="tbf rate ${RATE}mbit burst 16kb latency 25ms"
delay_us=0
if r tc qdisc add dev rs root handle 1: netem delay "$DELAY" 2>/dev/null; then
    r tc qdisc add dev rs parent 1: handle 2: $tbf
    delay_us=$(echo "$DELAY" | awk '/ms$/ {print $1 * 1000; next} /us$/ {print $1 + 0; next} {print $1 * 1000000}')
    echo "router forwards ${RATE} Mbit/s, delayed by $DELAY"
else
    r tc qdisc add dev rs root $tbf
    echo "router forwards ${RATE} Mbit/s (no netem in this kernel: no delay added)"
fi

sizes=$(for s in $SIZES; do printf '"%s", ' "$s"; done)
cat > "$WORK/bench.toml" <<EOF
[benchmark]
packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4063"]
tests = ["throughput", "latency", "frame_loss", "back_to_back"]
sizes = [${sizes%, }]
line_rate = "${LINE}mbps"
trial_duration = "$TRIAL"
warmup = "200ms"
resolution = 1.0
max_trials = 8
frame_loss_step = 10
burst_max = 5000
rx_wait = "300ms"
EOF

set +e
"$BIN" bench "$WORK/bench.toml" -i c0 --rx s0 --report "$WORK/bench.json" "$@"
status=$?
set -e
echo "router: packets sent and dropped by the bottleneck:"
r tc -s qdisc show dev rs | grep -E 'qdisc|Sent' || true
[ $status -eq 0 ] || exit $status

fail=0
check() {
    if jq -e "$2" "$WORK/bench.json" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        fail=1
    fi
}
[ -s "$WORK/bench.txt" ] && echo "ok: text report written" || { echo "FAILED: no text report"; fail=1; }
check "report carries run metadata" \
    '.format == "ferotrx-bench-1" and (.info.ferotrx_version | length > 0) and .info.tx_interface.name == "c0" and .info.rx_interface.name == "s0" and (.info.kernel | length > 0) and (.info.profile_text | contains("[benchmark]"))'
check "every size has every result" \
    "([.sizes[] | .throughput != null and .latency != null and (.frame_loss | length > 0) and .back_to_back != null] | all) and (.sizes | length) == $(echo $SIZES | wc -w)"
check "no duplicates" '[.sizes[].trials[] | .duplicates == 0] | all'
# Throughput: frames forwarded without loss, a little below the bottleneck.
jq -r '.sizes[] | "\(.size): throughput \(.throughput.load_pct)% = \(.throughput.mbps | floor) Mbit/s of frames, back-to-back \(.back_to_back.frames) frames"' "$WORK/bench.json"
check "throughput near ${RATE} Mbit/s" \
    "[.sizes[].throughput | .mbps > $RATE * 0.5 and .mbps < $RATE * 1.1] | all"
# Frame loss at the line rate: what comes through is the bottleneck's rate.
check "at the line rate, the router passes about ${RATE} Mbit/s" \
    "[.sizes[] | [.trials[] | select(.test == \"frame_loss\" and .load_pct == 100)][0] | .loss_pct > 20 and .rx_mbps > $RATE * 0.6 and .rx_mbps < $RATE * 1.3] | all"
check "frame loss falls to 0 at low loads" '[.sizes[].frame_loss | last | .loss_pct == 0] | all'
check "back-to-back finds a finite burst" '[.sizes[].back_to_back | .frames > 0 and .at_limit == false] | all'
if [ "$delay_us" != 0 ]; then
    check "latency at least the router's delay ($DELAY)" \
        "[.sizes[].latency.latency | .min_us >= $delay_us * 0.95 and .avg_us < $delay_us + 30000] | all"
else
    check "latency measured" '[.sizes[].latency.latency | .min_us > 0 and .max_us < 100000] | all'
fi
echo "--- text report ---"
cat "$WORK/bench.txt"
exit $fail
