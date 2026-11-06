#!/bin/sh
# Builds a small lab in Linux network namespaces and tests two services the
# Y.1564 way through a router that polices them, as a provider edge would:
#
#   ferotrx (this namespace)            router (namespace ferotrx-y1564)
#   c0 sends 10.9.1.2 -> 10.9.2.x ----- rc 10.9.1.1/24, policers by DSCP
#   s0 receives  <--------------------- rs 10.9.2.1/24
#
#   voice  DSCP 46, CIR 4 Mbit/s, no EIR: color blind, policed to 4 Mbit/s
#   data   DSCP 10 green, CIR 10 Mbit/s; DSCP 12 yellow, EIR 5 Mbit/s:
#          color aware, green policed to 10 Mbit/s and yellow to 5 Mbit/s
#
# The policers are tc police actions on the router's ingress (act_police);
# a kernel without them gets htb classes with short queues on its egress
# instead, which drop the excess the same way.
#
# 1. The test passes: every configuration step (50% and 100% of the CIR,
#    CIR + EIR, policing, a CBS burst) and the performance test.
# 2. With data's green policer at 70% of its CIR ("set too low"), the test
#    fails: data's 100% step loses green frames; voice still passes.
#
# Usage: sudo scripts/y1564-netns.sh [path/to/ferotrx] [extra ferotrx y1564 options]
# Needs root, ip and tc (iproute2) and jq. Removes the lab when done.
#
# STEP=2s     length of each configuration step
# PERF=10s    length of the performance test
# LOW=only    run only the "policer too low" test; LOW=no skips it
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
NS=ferotrx-y1564
STEP=${STEP:-2s}
PERF=${PERF:-10s}
LOW=${LOW:-yes}
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
# The receiving hosts are ferotrx in promiscuous mode on s0.
for h in 2 3; do
    r ip neigh replace 10.9.2.$h lladdr 02:00:00:00:02:02 dev rs nud permanent
done
r sysctl -qw net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.rc.send_redirects=0

# police VOICE GREEN YELLOW: the rates of the three policers, Mbit/s.
# On ingress a policer sees the IP packet only; overhead 18 adds the
# Ethernet header and FCS, so it counts frames as ferotrx y1564 does.
mode=
police() {
    r tc qdisc del dev rc ingress 2>/dev/null || true
    r tc qdisc del dev rs root 2>/dev/null || true
    if [ "$mode" != htb ] &&
        r tc qdisc add dev rc ingress 2>/dev/null &&
        r tc filter add dev rc ingress protocol ip prio 1 u32 match ip dsfield 0xb8 0xfc \
            action police rate "$1"mbit burst 30k overhead 18 drop 2>/dev/null; then
        mode=police
        r tc filter add dev rc ingress protocol ip prio 2 u32 match ip dsfield 0x28 0xfc \
            action police rate "$2"mbit burst 30k overhead 18 drop
        r tc filter add dev rc ingress protocol ip prio 3 u32 match ip dsfield 0x30 0xfc \
            action police rate "$3"mbit burst 30k overhead 18 drop
    else
        mode=htb
        r tc qdisc del dev rc ingress 2>/dev/null || true
        r tc qdisc add dev rs root handle 1: htb default 9
        r tc class add dev rs parent 1: classid 1:9 htb rate 1000mbit quantum 1514
        n=1
        for rate in "$1" "$2" "$3"; do
            r tc class add dev rs parent 1: classid 1:$n htb rate "$rate"mbit ceil "$rate"mbit burst 30k quantum 1514
            r tc qdisc add dev rs parent 1:$n handle 1$n: pfifo limit 30
            n=$((n + 1))
        done
        r tc filter add dev rs parent 1: protocol ip prio 1 u32 match ip dsfield 0xb8 0xfc flowid 1:1
        r tc filter add dev rs parent 1: protocol ip prio 2 u32 match ip dsfield 0x28 0xfc flowid 1:2
        r tc filter add dev rs parent 1: protocol ip prio 3 u32 match ip dsfield 0x30 0xfc flowid 1:3
    fi
    echo "router: voice policed to $1 Mbit/s, data green to $2 and yellow to $3 ($mode)"
}

eth='eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)'
cat > "$WORK/y1564.toml" <<EOF
format = 1

[y1564]
line_rate = "100mbps"
tests = ["configuration", "performance"]
steps = [50, 100]
step_duration = "$STEP"
performance_duration = "$PERF"
interval = "1s"
rx_wait = "300ms"

[[service]]
name = "voice"
packet = "$eth/ipv4(src=10.9.1.2,dst=10.9.2.2,dscp=46)/udp(sport=5004,dport=5004)"
sizes = 252
cir = "4mbps"
flr = 0.1
ftd = "100ms"
availability = 99

[[service]]
name = "data"
packet = "$eth/ipv4(src=10.9.1.2,dst=10.9.2.3,dscp=10)/udp(sport=4000,dport=9000)"
yellow_packet = "$eth/ipv4(src=10.9.1.2,dst=10.9.2.3,dscp=12)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4063"]
sizes = "emix:aceg"
cir = "10mbps"
eir = "5mbps"
cbs = 6000
flr = 0.1
ftd = "100ms"
availability = 99
EOF

fail=0
check() {
    if jq -e "$2" "$3" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        fail=1
    fi
}
router_counters() {
    echo "router: policers and what they dropped:"
    if [ $mode = police ]; then
        r tc -s filter show dev rc ingress | grep -E 'match|Sent|dropped' || true
    else
        r tc -s qdisc show dev rs | grep -E 'qdisc|Sent' || true
    fi
}

if [ "$LOW" != only ]; then
    echo "== 1. policers at the services' rates: the test passes"
    police 4 10 5
    set +e
    "$BIN" y1564 "$WORK/y1564.toml" -i c0 --rx s0 --report "$WORK/pass.json" "$@"
    status=$?
    set -e
    router_counters
    [ $status -eq 0 ] && echo "ok: ferotrx y1564 passed" || { echo "FAILED: ferotrx y1564 exited with $status"; fail=1; }
    j="$WORK/pass.json"
    check "report carries run metadata" \
        '.format == "ferotrx-y1564-1" and .info.tx_interface.name == "c0" and (.info.profile_text | contains("[[service]]"))' "$j"
    check "every configuration step passed" '[.configuration[].passed] | all' "$j"
    check "the steps ran: 2 + policing for voice, 2 + CIR+EIR + policing + CBS for data" \
        '(.configuration | length) == 8' "$j"
    check "data policing: yellow above the EIR dropped, IR at most CIR + EIR" \
        '[.configuration[] | select(.step.kind == "policing") | .services[] | select(.service == "data")][0] | .yellow_flr_pct > 10 and .ir_mbps <= 15.75 and .flr_pct == 0' "$j"
    check "voice policing: color blind, IR at most the CIR" \
        '[.configuration[] | select(.step.kind == "policing") | .services[] | select(.service == "voice")][0] | .green_judged == false and .ir_mbps <= 4.2 and .ir_mbps > 3.6' "$j"
    check "performance: both services at their CIR, available" \
        '.performance as $p | $p.passed and ([$p.services[] | .availability_pct >= 99 and (.intervals | length) >= ($p.duration_s - 2)] | all)' "$j"
    jq -r '.configuration[], .performance | .name as $n | .services[] | "\($n) \(.service): IR \(.ir_mbps * 1000 | floor / 1000) Mbit/s, FLR \(.flr_pct)%, yellow lost \(.yellow_flr_pct // "-")%, \(if .passed then "pass" else "FAIL" end)"' "$j"
fi

if [ "$LOW" != no ]; then
    echo "== 2. data's green policer at 70% of its CIR: the test fails"
    police 4 7 5
    set +e
    "$BIN" y1564 "$WORK/y1564.toml" -i c0 --rx s0 --tests configuration \
        --report "$WORK/low.json" "$@" >/dev/null
    status=$?
    set -e
    router_counters
    [ $status -ne 0 ] && echo "ok: ferotrx y1564 failed, as it should" || { echo "FAILED: ferotrx y1564 passed with the policer too low"; fail=1; }
    j="$WORK/low.json"
    check "data at 100% of its CIR loses green frames" \
        '[.configuration[] | select(.step == {"kind":"cir","pct":100.0}) | .services[] | select(.service == "data")][0] | .passed == false and .flr_pct > 15' "$j"
    check "data at 50% of its CIR still passes" \
        '[.configuration[] | select(.step == {"kind":"cir","pct":50.0}) | .services[] | select(.service == "data")][0] | .passed' "$j"
    check "voice passes, data fails" \
        '([.services[] | select(.service == "voice")][0].passed) and ([.services[] | select(.service == "data")][0].passed | not)' "$j"
    echo "--- text report ---"
    cat "$WORK/low.txt"
fi
exit $fail
