#!/bin/sh
# Builds a small lab in Linux network namespaces and measures loss and
# latency through a real router: the kernel's routing and masquerading, with
# delay (netem) and packet loss added on the way, as a WAN link would.
#
#   ferotrx (this namespace)            router (namespace ferotrx-lat)
#   c0 sends 10.9.1.2 -> 10.9.2.2 ----- rc 10.9.1.1/24
#                                       rs 10.9.2.1/24, masquerade, delay, loss
#   s0 receives  <--------------------- rs
#
# Two streams carry latency signatures and one does not; ferotrx sends on c0,
# receives on s0 and checks what it reports against what the router was told
# to do.
#
# Usage: sudo scripts/latency-netns.sh [path/to/ferotrx] [extra ferotrx run options]
# Needs root, ip (iproute2), tc and iptables (or iptables-nft). Removes the
# lab when done.
#
# DELAY=5ms   delay added by the router (needs the sch_netem module; without
#             it the delay is left out and not checked)
# LOSS=0.02   fraction of the packets the router drops (default 0)
# DURATION=4s how long to send
# IPV6=1      the same over IPv6: 10.9.1.x is fd00:9:1::x, 10.9.2.x is
#             fd00:9:2::x; the bulk stream also varies its source address. The
#             router masquerades with ip6tables when the kernel has IPv6 NAT,
#             else it only routes.
set -eu

# The binary: the first argument, else a build in this checkout, else the
# installed one.
if [ $# -gt 0 ]; then
    BIN=$1
    shift
else
    BIN=
    for b in ./target/debug/ferotrx ./target/release/ferotrx "$(command -v ferotrx || true)"; do
        if [ -n "$b" ] && [ -x "$b" ]; then BIN=$b; break; fi
    done
fi
if [ -z "$BIN" ] || ! [ -x "$BIN" ]; then
    echo "ferotrx not found${BIN:+ at $BIN}: build it first (cargo build -p ferotrx-cli)," >&2
    echo "or give its path: sudo $0 path/to/ferotrx" >&2
    exit 1
fi
echo "using $BIN"
NS=ferotrx-lat
DELAY=${DELAY:-5ms}
LOSS=${LOSS:-0}
DURATION=${DURATION:-4s}
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
if [ "${IPV6:-}" = 1 ]; then
    if ! [ -d /proc/sys/net/ipv6 ]; then
        echo "IPV6=1, but this kernel has IPv6 disabled (ipv6.disable=1?)" >&2
        exit 2
    fi
    r sysctl -qw net.ipv6.conf.all.forwarding=1
    a() { echo "fd00:9:$1::$2"; }
    plen=64
    ipt() { r ip6tables "$@"; }
    addr() { r ip -6 addr add "$1" dev "$2" nodad; }
else
    a() { echo "10.9.$1.$2"; }
    plen=24
    ipt() { r iptables "$@"; }
    addr() { r ip addr add "$1" dev "$2"; }
fi

for side in c:1 s:2; do
    n=${side%%:*}; net=${side##*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    # No IPv6: router solicitations would only add noise.
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    r ip link set r$n address 02:00:00:00:0$net:01
    addr "$(a $net 1)/$plen" r$n
    r ip link set r$n up
done
# The receiving host is ferotrx in promiscuous mode on s0; give the router
# its MAC so it need not ask.
r ip neigh replace "$(a 2 2)" lladdr 02:00:00:00:02:02 dev rs nud permanent
nat=yes
if ! ipt -t nat -A POSTROUTING -o rs -j MASQUERADE 2>/dev/null; then
    echo "no NAT for this IP version in the kernel: the router only routes"
    nat=no
fi
if [ "$LOSS" != 0 ]; then
    ipt -A FORWARD -m statistic --mode random --probability "$LOSS" -j DROP
fi
delay_us=0
if r tc qdisc add dev rs root netem delay "$DELAY" 2>/dev/null; then
    delay_us=$(echo "$DELAY" | awk '/ms$/ {print $1 * 1000; next} /us$/ {print $1 + 0; next} {print $1 * 1000000}')
    echo "router delays packets by $DELAY"
else
    echo "no netem in this kernel: no delay added, latency not checked"
fi

if [ "${IPV6:-}" = 1 ]; then
    ip="ipv6(src=$(a 1 2),dst=$(a 2 2))"
    voice_ip="ipv6(src=$(a 1 2),dst=$(a 2 2),tc=184)" # DSCP 46
    # 100 source addresses, stepping with the 100 source ports: 100 flows for
    # the router's connection tracking, as over IPv4. (256 addresses would
    # make lcm(256, 100) = 6400 flows, each a new NAT mapping.)
    vary_ip=", \"ip_src=$(a 1 100)..$(a 1 163)\""
else
    ip="ipv4(src=$(a 1 2),dst=$(a 2 2))"
    voice_ip="ipv4(src=$(a 1 2),dst=$(a 2 2),dscp=46)"
    vary_ip=
fi
eth="eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)"
cat > "$WORK/lab.toml" <<EOF
# Sent on c0 to the router (rc, 02:00:00:00:01:01), routed and masqueraded
# out of rs to $(a 2 2), received on s0.
[[stream]]
name = "voice"
packet = "$eth/$voice_ip/udp(sport=4000,dport=5004)/raw(len=160)"
interval = "1ms"
rate = "1000pps"
loops = 0
latency = true

[[stream]]
name = "bulk"
packet = "$eth/$ip/udp(sport=4001,dport=9000)/raw(len=1200)"
rate = "2000pps"
loops = 0
vary = ["port_src=4001..4100"$vary_ip]
latency = 7

# No signature: shows up as untagged on the receiver.
[[stream]]
name = "background"
packet = "$eth/$ip/udp(sport=4002,dport=9001)/raw(len=64)"
rate = "200pps"
loops = 0
EOF

set +e
"$BIN" run "$WORK/lab.toml" -i c0 --rx s0 -d "$DURATION" -q --report "$WORK/report.json" "$@"
status=$?
set -e
echo "router: connections masqueraded, and packets dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
# Where packets went missing, other than the LOSS rule: the router's IP
# counters and delay queue, and the links' drop counters.
echo "drops along the way (non-zero counters only):"
r nstat -az 2>/dev/null | awk '$1 ~ /Discard|NoRoute|TooBig|Drop|Fail/ && $2 > 0 {print "  router " $1 " " $2}' || true
r tc -s qdisc show dev rs 2>/dev/null | awk '/dropped/ {gsub("[(),]", ""); for (i = 1; i <= NF; i++) if ($i == "dropped" && $(i + 1) > 0) print "  router delay queue on rs: " $(i + 1) " dropped"}' || true
for l in c0 s0; do
    d=$(cat /sys/class/net/$l/statistics/rx_dropped /sys/class/net/$l/statistics/tx_dropped 2>/dev/null | paste -sd' ')
    [ "$d" = "0 0" ] || echo "  $l rx/tx dropped: $d"
done
for l in rc rs; do
    d=$(r cat /sys/class/net/$l/statistics/rx_dropped /sys/class/net/$l/statistics/tx_dropped 2>/dev/null | paste -sd' ')
    [ "$d" = "0 0" ] || echo "  router $l rx/tx dropped: $d"
done
[ $status -eq 0 ] || exit $status

fail=0
check() {
    if jq -e "$2" "$WORK/report.json" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        fail=1
    fi
}
check "two flows with signatures, voice and bulk" \
    '[.flows[].name] == ["voice", "bulk"] and [.flows[].flow] == [1, 7]'
check "every flow sent and received packets" '[.flows[] | .tx > 1000 and .rx > 1000] | all'
check "background traffic arrived without a signature" '.untagged > 100'
check "no duplicates" '[.flows[] | .duplicates == 0] | all'
# Reordering is not something the router was told to do, but the kernel does
# some on a busy machine or VM: veth queues a packet on the CPU the sender ran
# on, and packets of different connections (bulk varies its source port) are
# processed on different CPUs. So it is shown, and only a lot of it fails.
jq -r '.flows[] | "\(.name): \(.out_of_order) of \(.rx) packets out of order"' "$WORK/report.json"
check "little reordering (under 5%)" '[.flows[] | .out_of_order <= .rx / 20] | all'
if [ "$LOSS" = 0 ]; then
    check "no loss" '[.flows[] | .lost == 0] | all'
else
    pct=$(awk "BEGIN {print $LOSS * 100}")
    check "loss near ${pct}%" "[.flows[] | .loss_pct > $pct / 3 and .loss_pct < $pct * 3] | all"
fi
if [ "$delay_us" != 0 ]; then
    check "latency at least the router's delay ($DELAY)" \
        "[.flows[] | .latency.min_us >= $delay_us * 0.95 and .latency.avg_us < $delay_us + 20000] | all"
else
    check "latency measured" '[.flows[] | .latency.min_us > 0 and .latency.max_us < 1000000] | all'
fi
exit $fail
