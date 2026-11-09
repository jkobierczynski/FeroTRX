#!/bin/sh
# Builds a small lab in Linux network namespaces with the kernel as the far
# end of every tunnel FeroTRX makes, and checks that what goes in comes out.
#
#   ferotrx (this namespace)            tunnel endpoint (namespace ferotrx-tun)
#   c0 10.9.1.2 --- tunnels ----------- rc 10.9.1.1: ipip, gre (key 7),
#                                          gretap, vxlan (VNI 100), geneve
#                                          (VNI 200), MPLS label 100, sit
#   s0 receives  <--------------------- rs 10.9.2.1/24: the unwrapped packets,
#                                          routed to 10.9.2.2
#
# 1. Streams with latency signatures go into each tunnel the kernel has (the
#    packet builder makes them, one through an `encap=` rewrite); the kernel
#    unwraps them and routes the inner packets out of rs, where `--rx` counts
#    them. Every stream must arrive whole: same count, no loss.
# 2. A TCP run inside GTP-U, as from base stations to a user plane function:
#    ten clients 172.16.0.100-109 in tunnels from 10.9.1.2 (c0) to the server
#    172.16.1.50 at 10.9.2.2 (s0). The router only knows the outer addresses,
#    so the connections can only work through the tunnels. With tshark, it
#    checks on the router that each client had a TEID of its own. Then DNS
#    over UDP the same way, with the tunnels from a profile's [gtpu] table.
#
# Usage: sudo scripts/tunnel-netns.sh [path/to/ferotrx] [extra ferotrx run options]
# Needs root, ip (iproute2) and jq; tshark for the TEID check. Tunnel types
# the kernel lacks (modules ipip, ip_gre, vxlan, geneve, mpls_router,
# mpls_iptunnel, sit) are skipped and said so. Removes the lab when done.
#
# DURATION=3s how long the streams send
set -eu

# The binary: the first argument (unless it is an option), else a build in this checkout, else the
# installed one.
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
NS=ferotrx-tun
DURATION=${DURATION:-3s}
WORK=
CAP=

cleanup() {
    [ -z "$CAP" ] || kill "$CAP" 2>/dev/null || true
    for l in c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)
chmod 755 "$WORK"

for m in ipip ip_gre vxlan geneve mpls_router mpls_iptunnel sit; do
    modprobe $m 2>/dev/null || true
done

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
# The inner sources are on no link of the router: no reverse path filter.
r sysctl -qw net.ipv4.conf.all.rp_filter=0
r sysctl -qw net.ipv4.conf.default.rp_filter=0

for side in c:1 s:2; do
    n=${side%%:*}; net=${side##*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    r ip link set r$n address 02:00:00:00:0$net:01
    r ip addr add 10.9.$net.1/24 dev r$n
    r ip link set r$n up
    r sysctl -qw "net.ipv4.conf.r$n.rp_filter=0"
done
# The router's own UDP (VXLAN, Geneve) checks checksums: let veth fill them in.
ethtool -K c0 tx off >/dev/null 2>&1 || true
# The receiver is ferotrx in promiscuous mode on s0, and the tunnels' far
# end is ferotrx on c0: give the router their MACs so it need not ask.
r ip neigh replace 10.9.2.2 lladdr 02:00:00:00:02:02 dev rs nud permanent
r ip neigh replace 10.9.1.2 lladdr 02:00:00:00:01:02 dev rc nud permanent

# Each tunnel: a kernel device, then the packet that goes into it (outer
# headers from c0 to the router, inner from 10.9.<n>.2 to 10.9.2.2).
outer="eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.1.1)"
inner() { echo "ipv4(src=10.9.$1.2,dst=10.9.2.2)/udp(sport=4000,dport=$((5000 + $1)))/raw(len=200)"; }
STREAMS=
flow=0
skipped=
stream() {
    # name, packet[, extra TOML lines]
    flow=$((flow + 1))
    STREAMS="$STREAMS $1"
    cat >>"$WORK/lab.toml" <<EOF

[[stream]]
name = "$1"
packet = "$2"
rate = "500pps"
loops = 0
latency = $flow
${3:-}
EOF
}
: >"$WORK/lab.toml"

if r ip link add tipip type ipip local 10.9.1.1 remote 10.9.1.2 2>/dev/null; then
    r ip link set tipip up
    r sysctl -qw net.ipv4.conf.tipip.rp_filter=0
    stream ipip "$outer/$(inner 3)"
else skipped="$skipped ipip"; fi

if r ip link add tgre type gre local 10.9.1.1 remote 10.9.1.2 key 7 2>/dev/null; then
    r ip link set tgre up
    r sysctl -qw net.ipv4.conf.tgre.rp_filter=0
    stream gre "$outer/gre(key=7)/$(inner 4)"
else skipped="$skipped gre"; fi

if r ip link add tgtap type gretap local 10.9.1.1 remote 10.9.1.2 2>/dev/null; then
    r ip link set tgtap address 02:00:00:00:05:01 up
    r ip addr add 10.9.5.1/24 dev tgtap
    r sysctl -qw net.ipv4.conf.tgtap.rp_filter=0
    stream gretap "$outer/gre/eth(src=02:00:00:00:05:02,dst=02:00:00:00:05:01)/$(inner 5)"
else skipped="$skipped gretap"; fi

if r ip link add tvx type vxlan id 100 local 10.9.1.1 remote 10.9.1.2 dstport 4789 2>/dev/null; then
    r ip link set tvx address 02:00:00:00:06:01 up
    r ip addr add 10.9.6.1/24 dev tvx
    r sysctl -qw net.ipv4.conf.tvx.rp_filter=0
    stream vxlan "$outer/udp(sport=49152)/vxlan(vni=100)/eth(src=02:00:00:00:06:02,dst=02:00:00:00:06:01)/$(inner 6)"
    # The same tunnel, put on by a rewrite: plain packets in, VXLAN out.
    stream vxlan-encap "eth(src=02:00:00:00:06:02,dst=02:00:00:00:06:01)/$(inner 7)" \
        "rewrite = [\"encap=$outer/udp(sport=49153)/vxlan(vni=100)\"]"
    r ip route add 10.9.7.0/24 dev tvx
else skipped="$skipped vxlan"; fi

if r ip link add tgn type geneve id 200 remote 10.9.1.2 2>/dev/null; then
    r ip link set tgn address 02:00:00:00:08:01 up
    r ip addr add 10.9.8.1/24 dev tgn
    r sysctl -qw net.ipv4.conf.tgn.rp_filter=0
    stream geneve "$outer/udp(sport=49154)/geneve(vni=200)/eth(src=02:00:00:00:08:02,dst=02:00:00:00:08:01)/$(inner 8)"
else skipped="$skipped geneve"; fi

if r sysctl -qw net.mpls.platform_labels=1000 2>/dev/null &&
    r sysctl -qw net.mpls.conf.rc.input=1 &&
    r ip -f mpls route add 100 via inet 10.9.2.2 dev rs 2>/dev/null; then
    stream mpls "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/mpls(label=100,ttl=10)/$(inner 9)"
else skipped="$skipped mpls"; fi

# IPv6 inside IPv4, out of rs as IPv6.
if [ -d /proc/sys/net/ipv6 ] &&
    r ip link add tsit type sit local 10.9.1.1 remote 10.9.1.2 2>/dev/null; then
    r sysctl -qw net.ipv6.conf.all.forwarding=1
    r ip link set tsit up
    r ip -6 addr add fd00:9:2::1/64 dev rs nodad
    r ip -6 neigh replace fd00:9:2::2 lladdr 02:00:00:00:02:02 dev rs nud permanent
    stream sit "$outer/ipv6(src=fd00:9:a::2,dst=fd00:9:2::2)/udp(sport=4000,dport=5010)/raw(len=200)"
else skipped="$skipped sit"; fi

[ -z "$skipped" ] || echo "SKIP: this kernel has no$skipped tunnels"
if [ -z "$STREAMS" ]; then
    echo "no tunnel type available in this kernel" >&2
    exit 2
fi
echo "== streams through:$STREAMS"

fail=0
check() {
    if jq -e "$2" "$WORK/report.json" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        fail=1
    fi
}

set +e
"$BIN" run "$WORK/lab.toml" -i c0 --rx s0 -d "$DURATION" -q --report "$WORK/report.json" "$@"
status=$?
set -e
[ $status -eq 0 ] || exit $status
jq -r '.flows[] | "\(.name): \(.tx) sent, \(.rx) received, \(.lost) lost"' "$WORK/report.json"
n=$(echo "$STREAMS" | wc -w)
check "every tunnel delivered its stream" "(.flows | length) == $n and ([.flows[] | .tx > 500 and .rx == .tx] | all)"
check "no duplicates" '[.flows[] | .duplicates == 0] | all'

echo "== TCP inside GTP-U, through the router"
cap=no
if command -v tshark >/dev/null 2>&1; then
    r tshark -q -i rc -f "udp port 2152" -w "$WORK/gtp.pcap" 2>/dev/null &
    CAP=$!
    cap=yes
    sleep 2
fi
set +e
"$BIN" tcp examples/http.pcap --client-iface c0 --server-iface s0 \
    --client-ip 172.16.0.100/24 --client-ips 10 --client-gw 172.16.0.1 \
    --server-ip 172.16.1.50/24 --server-gw 172.16.1.1 \
    --client-gtpu local=10.9.1.2,remote=10.9.2.2,gateway=10.9.1.1,teid=1000,qfi=9,mac=02:00:00:00:01:02 \
    --server-gtpu local=10.9.2.2,remote=10.9.1.2,gateway=10.9.2.1,teid=1000,qfi=9,mac=02:00:00:00:02:02 \
    --cps 20 -n 100 --concurrency 20 >"$WORK/tcp.out" 2>&1
status=$?
set -e
cat "$WORK/tcp.out"
if [ $status -ne 0 ]; then
    echo "FAILED: the TCP run inside GTP-U ended with $status"
    fail=1
elif grep -Eq "client: .*100 completed" "$WORK/tcp.out"; then
    echo "ok: 100 connections completed inside GTP-U"
else
    echo "FAILED: not every connection completed inside GTP-U"
    fail=1
fi

echo "== DNS inside GTP-U, the tunnels from a profile's [gtpu] table"
cat >"$WORK/dns.toml" <<EOT
queries = ["www.lab.local A", "www.lab.local AAAA", "missing.lab.local A NXDOMAIN"]
records = ["www.lab.local A 172.16.1.80", "www.lab.local AAAA fd00:20::80"]
[client]
ip = "172.16.0.100/24"
ips = 10
gateway = "172.16.0.1"
iface = "c0"
[server]
ip = "172.16.1.53/24"
gateway = "172.16.1.1"
iface = "s0"
[gtpu]
client = "local=10.9.1.2,remote=10.9.2.2,gateway=10.9.1.1,teid=2000,mac=02:00:00:00:01:02"
server = "local=10.9.2.2,remote=10.9.1.2,gateway=10.9.2.1,teid=2000,mac=02:00:00:00:02:02"
EOT
set +e
"$BIN" udp -p "$WORK/dns.toml" --rate 100 -n 300 --concurrency 50 -q >"$WORK/udp.out" 2>&1
status=$?
set -e
cat "$WORK/udp.out"
if [ $status -eq 0 ] && grep -Eq "^  client: 300 transactions, 300 answered" "$WORK/udp.out"; then
    echo "ok: 300 DNS queries answered inside GTP-U"
else
    echo "FAILED: not every DNS query was answered inside GTP-U"
    fail=1
fi

if [ $cap = yes ]; then
    sleep 1
    kill "$CAP" 2>/dev/null || true
    wait "$CAP" 2>/dev/null || true
    CAP=
    teids=$(tshark -r "$WORK/gtp.pcap" -Y "ip.src == 10.9.1.2 && gtp.teid < 2000" -T fields -e gtp.teid 2>/dev/null | sort -u | wc -l)
    # What tshark says about HTTP is about the recorded page (its PNG is not
    # one), not about the packets.
    bad=$(tshark -r "$WORK/gtp.pcap" -Y "(_ws.malformed or _ws.expert.severity >= warning) and not http" 2>/dev/null | wc -l)
    echo "router saw $teids uplink TEIDs, $bad malformed or warned packets"
    if [ "$teids" -eq 10 ] && [ "$bad" -eq 0 ]; then
        echo "ok: a TEID per client, and tshark is happy with every packet"
    else
        echo "FAILED: expected 10 uplink TEIDs and no tshark warnings"
        fail=1
    fi
else
    echo "no tshark: TEIDs not checked"
fi
exit $fail
