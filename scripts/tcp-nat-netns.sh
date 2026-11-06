#!/bin/sh
# Builds a small lab in Linux network namespaces and replays a TCP session
# through a real NAT router: the kernel's routing, connection tracking and
# masquerading, as on a lab router between two VLANs.
#
#   ferotrx (this namespace)          router (namespace ferotrx-rtr)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.50(-53) vlan 20   masquerade out of rt.20
#
# Usage: sudo scripts/tcp-nat-netns.sh [path/to/ferotrx] [extra ferotrx tcp options]
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards, to see
# retransmits at work.
#
# MIX=1 plays a mix of templates instead of one session, like
# examples/lab-tcp-mix.toml: the HTTP session, a download on port 8080 and an
# echo on port 7, weighted 3:1:1, from the ten clients to four servers
# (192.168.20.50-53). It checks that every template completed connections.
#
# NETEM="delay 5ms reorder 10% 50% duplicate 2% loss 2%" impairs what the
# router forwards with netem (tc), both ways: delay, reordering, duplicates,
# loss, a rate limit. Needs the sch_netem module.
#
# BDP=1 plays a 2 MB download over a long fat pipe: 50 Mbit/s and 40 ms each
# way (netem; NETEM replaces that), 500 KB in flight to fill it. It checks
# that the server had more than 64 KB in flight, which needs window scaling.
#
# ECN=1 puts a bottleneck with an ECN-marking queue on the router, as an
# access link with fq_codel would have: 20 Mbit/s (tbf) into fq_codel with
# ecn, both ways. Three 2 MB downloads go through it with --ecn (add
# --congestion cubic to try CUBIC). It checks that every connection agreed
# on ECN, that the router marked CE and dropped nothing, and that the server
# slowed down for the marks without a single retransmission. Then, if
# python3 and ethtool are installed, the same with Linux as the sender: a
# web server on the router (its cubic, net.ipv4.tcp_ecn=1) and the emulated
# client with --ecn downloading from it, which must see CE marks and echo
# them. Needs the sch_tbf and sch_fq_codel modules.
#
# LOG_INVALID=1 logs why conntrack found packets INVALID (the router drops
# them) and prints the first of those kernel log lines at the end. It sets
# net.netfilter.nf_log_all_netns=1 on the host, which stays set.
#
# IPV6=1 does the same over IPv6: the client is fd00:10::100-109, the server
# fd00:20::50(-53), the router fd00:10::1 and fd00:20::1, and the emulated
# hosts find the router (and it them) with neighbor discovery instead of ARP.
# The router masquerades with ip6tables when the kernel has IPv6 NAT, else it
# only routes.
#
# QUEUES=4 gives the veth links four queues each, so a run with
# `--workers 4 -B af_xdp` has a queue per worker (veth needs XDP attached to
# use them; ferotrx's AF_XDP port does that).
#
# Without VLAN support in the kernel (no 8021q module), or with NO_VLAN=1, the
# client and the server get a link each instead of sharing a trunk:
#   c0 --- rc 192.168.10.1/24 (router) rs 192.168.20.1/24 --- s0
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
NS=ferotrx-rtr

cleanup() {
    for l in t0 c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
quiet_v6() { sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1" 2>/dev/null || true; }
# A router link moved into the namespace: no duplicate address detection.
no_dad() {
    [ "${IPV6:-}" = 1 ] || return 0
    r sysctl -qw "net/ipv6/conf/$1/accept_dad=0"
}

if [ "${IPV6:-}" = 1 ]; then
    if ! [ -d /proc/sys/net/ipv6 ]; then
        echo "IPV6=1, but this kernel has IPv6 disabled (ipv6.disable=1?)" >&2
        exit 2
    fi
    r sysctl -qw net.ipv6.conf.all.forwarding=1
    # No duplicate address detection on the router's links either, link-local
    # addresses included: while its link-local address is tentative (one to
    # two seconds after the link comes up), Linux cannot send the neighbor
    # solicitations it needs to forward to new hosts, and the first
    # connections stall.
    r sysctl -qw net.ipv6.conf.default.accept_dad=0
    r sysctl -qw net.ipv6.conf.all.accept_dad=0
    net() { echo "fd00:$1::"; }
    plen=64
    ipt() { r ip6tables "$@"; }
    # No duplicate address detection: the addresses work at once.
    addr() { r ip -6 addr add "$1" dev "$2" nodad; }
else
    net() { echo "192.168.$1."; }
    plen=24
    ipt() { r iptables "$@"; }
    addr() { r ip addr add "$1" dev "$2"; }
fi

queues=
if [ -n "${QUEUES:-}" ]; then
    queues="numtxqueues $QUEUES numrxqueues $QUEUES"
fi

vlan=yes
if [ "${NO_VLAN:-}" = 1 ]; then
    vlan=no
elif ! r ip link add dummy0 type dummy 2>/dev/null || ! r ip link add link dummy0 name probe.10 type vlan id 10 2>/dev/null; then
    echo "no VLAN support in this kernel: using one link per side"
    vlan=no
fi
r ip link del dummy0 2>/dev/null || true

set +e
if [ $vlan = yes ]; then
    # shellcheck disable=SC2086
    ip link add t0 $queues type veth peer name rt $queues
    ip link set rt netns $NS
    # No IPv6 on the trunk: router solicitations would only add noise.
    quiet_v6 t0
    no_dad rt
    ip link set t0 up
    r ip link set rt up
    # Tags in the frames, not beside them: a veth hands a tag it was given
    # aside to the other end aside too, where XDP (-B af_xdp) cannot see it,
    # as a NIC that strips tags on receive would.
    if command -v ethtool >/dev/null 2>&1; then
        r ethtool -K rt txvlan off >/dev/null 2>&1 || true
    fi
    r ip link add link rt name rt.10 type vlan id 10
    r ip link add link rt name rt.20 type vlan id 20
    no_dad rt.10
    no_dad rt.20
    addr "$(net 10)1/$plen" rt.10
    addr "$(net 20)1/$plen" rt.20
    r ip link set rt.10 up
    r ip link set rt.20 up
    out=rt.20
else
    for side in c:10 s:20; do
        n=${side%%:*}; net=${side##*:}
        # shellcheck disable=SC2086
        ip link add ${n}0 $queues type veth peer name r$n $queues
        ip link set r$n netns $NS
        quiet_v6 ${n}0
        no_dad r$n
        ip link set ${n}0 up
        addr "$(net $net)1/$plen" r$n
        r ip link set r$n up
    done
    out=rs
fi
if [ "${IPV6:-}" = 1 ]; then
    # In case the kernel still runs duplicate address detection: wait until
    # no address of the router is tentative.
    i=0
    while [ -n "$(r ip -6 addr show tentative)" ] && [ $i -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
fi
nat=yes
if ! ipt -t nat -A POSTROUTING -o $out -j MASQUERADE 2>/dev/null; then
    echo "no NAT for this IP version in the kernel: the router only routes"
    nat=no
fi
if [ -n "${LOSS:-}" ]; then
    ipt -A FORWARD -m statistic --mode random --probability "$LOSS" -j DROP
fi
if [ "${BDP:-}" = 1 ] && [ -z "${NETEM:-}" ]; then
    NETEM="delay 40ms rate 50mbit limit 5000"
fi
# The router's ways out: the trunk carries both directions; without VLANs,
# one link to each side.
if [ $vlan = yes ]; then links=rt; else links="rc rs"; fi
if [ "${ECN:-}" = 1 ]; then
    for l in $links; do
        if ! r tc qdisc add dev $l root handle 1: tbf rate 20mbit burst 20k latency 1s ||
            ! r tc qdisc add dev $l parent 1:1 fq_codel ecn; then
            echo "cannot add tbf and fq_codel on $l (no sch_tbf or sch_fq_codel module?)" >&2
            exit 2
        fi
    done
    echo "router: a 20 Mbit/s bottleneck into fq_codel, which marks ECN-capable packets"
fi
if [ -n "${NETEM:-}" ]; then
    for l in $links; do
        # shellcheck disable=SC2086
        if ! r tc qdisc add dev $l root netem $NETEM; then
            echo "cannot add netem on $l (no sch_netem module, or no tc?)" >&2
            exit 2
        fi
    done
    echo "router impairs what it forwards: netem $NETEM"
fi
# Drop what conntrack thinks is not part of a valid connection, as strict
# firewalls do: a stateless replay of a TCP session would not get through.
ipt -A FORWARD -m conntrack --ctstate INVALID -j DROP
# And on the way in to the router itself: conntrack does not undo the
# masquerading of an INVALID packet, so a server's reply that conntrack finds
# INVALID is addressed to the router, whose own TCP answers it with a reset
# that ends the connection (kube-proxy drops these for the same reason). The
# second rule counts the TCP packets that still reach the router itself.
ipt -A INPUT -m conntrack --ctstate INVALID -j DROP
ipt -A INPUT -p tcp
if [ "${LOG_INVALID:-}" = 1 ]; then
    # Why conntrack found packets INVALID, in the kernel log.
    modprobe nf_log_syslog 2>/dev/null || true
    sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null || true
    r sysctl -qw net.netfilter.nf_conntrack_log_invalid=6 2>/dev/null || true
    dmesg_start=$(dmesg 2>/dev/null | wc -l)
fi

# ECN=1: the router's queues marked packets CE and dropped none.
ecn_qdisc_check() {
    stats=$(for l in $links; do r tc -s qdisc show dev $l; done)
    marked=$(echo "$stats" | sed -n 's/.*ecn_mark \([0-9]*\).*/\1/p' | awk '{n += $1} END {print n + 0}')
    dropped=$(echo "$stats" | sed -n 's/.*(dropped \([0-9]*\),.*/\1/p' | awk '{n += $1} END {print n + 0}')
    echo "router: $marked packets marked CE, $dropped dropped"
    if [ "$marked" -eq 0 ]; then
        echo "FAIL: the router marked nothing: no ECN-capable packets, or no queue?" >&2
        return 1
    fi
    if [ "$dropped" -ne 0 ]; then
        echo "FAIL: the router dropped packets: they should have been marked" >&2
        return 1
    fi
}

# The addresses are given here rather than taken from examples/lab-tcp.toml,
# so editing that profile for a real lab does not break this script.
# (the client's alone too, for runs against a real server: client_links,
# client_hosts, and the number of link options before the caller's).
if [ $vlan = yes ]; then
    client_links="-i t0 --client-vlan 10"
    set -- -i t0 --client-vlan 10 --server-vlan 20 "$@"
    nlinks=6
else
    client_links="--client-iface c0"
    set -- --client-iface c0 --server-iface s0 "$@"
    nlinks=4
fi
client_hosts="--client-ip $(net 10)100/$plen --client-ips 10 --client-gw $(net 10)1"
hosts="$client_hosts --server-ip $(net 20)50/$plen --server-gw $(net 20)1"
if [ "${MIX:-}" = 1 ]; then
    examples=$(cd "$(dirname "$0")/../examples" && pwd)
    profile=$(mktemp /tmp/ferotrx-mix.XXXXXX)
    out=$(mktemp /tmp/ferotrx-mix-out.XXXXXX)
    cat >"$profile" <<EOT
[[template]]
name = "http"
pcap = "$examples/http.pcap"
weight = 3

[[template]]
name = "download"
pcap = "$examples/web.pcap"
port = 8080
weight = 1

[[template]]
name = "echo"
port = 7
closer = "server"
[[template.message]]
from = "client"
text = "hello from FeroTRX\r\n"
[[template.message]]
from = "server"
text = "hello from FeroTRX\r\n"

# Addresses come from the command line.
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$profile" $hosts --server-ips 4 \
        --cps 50 -n 500 --concurrency 50 "$@" >"$out" 2>&1
    status=$?
    cat "$out"
    # Every template must have completed connections, on both sides.
    for t in http download echo; do
        for side in client server; do
            if ! grep -Eq "^    $t $side: .* [1-9][0-9]* completed" "$out"; then
                echo "FAIL: template $t has no completed $side connections" >&2
                status=1
            fi
        done
    done
    # The router must have reached all four servers.
    servers=$(r ip neigh show | awk '/lladdr/ {print $1}' |
        grep -Fxc -e "$(net 20)50" -e "$(net 20)51" -e "$(net 20)52" -e "$(net 20)53" || true)
    echo "router knows $servers of the 4 servers"
    if [ "$servers" -ne 4 ]; then
        echo "FAIL: the clients did not connect to all four servers" >&2
        status=1
    fi
    rm -f "$profile" "$out"
elif [ "${BDP:-}" = 1 ] || [ "${ECN:-}" = 1 ]; then
    profile=$(mktemp /tmp/ferotrx-bdp.XXXXXX)
    out=$(mktemp /tmp/ferotrx-bdp-out.XXXXXX)
    {
        printf '%s\n' 'port = 8080'
        printf '%s\n' 'closer = "server"'
        printf '%s\n' '[[message]]'
        printf '%s\n' 'from = "client"'
        printf '%s\n' 'text = "GET /2MB HTTP/1.1\r\n\r\n"'
        printf '%s\n' '[[message]]'
        printf '%s\n' 'from = "server"'
        printf 'text = "'
        head -c 2097152 /dev/zero | tr '\0' 'x'
        printf '%s\n' '"'
        printf '%s\n' '[client]'
        printf '%s\n' 'ip = "0.0.0.0"'
        printf '%s\n' '[server]'
        printf '%s\n' 'ip = "0.0.0.0"'
    } >"$profile"
    ecn=
    [ "${ECN:-}" = 1 ] && ecn=--ecn
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$profile" $hosts -n 3 --cps 1 $ecn "$@" >"$out" 2>&1
    status=$?
    cat "$out"
    if [ "${BDP:-}" = 1 ]; then
        flight=$(sed -n 's/^  server: .*at most \([0-9]*\) bytes in flight.*/\1/p' "$out")
        echo "the server had at most ${flight:-?} bytes in flight"
        if [ -z "$flight" ] || [ "$flight" -le 65535 ]; then
            echo "FAIL: no more than 64 KB in flight: is window scaling working?" >&2
            status=1
        fi
    fi
    if [ "${ECN:-}" = 1 ]; then
        # ECN on all three, both ends; CE marks reached the client; the
        # server reduced for them and resent nothing.
        client=$(grep '^  client: ' "$out" || true)
        server=$(grep '^  server: ' "$out" || true)
        marks=$(echo "$client" | sed -n 's/.*ECN on 3, \([0-9]*\) CE marks received.*/\1/p')
        reductions=$(echo "$server" | sed -n 's/.*ECN on 3, [0-9]* CE marks received, \([0-9]*\) reductions.*/\1/p')
        rtx=$(echo "$server" | sed -n 's/.* \([0-9]*\) retransmits.*/\1/p')
        echo "ECN: ${marks:-?} CE marks at the client, ${reductions:-?} reductions at the server, ${rtx:-?} retransmits"
        if [ -z "$marks" ] || [ "$marks" -eq 0 ] || [ -z "$reductions" ] || [ "$reductions" -eq 0 ]; then
            echo "FAIL: no ECN, or no CE marks echoed and acted on" >&2
            status=1
        fi
        if [ "${rtx:-1}" -ne 0 ]; then
            echo "FAIL: the server retransmitted: the queue dropped instead of marking?" >&2
            status=1
        fi
        ecn_qdisc_check || status=1
    fi
    rm -f "$profile" "$out"
else
    # shellcheck disable=SC2086
    "$BIN" tcp examples/http.pcap $hosts \
        --cps 20 -n 200 --concurrency 50 "$@"
    status=$?
fi

if [ "${ECN:-}" = 1 ] && [ $status = 0 ]; then
    if command -v python3 >/dev/null 2>&1 && command -v ethtool >/dev/null 2>&1; then
        echo "== Linux as the sender: cubic with ECN on the router, the emulated client echoes"
        www=$(mktemp -d /tmp/ferotrx-www.XXXXXX)
        out=$(mktemp /tmp/ferotrx-ecn-out.XXXXXX)
        head -c 2097152 /dev/zero >"$www/big"
        r sysctl -qw net.ipv4.tcp_ecn=1
        r sysctl -qw net.ipv4.tcp_congestion_control=cubic 2>/dev/null || true
        echo "the router's TCP: $(r sysctl -n net.ipv4.tcp_congestion_control)," \
            "net.ipv4.tcp_ecn=$(r sysctl -n net.ipv4.tcp_ecn)"
        # Full checksums on what the router itself sends through the veth.
        if [ $vlan = yes ]; then rlinks="rt rt.10 rt.20"; else rlinks="rc rs"; fi
        for l in $rlinks; do r ethtool -K $l tx off >/dev/null 2>&1 || true; done
        if [ "${IPV6:-}" = 1 ]; then bind=::; else bind=0.0.0.0; fi
        (cd "$www" && exec ip netns exec $NS python3 -m http.server 8000 --bind $bind) \
            >/dev/null 2>&1 &
        pypid=$!
        sleep 1
        cat >"$www/client.toml" <<EOT
app = "http"
port = 8000
[http]
requests = ["GET /big 200"]
[client]
ip = "0.0.0.0"
EOT
        shift $nlinks
        # shellcheck disable=SC2086
        "$BIN" tcp -p "$www/client.toml" $client_links $client_hosts \
            --connect "$(net 10)1" -n 3 --cps 1 --ecn "$@" >"$out" 2>&1 || status=1
        kill $pypid 2>/dev/null || true
        wait $pypid 2>/dev/null || true
        cat "$out"
        client=$(grep '^  client: ' "$out" || true)
        marks=$(echo "$client" | sed -n 's/.*ECN on 3, \([0-9]*\) CE marks received.*/\1/p')
        echo "Linux as the sender: ${marks:-no ECN, no} CE marks echoed to it"
        if ! echo "$client" | grep -q '3 completed'; then
            echo "FAIL: the downloads from Linux did not complete" >&2
            status=1
        fi
        if [ -z "$marks" ] || [ "$marks" -eq 0 ]; then
            echo "FAIL: Linux did not agree on ECN, or nothing was marked" >&2
            status=1
        fi
        ecn_qdisc_check || status=1
        rm -rf "$www" "$out"
    else
        echo "no python3 or ethtool: skipping Linux as the sender"
    fi
fi

if [ "${IPV6:-}" = 1 ]; then
    # The router found the client addresses it answered by neighbor discovery.
    echo "router's IPv6 neighbors:"
    r ip -6 neigh show | grep -v '^fe80' || true
fi
if [ "${ECN:-}" = 1 ]; then
    echo "the router's bottleneck:"
    for l in $links; do r tc -s qdisc show dev $l; done
fi
if [ -n "${NETEM:-}" ]; then
    echo "netem on the router:"
    for l in $links; do r tc -s qdisc show dev $l | sed -n '1,3p'; done
fi
echo "router: connections masqueraded, and packets dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
echo "router: packets dropped on the way in to the router, and TCP that reached it:"
ipt -L INPUT -v -n | sed -n '3,$p'
if [ "${LOG_INVALID:-}" = 1 ]; then
    echo "conntrack's INVALID packets (first 20):"
    dmesg 2>/dev/null | sed -n "$((dmesg_start + 1)),\$p" | grep -i 'nf_ct' | head -20 || true
fi
exit $status
