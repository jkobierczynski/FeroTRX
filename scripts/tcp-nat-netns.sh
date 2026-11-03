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
# Without VLAN support in the kernel (no 8021q module), or with NO_VLAN=1, the
# client and the server get a link each instead of sharing a trunk:
#   c0 --- rc 192.168.10.1/24 (router) rs 192.168.20.1/24 --- s0
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
    ip link add t0 type veth peer name rt
    ip link set rt netns $NS
    # No IPv6 on the trunk: router solicitations would only add noise.
    quiet_v6 t0
    ip link set t0 up
    r ip link set rt up
    r ip link add link rt name rt.10 type vlan id 10
    r ip link add link rt name rt.20 type vlan id 20
    r ip addr add 192.168.10.1/24 dev rt.10
    r ip addr add 192.168.20.1/24 dev rt.20
    r ip link set rt.10 up
    r ip link set rt.20 up
    out=rt.20
else
    for side in c:10 s:20; do
        n=${side%%:*}; net=${side##*:}
        ip link add ${n}0 type veth peer name r$n
        ip link set r$n netns $NS
        quiet_v6 ${n}0
        ip link set ${n}0 up
        r ip addr add 192.168.$net.1/24 dev r$n
        r ip link set r$n up
    done
    out=rs
fi
r iptables -t nat -A POSTROUTING -o $out -j MASQUERADE
if [ -n "${LOSS:-}" ]; then
    r iptables -A FORWARD -m statistic --mode random --probability "$LOSS" -j DROP
fi
# Drop what conntrack thinks is not part of a valid connection, as strict
# firewalls do: a stateless replay of a TCP session would not get through.
r iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# The addresses are given here rather than taken from examples/lab-tcp.toml,
# so editing that profile for a real lab does not break this script.
if [ $vlan = yes ]; then
    set -- -i t0 --client-vlan 10 --server-vlan 20 "$@"
else
    set -- --client-iface c0 --server-iface s0 "$@"
fi
hosts="--client-ip 192.168.10.100/24 --client-ips 10 --client-gw 192.168.10.1
       --server-ip 192.168.20.50/24 --server-gw 192.168.20.1"
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
    servers=$(r ip neigh show | grep -c '^192\.168\.20\.5[0-3] .*lladdr')
    echo "router knows $servers of the 4 servers"
    if [ "$servers" -ne 4 ]; then
        echo "FAIL: the clients did not connect to all four servers" >&2
        status=1
    fi
    rm -f "$profile" "$out"
else
    # shellcheck disable=SC2086
    "$BIN" tcp examples/http.pcap $hosts \
        --cps 20 -n 200 --concurrency 50 "$@"
    status=$?
fi

echo "router: connections masqueraded, and packets dropped:"
r iptables -t nat -L POSTROUTING -v -n | sed -n '3p'
r iptables -L FORWARD -v -n | sed -n '3,$p'
exit $status
