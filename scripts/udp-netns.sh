#!/bin/sh
# Builds a small lab in Linux network namespaces and plays stateful UDP
# transactions through a real NAT router: the kernel's routing, connection
# tracking and masquerading, as on a lab router between two VLANs.
#
#   ferotrx (this namespace)          router (namespace ferotrx-udp)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (servers)
#     server 192.168.20.53 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/udp-netns.sh [path/to/ferotrx] [extra ferotrx udp options]
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# By default it plays DNS lookups (the queries and records of
# examples/lab-dns.toml, two of them answered with errors) and checks that every one was answered, with the
# expected response codes. Then, if `dig` and `ethtool` are installed, it runs the DNS server
# alone and asks it from the router with dig: a real resolver library must
# understand its answers.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards: the clients
# must ask again, and still get every answer.
#
# MIX=1 plays a mix instead, like examples/lab-udp-mix.toml: DNS from
# examples/dns-lookups.pcap, NTP at its own rate, and a two-round echo with
# capture timing, to two servers. It checks that every template was answered.
#
# IPV6=1 does the same over IPv6 (fd00:10::/64 and fd00:20::/64), with
# neighbor discovery instead of ARP. The router masquerades with ip6tables
# when the kernel has IPv6 NAT, else it only routes.
#
# NO_VLAN=1 (or no 8021q module) gives the client and the server a link each
# instead of a shared trunk.
set -eu

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
NS=ferotrx-udp
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-udp.XXXXXX)

cleanup() {
    [ -z "${server_pid:-}" ] || kill "$server_pid" 2>/dev/null || true
    for l in t0 c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT
for l in t0 c0 s0; do ip link del $l 2>/dev/null || true; done
ip netns del $NS 2>/dev/null || true

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
quiet_v6() { sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1" 2>/dev/null || true; }
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
    r sysctl -qw net.ipv6.conf.default.accept_dad=0
    r sysctl -qw net.ipv6.conf.all.accept_dad=0
    net() { echo "fd00:$1::"; }
    plen=64
    ipt() { r ip6tables "$@"; }
    addr() { r ip -6 addr add "$1" dev "$2" nodad; }
else
    net() { echo "192.168.$1."; }
    plen=24
    ipt() { r iptables "$@"; }
    addr() { r ip addr add "$1" dev "$2"; }
fi

vlan=yes
if [ "${NO_VLAN:-}" = 1 ]; then
    vlan=no
elif ! r ip link add dummy0 type dummy 2>/dev/null || ! r ip link add link dummy0 name probe.10 type vlan id 10 2>/dev/null; then
    echo "no VLAN support in this kernel: using one link per side"
    vlan=no
fi
r ip link del dummy0 2>/dev/null || true

if [ $vlan = yes ]; then
    ip link add t0 type veth peer name rt
    ip link set rt netns $NS
    quiet_v6 t0
    no_dad rt
    ip link set t0 up
    r ip link set rt up
    r ip link add link rt name rt.10 type vlan id 10
    r ip link add link rt name rt.20 type vlan id 20
    no_dad rt.10
    no_dad rt.20
    addr "$(net 10)1/$plen" rt.10
    addr "$(net 20)1/$plen" rt.20
    r ip link set rt.10 up
    r ip link set rt.20 up
    out=rt.20
    links="-i t0 --client-vlan 10 --server-vlan 20"
    server_links="-i t0 --server-vlan 20"
else
    for side in c:10 s:20; do
        n=${side%%:*}; net=${side##*:}
        ip link add ${n}0 type veth peer name r$n
        ip link set r$n netns $NS
        quiet_v6 ${n}0
        no_dad r$n
        ip link set ${n}0 up
        addr "$(net $net)1/$plen" r$n
        r ip link set r$n up
    done
    out=rs
    links="--client-iface c0 --server-iface s0"
    server_links="--server-iface s0"
fi
if [ "${IPV6:-}" = 1 ]; then
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

hosts="--client-ip $(net 10)100/$plen --client-ips 10 --client-gw $(net 10)1
       --server-ip $(net 20)53/$plen --server-gw $(net 20)1"
status=0
log=$tmp/out

# A transaction count, as the summary line of a side reports it.
count() { # side, what
    sed -n "s/^  $1: \([0-9]*\) transactions, \([0-9]*\) answered.*/\\$2/p" "$log"
}

if [ "${MIX:-}" = 1 ]; then
    cat >"$tmp/mix.toml" <<EOT
transactions = 300
rate = 100
[[template]]
name = "dns"
app = "dns"
pcap = "$examples/dns-lookups.pcap"
weight = 4
[[template]]
name = "ntp"
app = "ntp"
rate = 20
transactions = 20
think_time = "2ms"
[[template]]
name = "echo"
port = 7
concurrency = 10
[[template.message]]
from = "client"
text = "ping 1"
[[template.message]]
from = "server"
text = "pong 1"
[[template.message]]
from = "client"
text = "ping 2"
delay = "20ms"
[[template.message]]
from = "server"
text = "pong 2"
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
[udp]
timeout = "300ms"
retries = 5
keep_timing = true
EOT
    # shellcheck disable=SC2086
    "$BIN" udp -p "$tmp/mix.toml" $links $hosts --server-ips 2 -q "$@" >"$log" 2>&1 || status=$?
    cat "$log"
    for t in dns ntp echo; do
        for side in client server; do
            if ! grep -Eq "^    $t $side: [0-9]+ transactions, [1-9][0-9]* answered" "$log"; then
                echo "FAIL: template $t has no answered $side transactions" >&2
                status=1
            fi
        done
    done
    servers=$(r ip neigh show | awk '/lladdr/ {print $1}' |
        grep -Fxc -e "$(net 20)53" -e "$(net 20)54" || true)
    echo "router knows $servers of the 2 servers"
    if [ "$servers" -ne 2 ]; then
        echo "FAIL: the clients did not send to both servers" >&2
        status=1
    fi
else
    # The queries and records of examples/lab-dns.toml; addresses and VLANs
    # come from the command line, so editing that file for a real lab does
    # not break this script.
    cat >"$tmp/dns.toml" <<EOT
queries = ["www.lab.local A", "www.lab.local AAAA", "lab.local MX", "lab.local TXT",
           "_sip._udp.lab.local SRV", "missing.lab.local A NXDOMAIN", "broken.lab.local A SERVFAIL"]
records = ["www.lab.local CNAME web.lab.local", "web.lab.local A 192.168.20.80",
           "web.lab.local AAAA fd00:20::80", "lab.local MX 10 mail.lab.local",
           "lab.local TXT \\"v=spf1 mx -all\\"", "_sip._udp.lab.local SRV 0 5 5060 sip.lab.local",
           "broken.lab.local SERVFAIL"]
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
    # shellcheck disable=SC2086
    "$BIN" udp -p "$tmp/dns.toml" $links $hosts \
        --rate 200 -n 600 --concurrency 100 --timeout 300ms --retries 5 -q "$@" >"$log" 2>&1 || status=$?
    cat "$log"
    sent=$(count client 1)
    answered=$(count client 2)
    echo "client: ${sent:-?} sent, ${answered:-?} answered"
    if [ "${sent:-0}" -ne 600 ] || [ "${answered:-0}" -ne 600 ]; then
        echo "FAIL: not every DNS query was answered" >&2
        status=1
    fi
    if [ -n "${LOSS:-}" ] && ! grep -Eq "^  client: .* [1-9][0-9]* sent again" "$log"; then
        echo "FAIL: with loss, the clients never asked again" >&2
        status=1
    fi

    # Real resolver code against the emulated DNS server. The router's own
    # datagrams leave with the checksum left to the (virtual) NIC, which a
    # veth never fills in: have the kernel fill it in.
    if command -v dig >/dev/null 2>&1 && command -v ethtool >/dev/null 2>&1; then
        if [ $vlan = yes ]; then rlinks="rt rt.20"; else rlinks=rs; fi
        for l in $rlinks; do r ethtool -K $l tx off >/dev/null; done
        sed '/^\[client\]/,/^ip/d' "$tmp/dns.toml" >"$tmp/dns-server.toml"
        # shellcheck disable=SC2086
        "$BIN" udp -p "$tmp/dns-server.toml" $server_links \
            --server-ip $(net 20)53/$plen --server-gw $(net 20)1 -d 8s -q \
            >"$tmp/server" 2>&1 &
        server_pid=$!
        ask() { # name, type
            r dig @"$(net 20)53" "$1" "$2" +time=1 +tries=3 +norecurse +noall +comments +answer 2>&1 || true
        }
        sleep 1
        a=$(ask www.lab.local A)
        echo "$a" | sed 's/^/  dig: /'
        aaaa=$(ask www.lab.local AAAA)
        mx=$(ask lab.local MX)
        nx=$(ask missing.lab.local A)
        sf=$(ask broken.lab.local A)
        echo "$a" | grep -q "web.lab.local.*IN.*A.*192.168.20.80" || { echo "FAIL: dig got no A record" >&2; status=1; }
        echo "$a" | grep -q "status: NOERROR" || { echo "FAIL: dig: no NOERROR" >&2; status=1; }
        echo "$aaaa" | grep -q "AAAA.*fd00:20::80" || { echo "FAIL: dig got no AAAA record" >&2; status=1; }
        echo "$mx" | grep -q "MX.*10 mail.lab.local" || { echo "FAIL: dig got no MX record" >&2; status=1; }
        echo "$nx" | grep -q "status: NXDOMAIN" || { echo "FAIL: dig: no NXDOMAIN" >&2; status=1; }
        echo "$sf" | grep -q "status: SERVFAIL" || { echo "FAIL: dig: no SERVFAIL" >&2; status=1; }
        [ $status -ne 0 ] || echo "dig: A, AAAA, MX, NXDOMAIN and SERVFAIL as expected"
        wait "$server_pid" || true
        server_pid=
        cat "$tmp/server"
    else
        echo "no dig or ethtool: skipping the check with a real resolver"
    fi
fi

echo "router: datagrams masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
exit $status
