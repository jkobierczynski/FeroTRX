#!/bin/sh
# Builds a small LAN in a Linux network namespace and checks FeroTRX's host
# emulation against the kernel and a real DHCP server:
#
#   ferotrx (this namespace)          lab (namespace ferotrx-hosts)
#   h0 --- veth ------------------ hb ┐
#   h1 --- veth ------------------ hc ┼ br0 10.77.0.1/24, fd00:77::1/64
#                                   kh ┘  (bridge with IGMP/MLD snooping and
#                  k0 (namespace ferotrx-hosts-k)   a querier every 2 s)
#                                          dnsmasq: DHCP 10.77.0.100-199,
#                                          DHCPv6 and router advertisements
#
# Usage: sudo scripts/hosts-netns.sh [path/to/ferotrx] [extra ferotrx options]
# (the extra options, e.g. -B af_xdp, go to each `ferotrx host` and `ferotrx tcp`)
# Needs root, ip and bridge (iproute2), dnsmasq and ping. Removes the lab
# when done.
#
# It checks that:
#   1. three DHCP clients (`ferotrx host --ipv4 dhcp`) get leases from
#      dnsmasq, answer pings at them, join 239.1.2.3 (the bridge's snooping
#      table lists them on their port, and still does after several query
#      intervals: the hosts answer queries), count multicast pings sent to
#      the group, and release their leases at the end;
#   2. a static host's gratuitous ARP puts it in the lab's neighbor table
#      before anything was sent to it;
#   3. a TCP client with `--client-ip dhcp` gets a lease and plays
#      examples/http.pcap with a static server on the other link.
#
# IPV6=1 does the IPv6 side instead: SLAAC and DHCPv6 hosts (dnsmasq's
# router advertisements and DHCPv6), MLD joins of ff15::1234 in the snooping
# table, a FeroTRX router whose advertisements give a kernel host (k0) an
# address and a default route, and a TCP client with `--client-ip slaac`.
set -eu

if [ "$(id -u)" != 0 ]; then
    echo "needs root (network namespaces, a bridge): sudo $0 $*" >&2
    exit 2
fi

if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
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
for tool in ip bridge dnsmasq ping; do
    if ! command -v $tool >/dev/null 2>&1; then
        case $tool in
            ip | bridge) pkg=iproute2 ;;
            dnsmasq) pkg="dnsmasq-base (or dnsmasq)" ;;
            ping) pkg=iputils-ping ;;
        esac
        echo "$tool is not installed: apt-get install $pkg" >&2
        exit 2
    fi
done
echo "using $BIN"
NS=ferotrx-hosts
KNS=ferotrx-hosts-k
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-hosts.XXXXXX)
chmod 755 "$tmp"

cleanup() {
    [ -z "${dns_pid:-}" ] || kill "$dns_pid" 2>/dev/null || true
    [ -z "${host_pid:-}" ] || kill "$host_pid" 2>/dev/null || true
    for l in h0 h1; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    ip netns del $KNS 2>/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT
for l in h0 h1; do ip link del $l 2>/dev/null || true; done
ip netns del $NS 2>/dev/null || true
ip netns del $KNS 2>/dev/null || true

v6=no
if [ "${IPV6:-}" = 1 ]; then
    if ! [ -d /proc/sys/net/ipv6 ]; then
        echo "IPV6=1, but this kernel has IPv6 disabled (ipv6.disable=1?)" >&2
        exit 2
    fi
    v6=yes
fi

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r ip link add br0 type bridge mcast_snooping 1 mcast_querier 1 \
    mcast_igmp_version 3 mcast_mld_version 2 \
    mcast_query_interval 200 mcast_query_response_interval 100 \
    mcast_startup_query_interval 100 mcast_membership_interval 500
quiet_v6() { sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1" 2>/dev/null || true; }
for side in 0:b 1:c; do
    n=${side%%:*}; peer=h${side##*:}
    ip link add h$n type veth peer name $peer
    ip link set $peer netns $NS
    quiet_v6 h$n
    ip link set h$n up
    r ip link set $peer master br0
    r ip link set $peer up
done
if [ $v6 = yes ]; then
    r sysctl -qw net.ipv6.conf.br0.accept_dad=0
fi
r ip link set br0 up
r ip addr add 10.77.0.1/24 dev br0
# Gratuitous ARPs may make new neighbor entries (check 2).
r sysctl -qw net.ipv4.conf.br0.arp_accept=1
if [ $v6 = yes ]; then
    r ip -6 addr add fd00:77::1/64 dev br0 nodad
    i=0
    while [ -n "$(r ip -6 addr show dev br0 tentative)" ] && [ $i -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
fi

leases=$tmp/leases
: >"$leases"
dhcp6=
if [ $v6 = yes ]; then
    # DHCPv6 from the range, and router advertisements that also offer
    # the prefix for autoconfiguration (A and M flags).
    dhcp6="--enable-ra --dhcp-range=fd00:77::100,fd00:77::1ff,slaac,64,2m --ra-param=br0,3"
fi
# shellcheck disable=SC2086
r dnsmasq --no-daemon --conf-file=/dev/null --port=0 --no-resolv --no-hosts \
    --interface=br0 --bind-interfaces --dhcp-authoritative --no-ping \
    --dhcp-range=10.77.0.100,10.77.0.199,2m --dhcp-option=3,10.77.0.1 \
    --dhcp-leasefile="$leases" --log-dhcp $dhcp6 \
    >"$tmp/dnsmasq.log" 2>&1 &
dns_pid=$!
sleep 1
if ! kill -0 $dns_pid 2>/dev/null; then
    echo "dnsmasq did not start:" >&2
    cat "$tmp/dnsmasq.log" >&2
    exit 1
fi

status=0
fail() {
    echo "FAIL: $*"
    status=1
}

# The bridge's snooping table has GROUP on PORT.
in_mdb() { # port group
    r bridge mdb show dev br0 | grep "port $1 " | grep -q "grp $2 "
}

# Waits up to 10 s for the host run to print a line matching $1.
wait_for() {
    i=0
    while ! grep -q "$1" "$tmp/host.log" 2>/dev/null; do
        if ! kill -0 "$host_pid" 2>/dev/null || [ $i -ge 100 ]; then
            return 1
        fi
        sleep 0.1
        i=$((i + 1))
    done
}

if [ $v6 = no ]; then
    echo "== 1. DHCP clients with a multicast group"
    "$BIN" host -i h0 --count 3 --ipv4 dhcp --hostname "lab-{n}" --join 239.1.2.3 \
        --duration 14s "$@" >"$tmp/host.log" 2>&1 &
    host_pid=$!
    i=0
    while [ "$(grep -c 02:dc:00:00:01:0 "$leases")" -lt 3 ] && [ $i -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    echo "leases:"
    sed 's/^/  /' "$leases"
    [ "$(grep -c 02:dc:00:00:01:0 "$leases")" = 3 ] || fail "dnsmasq did not lease 3 addresses"
    grep -q "lab-2" "$leases" || fail "the host names did not reach dnsmasq"
    for ip in $(awk '/02:dc:00:00:01:0/ {print $3}' "$leases"); do
        if r ping -c 1 -W 2 "$ip" >/dev/null; then
            echo "  $ip answers pings"
        else
            fail "no answer to a ping at $ip"
        fi
    done
    sleep 1
    in_mdb hb 239.1.2.3 || fail "239.1.2.3 is not in the snooping table on port hb"
    # The membership interval is 5 s: still there after 8 s more only if the
    # hosts answer the bridge's queries.
    sleep 8
    r bridge mdb show dev br0 | sed 's/^/  /'
    in_mdb hb 239.1.2.3 || fail "239.1.2.3 expired: the hosts did not answer queries"
    r ping -c 3 -i 0.2 -W 1 -t 1 -I br0 239.1.2.3 >/dev/null 2>&1 || true
    wait "$host_pid" || fail "ferotrx host failed"
    host_pid=
    cat "$tmp/host.log"
    [ "$(grep -c "ready after" "$tmp/host.log")" -ge 3 ] || fail "not every host got ready"
    grep -q "group 239.1.2.3 ([0-9]* reports, 3 frames received)" "$tmp/host.log" \
        || fail "the hosts did not count the 3 multicast pings"
    sleep 0.5
    if grep -q 02:dc:00:00:01:0 "$leases"; then
        fail "the leases were not released"
    else
        echo "  leases released"
    fi

    echo "== 2. A gratuitous ARP"
    r ip neigh flush dev br0
    "$BIN" host -i h0 --ipv4 10.77.0.50/24 --announce --until-ready "$@" >"$tmp/host.log" 2>&1 \
        || { cat "$tmp/host.log"; fail "ferotrx host failed"; }
    sleep 0.2
    r ip neigh show dev br0 | sed 's/^/  /'
    r ip neigh show dev br0 | grep -q "10.77.0.50 lladdr 02:dc:00:00:01:01" \
        || fail "the gratuitous ARP did not reach the neighbor table"

    echo "== 3. A TCP client with a DHCP address"
    if "$BIN" tcp "$examples/http.pcap" -n 20 --cps 50 \
        --client-iface h0 --client-ip dhcp \
        --server-iface h1 --server-ip 10.77.0.20/24 --duration 30s "$@" >"$tmp/tcp.log" 2>&1; then
        :
    else
        fail "ferotrx tcp failed"
    fi
    cat "$tmp/tcp.log"
    grep -q "client: 20 connections, 20 established, 20 completed" "$tmp/tcp.log" \
        || fail "not all 20 connections completed"
    grep -q "ipv4 10.77.0.1[0-9][0-9]/24 via 10.77.0.1 (dhcp from 10.77.0.1" "$tmp/tcp.log" \
        || fail "the client's lease is not in the summary"
else
    echo "== 1. SLAAC and DHCPv6 hosts with an MLD group"
    cat >"$tmp/hosts.toml" <<EOT
format = 1
[[host]]
count = 2
mac = "02:dc:00:00:01:01"
ipv6 = "slaac"
groups = ["ff15::1234"]
[[host]]
mac = "02:dc:00:00:02:01"
ipv6 = "dhcpv6"
EOT
    "$BIN" host "$tmp/hosts.toml" -i h0 --duration 14s "$@" >"$tmp/host.log" 2>&1 &
    host_pid=$!
    for m in 01:01 01:02 02:01; do
        wait_for "02:dc:00:00:$m ready" || fail "host 02:dc:00:00:$m did not get ready"
    done
    cat "$tmp/host.log"
    slaac=fd00:77::dc:ff:fe00:101
    grep -q "ipv6 $slaac/64 via fe80::" "$tmp/host.log" || fail "no SLAAC address $slaac"
    dhcp=$(sed -n 's/.*02:dc:00:00:02:01 ready.*ipv6 \(fd00:77::1[0-9a-f]*\)\/.*dhcpv6.*/\1/p' "$tmp/host.log")
    [ -n "$dhcp" ] || fail "no DHCPv6 address"
    for ip in $slaac $dhcp; do
        if r ping -6 -c 1 -W 2 "$ip" >/dev/null; then
            echo "  $ip answers pings"
        else
            fail "no answer to a ping at $ip"
        fi
    done
    in_mdb hb ff15::1234 || fail "ff15::1234 is not in the snooping table on port hb"
    sleep 8
    r bridge mdb show dev br0 | sed 's/^/  /'
    in_mdb hb ff15::1234 || fail "ff15::1234 expired: the hosts did not answer queries"
    wait "$host_pid" || fail "ferotrx host failed"
    host_pid=

    echo "== 2. A FeroTRX router advertises a prefix to a kernel host"
    ip netns add $KNS
    r ip link add kh type veth peer name k0
    r ip link set k0 netns $KNS
    r ip link set kh master br0
    r ip link set kh up
    ip netns exec $KNS sysctl -qw net.ipv6.conf.k0.accept_dad=0
    ip netns exec $KNS sysctl -qw net.ipv6.conf.k0.accept_ra=2
    ip netns exec $KNS ip link set k0 up
    "$BIN" host -i h0 --mac 02:dc:00:00:09:01 --ra fd00:99::/64 --ra-interval 2s \
        --duration 8s "$@" >"$tmp/host.log" 2>&1 &
    host_pid=$!
    i=0
    while ! ip netns exec $KNS ip -6 addr show dev k0 | grep -q "inet6 fd00:99:" && [ $i -lt 60 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    ip netns exec $KNS ip -6 addr show dev k0 | sed 's/^/  /'
    ip netns exec $KNS ip -6 route show | sed 's/^/  /'
    ip netns exec $KNS ip -6 addr show dev k0 | grep -q "inet6 fd00:99:" \
        || fail "the kernel host took no address from the advertised prefix"
    ip netns exec $KNS ip -6 route show default | grep -q "via fe80::dc:ff:fe00:901" \
        || fail "the kernel host has no default route through the FeroTRX router"
    wait "$host_pid" || fail "ferotrx host failed"
    host_pid=
    cat "$tmp/host.log"

    echo "== 3. A TCP client with a SLAAC address"
    if "$BIN" tcp "$examples/http.pcap" -n 20 --cps 50 \
        --client-iface h0 --client-ip slaac \
        --server-iface h1 --server-ip fd00:77::20/64 --duration 30s "$@" >"$tmp/tcp.log" 2>&1; then
        :
    else
        fail "ferotrx tcp failed"
    fi
    cat "$tmp/tcp.log"
    grep -q "client: 20 connections, 20 established, 20 completed" "$tmp/tcp.log" \
        || fail "not all 20 connections completed"
    grep -q "ipv6 fd00:77::dc:ff:fe00:1/64 via fe80::" "$tmp/tcp.log" \
        || fail "the client's SLAAC address is not in the summary"
fi

if [ $status = 0 ]; then
    echo "hosts lab: all checks passed"
else
    echo "dnsmasq log:"
    tail -40 "$tmp/dnsmasq.log"
fi
exit $status
