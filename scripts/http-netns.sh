#!/bin/sh
# Builds a small lab in Linux network namespaces and runs HTTP/1.1
# workloads with success checks over stateful TCP through a real NAT
# router: every response is checked (status, body, size, headers) and
# counted as passed or failed per request, with the reason.
#
#   ferotrx (this namespace)          router (namespace ferotrx-http)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/http-netns.sh [path/to/ferotrx] [extra ferotrx tcp options]
# (the options go to the runs with both ends emulated, 1 and 2)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. examples/lab-http-checks.toml between emulated ends: a page with texts
#    it must and must not have and headers, a chunked 256 KB download of an
#    exact size, a POST answered with an exact JSON body. Every request must
#    pass.
# 2. The same with a server that answers the POST with another body: exactly
#    that request must fail on every connection, with the reason counted,
#    and the run must exit with an error.
# 3. If python3 and ethtool are installed: a real web server
#    (python3 -m http.server) on the router, and the emulated client checks
#    a page's exact body (from a file), a text in it, its size and headers,
#    a missing page's 404, and one check that must fail.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards.
# IPV6=1 does the same over IPv6 (fd00:10::/64 and fd00:20::/64).
# NO_VLAN=1 (or no 8021q module) gives the client and the server a link each.
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
NS=ferotrx-http
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-http.XXXXXX)

cleanup() {
    [ -z "${bg_pid:-}" ] || kill "$bg_pid" 2>/dev/null || true
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
    url() { echo "http://[$1]:$2"; }
else
    net() { echo "192.168.$1."; }
    plen=24
    ipt() { r iptables "$@"; }
    addr() { r ip addr add "$1" dev "$2"; }
    url() { echo "http://$1:$2"; }
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
    rlinks="rt rt.10 rt.20"
    links="-i t0 --client-vlan 10 --server-vlan 20"
    server_links="-i t0 --server-vlan 20"
    client_links="-i t0 --client-vlan 10"
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
    rlinks="rc rs"
    links="--client-iface c0 --server-iface s0"
    server_links="--server-iface s0"
    client_links="--client-iface c0"
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
# Packets conntrack cannot place (late duplicates) are dropped, not de-NATed.
ipt -A FORWARD -m conntrack --ctstate INVALID -j DROP
ipt -A INPUT -m conntrack --ctstate INVALID -j DROP
if [ -n "${LOSS:-}" ]; then
    ipt -A FORWARD -m statistic --mode random --probability "$LOSS" -j DROP
fi

server="--server-ip $(net 20)80/$plen --server-gw $(net 20)1"
client="--client-ip $(net 10)100/$plen --client-ips 10 --client-gw $(net 10)1"
status=0
log=$tmp/out
fail() { echo "FAIL: $*" >&2; status=1; }

# The router's own packets leave with the checksum left to the (virtual)
# NIC, which a veth never fills in, and the emulated hosts check it: have
# the kernel fill it in.
have_ethtool=no
if command -v ethtool >/dev/null 2>&1; then
    for l in $rlinks; do r ethtool -K "$l" tx off >/dev/null 2>&1 || true; done
    have_ethtool=yes
fi

# The client's numbers from its line: connections, completed, transactions,
# failed.
counts() { # line
    c=$(echo "$1" | sed -n 's/^ *client: \([0-9]*\) connections, \([0-9]*\) established, \([0-9]*\) completed.*/\1 \3/p')
    t=$(echo "$1" | sed -n 's/.*; \([0-9]*\) transactions ([^)]*), \([0-9]*\) failed.*/\1 \2/p')
    echo "$c $t"
}

# The example profile without its [client] and [server] tables: the
# addresses come from the command line.
sed '/^\[client\]/,$d' "$examples/lab-http-checks.toml" >"$tmp/checks.toml"
cat >>"$tmp/checks.toml" <<EOT
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT

echo "== HTTP with response checks, all must pass"
code=0
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/checks.toml" $links $client $server -n 150 --cps 75 -q "$@" >"$log" 2>&1 || code=$?
cat "$log"
line=$(grep -E "^  client: " "$log" || true)
read -r conns done txns failed <<EOT || true
$(counts "$line")
EOT
if [ "$code" -ne 0 ] || [ -z "${failed:-}" ] || [ "$conns" -ne 150 ] || [ "$done" -ne 150 ] ||
    [ "$txns" -ne 450 ] || [ "$failed" -ne 0 ]; then
    fail "not every request passed its checks (exit $code): $line"
else
    echo "450 requests on 150 connections, all passed their checks"
fi
echo "$line" | grep -q "passed per request: GET /download 150 of 150, POST /api/status 150 of 150, home 150 of 150" ||
    fail "the counts per request are not the expected ones"

echo "== the same with a server that answers the POST with another body"
sed 's/^body = .{"status":"ok"}.$/body = '"'"'{"status":"degraded"}'"'"'/' "$tmp/checks.toml" >"$tmp/broken.toml"
grep -q degraded "$tmp/broken.toml" || fail "could not change the server's answer"
code=0
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/broken.toml" $links $client $server -n 60 --cps 60 -q "$@" >"$log" 2>&1 || code=$?
cat "$log"
line=$(grep -E "^  client: " "$log" || true)
read -r conns done txns failed <<EOT || true
$(counts "$line")
EOT
if [ "$code" -eq 0 ]; then
    fail "the run with failed checks exited 0"
fi
if [ -z "${failed:-}" ] || [ "$txns" -ne 180 ] || [ "$failed" -ne 60 ]; then
    fail "expected 60 of 180 requests to fail: $line"
else
    echo "60 of 180 requests failed, as they must"
fi
echo "$line" | grep -q "POST /api/status: body differs at byte 11 (21 bytes, expected 15) x60" ||
    fail "the reason the POST failed is not counted"
echo "$line" | grep -q "GET /download 60 of 60, POST /api/status 0 of 60, home 60 of 60" ||
    fail "the other requests did not all pass"

if command -v python3 >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== the emulated client checks a real web server"
    mkdir -p "$tmp/www"
    printf '<html><body><h1>A real server</h1></body></html>\n' >"$tmp/www/index.html"
    size=$(wc -c <"$tmp/www/index.html" | tr -d ' ')
    if [ "${IPV6:-}" = 1 ]; then bind=::; else bind=0.0.0.0; fi
    (cd "$tmp/www" && exec ip netns exec $NS python3 -m http.server 8000 --bind $bind) \
        >"$tmp/pyserver" 2>&1 &
    bg_pid=$!
    sleep 1
    cat >"$tmp/client.toml" <<EOT
format = 1
app = "http"
port = 8000
[http]
# http.server speaks HTTP/1.0 and closes after each answer: one request
# per connection, the three in turn.
per_connection = 1
[[http.request]]
path = "/index.html"
name = "page"
expect = 200
expect_body_file = "$tmp/www/index.html"
expect_contains = "A real server"
expect_size = $size
expect_headers = { "Content-Type" = "text/html*", "Server" = "SimpleHTTP*", "Content-Length" = "$size", "Set-Cookie" = "!" }
[[http.request]]
path = "/missing"
expect = 404
[[http.request]]
path = "/index.html"
name = "must fail"
expect_lacks = "real"
[client]
ip = "0.0.0.0"
EOT
    code=0
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/client.toml" $client_links $client --connect "$(net 10)1" \
        -n 60 --cps 30 -q >"$log" 2>&1 || code=$?
    cat "$log"
    line=$(grep -E "^  client: " "$log" || true)
    read -r conns done txns failed <<EOT || true
$(counts "$line")
EOT
    if [ -z "${failed:-}" ] || [ "$done" -ne 60 ] || [ "$txns" -ne 60 ] || [ "$failed" -ne 20 ]; then
        fail "expected 20 of 60 checks against the real server to fail: $line"
    fi
    echo "$line" | grep -q "GET /missing 20 of 20, must fail 0 of 20, page 20 of 20" ||
        fail "the real server's answers did not pass their checks"
    echo "$line" | grep -q 'must fail: body has "real" x20' ||
        fail "the failing check's reason is not counted"
    [ "$code" -ne 0 ] || fail "the run with failed checks exited 0"
    kill "$bg_pid" 2>/dev/null || true
    wait "$bg_pid" 2>/dev/null || true
    bg_pid=
else
    echo "no python3 or ethtool: skipping the emulated client against a real server"
fi

echo "router: connections masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all HTTP check runs passed"
exit $status
