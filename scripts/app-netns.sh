#!/bin/sh
# Builds a small lab in Linux network namespaces and plays application
# protocols over stateful TCP through a real NAT router: HTTP/1.1 and DNS
# over TCP between emulated clients and an emulated server, then real
# software against each emulated end.
#
#   ferotrx (this namespace)          router (namespace ferotrx-app)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/app-netns.sh [path/to/ferotrx] [extra ferotrx tcp options]
# (the options go to the runs with both ends emulated, 1 and 4)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. A mix of two templates (examples/lab-http.toml without its addresses):
#    HTTP with three requests per connection (a page, a chunked 200 KB
#    download, a POST answered 201 after a delay, and a missing page that
#    must be answered 404) and DNS over TCP with two queries per
#    connection. Every connection must complete and every answer be the
#    expected one.
# 2. If curl and ethtool are installed: the emulated HTTP server alone,
#    and curl from the router asks it for a page, a missing page, the chunked
#    download and a POST. A real HTTP client must understand its answers.
# 3. If python3 is installed: a real web server (python3 -m http.server) on
#    the router, and the emulated client loads a page and a missing page
#    from it.
# 4. HTTPS and DNS over TLS (examples/lab-https.toml): TLS 1.3 with a
#    verified certificate and resumed sessions, TLS 1.2 with one cipher
#    suite and client certificates, handshakes that must fail (a 1.2 client
#    against a 1.3 server), and DNS over TLS.
# 5. If curl is installed: curl from the router against the emulated HTTPS
#    server, over TLS 1.3 and 1.2.
# 6. If openssl is installed: openssl s_server on the router with an RSA
#    certificate, and the emulated client loads its page over TLS 1.2 with
#    an ECDHE_RSA suite and over TLS 1.3.
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
NS=ferotrx-app
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-app.XXXXXX)

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

# The example profile without its [client] and [server] tables: the
# addresses come from the command line.
sed '/^\[client\]/,$d' "$examples/lab-http.toml" >"$tmp/http.toml"
cat >>"$tmp/http.toml" <<EOT
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT

echo "== HTTP and DNS over TCP through the router"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/http.toml" $links $client $server -n 200 --cps 100 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
# Per template: connections and completions, then transactions and failures.
check_template() { # name, transactions per connection
    line=$(grep -E "^    $1 client: " "$log" || true)
    conns=$(echo "$line" | sed -n 's/^    [a-z0-9]* client: \([0-9]*\) connections, \([0-9]*\) established, \([0-9]*\) completed.*/\1 \3/p')
    txns=$(echo "$line" | sed -n 's/.*; \([0-9]*\) transactions (.*), \([0-9]*\) failed.*/\1 \2/p')
    set -- "$1" "$2" $conns $txns
    if [ $# -ne 6 ] || [ "$3" -eq 0 ] || [ "$3" -ne "$4" ]; then
        fail "template $1: not every connection completed ($line)"
        return
    fi
    if [ "$5" -ne $(($3 * $2)) ] || [ "$6" -ne 0 ]; then
        fail "template $1: $5 transactions for $3 connections of $2, $6 failed"
        return
    fi
    echo "template $1: $3 connections, $5 transactions, all as expected"
}
check_template web 3
check_template dns 2
grep -Eq "^    web client: .*404 x[1-9]" "$log" || fail "no 404 answers counted"
grep -Eq "^    web client: .*201 x[1-9]" "$log" || fail "no 201 answers counted"
grep -Eq "^    dns client: .*NXDOMAIN x[1-9]" "$log" || fail "no NXDOMAIN answers counted"

# The router's own packets leave with the checksum left to the (virtual)
# NIC, which a veth never fills in, and the emulated hosts check it: have
# the kernel fill it in.
have_ethtool=no
if command -v ethtool >/dev/null 2>&1; then
    for l in $rlinks; do r ethtool -K "$l" tx off >/dev/null 2>&1 || true; done
    have_ethtool=yes
fi

if command -v curl >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== curl against the emulated HTTP server"
    sed '/^\[client\]/,$d' "$tmp/http.toml" >"$tmp/server.toml"
    printf '[server]\nip = "0.0.0.0"\n' >>"$tmp/server.toml"
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/server.toml" $server_links $server -d 10s -q >"$tmp/server" 2>&1 &
    bg_pid=$!
    sleep 1
    base=$(url "$(net 20)80" 80)
    get() { # path, extra curl options
        p=$1
        shift
        r curl --noproxy '*' -s -o "$tmp/body" -w '%{http_code} %{size_download}' \
            --max-time 5 "$@" "$base$p" 2>&1 || true
    }
    page=$(get /)
    missing=$(get /missing)
    big=$(get /big)
    post=$(get /upload -X POST --data-binary "hello")
    head=$(get /big -I)
    echo "  curl: / $page, /missing $missing, /big $big, POST /upload $post, HEAD /big $head"
    [ "${page%% *}" = 200 ] || fail "curl: / was not 200 ($page)"
    [ "${missing%% *}" = 404 ] || fail "curl: /missing was not 404 ($missing)"
    [ "$big" = "200 204800" ] || fail "curl: /big was not 200 with 204800 bytes ($big)"
    [ "${post%% *}" = 201 ] || fail "curl: POST /upload was not 201 ($post)"
    [ "${head%% *}" = 200 ] || fail "curl: HEAD /big was not 200 ($head)"
    wait "$bg_pid" || true
    bg_pid=
    cat "$tmp/server"
else
    echo "no curl or ethtool: skipping curl against the emulated server"
fi

if command -v python3 >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== the emulated HTTP client against a real web server"
    mkdir -p "$tmp/www"
    echo "a page from a real server" >"$tmp/www/index.html"
    if [ "${IPV6:-}" = 1 ]; then bind=::; else bind=0.0.0.0; fi
    (cd "$tmp/www" && exec ip netns exec $NS python3 -m http.server 8000 --bind $bind) \
        >"$tmp/pyserver" 2>&1 &
    bg_pid=$!
    sleep 1
    cat >"$tmp/client.toml" <<EOT
app = "http"
port = 8000
[http]
requests = ["GET /index.html 200", "GET /missing 404"]
[client]
ip = "0.0.0.0"
EOT
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/client.toml" $client_links $client --connect "$(net 10)1" \
        -n 20 --cps 20 -q >"$log" 2>&1 || status=$?
    cat "$log"
    line=$(grep -E "^  client: " "$log" || true)
    echo "$line" | grep -Eq "^  client: 20 connections, 20 established, 20 completed;" ||
        fail "the emulated client did not complete its connections to the real server"
    echo "$line" | grep -Eq "20 transactions \((200 x10, 404 x10|404 x10, 200 x10)\), 0 failed" ||
        fail "the real server's answers were not the expected ones"
    kill "$bg_pid" 2>/dev/null || true
    wait "$bg_pid" 2>/dev/null || true
    bg_pid=
else
    echo "no python3 or ethtool: skipping the emulated client against a real server"
fi

# The TLS example without its addresses, as for HTTP.
sed '/^\[client\]/,$d' "$examples/lab-https.toml" >"$tmp/https.toml"
cat >>"$tmp/https.toml" <<EOT
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
# Per template: every connection had a handshake, and `$2` of them failed
# (as expected).
check_tls() { # name, how many handshakes must fail: none or all
    line=$(grep -E "^    $1 client: " "$log" || true)
    h=$(echo "$line" | sed -n 's/.*; \([0-9]*\) TLS handshakes (.*), \([0-9]*\) resumed, \([0-9]*\) failed.*/\1 \3/p')
    conns=$(echo "$line" | sed -n 's/^    [a-z0-9]* client: \([0-9]*\) connections.*/\1/p')
    set -- "$1" "$2" $h "$conns"
    if [ $# -ne 5 ] || [ "$3" -ne "$5" ]; then
        fail "template $1: not one TLS handshake per connection ($line)"
        return
    fi
    if [ "$2" = all ] && [ "$4" -ne "$3" ]; then
        fail "template $1: $4 of $3 handshakes failed, all should have"
    elif [ "$2" = none ] && [ "$4" -ne 0 ]; then
        fail "template $1: $4 of $3 handshakes failed"
    else
        echo "template $1: $3 TLS handshakes, $4 failed, as expected"
    fi
    if echo "$line" | grep -q "not as expected"; then
        fail "template $1: handshakes with another outcome than expected"
    fi
}

echo "== HTTPS and DNS over TLS through the router"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/https.toml" $links $client $server -n 160 --cps 80 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
check_template https 2
check_template mtls12 1
check_template dot 2
check_template refused 0
check_tls https none
check_tls mtls12 none
check_tls dot none
check_tls refused all
grep -Eq "^    https client: .*TLSv1\.3 TLS13_[A-Z0-9_]* http/1\.1 x" "$log" ||
    fail "https: not TLS 1.3 with ALPN http/1.1"
grep -Eq "^    https client: .*, [1-9][0-9]* resumed" "$log" ||
    fail "https: no session resumed"
grep -Eq "^    mtls12 client: .*TLSv1\.2 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 http/1\.1 x" "$log" ||
    fail "mtls12: not TLS 1.2 with the one suite"

if command -v curl >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== curl against the emulated HTTPS server"
    sed '/^\[client\]/,$d' "$tmp/https.toml" >"$tmp/tls-server.toml"
    printf '[server]\nip = "0.0.0.0"\n' >>"$tmp/tls-server.toml"
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/tls-server.toml" $server_links $server -d 8s -q >"$tmp/server" 2>&1 &
    bg_pid=$!
    sleep 1
    base=$(url "$(net 20)80" 443 | sed 's/^http:/https:/')
    sget() { # path, extra curl options
        p=$1
        shift
        r curl --noproxy '*' -k -s -o "$tmp/body" -w '%{http_code} %{size_download}' \
            --max-time 5 "$@" "$base$p" 2>&1 || true
    }
    v13=$(sget / --tlsv1.3)
    v12=$(sget / --tlsv1.2 --tls-max 1.2)
    missing=$(sget /missing)
    echo "  curl: / over TLS 1.3 $v13, / over TLS 1.2 $v12, /missing $missing"
    [ "${v13%% *}" = 200 ] || fail "curl over TLS 1.3: / was not 200 ($v13)"
    [ "${v12%% *}" = 200 ] || fail "curl over TLS 1.2: / was not 200 ($v12)"
    [ "${missing%% *}" = 404 ] || fail "curl over TLS: /missing was not 404 ($missing)"
    wait "$bg_pid" || fail "the emulated HTTPS server failed connections from curl"
    bg_pid=
    cat "$tmp/server"
    grep -Eq "^    https server: .*TLSv1\.3 .* x[1-9].*TLSv1\.2 |^    https server: .*TLSv1\.2 .* x[1-9].*TLSv1\.3 " "$tmp/server" ||
        fail "the emulated server did not count a TLS 1.3 and a TLS 1.2 handshake"
else
    echo "no curl or ethtool: skipping curl against the emulated HTTPS server"
fi

if command -v openssl >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== the emulated HTTPS client against openssl s_server"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/rsa-key.pem" -out "$tmp/rsa.pem" \
        -days 2 -subj /CN=router.lab -addext subjectAltName=DNS:router.lab >/dev/null 2>&1
    for v in 1.2 1.3; do
        if [ $v = 1.2 ]; then
            suite='cipher_suites = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]'
            want="TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        else
            suite=
            want="TLSv1.3 TLS13_"
        fi
        if [ "${IPV6:-}" = 1 ]; then acc="[::]:4433"; else acc=4433; fi
        r openssl s_server -accept $acc -cert "$tmp/rsa.pem" -key "$tmp/rsa-key.pem" -www -quiet \
            >"$tmp/s_server" 2>&1 &
        bg_pid=$!
        sleep 1
        cat >"$tmp/tls-client.toml" <<EOT
app = "https"
port = 4433
[http]
requests = ["GET / 200"]
[tls]
versions = ["$v"]
$suite
server_name = "router.lab"
[client]
ip = "0.0.0.0"
EOT
        # shellcheck disable=SC2086
        "$BIN" tcp -p "$tmp/tls-client.toml" $client_links $client --connect "$(net 10)1" \
            -n 10 --cps 10 -q >"$log" 2>&1 || status=$?
        cat "$log"
        line=$(grep -E "^  client: " "$log" || true)
        echo "$line" | grep -Eq "^  client: 10 connections, 10 established, 10 completed;" ||
            fail "TLS $v: the emulated client did not complete its connections to openssl"
        echo "$line" | grep -q "10 TLS handshakes ($want" ||
            fail "TLS $v: not the handshakes expected ($want)"
        echo "$line" | grep -Eq "10 transactions \(200 x10\), 0 failed" ||
            fail "TLS $v: openssl's answers were not the expected ones"
        kill "$bg_pid" 2>/dev/null || true
        wait "$bg_pid" 2>/dev/null || true
        bg_pid=
    done
else
    echo "no openssl or ethtool: skipping the emulated HTTPS client against openssl"
fi

echo "router: connections masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all application checks passed"
exit $status
