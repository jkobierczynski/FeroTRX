#!/bin/sh
# Builds a small lab in Linux network namespaces and plays HTTP/3 over QUIC
# through a real NAT router: the kernel's routing, connection tracking and
# masquerading, as on a lab router between two VLANs. Then aioquic against
# each emulated end.
#
#   ferotrx (this namespace)          router (namespace ferotrx-h3)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/h3-netns.sh [path/to/ferotrx] [extra ferotrx udp options]
# (the options go to run 1, with both ends emulated)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. The templates of examples/lab-h3.toml: connections with 12 requests
#    each, six at once (a page, its style and script, 300 KB, a 404 and a
#    POST), the certificate checked; a server that sends a Retry first,
#    with key updates every 50 packets; and a client with only an old
#    draft's ALPN, which the server must refuse in the handshake. Every
#    request must get the status expected.
# 2. If python3 with aioquic (python3-aioquic; PYTHON= names another python), openssl and ethtool are
#    installed: the emulated server alone, and scripts/h3-peer.py on the
#    router as the client (requests at once, a key update, a wrong ALPN
#    refused, the Retry server).
# 3. The same: h3-peer.py as the server on the router (and one with Retry),
#    and the emulated clients against it.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards: QUIC must
# find the losses and send again.
# IPV6=1 plays run 1 over IPv6 (fd00:10::/64 and fd00:20::/64); 2 and 3 are
# IPv4 only.
# NO_VLAN=1 (or no 8021q module) gives the client and the server a link each
# instead of a shared trunk.
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
NS=ferotrx-h3
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-h3.XXXXXX)

cleanup() {
    [ -z "${peer_pid:-}" ] || kill "$peer_pid" 2>/dev/null || true
    [ -z "${peer_retry_pid:-}" ] || kill "$peer_retry_pid" 2>/dev/null || true
    for p in ${server_pid:-} ${sipp_pid:-}; do kill "$p" 2>/dev/null || true; done
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

# QUEUES=4: four queues on each veth link, for `--workers 4 -B af_xdp`.
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

if [ $vlan = yes ]; then
    # shellcheck disable=SC2086
    ip link add t0 $queues type veth peer name rt $queues
    ip link set rt netns $NS
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
    links="-i t0 --client-vlan 10 --server-vlan 20"
    client_links="-i t0 --client-vlan 10"
    server_links="-i t0 --server-vlan 20"
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
    links="--client-iface c0 --server-iface s0"
    client_links="--client-iface c0"
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
       --server-ip $(net 20)80/$plen --server-gw $(net 20)1"
# The Python with aioquic (PYTHON=/usr/bin/python3.12 to pick one).
PY=${PYTHON:-python3}
status=0
log=$tmp/out
fail() {
    echo "FAIL: $*" >&2
    status=1
}

# The example profile without its [client] and [server] tables: the
# addresses come from the command line.
sed -e '/^\[client\]/,$d' "$examples/lab-h3.toml" >"$tmp/h3.toml"
cat >>"$tmp/h3.toml" <<EOT
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
[udp]
session_timeout = "15s"
EOT

# A template's line: "    NAME SIDE: N transactions, N answered, ...".
line() { # template, side
    grep -E "^    $1 $2: " "$log" | head -1
}
# Every connection of a template ended as expected.
all_answered() { # template
    l=$(line "$1" client)
    n=$(echo "$l" | sed -n 's/^    [a-z0-9]* client: \([0-9]*\) transactions, \([0-9]*\) answered.*/\1 \2/p')
    set -- "$1" $n
    if [ $# -ne 3 ] || [ "$2" -eq 0 ] || [ "$2" -ne "$3" ]; then
        fail "template $1: not every connection ended: $l"
    elif echo "$l" | grep -Eq "timed out|other answers than expected"; then
        fail "template $1: some connections failed: $l"
    fi
}

echo "== 1. HTTP/3 between emulated ends through the router"
# shellcheck disable=SC2086
"$BIN" udp -p "$tmp/h3.toml" $links $hosts -n 30 --rate 15 "$@" >"$log" 2>&1 || status=$?
cat "$log"
all_answered browser
all_answered retry
all_answered draft
grep -Eq "^    browser client: .*QUIC handshakes \(QUIC v1 TLS13_[A-Z0-9_]* h3 x[1-9]" "$log" ||
    fail "browser: no QUIC handshakes with ALPN h3"
grep -Eq "^    browser client: .*404 x[1-9]" "$log" || fail "browser: no 404 for /missing"
grep -Eq "^    browser client: .*201 x[1-9]" "$log" || fail "browser: no 201 for the POST"
grep -Eq "^    draft client: .*failed: QUIC CRYPTO_ERROR 0x78" "$log" ||
    fail "draft: the server did not refuse the old ALPN (no_application_protocol)"
if [ -n "${LOSS:-}" ] && ! grep -Eq "^  (client|server): .* [1-9][0-9]* sent again" "$log"; then
    fail "with loss, no QUIC packet was sent again"
fi

if [ "${IPV6:-}" = 1 ]; then
    echo "IPV6=1: skipping the runs with aioquic"
elif ! $PY -c 'import aioquic.asyncio, aioquic.h3.connection' 2>/dev/null || ! command -v ethtool >/dev/null 2>&1 ||
    ! command -v openssl >/dev/null 2>&1; then
    echo "no python3 aioquic, openssl or ethtool: skipping the runs with aioquic"
else
    # The router's own datagrams leave with the checksum left to the
    # (virtual) NIC, which a veth never fills in: have the kernel fill it in.
    if [ $vlan = yes ]; then rlinks="rt rt.10 rt.20"; else rlinks="rc rs"; fi
    for l in $rlinks; do r ethtool -K $l tx off >/dev/null; done
    peer=$(cd "$(dirname "$0")" && pwd)/h3-peer.py

    echo "== 2. aioquic's client against the emulated server"
    sed '/^\[client\]/,/^ip/d' "$tmp/h3.toml" >"$tmp/server.toml"
    # shellcheck disable=SC2086
    "$BIN" udp -p "$tmp/server.toml" $server_links \
        --server-ip $(net 20)80/$plen --server-gw $(net 20)1 -d 30s -q \
        >"$tmp/server" 2>&1 &
    server_pid=$!
    sleep 1
    peer_client() { # what, h3-peer.py client options...
        what=$1
        shift
        if r $PY -I "$peer" client "$@" >"$tmp/peer" 2>&1; then
            echo "aioquic: $what: $(tail -1 "$tmp/peer")"
        else
            fail "aioquic: $what"
        fi
        sed 's/^/    /' "$tmp/peer" | head -12
    }
    peer_client "5 connections of 12 requests" "https://$(net 20)80/" -c 5 -n 12 \
        --server-name www.lab.local --path / --path /style.css --path /big --path /missing:404 \
        --path "POST /api:201"
    peer_client "a key update" "https://$(net 20)80/" -n 20 --key-update --path /big
    peer_client "the Retry server" "https://$(net 20)80:4433/" -c 3 -n 10 --path / --path /big
    peer_client "an old draft's ALPN refused" "https://$(net 20)80:4434/" --alpn h3-29 --expect-failure
    wait "$server_pid" || true
    server_pid=
    cat "$tmp/server"
    grep -Eq "^    browser server: .*QUIC handshakes \(QUIC v1 TLS13_[A-Z0-9_]* h3 x[1-9]" "$tmp/server" ||
        fail "the emulated server counted no QUIC handshakes with aioquic"
    grep -Eq "^    retry server: .*QUIC handshakes \(QUIC v1 [^)]*x3\)" "$tmp/server" ||
        fail "the Retry server did not take aioquic's 3 connections"
    grep -Eq "^  server: .*(other answers than expected|protocol errors)" "$tmp/server" &&
        fail "the emulated server saw errors with aioquic"

    echo "== 3. The emulated clients against aioquic's server"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
        -subj /CN=www.lab.local -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
    r $PY -I "$peer" server --host $(net 10)1 --port 443 --cert "$tmp/cert.pem" \
        --key "$tmp/key.pem" --duration 40 >"$tmp/peer-server" 2>&1 &
    peer_pid=$!
    r $PY -I "$peer" server --host $(net 10)1 --port 4433 --cert "$tmp/cert.pem" \
        --key "$tmp/key.pem" --retry --duration 40 >"$tmp/peer-retry" 2>&1 &
    peer_retry_pid=$!
    sleep 2
    run_client() { # what, port, h3 table lines...
        what=$1 port=$2
        shift 2
        {
            printf 'app = "h3"\nrate = 10\ntransactions = 10\n[h3]\n'
            printf '%s\n' "$@"
            printf '[client]\nip = "0.0.0.0"\n'
        } >"$tmp/client.toml"
        # shellcheck disable=SC2086
        "$BIN" udp -p "$tmp/client.toml" $client_links --client-ip $(net 10)100/$plen \
            --client-ips 10 --client-gw $(net 10)1 --connect $(net 10)1:$port >"$log" 2>&1 || true
        l=$(grep -E "^  client: " "$log" | head -1)
        if echo "$l" | grep -Eq "^  client: 10 transactions, 10 answered" &&
            ! echo "$l" | grep -Eq "timed out|other answers than expected"; then
            echo "  $what: $(echo "$l" | sed -n 's/.*; \([0-9]* QUIC handshakes [^;]*\).*/\1/p')"
            echo "    $(echo "$l" | sed -n 's/.*; \(requests [^;]*\|[0-9]* transactions ([^)]*)\).*/\1/p')"
        else
            fail "the emulated clients against aioquic's server, $what"
            cat "$log"
            tail -20 "$tmp/peer-server"
        fi
    }
    run_client "12 requests, 6 at once" 443 'requests = ["GET /", "GET /big", "GET /missing 404", "POST /api 201"]' \
        'per_connection = 12' 'concurrent = 6'
    run_client "key updates every 30 packets" 443 'requests = ["GET /big"]' 'per_connection = 4' \
        'key_update_after = 30'
    run_client "aioquic's Retry" 4433 'requests = ["GET /", "GET /big"]' 'per_connection = 6'
    kill "$peer_pid" "$peer_retry_pid" 2>/dev/null || true
    wait "$peer_pid" "$peer_retry_pid" 2>/dev/null || true
    peer_pid=
    peer_retry_pid=
    grep -c " 200 " "$tmp/peer-server" | sed 's/^/aioquic server: requests answered 200: /'
fi

echo "router: datagrams masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all HTTP/3 checks passed"
exit $status
