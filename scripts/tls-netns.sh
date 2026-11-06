#!/bin/sh
# Builds a small lab in Linux network namespaces and generates TLS
# handshakes over stateful TCP through a real NAT router: new sessions
# (no resumption), a share of resumed ones, SNI names in turn, between
# emulated clients and an emulated server, then real software against each
# emulated end.
#
#   ferotrx (this namespace)          router (namespace ferotrx-tls)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/tls-netns.sh [path/to/ferotrx] [extra ferotrx tcp options]
# (the options go to the runs with both ends emulated, 1 to 3)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. Handshakes only (app = "tls"), every one a new session: TLS 1.3 with a
#    verified certificate and three SNI names in turn. Every connection
#    must complete with one handshake, none resumed, none failed, and the
#    rate must be counted.
# 2. A share of resumed sessions (resumption = 0.3) over TLS 1.3 and TLS
#    1.2 (tickets and session ids): about 30% must resume.
# 3. HTTPS with new sessions and connections held open after their
#    handshakes: every handshake new, every request answered.
# 4. If openssl and ethtool are installed: openssl s_time against the
#    emulated server, with new sessions (-new) and resumed ones (-reuse);
#    the server must count the handshakes and resumptions s_time made.
# 5. If openssl and ethtool are installed: openssl s_server on the router,
#    and the emulated client makes new sessions with it, then resumed ones
#    with its tickets.
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
NS=ferotrx-tls
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-tls.XXXXXX)

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

# A side's handshake counts from its line: handshakes, resumed, failed and
# new sessions.
handshakes() { # line
    echo "$1" | sed -n 's/.*; \([0-9]*\) TLS handshakes (.*), \([0-9]*\) resumed, \([0-9]*\) failed, \([0-9]*\) new sessions.*/\1 \2 \3 \4/p'
}
completed() { # line
    echo "$1" | sed -n 's/^ *[a-z0-9]* *client: \([0-9]*\) connections, \([0-9]*\) established, \([0-9]*\) completed.*/\1 \3/p'
}
# Per template: every connection completed with one handshake, none
# failed, and `$2` of them resumed: none, or a share in percent from-to.
check_handshakes() { # template, resumed: none | MIN-MAX (percent)
    # A profile with one template prints only the side's line.
    line=$(grep -E "^    $1 client: " "$log" || grep -E "^  client: " "$log" || true)
    set -- "$1" "$2" $(completed "$line") $(handshakes "$line")
    if [ $# -ne 8 ] || [ "$3" -eq 0 ] || [ "$3" -ne "$4" ]; then
        fail "template $1: not every connection completed ($line)"
        return
    fi
    conns=$3 hs=$5 resumed=$6 failed=$7 new=$8
    if [ "$hs" -ne "$conns" ] || [ "$failed" -ne 0 ] || [ $((resumed + new)) -ne "$hs" ]; then
        fail "template $1: $hs handshakes for $conns connections, $failed failed, $resumed resumed, $new new"
        return
    fi
    case $2 in
    none)
        [ "$resumed" -eq 0 ] || fail "template $1: $resumed sessions resumed, none should have"
        ;;
    *)
        pct=$((resumed * 100 / hs))
        [ "$pct" -ge "${2%-*}" ] && [ "$pct" -le "${2#*-}" ] ||
            fail "template $1: $pct% resumed, not $2%"
        ;;
    esac
    echo "$line" | grep -Eq "new sessions, [0-9.]+/s; handshake ms" ||
        fail "template $1: no handshake rate"
    echo "template $1: $conns connections, $hs handshakes, $resumed resumed, $new new"
}

cat >"$tmp/new.toml" <<EOT
format = 1
[[template]]
name = "new"
app = "tls"
[template.tls]
versions = ["1.3"]
resumption = false
verify = true
server_name = ["a.lab.local", "b.lab.local", "c.lab.local"]
names = ["a.lab.local", "b.lab.local", "c.lab.local"]
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
echo "== new TLS sessions only, handshakes and nothing else"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/new.toml" $links $client $server -n 300 --cps 150 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
check_handshakes new none
sline=$(grep -E "^  server: " "$log" || true)
read -r hs resumed failed new <<EOT || true
$(handshakes "$sline")
EOT
[ -n "${new:-}" ] && [ "$resumed" -eq 0 ] && [ "$failed" -eq 0 ] ||
    fail "the server resumed or failed handshakes ($sline)"

cat >"$tmp/share.toml" <<EOT
format = 1
[[template]]
name = "v13"
app = "tls"
weight = 1
[template.tls]
versions = ["1.3"]
resumption = 0.3
hold = "50ms"
[[template]]
name = "v12"
app = "tls"
weight = 1
port = 8443
[template.tls]
versions = ["1.2"]
resumption = "30%"
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
echo "== 30% of the sessions resumed, TLS 1.3 tickets and TLS 1.2"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/share.toml" $links $client $server -n 400 --cps 200 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
# The first connections that offer have nothing to resume yet, and under
# loss a ticket can be lost with its connection.
check_handshakes v13 20-30
check_handshakes v12 20-30
grep -Eq "^    v12 client: .*TLSv1\.2 " "$log" || fail "v12: not TLS 1.2"

cat >"$tmp/https.toml" <<EOT
format = 1
[[template]]
name = "https"
app = "https"
[template.http]
requests = ["GET / 200", "GET /index.html 200"]
per_connection = 2
[template.tls]
resumption = false
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT
echo "== HTTPS with a new session per connection"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/https.toml" $links $client $server -n 100 --cps 50 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
check_handshakes https none
grep -Eq "^  client: .*; 200 transactions \(200 x200\), 0 failed" "$log" ||
    fail "https: not every request answered as expected"

if command -v openssl >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== openssl s_time against the emulated server"
    cat >"$tmp/server.toml" <<EOT
format = 1
app = "tls"
[server]
ip = "0.0.0.0"
EOT
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/server.toml" $server_links $server -d 12s -q >"$tmp/server" 2>&1 &
    bg_pid=$!
    sleep 1
    if [ "${IPV6:-}" = 1 ]; then to="[$(net 20)80]:443"; else to="$(net 20)80:443"; fi
    # TLS 1.3 for new sessions; TLS 1.2 session ids for resumed ones (s_time
    # does not wait for TLS 1.3 tickets).
    new=$(r openssl s_time -connect "$to" -new -time 3 2>&1 || true)
    reuse=$(r openssl s_time -connect "$to" -reuse -tls1_2 -time 3 2>&1 || true)
    nconn=$(echo "$new" | sed -n 's/^\([0-9]*\) connections in .*/\1/p' | head -1)
    rconn=$(echo "$reuse" | sed -n 's/^\([0-9]*\) connections in .*/\1/p' | head -1)
    echo "  s_time -new: ${nconn:-?} connections, -reuse: ${rconn:-?} connections"
    # s_time closes its sockets without close_notify, before the TLS 1.3
    # tickets were read: the kernel resets them, so the server's resets are
    # not failures here.
    wait "$bg_pid" || true
    bg_pid=
    cat "$tmp/server"
    sline=$(grep -E "^  server: " "$tmp/server" || true)
    read -r hs resumed failed new <<EOT || true
$(handshakes "$sline")
EOT
    if [ -z "$nconn" ] || [ "$nconn" -lt 10 ] || [ -z "$rconn" ] || [ "$rconn" -lt 10 ]; then
        fail "s_time made too few connections (${nconn:-none} new, ${rconn:-none} reused)"
    elif [ -z "${new:-}" ]; then
        fail "the emulated server counted no handshakes ($sline)"
    else
        # Each s_time run may leave one connection cut short when its time
        # is up, and the first of -reuse is a new session.
        [ "$hs" -ge $((nconn + rconn)) ] || fail "the server counted $hs handshakes, s_time made $((nconn + rconn))"
        [ "$resumed" -ge $((rconn - 2)) ] || fail "the server resumed $resumed sessions, s_time reused $rconn"
        [ "$new" -ge "$nconn" ] || fail "the server made $new new sessions, s_time asked for $nconn"
        [ "$failed" -eq 0 ] || fail "$failed handshakes with s_time failed"
        echo "s_time: the server counted $hs handshakes, $resumed resumed, $new new"
    fi
else
    echo "no openssl or ethtool: skipping s_time against the emulated server"
fi


if command -v openssl >/dev/null 2>&1 && [ $have_ethtool = yes ]; then
    echo "== the emulated client against openssl s_server"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -days 2 -subj /CN=router.lab \
        -addext subjectAltName=DNS:router.lab >/dev/null 2>&1
    if [ "${IPV6:-}" = 1 ]; then acc="[::]:4433"; else acc=4433; fi
    r openssl s_server -accept $acc -cert "$tmp/cert.pem" -key "$tmp/key.pem" -www -quiet \
        >"$tmp/s_server" 2>&1 &
    bg_pid=$!
    sleep 1
    for mode in new resumed; do
        if [ $mode = new ]; then res=false; else res=true; fi
        cat >"$tmp/client.toml" <<EOT
format = 1
app = "tls"
port = 4433
[tls]
resumption = $res
server_name = "router.lab"
[client]
ip = "0.0.0.0"
EOT
        # shellcheck disable=SC2086
        "$BIN" tcp -p "$tmp/client.toml" $client_links $client --connect "$(net 10)1" \
            -n 20 --cps 20 -q >"$log" 2>&1 || status=$?
        cat "$log"
        line=$(grep -E "^  client: " "$log" || true)
        read -r conns done hs resumed failed new <<EOT || true
$(completed "$line") $(handshakes "$line")
EOT
        if [ -z "${new:-}" ] || [ "$conns" -ne 20 ] || [ "$done" -ne 20 ] || [ "$hs" -ne 20 ] || [ "$failed" -ne 0 ]; then
            fail "$mode: the emulated client did not make 20 handshakes with openssl ($line)"
        elif [ $mode = new ] && [ "$resumed" -ne 0 ]; then
            fail "new: $resumed sessions resumed with openssl"
        elif [ $mode = resumed ] && [ "$resumed" -lt 15 ]; then
            fail "resumed: only $resumed of 20 sessions resumed with openssl's tickets"
        else
            echo "$mode: 20 handshakes with openssl, $resumed resumed"
        fi
    done
    kill "$bg_pid" 2>/dev/null || true
    wait "$bg_pid" 2>/dev/null || true
    bg_pid=
else
    echo "no openssl or ethtool: skipping the emulated client against openssl"
fi

echo "router: connections masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all TLS handshake checks passed"
exit $status
