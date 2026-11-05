#!/bin/sh
# Builds a small lab in Linux network namespaces and plays SIP calls with
# RTP audio through a real NAT router: the kernel's routing, connection
# tracking and masquerading, as on a lab router between two VLANs. Then
# SIPp against each emulated end.
#
#   ferotrx (this namespace)          router (namespace ferotrx-sip)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (phones)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (SIP server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/sip-netns.sh [path/to/ferotrx] [extra ferotrx udp options]
# (the options go to run 1, with both ends emulated)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. The templates of examples/lab-sip.toml (with shorter calls): phones
#    that register with a password (digest, MD5), call with G.711 for 3 s
#    and hang up; calls without registering, with Opus; and a busy line that
#    must be refused with 486. Every call must end as expected, and RTP must
#    flow both ways through the NAT (the server finds the phones behind it
#    from their first packets).
# 2. If sipp and ethtool are installed: the emulated server alone, and SIPp
#    on the router calls it (its built-in caller, echoing the server's RTP
#    back), registers with the right password (a scenario of its own that
#    answers the digest challenge) and with a wrong one, which must be
#    refused with 403.
# 3. If sipp and ethtool are installed: SIPp's built-in answering end on the
#    router (echoing RTP), and the emulated phones call it.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards: SIP must
# send again, and RTP loss shows in the counters.
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
NS=ferotrx-sip
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-sip.XXXXXX)

cleanup() {
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
status=0
log=$tmp/out
fail() {
    echo "FAIL: $*" >&2
    status=1
}

# The templates of examples/lab-sip.toml; addresses and VLANs come from the
# command line, so editing that file for a real lab does not break this.
cat >"$tmp/sip.toml" <<EOT
rate = 20
transactions = 60
concurrency = 60

[[template]]
name = "office"
app = "sip"
weight = 4
[template.sip]
user = "alice"
password = "lab"
domain = "lab.local"
call = "bob"
duration = "3s"
codecs = ["PCMU", "PCMA"]
users = { alice = "lab", bob = "lab" }
ring = "200ms"

[[template]]
name = "open"
app = "sip"
port = 5070
weight = 1
[template.sip]
register = false
call = "echo"
duration = "2s"
codecs = ["opus", "PCMU"]

[[template]]
name = "busy"
app = "sip"
port = 5080
weight = 1
[template.sip]
register = false
call = "carol"
answer = 486
expect = 486

[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
[udp]
session_timeout = "10s"
EOT

# A template's line: "    NAME SIDE: N transactions, N answered, ...".
line() { # template, side
    grep -E "^    $1 $2: " "$log" | head -1
}
# Every one of a template's client transactions answered as expected.
all_answered() { # template
    l=$(line "$1" client)
    if ! echo "$l" | grep -Eq "^    $1 client: ([1-9][0-9]*) transactions, \1 answered"; then
        fail "template $1: not every client session ended: $l"
    elif echo "$l" | grep -Eq "timed out|other answers than expected"; then
        fail "template $1: some client sessions failed: $l"
    fi
}
# A template's media both ways: streams, and packets received.
media_both_ways() { # template
    for side in client server; do
        l=$(line "$1" $side)
        if ! echo "$l" | grep -Eq "[1-9][0-9]* media streams [^:]*: [1-9][0-9]* packets sent, [1-9][0-9]* received"; then
            fail "template $1: no RTP both ways on the $side: $l"
        fi
    done
}
# The loss a line reports, in whole percent.
loss_pct() {
    sed -n 's/.* lost (\([0-9]*\)\.[0-9]*%).*/\1/p'
}

echo "== 1. SIP calls between emulated ends"
# shellcheck disable=SC2086
"$BIN" udp -p "$tmp/sip.toml" $links $hosts "$@" >"$log" 2>&1 || status=$?
cat "$log"
for t in office open busy; do all_answered $t; done
media_both_ways office
media_both_ways open
grep -q "office client: .*REGISTER 200 x[1-9]" "$log" || fail "office: no REGISTER 200"
grep -q "busy client: .*INVITE 486 x[1-9]" "$log" || fail "busy: no INVITE 486"
if [ -z "${LOSS:-}" ]; then
    for t in office open; do
        for side in client server; do
            p=$(line $t $side | loss_pct)
            if [ "${p:-0}" -ge 1 ]; then
                fail "template $t: ${p}% RTP loss on the $side without loss on the router"
            fi
        done
    done
elif ! grep -Eq "^  client: .* [1-9][0-9]* lost" "$log"; then
    fail "with loss, no RTP packet was lost"
fi

if [ "${IPV6:-}" = 1 ]; then
    echo "IPV6=1: skipping the runs with SIPp"
elif ! command -v sipp >/dev/null 2>&1 || ! command -v ethtool >/dev/null 2>&1; then
    echo "no sipp or ethtool: skipping the runs with SIPp"
else
    # The router's own datagrams leave with the checksum left to the
    # (virtual) NIC, which a veth never fills in: have the kernel fill it in.
    if [ $vlan = yes ]; then rlinks="rt rt.10 rt.20"; else rlinks="rc rs"; fi
    for l in $rlinks; do r ethtool -K $l tx off >/dev/null; done

    echo "== 2. SIPp against the emulated server"
    sed '/^\[client\]/,/^ip/d' "$tmp/sip.toml" >"$tmp/server.toml"
    # shellcheck disable=SC2086
    "$BIN" udp -p "$tmp/server.toml" $server_links \
        --server-ip $(net 20)80/$plen --server-gw $(net 20)1 -d 25s -q \
        >"$tmp/server" 2>&1 &
    server_pid=$!
    sleep 1
    sipp_log=$tmp/sipp
    sipp_run() { # what, sipp options...
        what=$1
        shift
        if r sipp "$@" -i $(net 20)1 -m 10 -r 10 -l 10 -timeout 30s -nostdin -max_socket 100 \
            -trace_screen -screen_file "$sipp_log" >"$tmp/sipp.err" 2>&1; then
            echo "sipp: $what: all calls successful"
        else
            fail "sipp: $what did not succeed"
            cat "$tmp/sipp.err" "$sipp_log" 2>/dev/null | tail -40 || true
        fi
    }
    # The built-in caller: INVITE, ACK, 2 s of the server's RTP echoed back,
    # BYE; one socket per call, so each call is a flow of its own.
    sipp_run "10 calls" -sn uac -s echo -t un -d 2000 -rtp_echo \
        "$(net 20)80:5070"
    # REGISTER, the challenge answered with the password; and a wrong one.
    cat >"$tmp/register.xml" <<'EOT'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="register with digest">
  <send retrans="500"><![CDATA[
REGISTER sip:lab.local SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: <sip:alice@lab.local>;tag=[pid]SIPpTag00[call_number]
To: <sip:alice@lab.local>
Call-ID: [call_id]
CSeq: 1 REGISTER
Contact: <sip:alice@[local_ip]:[local_port]>
Max-Forwards: 70
Expires: 3600
Content-Length: 0

]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
REGISTER sip:lab.local SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: <sip:alice@lab.local>;tag=[pid]SIPpTag00[call_number]
To: <sip:alice@lab.local>
Call-ID: [call_id]
CSeq: 2 REGISTER
Contact: <sip:alice@[local_ip]:[local_port]>
[authentication username=alice password=[$pw]]
Max-Forwards: 70
Expires: 3600
Content-Length: 0

]]></send>
  <recv response="[$code]"/>
</scenario>
EOT
    sed -e 's/\[\$pw\]/lab/' -e 's/\[\$code\]/200/' "$tmp/register.xml" >"$tmp/register-ok.xml"
    sed -e 's/\[\$pw\]/guess/' -e 's/\[\$code\]/403/' "$tmp/register.xml" >"$tmp/register-bad.xml"
    sipp_run "10 registrations" -sf "$tmp/register-ok.xml" -t un "$(net 20)80:5060"
    sipp_run "10 wrong passwords refused" -sf "$tmp/register-bad.xml" -t un "$(net 20)80:5060"
    wait "$server_pid" || true
    server_pid=
    cat "$tmp/server"
    s_open=$(grep -E "^    open server: " "$tmp/server" | head -1)
    echo "$s_open" | grep -q "INVITE 200 x10" || fail "the server did not answer SIPp's 10 calls"
    echo "$s_open" | grep -Eq "10 media streams [^:]*: [1-9][0-9]* packets sent, [1-9][0-9]* received" ||
        fail "the server got none of its RTP back from SIPp"
    s_office=$(grep -E "^    office server: " "$tmp/server" | head -1)
    echo "$s_office" | grep -q "REGISTER 200 x10" || fail "the server did not register SIPp 10 times"
    echo "$s_office" | grep -q "REGISTER 403 x10" || fail "the server did not refuse SIPp's wrong password"

    echo "== 3. The emulated phones against SIPp's answering end"
    # SIPp answers with PCMU and echoes the RTP it gets.
    r sipp -sn uas -i $(net 10)1 -p 5060 -rtp_echo -m 10 -timeout 60s -nostdin -max_socket 100 \
        -trace_screen -screen_file "$tmp/sipp-uas" >"$tmp/sipp-uas.err" 2>&1 &
    sipp_pid=$!
    sleep 1
    cat >"$tmp/client.toml" <<EOT
app = "sip"
rate = 10
transactions = 10
[sip]
register = false
call = "service"
duration = "2s"
codecs = ["opus", "PCMU"]
[client]
ip = "0.0.0.0"
EOT
    # shellcheck disable=SC2086
    "$BIN" udp -p "$tmp/client.toml" $client_links --client-ip $(net 10)100/$plen --client-ips 10 \
        --client-gw $(net 10)1 --connect $(net 10)1:5060 >"$log" 2>&1 || status=$?
    cat "$log"
    if ! grep -Eq "^  client: 10 transactions, 10 answered" "$log" ||
        grep -Eq "^  client: .*(timed out|other answers than expected)" "$log"; then
        fail "the emulated phones' calls to SIPp did not all end well"
    fi
    grep -Eq "^  client: .*10 media streams \(PCMU x10\): [1-9][0-9]* packets sent, [1-9][0-9]* received" "$log" ||
        fail "the emulated phones got none of their RTP back from SIPp"
    if wait "$sipp_pid"; then
        echo "sipp: answered 10 calls"
    else
        fail "sipp's answering end did not see 10 successful calls"
        cat "$tmp/sipp-uas.err" "$tmp/sipp-uas" 2>/dev/null | tail -40 || true
    fi
    sipp_pid=
fi

echo "router: datagrams masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all SIP checks passed"
exit $status
