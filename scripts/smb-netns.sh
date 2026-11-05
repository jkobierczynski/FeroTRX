#!/bin/sh
# Builds a small lab in Linux network namespaces and plays SMB 2 and 3 over
# stateful TCP through a real NAT router: emulated file clients against an
# emulated file server, then smbclient against the emulated server and the
# emulated clients against Samba's smbd.
#
#   ferotrx (this namespace)          router (namespace ferotrx-smb)
#   t0 trunk --- veth --------------- rt: rt.10 192.168.10.1/24  (clients)
#     client 192.168.10.100-109 vlan 10   rt.20 192.168.20.1/24  (server)
#     server 192.168.20.80 vlan 20        masquerade out of rt.20
#
# Usage: sudo scripts/smb-netns.sh [path/to/ferotrx] [extra ferotrx tcp options]
# (the options go to run 1, with both ends emulated)
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done.
#
# 1. The templates of examples/lab-smb.toml: SMB 3.1.1 logins with signing,
#    a 1 MB file written, read back and checked, a directory listed and the
#    file deleted; SMB 2.1 signed with HMAC-SHA256; anonymous reads of a
#    read-only share, whose write must be refused; and a wrong password
#    that must be refused. Every operation must end as expected.
# 2. If smbclient and ethtool are installed: the emulated server alone, and
#    smbclient on the router uploads a file, lists the share, downloads the
#    file (and compares it), reads a file of the server's and deletes its
#    upload, with SMB 3.1.1 signed, SMB 3.0, SMB 2.1 and SMB 2.0.2; a wrong
#    password must be refused, and an anonymous login can read the public
#    share but not write to it.
# 3. If smbd, smbpasswd and ethtool are installed: Samba's smbd on the
#    router (its own configuration, share and password database, nothing
#    of the system's), and the emulated clients write, read back, list and
#    delete files there with SMB 3.1.1, 3.0.2 and 2.1, signed and not, and
#    a wrong password that smbd must refuse.
#
# LOSS=0.03 makes the router drop 3% of the packets it forwards.
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
NS=ferotrx-smb
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-smb.XXXXXX)

# smbd and the children it forked for each connection.
stop_smbd() {
    [ -n "${smbd_pid:-}" ] || return 0
    pids="$smbd_pid $(cat "$tmp/samba/pid/smbd.pid" 2>/dev/null || true)"
    pids="$pids $(pgrep -f "smbd .*$tmp/samba" 2>/dev/null || true)"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    i=0
    while kill -0 "$smbd_pid" 2>/dev/null && [ $i -lt 30 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    # shellcheck disable=SC2086
    kill -9 $pids $(pgrep -f "smbd .*$tmp/samba" 2>/dev/null || true) 2>/dev/null || true
}

cleanup() {
    [ -z "${server_pid:-}" ] || kill "$server_pid" 2>/dev/null || true
    stop_smbd
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
fail() {
    echo "FAIL: $*" >&2
    status=1
}

# The example profile without its [client] and [server] tables: the
# addresses come from the command line.
# Smaller files than the example's, to keep a debug build quick.
sed -e '/^\[client\]/,$d' -e 's/ 1M"/ 256K"/' -e 's/= "512K"/= "128K"/' \
    "$examples/lab-smb.toml" >"$tmp/smb.toml"
cat >>"$tmp/smb.toml" <<EOT
[client]
ip = "0.0.0.0"
[server]
ip = "0.0.0.0"
EOT

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

echo "== 1. SMB clients and server through the router"
# shellcheck disable=SC2086
"$BIN" tcp -p "$tmp/smb.toml" $links $client $server -n 30 --cps 20 -q "$@" >"$log" 2>&1 || status=$?
cat "$log"
# negotiate, login, tree connect, the operations, logoff
check_template office 9
check_template legacy 7
check_template public 7
check_template intruder 2
grep -Eq "^    office client: .*SMB logins \(SMB 3.1.1 signed AES-CMAC x[1-9][0-9]*\), 0 failed" "$log" ||
    fail "office: not every login was SMB 3.1.1 signed with AES-CMAC"
grep -Eq "^    legacy client: .*SMB 2.1 signed HMAC-SHA256 x[1-9]" "$log" ||
    fail "legacy: no SMB 2.1 logins signed with HMAC-SHA256"
grep -Eq "^    public client: .*write STATUS_ACCESS_DENIED x[1-9]" "$log" ||
    fail "public: the read-only share took a write"
grep -Eq "^    intruder client: .*login STATUS_LOGON_FAILURE x[1-9]" "$log" ||
    fail "intruder: the wrong password was not refused"
grep -q "wrong data" "$log" && fail "a file read back was not what was written"

if [ "${IPV6:-}" = 1 ]; then
    echo "IPV6=1: skipping the runs with smbclient and smbd"
    rlinks=
elif ! command -v ethtool >/dev/null 2>&1; then
    echo "no ethtool: skipping the runs with smbclient and smbd"
    rlinks=
else
    # The router's own packets leave with the checksum left to the (virtual)
    # NIC, which a veth never fills in, and the emulated hosts check it:
    # have the kernel fill it in.
    if [ $vlan = yes ]; then rlinks="rt rt.10 rt.20"; else rlinks="rc rs"; fi
    for l in $rlinks; do r ethtool -K $l tx off >/dev/null 2>&1 || true; done
fi

if [ -n "$rlinks" ] && command -v smbclient >/dev/null 2>&1; then
    echo "== 2. smbclient against the emulated server"
    sed '/^\[client\]/,$d' "$tmp/smb.toml" >"$tmp/server.toml"
    printf '[server]\nip = "0.0.0.0"\n' >>"$tmp/server.toml"
    # shellcheck disable=SC2086
    "$BIN" tcp -p "$tmp/server.toml" $server_links $server -d 40s -q >"$tmp/server" 2>&1 &
    server_pid=$!
    sleep 1
    head -c 300000 /dev/urandom >"$tmp/up.bin"
    smb() { # user%password, share, protocol, commands, extra smbclient options
        cred=$1 share=$2 proto=$3 cmds=$4
        shift 4
        # A configuration of its own: nothing from the system's smb.conf.
        r smbclient -s /dev/null "//$(net 20)80/$share" $cred -m "$proto" \
            --option="client min protocol=SMB2_02" "$@" -c "$cmds" >"$tmp/smbclient" 2>&1
    }
    for proto in SMB3_11 SMB3 SMB2_10 SMB2_02; do
        rm -f "$tmp/down.bin"
        if smb "-Ualice%lab" lab $proto \
            "lcd $tmp; put up.bin up-$proto.bin; ls; get up-$proto.bin down.bin; get readme.txt readme.txt; del up-$proto.bin" \
            --option="client signing=required" &&
            cmp -s "$tmp/up.bin" "$tmp/down.bin" && [ "$(wc -c <"$tmp/readme.txt")" -eq 4096 ]; then
            echo "  smbclient $proto signed: put, ls, get (300000 bytes, the same), get readme.txt, del"
        else
            fail "smbclient $proto: put, ls, get or del failed"
            sed 's/^/    /' "$tmp/smbclient" | tail -20
        fi
    done
    if smb "-Ualice%guess" lab SMB3 "ls"; then
        fail "smbclient: a wrong password was taken"
    elif grep -q LOGON_FAILURE "$tmp/smbclient"; then
        echo "  smbclient: a wrong password gave NT_STATUS_LOGON_FAILURE"
    else
        fail "smbclient: a wrong password failed otherwise: $(tail -1 "$tmp/smbclient")"
    fi
    # The public template's server is on port 1446.
    if smb "-N" public SMB3 "lcd $tmp; get readme.txt anon.txt" -p 1446 && [ -s "$tmp/anon.txt" ]; then
        echo "  smbclient: anonymous read of the public share"
    else
        fail "smbclient: an anonymous read of the public share failed"
        sed 's/^/    /' "$tmp/smbclient" | tail -10
    fi
    if smb "-N" public SMB3 "lcd $tmp; put up.bin x.bin" -p 1446; then
        fail "smbclient: the read-only share took a file"
    elif grep -q "ACCESS_DENIED" "$tmp/smbclient"; then
        echo "  smbclient: the read-only share refused a file (NT_STATUS_ACCESS_DENIED)"
    else
        fail "smbclient: a write to the read-only share failed otherwise: $(tail -1 "$tmp/smbclient")"
    fi
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
    cat "$tmp/server"
    grep -q "bad signature" "$tmp/server" && fail "the emulated server saw bad signatures"
else
    echo "no smbclient or ethtool: skipping smbclient against the emulated server"
fi

if [ -n "$rlinks" ] && command -v smbd >/dev/null 2>&1 && command -v smbpasswd >/dev/null 2>&1; then
    echo "== 3. The emulated clients against smbd"
    # Everything in $tmp: configuration, share, password database, state.
    sd=$tmp/samba
    mkdir -p "$sd/share" "$sd/private" "$sd/lock" "$sd/state" "$sd/cache" "$sd/pid" "$sd/log"
    chmod 777 "$sd/share"
    cat >"$sd/smb.conf" <<EOT
[global]
    server role = standalone server
    workgroup = LAB
    netbios name = SAMBA
    disable netbios = yes
    smb ports = 445
    private dir = $sd/private
    lock directory = $sd/lock
    state directory = $sd/state
    cache directory = $sd/cache
    pid directory = $sd/pid
    log file = $sd/log/%m.log
    ncalrpc dir = $sd/lock/ncalrpc
    passdb backend = tdbsam:$sd/private/passdb.tdb
    map to guest = never
    server min protocol = SMB2_02
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
[lab]
    path = $sd/share
    read only = no
EOT
    printf 'lab\nlab\n' | r smbpasswd -c "$sd/smb.conf" -a -s root >/dev/null
    r smbd --foreground -s "$sd/smb.conf" >"$sd/log/smbd.out" 2>&1 &
    smbd_pid=$!
    i=0
    while ! r ss -ltn 2>/dev/null | grep -q ':445 ' && [ $i -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    sleep 1
    run_client() { # label, smb table lines
        what=$1
        shift
        {
            printf 'app = "smb"\n[smb]\nuser = "root"\nshare = "lab"\n'
            printf '%s\n' "$@"
            printf '[client]\nip = "0.0.0.0"\n'
        } >"$tmp/client.toml"
        # shellcheck disable=SC2086
        "$BIN" tcp -p "$tmp/client.toml" $client_links $client --connect "$(net 10)1" \
            -n 4 --cps 4 -q >"$log" 2>&1 || true
        line=$(grep -E "^  client: " "$log" || true)
        if echo "$line" | grep -Eq "^  client: 4 connections, 4 established, 4 completed;" &&
            echo "$line" | grep -Eq "\), 0 failed"; then
            echo "  $what: $(echo "$line" | sed -n 's/.*; \([0-9]* transactions ([^)]*)\).*/\1/p')"
        else
            fail "the emulated client against smbd, $what"
            cat "$log"
            tail -20 "$sd/log/smbd.out" "$sd"/log/*.log 2>/dev/null | tail -30
        fi
        echo "$line"
    }
    ops='ops = ["write ferotrx-{n}.bin 300K", "read ferotrx-{n}.bin", "mkdir d-{n}", "list", "rmdir d-{n}", "delete ferotrx-{n}.bin"]'
    run_client "SMB 3.1.1 signed" 'password = "lab"' 'dialects = ["3.1.1"]' 'signing = "required"' "$ops"
    run_client "SMB 3.1.1" 'password = "lab"' 'dialects = ["3.1.1"]' "$ops"
    run_client "SMB 3.0.2 signed" 'password = "lab"' 'dialects = ["3.0.2"]' 'signing = "required"' "$ops"
    run_client "SMB 2.1 signed" 'password = "lab"' 'dialects = ["2.1"]' 'signing = "required"' "$ops"
    run_client "a wrong password" 'password = "guess"' 'expect = "LOGON_FAILURE"'
    stop_smbd
    smbd_pid=
else
    echo "no smbd, smbpasswd or ethtool: skipping the emulated clients against smbd"
fi

echo "router: connections masqueraded, and dropped:"
[ $nat = no ] || ipt -t nat -L POSTROUTING -v -n | sed -n '3p'
ipt -L FORWARD -v -n | sed -n '3,$p'
[ $status -ne 0 ] || echo "all SMB checks passed"
exit $status
