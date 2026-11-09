#!/bin/sh
# Checks FeroTRX's link services against the usual tools, on a veth link
# into a network namespace:
#
#   ferotrx (this namespace)          peer (namespace ferotrx-svc)
#   s0 --- veth ------------------ p0 10.80.0.1/24, fd00:80::1/64
#
# Usage: sudo scripts/services-netns.sh [path/to/ferotrx] [extra ferotrx options]
# (the extra options, e.g. -B af_xdp, go to each `ferotrx host`)
# Needs root and ip (iproute2). The checks need lldpd, dig (bind9-dnsutils),
# avahi-daemon, wpa_supplicant, hostapd and tshark; with IPV6=1 also rdisc6
# (ndisc6) and dhcpcd (dhcpcd-base). A check whose tool is missing is skipped
# with a note; SKIP_MISSING=0 makes that a failure (CI).
#
# It checks that:
#   1. lldpd lists a FeroTRX host by LLDP and by CDP, with its name and
#      address, and the host lists lldpd's system as its LLDP neighbor;
#   2. dig (legacy unicast mDNS queries to the host's address, port 5353)
#      gets a FeroTRX host's address and its DNS-SD service; the host finds a
#      service that avahi publishes (by multicast);
#   3. wpa_supplicant (wired, EAP-MD5) authenticates against a FeroTRX
#      802.1X authenticator, and is refused with a wrong password; a FeroTRX
#      supplicant authenticates against hostapd's wired authenticator, and
#      fails with a wrong password;
#   4. tshark decodes the IPFIX and the NetFlow v9 records a FeroTRX host
#      exports to a collector address in the namespace, after the host
#      resolved it by ARP.
#
# IPV6=1 adds:
#   5. rdisc6 sees the MTU, DNS server (RDNSS) and search domain (DNSSL) in a
#      FeroTRX router's advertisements;
#   6. dhcpcd gets an address and a delegated prefix from a FeroTRX DHCPv6
#      server, and so does a FeroTRX requesting router in the same run.
set -eu

if [ "$(id -u)" != 0 ]; then
    echo "needs root (network namespaces): sudo $0 $*" >&2
    exit 2
fi

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
if ! command -v ip >/dev/null 2>&1; then
    echo "ip is not installed: apt-get install iproute2" >&2
    exit 2
fi
echo "using $BIN"

v6=no
if [ "${IPV6:-}" = 1 ]; then
    if ! [ -d /proc/sys/net/ipv6 ]; then
        echo "IPV6=1, but this kernel has IPv6 disabled (ipv6.disable=1?)" >&2
        exit 2
    fi
    v6=yes
fi

NS=ferotrx-svc
tmp=$(mktemp -d /tmp/ferotrx-svc.XXXXXX)
# lldpd and avahi drop root: they must reach their sockets and files here.
chmod 755 "$tmp"
pids=

cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    ip link del s0 2>/dev/null || true
    ip netns del $NS 2>/dev/null || true
    rm -rf "/etc/netns/$NS"
    rm -rf "$tmp"
}
trap cleanup EXIT
ip link del s0 2>/dev/null || true
ip netns del $NS 2>/dev/null || true

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
ip link add s0 type veth peer name p0
ip link set p0 netns $NS
r ip link set p0 address 02:80:00:00:00:01
if [ $v6 = yes ]; then
    # The FeroTRX side needs no kernel IPv6: its hosts have their own.
    sysctl -qw net.ipv6.conf.s0.disable_ipv6=1
    r sysctl -qw net.ipv6.conf.p0.accept_dad=0
else
    sysctl -qw net.ipv6.conf.s0.disable_ipv6=1 2>/dev/null || true
fi
ip link set s0 up
r ip link set p0 up
r ip addr add 10.80.0.1/24 dev p0
# Multicast (mDNS) out of p0.
r ip route add 224.0.0.0/4 dev p0
if [ $v6 = yes ]; then
    r ip -6 addr add fd00:80::1/64 dev p0 nodad
fi

status=0
fail() {
    echo "FAIL: $*"
    status=1
}
# Skips a check whose tool is missing, or fails it with SKIP_MISSING=0.
have() { # tool package
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    if [ "${SKIP_MISSING:-1}" = 0 ]; then
        fail "$1 is not installed (apt-get install $2)"
    else
        echo "skipped: $1 is not installed (apt-get install $2)"
    fi
    return 1
}
# (Daemons start with `ip netns exec` itself, not `r`, so that $! is theirs.)
# Waits up to $2 tenths of a second for the command in $3... to succeed.
wait_for() { # tenths command...
    n=$1
    shift
    i=0
    while ! "$@" >/dev/null 2>&1; do
        [ $i -lt "$n" ] || return 1
        sleep 0.1
        i=$((i + 1))
    done
}
show() { # file
    sed 's/^/    /' "$1"
}

# --- 1. LLDP and CDP with lldpd ----------------------------------------------
echo "== 1. LLDP and CDP with lldpd"
if have lldpd lldpd; then
    # -cccc: CDPv2 only, sent once a CDP neighbor shows up.
    ip netns exec $NS lldpd -d -cccc -I p0 -u "$tmp/lldpd.socket" >"$tmp/lldpd.log" 2>&1 &
    pids="$pids $!"
    lldpcli() { r lldpcli -u "$tmp/lldpd.socket" "$@"; }
    if ! wait_for 50 lldpcli show configuration; then
        fail "lldpd did not start"
        show "$tmp/lldpd.log"
    else
        lldpcli configure lldp tx-interval 1 >/dev/null
        lldpcli configure system hostname lab-peer >/dev/null
        "$BIN" host -i s0 --ipv4 10.80.0.5/24 --hostname ftrx-lldp --lldp --cdp \
            --lldp-interval 2s -d 8s "$@" >"$tmp/lldp.log" 2>&1 &
        host_pid=$!
        pids="$pids $host_pid"
        sleep 5
        # `hidden`: lldpd's smart filter shows only the LLDP entry of a
        # neighbor that speaks LLDP and CDP.
        lldpcli show neighbors details hidden >"$tmp/neighbors" 2>&1 || true
        if grep -q "SysName: *ftrx-lldp" "$tmp/neighbors" &&
            grep -q "via: LLDP" "$tmp/neighbors" &&
            grep -q "via: CDPv2" "$tmp/neighbors" &&
            grep -q "MgmtIP: *10.80.0.5" "$tmp/neighbors"; then
            echo "ok: lldpd lists ftrx-lldp by LLDP and CDP, at 10.80.0.5"
        else
            fail "lldpd does not list ftrx-lldp by LLDP and CDPv2"
            show "$tmp/neighbors"
        fi
        if ! wait "$host_pid"; then
            fail "ferotrx host (LLDP) failed"
        fi
        if grep -q "lldp neighbor lab-peer port " "$tmp/lldp.log"; then
            echo "ok: the FeroTRX host lists lab-peer as its LLDP neighbor"
        else
            fail "the FeroTRX host does not list lab-peer"
            show "$tmp/lldp.log"
        fi
        sleep 1
        lldpcli show neighbors >"$tmp/neighbors" 2>&1 || true
        if grep "via: LLDP" "$tmp/neighbors" >/dev/null; then
            fail "lldpd still lists the LLDP neighbor after its shutdown frame"
            show "$tmp/neighbors"
        else
            echo "ok: the shutdown frame removed the LLDP neighbor"
        fi
    fi
fi

# --- 2. mDNS with dig and avahi ----------------------------------------------
echo "== 2. mDNS"
if have dig bind9-dnsutils; then
    avahi=no
    if command -v avahi-daemon >/dev/null 2>&1; then
        # `ip netns exec` puts /etc/netns/$NS/avahi over /etc/avahi.
        mkdir -p "/etc/netns/$NS/avahi/services"
        cat >"/etc/netns/$NS/avahi/avahi-daemon.conf" <<EOT
[server]
host-name=lab-peer
use-ipv4=yes
use-ipv6=no
allow-interfaces=p0
enable-dbus=no
[publish]
publish-addresses=yes
EOT
        cat >"/etc/netns/$NS/avahi/services/ipp.service" <<EOT
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name>Lab printer</name>
  <service><type>_ipp._tcp</type><port>631</port></service>
</service-group>
EOT
        # Its own /run/avahi-daemon, for the PID file and socket.
        mkdir -p /run/avahi-daemon
        ip netns exec $NS unshare -m sh -c \
            'mount -t tmpfs tmpfs /run/avahi-daemon &&
             exec avahi-daemon --no-drop-root --no-chroot --no-rlimits' \
            >"$tmp/avahi.log" 2>&1 &
        pids="$pids $!"
        avahi=yes
        sleep 2
    else
        have avahi-daemon avahi-daemon || true
    fi
    "$BIN" host -i s0 --ipv4 10.80.0.6/24 --hostname ftrx-mdns --mdns \
        --mdns-service "_http._tcp:8080:FeroTRX web" --mdns-query _ipp._tcp \
        -d 8s "$@" >"$tmp/mdns.log" 2>&1 &
    host_pid=$!
    pids="$pids $host_pid"
    sleep 2
    a=$(r dig +short +tries=2 +time=1 -p 5353 @10.80.0.6 ftrx-mdns.local A || true)
    if [ "$a" = 10.80.0.6 ]; then
        echo "ok: dig gets ftrx-mdns.local = 10.80.0.6"
    else
        fail "dig got '$a' for ftrx-mdns.local, not 10.80.0.6"
    fi
    ptr=$(r dig +short +tries=2 +time=1 -p 5353 @10.80.0.6 _http._tcp.local PTR || true)
    srv=$(r dig +short +tries=2 +time=1 -p 5353 @10.80.0.6 \
        'FeroTRX\032web._http._tcp.local' SRV || true)
    if printf '%s\n' "$ptr" | grep -q 'FeroTRX\\032web._http._tcp.local' &&
        printf '%s\n' "$srv" | grep -q "8080 ftrx-mdns.local"; then
        echo "ok: dig browses _http._tcp: FeroTRX web, port 8080 on ftrx-mdns.local"
    else
        fail "dig did not find the _http._tcp service (PTR '$ptr', SRV '$srv')"
    fi
    if ! wait "$host_pid"; then
        fail "ferotrx host (mDNS) failed"
        show "$tmp/mdns.log"
    fi
    if [ $avahi = yes ]; then
        if grep -q "mdns _ipp._tcp.local PTR Lab printer._ipp._tcp.local" "$tmp/mdns.log" &&
            grep -q "mdns Lab printer._ipp._tcp.local SRV 0 0 631 lab-peer.local" "$tmp/mdns.log"; then
            echo "ok: the FeroTRX host found avahi's Lab printer (_ipp._tcp, port 631)"
        else
            fail "the FeroTRX host did not find avahi's _ipp._tcp service"
            show "$tmp/mdns.log"
            show "$tmp/avahi.log"
        fi
    fi
fi

# --- 3. 802.1X with wpa_supplicant and hostapd -------------------------------
echo "== 3. 802.1X"
# wpa_supplicant against a FeroTRX authenticator; $1 is its password.
supplicant() { # password log [extra ferotrx options]
    pw=$1
    log=$2
    shift 2
    cat >"$tmp/wpa.conf" <<EOT
ctrl_interface=$tmp/wpa
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="alice"
    password="$pw"
    eapol_flags=0
}
EOT
    "$BIN" host -i s0 --mac 02:dc:00:00:0a:01 --dot1x-user alice:secret -d 6s "$@" \
        >"$tmp/$log.log" 2>&1 &
    host_pid=$!
    pids="$pids $host_pid"
    sleep 1
    ip netns exec $NS wpa_supplicant -D wired -i p0 -c "$tmp/wpa.conf" >"$tmp/$log.wpa" 2>&1 &
    wpa=$!
    pids="$pids $wpa"
    sleep 3
    r wpa_cli -p "$tmp/wpa" -i p0 status >"$tmp/$log.status" 2>&1 || true
    kill $wpa 2>/dev/null || true
    wait $wpa 2>/dev/null || true
    wait "$host_pid" || true
}
if have wpa_supplicant wpasupplicant; then
    supplicant secret dot1x-auth "$@"
    if grep -q "Supplicant PAE state=AUTHENTICATED" "$tmp/dot1x-auth.status" &&
        grep -q "802.1X 02:80:00:00:00:01 authorized as alice" "$tmp/dot1x-auth.log"; then
        echo "ok: wpa_supplicant authenticated as alice with the FeroTRX authenticator"
    else
        fail "wpa_supplicant was not authenticated by the FeroTRX authenticator"
        show "$tmp/dot1x-auth.status"
        show "$tmp/dot1x-auth.log"
    fi
    supplicant wrong dot1x-refused "$@"
    if ! grep -q "Supplicant PAE state=AUTHENTICATED" "$tmp/dot1x-refused.status" &&
        grep -q "802.1X 02:80:00:00:00:01 refused as alice" "$tmp/dot1x-refused.log"; then
        echo "ok: with a wrong password the FeroTRX authenticator refused it"
    else
        fail "a wrong password was not refused"
        show "$tmp/dot1x-refused.status"
        show "$tmp/dot1x-refused.log"
    fi
fi
if have hostapd hostapd; then
    printf '"bob" MD5 "secret"\n' >"$tmp/eap_users"
    cat >"$tmp/hostapd.conf" <<EOT
interface=p0
driver=wired
logger_stdout=-1
logger_stdout_level=2
ieee8021x=1
eapol_version=2
eap_server=1
eap_user_file=$tmp/eap_users
use_pae_group_addr=1
EOT
    ip netns exec $NS hostapd "$tmp/hostapd.conf" >"$tmp/hostapd.log" 2>&1 &
    pids="$pids $!"
    sleep 1
    if "$BIN" host -i s0 --mac 02:dc:00:00:0b:01 --ipv4 10.80.0.7/24 \
        --dot1x bob:secret --until-ready -d 10s "$@" >"$tmp/dot1x-sup.log" 2>&1 &&
        grep -q "802.1X authorized as bob with 02:80:00:00:00:01" "$tmp/dot1x-sup.log"; then
        echo "ok: a FeroTRX supplicant authenticated as bob with hostapd, then took its address"
    else
        fail "the FeroTRX supplicant was not authenticated by hostapd"
        show "$tmp/dot1x-sup.log"
        show "$tmp/hostapd.log"
    fi
    if "$BIN" host -i s0 --mac 02:dc:00:00:0b:02 --ipv4 10.80.0.8/24 \
        --dot1x bob:wrong --until-ready -d 10s "$@" >"$tmp/dot1x-bad.log" 2>&1; then
        fail "a FeroTRX supplicant with a wrong password was ready"
        show "$tmp/dot1x-bad.log"
    elif grep -q "802.1X authentication failed" "$tmp/dot1x-bad.log"; then
        echo "ok: with a wrong password hostapd refused the FeroTRX supplicant"
    else
        fail "the FeroTRX supplicant with a wrong password failed for another reason"
        show "$tmp/dot1x-bad.log"
    fi
fi

# --- 4. NetFlow v9 and IPFIX with tshark -------------------------------------
echo "== 4. flow export"
# Exports to the namespace's address on port $2 as version $1; tshark
# decodes the records.
flows() { # version port
    ip netns exec $NS tshark -n -i p0 -a duration:6 -f "udp port $2" -d "udp.port==$2,cflow" \
        -T fields -e cflow.version -e cflow.srcaddr -e cflow.dstaddr \
        >"$tmp/flows-$1" 2>"$tmp/tshark-$1.log" &
    tsh=$!
    pids="$pids $tsh"
    sleep 2
    shift 2
    "$BIN" host -i s0 --ipv4 10.80.0.9/24 --flow-export "10.80.0.1:$port" \
        --flow-version "$version" --flow-records 5 -d 3s "$@" >"$tmp/flow-$version.log" 2>&1 ||
        fail "ferotrx host (flow export $version) failed"
    wait $tsh 2>/dev/null || true
}
if have tshark tshark; then
    for spec in ipfix:4739:10 netflow9:2055:9; do
        version=${spec%%:*}
        rest=${spec#*:}
        port=${rest%%:*}
        want=${rest#*:}
        flows "$version" "$port" "$@"
        records=$(awk -v v="$want" '$1 == v && $2 ~ /^10\.1\./ && $3 ~ /^10\.2\./' \
            "$tmp/flows-$version" | tr ',' '\n' | wc -l)
        packets=$(awk -v v="$want" '$1 == v' "$tmp/flows-$version" | wc -l)
        if [ "$packets" -ge 2 ] && [ "$records" -ge 10 ]; then
            echo "ok: tshark decoded $packets $version packets from the FeroTRX exporter"
        else
            fail "tshark decoded $packets $version packets ($records records)"
            show "$tmp/flows-$version"
            show "$tmp/tshark-$version.log"
            show "$tmp/flow-$version.log"
        fi
    done
fi

# --- 5, 6. IPv6: router advertisement options, prefix delegation ------------
if [ $v6 = yes ]; then
    echo "== 5. router advertisement options"
    if have rdisc6 ndisc6; then
        "$BIN" host -i s0 --ra fd00:80::/64 --ra-interval 2s --ra-mtu 1400 \
            --ra-dns fd00:80::53 --ra-search lab.test -d 6s "$@" >"$tmp/ra.log" 2>&1 &
        host_pid=$!
        pids="$pids $host_pid"
        sleep 1
        r rdisc6 -1 -w 3000 p0 >"$tmp/rdisc6" 2>&1 || true
        wait "$host_pid" || fail "ferotrx host (router) failed"
        if grep -q "MTU *: *1400" "$tmp/rdisc6" &&
            grep -q "Recursive DNS server *: *fd00:80::53" "$tmp/rdisc6" &&
            grep -q "DNS search list *: *lab.test" "$tmp/rdisc6"; then
            echo "ok: rdisc6 sees MTU 1400, DNS server fd00:80::53 and search domain lab.test"
        else
            fail "rdisc6 does not see the MTU, RDNSS and DNSSL options"
            show "$tmp/rdisc6"
        fi
    fi
    echo "== 6. DHCPv6 prefix delegation"
    if have dhcpcd dhcpcd-base; then
        cat >"$tmp/pd.toml" <<EOT
format = 1
duration = "12s"
[[host]]
mac = "02:dc:00:00:0d:01"
[host.router]
prefixes = ["fd00:80::/64"]
interval = "2s"
managed = true
[host.dhcpv6_server]
pool = "fd00:80::100-fd00:80::1ff"
lease = "60s"
pd_pool = "fd00:8000::/40"
pd_length = 56
[[host]]
mac = "02:dc:00:00:0d:02"
ipv6 = "slaac"
prefix_delegation = 56
EOT
        # A /56 hint; "-": put the prefix on no interface.
        cat >"$tmp/dhcpcd.conf" <<EOT
ipv6only
nohook resolv.conf
duid ll
ia_na 1
ia_pd 2/::/56 -
EOT
        "$BIN" host "$tmp/pd.toml" -i s0 "$@" >"$tmp/pd.log" 2>&1 &
        host_pid=$!
        pids="$pids $host_pid"
        sleep 1
        # dhcpcd keeps its lease when stopped (no release without -k).
        r timeout 8 dhcpcd -6 -B -d -f "$tmp/dhcpcd.conf" p0 >"$tmp/dhcpcd.log" 2>&1 || true
        wait "$host_pid" || fail "ferotrx host (DHCPv6 server) failed"
        # The server's lease lines: `lease fd00:8000:100::/56 to MAC, ...`.
        if grep -qE "lease fd00:80[0-9a-f:]*/56 to 02:80:00:00:00:01" "$tmp/pd.log"; then
            echo "ok: dhcpcd got a /56 from fd00:8000::/40"
        else
            fail "dhcpcd got no delegated prefix"
            show "$tmp/dhcpcd.log"
            show "$tmp/pd.log"
        fi
        if grep -qE "lease fd00:80::1[0-9a-f]{2} to 02:80:00:00:00:01" "$tmp/pd.log"; then
            echo "ok: and an address from fd00:80::100-1ff"
        else
            fail "dhcpcd got no address"
        fi
        if grep -q "delegated prefix fd00:80[0-9a-f:]*/56" "$tmp/pd.log"; then
            echo "ok: the FeroTRX requesting router got a delegated prefix too"
        else
            fail "the FeroTRX requesting router got no delegated prefix"
            show "$tmp/pd.log"
        fi
    fi
fi

if [ $status = 0 ]; then
    echo "all link service checks passed"
fi
exit $status
