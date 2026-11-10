#!/bin/sh
# Builds a small lab in Linux network namespaces and checks that FeroTRX's
# realistic workloads measure what they were given: session lengths, think
# times, users kept online with lifetimes, and personas, through a NAT
# router.
#
#   ferotrx (this namespace)          router (namespace ferotrx-real)
#   c0 --- veth --------------------- rc 192.168.10.1/24  (clients)
#   s0 --- veth --------------------- rs 192.168.20.1/24  (servers)
#                                     masquerade out of rs
#
# Usage: sudo scripts/realism-netns.sh [path/to/ferotrx] [extra ferotrx options]
# Needs root, ip (iproute2), iptables and jq. Removes the lab when done.
#
# 1. HTTP users: 20 kept online, think exp(200ms) between sessions, stay
#    exp(4s); sessions of lognormal(median=4, sigma=0.6) requests with
#    uniform(20ms, 60ms) between them. The measured median and mean of the
#    requests per session, the mean think time, the users' mean stay and
#    the users online must match.
# 2. A capture (examples/http.pcap) played in rounds for 1 s per session:
#    the sessions' measured length must be 1 s and a bit.
# 3. UDP users: 20 DNS users, think exp(100ms): the rate (users / think)
#    and the mean think time must match.
# 4. The persona files (examples/personas: office, iot, server over TCP;
#    office and iot over UDP), with livelier think times: every group's
#    users online, making sessions, none failed.
#
# LOSS=0.02 makes the router drop 2% of what it forwards (the checks of
# distributions still hold; failed sessions, fewer rounds per second and
# fewer lookups per second are allowed then).
set -eu

if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    BIN=$1
    shift
else
    BIN=
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
command -v jq >/dev/null 2>&1 || { echo "needs jq" >&2; exit 1; }
echo "using $BIN"
NS=ferotrx-real
examples=$(cd "$(dirname "$0")/../examples" && pwd)
tmp=$(mktemp -d /tmp/ferotrx-real.XXXXXX)

cleanup() {
    for l in c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT
cleanup
tmp=$(mktemp -d /tmp/ferotrx-real.XXXXXX)

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
for side in c:10 s:20; do
    n=${side%%:*}; net=${side##*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    r ip addr add "192.168.$net.1/24" dev r$n
    r ip link set r$n up
    if command -v ethtool >/dev/null 2>&1; then
        r ethtool -K r$n tx off >/dev/null 2>&1 || true
    fi
done
r iptables -t nat -A POSTROUTING -o rs -j MASQUERADE 2>/dev/null ||
    echo "no NAT in this kernel: the router only routes"
r iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
r iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
if [ -n "${LOSS:-}" ]; then
    r iptables -A FORWARD -m statistic --mode random --probability "$LOSS" -j DROP
fi

hosts="--client-iface c0 --server-iface s0 --client-ip 192.168.10.50/24 --client-ips 100 --client-gw 192.168.10.1 --server-ip 192.168.20.80/24 --server-gw 192.168.20.1"
min_rounds=3 min_tps=160
[ -n "${LOSS:-}" ] && min_rounds=1 min_tps=100
status=0
fail() { echo "FAIL: $*" >&2; status=1; }

# Is $1 within [$2, $3]? (numbers, with decimals)
within() { awk -v v="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(v != "" && v != "null" && v >= lo && v <= hi) }'; }
check() { # what value lo hi
    if within "$2" "$3" "$4"; then
        echo "  ok    $1: $2 (expected $3 to $4)"
    else
        fail "$1: $2, expected $3 to $4"
    fi
}
no_failures() { # report kind
    [ -n "${LOSS:-}" ] && return 0
    f=$(jq ".$2.client.reset + .$2.client.timed_out // 0" "$1" 2>/dev/null || echo "?")
    [ "$2" = udp ] && f=$(jq ".udp.client.timed_out // 0" "$1")
    [ "$f" = 0 ] || fail "$f $2 sessions failed"
}
run() { # kind profile duration report [options]
    kind=$1 profile=$2 d=$3 report=$4
    shift 4
    # The addresses come from the command line.
    printf '[client]\nip = "0.0.0.0"\n[server]\nip = "0.0.0.0"\n' >>"$profile"
    code=0
    # shellcheck disable=SC2086
    "$BIN" "$kind" -p "$profile" $hosts -d "$d" -q --report "$report" "$@" >"$tmp/log" 2>&1 || code=$?
    if ! [ -s "$report" ]; then
        cat "$tmp/log" >&2
        fail "$kind run of $profile wrote no report (exit $code)"
        return 1
    fi
    sed -n '/^done\|^stopped/,$p' "$tmp/log" | grep -E "client:|users " | cut -c1-240 || true
}
j() { jq -r "$1" "$2"; }

echo "== 1. HTTP users: session lengths, think times, lifetimes"
cat >"$tmp/users.toml" <<EOT
format = 1
app = "http"
session_requests = "lognormal(median=4, sigma=0.6, max=40)"
think_time = "uniform(20ms, 60ms)"
[users]
count = 20
think = "exp(200ms)"
lifetime = "exp(4s)"
[http]
requests = ["GET /", "GET /a"]
[tcp]
seed = 7
EOT
if run tcp "$tmp/users.toml" 20s "$tmp/1.json" "$@"; then
    no_failures "$tmp/1.json" tcp
    check "requests per session, median" "$(j .tcp.client.session_requests.p50 "$tmp/1.json")" 3 5
    # e^(mu + sigma^2/2) = 4 x e^0.18 = 4.79
    check "requests per session, mean" "$(j .tcp.client.session_requests.avg "$tmp/1.json")" 4.2 5.4
    check "requests per session, fewest" "$(j .tcp.client.session_requests.min "$tmp/1.json")" 1 2
    check "think time between sessions, mean ms" "$(j '.tcp.users[-1].think.avg_us / 1000' "$tmp/1.json")" 175 225
    check "users online" "$(j '.tcp.users[-1].online' "$tmp/1.json")" 20 20
    check "users that left" "$(j '.tcp.users[-1].departed' "$tmp/1.json")" 50 160
    # A user leaves when the session it is in ends. Users still online at the
    # end are left out, so the measured stay is a little under 4 s.
    check "stay of users that left, mean s" "$(j '.tcp.users[-1].lifetime.avg_us / 1e6' "$tmp/1.json")" 2.4 5.5
    check "sessions" "$(j '.tcp.users[-1].sessions' "$tmp/1.json")" 400 2500
fi

echo "== 2. a capture played in rounds for 1 s per session"
cat >"$tmp/rounds.toml" <<EOT
format = 1
pcap = "$examples/http.pcap"
session_duration = "1s"
think_time = "100ms"
[users]
count = 5
EOT
if run tcp "$tmp/rounds.toml" 12s "$tmp/2.json" "$@"; then
    no_failures "$tmp/2.json" tcp
    check "session length, mean s" "$(j '.tcp.client.session_time.avg_us / 1e6' "$tmp/2.json")" 1.0 1.4
    # Think time pauses both ends: about 200 ms a round. A lost segment
    # costs a retransmit timeout.
    check "rounds per session, fewest" "$(j .tcp.client.session_requests.min "$tmp/2.json")" "$min_rounds" 10
    [ "$(j '.tcp.client.mismatched' "$tmp/2.json")" = 0 ] || fail "rounds carried other bytes than the capture"
fi

echo "== 3. UDP users: DNS lookups, think exp(100ms)"
cat >"$tmp/dns.toml" <<EOT
format = 1
app = "dns"
queries = ["www.lab.local A"]
records = ["www.lab.local A 192.168.20.80"]
[users]
count = 20
think = "exp(100ms)"
[udp]
seed = 9
EOT
if run udp "$tmp/dns.toml" 10s "$tmp/3.json" "$@"; then
    no_failures "$tmp/3.json" udp
    # 20 users / (0.1 s + an answer) each; a lost query or answer waits for
    # the 1 s timeout.
    check "lookups per second" "$(j .udp.tps "$tmp/3.json")" "$min_tps" 205
    check "think time, mean ms" "$(j '.udp.users[-1].think.avg_us / 1000' "$tmp/3.json")" 90 110
fi

echo "== 4. personas"
cat >"$tmp/personas.toml" <<EOT
format = 1
[[persona]]
file = "$examples/personas/office.toml"
users = 10
think = "exp(300ms)"
[[persona]]
file = "$examples/personas/iot.toml"
users = 30
think = "exp(500ms)"
[[persona]]
file = "$examples/personas/server.toml"
users = 2
[tcp]
idle_timeout = "1m"
EOT
if run tcp "$tmp/personas.toml" 15s "$tmp/4.json" "$@"; then
    no_failures "$tmp/4.json" tcp
    [ "$(j '.tcp.client.mismatched' "$tmp/4.json")" = 0 ] || fail "persona sessions failed their checks"
    for g in office:10 iot:30 server:2 all:42; do
        name=${g%%:*} n=${g##*:}
        online=$(j ".tcp.users[] | select(.name == \"$name\") | .online" "$tmp/4.json")
        sessions=$(j ".tcp.users[] | select(.name == \"$name\") | .sessions" "$tmp/4.json")
        echo "  users $name: $online online, $sessions sessions"
        [ "$online" = "$n" ] || fail "persona $name: $online users online, expected $n"
        within "$sessions" 1 1000000 || fail "persona $name made no sessions"
    done
    [ "$(j '[.tcp.templates[] | select(.client.started > 0)] | length' "$tmp/4.json")" = 4 ] ||
        fail "not every persona template was used: $(j '[.tcp.templates[] | {name, started: .client.started}]' "$tmp/4.json")"
fi
cat >"$tmp/personas-udp.toml" <<EOT
format = 1
[[persona]]
file = "$examples/personas/office.toml"
users = 10
think = "exp(300ms)"
[[persona]]
file = "$examples/personas/iot.toml"
users = 30
think = "exp(500ms)"
[udp]
timeout = "1s"
EOT
if run udp "$tmp/personas-udp.toml" 10s "$tmp/5.json" "$@"; then
    no_failures "$tmp/5.json" udp
    for name in office iot; do
        sessions=$(j ".udp.users[] | select(.name == \"$name\") | .sessions" "$tmp/5.json")
        echo "  users $name (UDP): $sessions sessions"
        within "$sessions" 10 1000000 || fail "persona $name made too few UDP sessions"
    done
fi

[ $status = 0 ] && echo "all checks passed"
exit $status
