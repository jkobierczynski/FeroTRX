#!/bin/sh
# Builds a small lab in Linux network namespaces and checks the stateless
# port's addresses of its own (TRex's L3 mode) and live rate control:
#
#   ferotrx (this namespace)            router (namespace ftrx-link)
#   c0 port 10.51.1.2/24 -------------- rc 10.51.1.1/24 (MAC unknown to ferotrx)
#                                       rs 10.51.2.1/24
#   s0 receives  <--------------------- rs
#
# 1. `ferotrx run` with --ip/--gateway: the router's MAC is found by ARP and
#    goes into every frame (the profile names no MACs), the router reaches
#    the port by ARP and its pings are answered, everything arrives on s0.
#    One stream asks for 50% of a 10 Mbit/s line rate, another sends bursts
#    and then starts a third.
# 2. `ferotrx bench` (a short latency test) with the same addresses: no
#    loss through the router.
# 3. The same through `ferotrx serve`: `ctl update -m 3` triples the rate of
#    the running run, `ctl pause` holds it and `ctl resume` goes on.
# 4. Loss made at a known place lands in the right column of the loss
#    report: the router drops every 20th frame (network), then the
#    router's port goes down for half a second, so the sending veth drops
#    what it is handed (generator, counted in its tx_dropped).
#
# Usage: sudo scripts/link-netns.sh [path/to/ferotrx] [extra ferotrx run options]
# Needs root, ip (iproute2), iptables, ping and jq. Removes the lab when done.
#
# IPV6=1      the same over IPv6 (fd00:51:1::/64, fd00:51:2::/64): neighbor
#             discovery instead of ARP, ping -6.
set -eu

# The binary: the first argument (unless it is an option), else a build in this checkout, else the
# installed one.
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
NS=ftrx-link
CTL=127.0.0.1:4591
WORK=
SERVER=

cleanup() {
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    for l in c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
if [ "${IPV6:-}" = 1 ]; then
    if ! [ -d /proc/sys/net/ipv6 ]; then
        echo "IPV6=1, but this kernel has IPv6 disabled (ipv6.disable=1?)" >&2
        exit 2
    fi
    r sysctl -qw net.ipv6.conf.all.forwarding=1
    a() { echo "fd00:51:$1::$2"; }
    plen=64
    addr() { r ip -6 addr add "$1" dev "$2" nodad; }
    ipl=ipv6
    ping6=-6
else
    a() { echo "10.51.$1.$2"; }
    plen=24
    addr() { r ip addr add "$1" dev "$2"; }
    ipl=ipv4
    ping6=
fi

for side in c:1 s:2; do
    n=${side%%:*}; net=${side##*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    # The host's own stack stays out of it: no addresses, no IPv6 on c0/s0.
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    if [ "${IPV6:-}" = 1 ]; then
        r sysctl -qw "net/ipv6/conf/r$n/accept_dad=0"
    fi
    addr "$(a $net 1)/$plen" r$n
    r ip link set r$n up
done
# The receiving host is ferotrx in promiscuous mode on s0.
r ip neigh replace "$(a 2 2)" lladdr 02:00:00:00:02:02 dev rs nud permanent
echo "router MAC on rc (ferotrx must find it): $(r cat /sys/class/net/rc/address)"

pkt="eth/$ipl(src=$(a 1 2),dst=$(a 2 2))/udp(sport=4000,dport=9000)/raw(len=18)"
cat > "$WORK/lab.toml" <<EOF
format = 1

[output]
line_rate = "10mbps"

# No MACs: the port's goes in as the source, the router's as the destination.
[[stream]]
name = "half"
packet = "$pkt"
rate = "50%"
loops = 0
latency = 1

[[stream]]
name = "bursts"
packet = "$pkt"
rate = "10kpps"
loops = 0
burst_size = 50
bursts = 4
burst_gap = "100ms"
next = "after"
latency = 2

# Waits for "bursts" to end, then sends 100 packets.
[[stream]]
name = "after"
packet = "$pkt"
rate = "1000pps"
loops = 0
limit = 100
latency = 3
EOF

fail=0
check() {
    if jq -e "$2" "$3" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        jq -c "$4" "$3" || true
        fail=1
    fi
}

echo "== 1. ferotrx run with the port's own address"
# The router pings the port while it runs (after it has resolved the gateway).
(sleep 1; r ping $ping6 -c 3 -i 0.3 -W 1 "$(a 1 2)" > "$WORK/ping.txt" 2>&1; echo $? > "$WORK/ping.status") &
pinger=$!
set +e
"$BIN" run "$WORK/lab.toml" -i c0 --ip "$(a 1 2)/$plen" --gateway "$(a 1 1)" \
    --rx s0 -d 3s --report "$WORK/run.json" "$@" > "$WORK/run.txt" 2>&1
status=$?
set -e
cat "$WORK/run.txt"
wait $pinger || true
[ $status -eq 0 ] || exit $status

if grep -q "next hop at $(r cat /sys/class/net/rc/address)" "$WORK/run.txt"; then
    echo "ok: the router's MAC was found"
else
    echo "FAILED: the router's MAC was not found"
    fail=1
fi
if [ "$(cat "$WORK/ping.status")" = 0 ]; then
    echo "ok: the router's pings to the port were answered"
else
    echo "FAILED: the router's pings to the port were not answered"
    cat "$WORK/ping.txt"
    fail=1
fi
f=$WORK/run.json
check "everything sent arrived through the router" '[.flows[] | .lost == 0 and .rx > 0] | all' "$f" '.flows'
# 50% of 10 Mbit/s on the wire: the frames' bits plus 24 bytes each.
check "\"50%\" of 10 Mbit/s is 5 Mbit/s on the wire" \
    '.flows[] | select(.name == "half") | .send | (.achieved_mbps + .achieved_pps * 24 * 8 / 1e6) as $w | $w > 4.5 and $w < 5.2' \
    "$f" '.flows[] | select(.name == "half") | .send'
check "4 bursts of 50" '(.flows[] | select(.name == "bursts") | .rx) == 200' "$f" '.flows'
check "\"after\" ran once bursts ended" '(.flows[] | select(.name == "after") | .rx) == 100' "$f" '.flows'

echo "== 2. ferotrx bench with the port's own address"
cat > "$WORK/bench.toml" <<EOF
format = 1

[benchmark]
packet = "$pkt"
tests = ["latency"]
sizes = [64]
line_rate = "10mbps"
latency_load = 10
trial_duration = "1s"
warmup = "200ms"

[output]
ip = "$(a 1 2)/$plen"
gateway = "$(a 1 1)"
EOF
"$BIN" bench "$WORK/bench.toml" -i c0 --rx s0 --report "$WORK/bench.json" -q > "$WORK/bench.txt" 2>&1 \
    || { cat "$WORK/bench.txt"; exit 1; }
b=$WORK/bench.json
check "the benchmark found the router and lost nothing" \
    '[.. | objects | select(has("lost")) | .lost] as $l | ($l | length) > 0 and ($l | all(. == 0)) and (.info.backend | test("next hop"))' \
    "$b" '{backend: .info.backend, lost: [.. | objects | select(has("lost")) | .lost]}'

echo "== 3. live rate control through ferotrx serve"
"$BIN" serve --listen $CTL --data-dir "$WORK" > "$WORK/serve.log" 2>&1 &
SERVER=$!
n=0
until "$BIN" ctl -c $CTL info >/dev/null 2>&1; do
    n=$((n + 1))
    [ $n -lt 50 ] || { echo "the server did not start"; cat "$WORK/serve.log"; exit 1; }
    sleep 0.1
done
cat > "$WORK/steady.toml" <<EOF
format = 1

[[stream]]
name = "steady"
packet = "$pkt"
rate = "1000pps"
loops = 0
EOF
ctl() { "$BIN" ctl -c $CTL "$@"; }
ctl load "$WORK/steady.toml" -n steady >/dev/null
id=$(ctl --json start steady -i c0 --ip "$(a 1 2)/$plen" --gateway "$(a 1 1)" | jq .id)
ctl stats "$id" | sed -n '1,2p'
# Packets and the run's own clock, from one snapshot of its counters.
snap() { ctl --json stats "$id" | jq -r '"\(.total.packets) \(.total.elapsed_s)"'; }
# Packets sent in 2 s, by the run's clock between two snapshots: a slow
# `ctl` call (a busy VM) makes the window longer, not the rate higher.
rate2s() {
    s0=$(snap)
    sleep 2
    s1=$(snap)
    echo "$s0 $s1" | awk '{ d = $4 - $2; if (d <= 0) print $3 - $1; else printf "%d\n", ($3 - $1) * 2 / d }'
}
sleep 0.5
before=$(rate2s)
ctl update "$id" -m 3 >/dev/null
sleep 0.2
after=$(rate2s)
ctl pause "$id" >/dev/null
sleep 0.2
held=$(rate2s)
ctl resume "$id" >/dev/null
sleep 0.2
resumed=$(rate2s)
info=$WORK/info.json
ctl --json stop "$id" > "$info"
echo "packets in 2 s: $before at 1000 pps, $after at x3, $held paused, $resumed resumed"
j() { echo "{\"before\":$before,\"after\":$after,\"held\":$held,\"resumed\":$resumed}" > "$WORK/rates.json"; }
j
r2=$WORK/rates.json
check "1000 pps at first" '.before > 1700 and .before < 2200' "$r2" .
check "about 3000 pps after update -m 3" '.after > 5100 and .after < 6600' "$r2" .
check "nothing sent while paused" '.held <= 2' "$r2" .
check "3000 pps again after resume" '.resumed > 5100 and .resumed < 6600' "$r2" .
check "the run reports its multiplier and port" '.multiplier == 3 and (.link | test("next hop"))' "$info" '{multiplier, link}'
kill "$SERVER" 2>/dev/null || true
wait "$SERVER" 2>/dev/null || true
SERVER=

echo "== 4. where frames are lost"
cat > "$WORK/probe.toml" <<EOF
format = 1

[[stream]]
name = "probe"
packet = "$pkt"
rate = "2000pps"
loops = 0
latency = 1
EOF
if [ "${IPV6:-}" = 1 ]; then ipt=ip6tables; else ipt=iptables; fi
probe() {
    "$BIN" run "$WORK/probe.toml" -i c0 --ip "$(a 1 2)/$plen" --gateway "$(a 1 1)" \
        --rx s0 -d 3s -q --ignore-errors --report "$1" > "$WORK/probe.txt" 2>&1 \
        || { cat "$WORK/probe.txt"; exit 1; }
    grep "lost .* of" "$WORK/probe.txt" || true
}
r $ipt -I FORWARD -m statistic --mode nth --every 20 --packet 0 -j DROP
probe "$WORK/net.json"
dropped=$(r $ipt -L FORWARD -v -n -x | awk '$3 == "DROP" {print $1; exit}')
r $ipt -D FORWARD -m statistic --mode nth --every 20 --packet 0 -j DROP
echo "the router dropped $dropped"
check "the router's drops are network loss" \
    ".loss.network == $dropped and .loss.network > 100 and .loss.generator == 0 and .loss.receiver == 0" \
    "$WORK/net.json" '.loss'
(sleep 1.2; r ip link set rc down; sleep 0.5; r ip link set rc up) &
flap=$!
probe "$WORK/gen.json"
wait $flap || true
# Depending on the kernel, the sending veth drops the frames and counts them
# (tx_dropped), or refuses them (ENOBUFS, a send error); both are the
# generator's. Frames the receiver's capture buffer dropped (a VM that
# stalls) are counted as the receiver's, apart from these.
check "frames the sending veth dropped or refused are generator loss" \
    '.loss.generator > 100 and .loss.generator >= 0.9 * (.loss.generator + .loss.network) and (.drops.nic_tx_errors > 0 or .loss.send_errors > 0)' \
    "$WORK/gen.json" '{loss, drops}'
exit $fail
