#!/bin/sh
# Checks live captures: `ferotrx capture` with BPF filters, pcap to a file,
# a ring of files and standard output (as Wireshark reads it), captures on a
# control server read from another machine (`ferotrx ctl capture`,
# `capture-start`, `fetch`), and `--capture` next to a run.
#
#   namespace ftrx-cap-a                namespace ftrx-cap-b
#   a0 10.9.4.1 ----------------------- b0 10.9.4.2   (ferotrx serve on b)
#
# 1. A filter: a run sends UDP to ports 9 and 10; a capture of 'udp dst
#    port 9' takes only those, and tcpdump agrees with what it wrote.
# 2. -w -: the pcap on standard output, read by tcpdump as it comes.
# 3. A ring: --rotate 2K --files 3 keeps the newest three files.
# 4. --direction in: pings from b, only the replies.
# 5. A capture on the server in b, from a: frames piped to tcpdump here;
#    then a capture into a file on the server, fetched here.
# 6. --capture on a run: what the run sent, in a pcap.
# 7. inspect -f: the same filter on a file.
#
# Usage: sudo scripts/capture-netns.sh [path/to/ferotrx]
# Needs root, ip (iproute2), ping and tcpdump. Removes the lab when done.
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
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
echo "using $BIN"
command -v tcpdump >/dev/null || { echo "tcpdump is needed (apt-get install tcpdump)" >&2; exit 1; }
A=ftrx-cap-a
B=ftrx-cap-b
WORK=
SERVER=

cleanup() {
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    ip netns del $A 2>/dev/null || true
    ip netns del $B 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)
mkdir -p "$WORK/server"

ip netns add $A
ip netns add $B
ip link add a0 netns $A type veth peer name b0 netns $B
for s in a:1:$A b:2:$B; do
    n=${s%%:*}; rest=${s#*:}; k=${rest%%:*}; ns=${rest#*:}
    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.all.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set ${n}0 address 02:00:00:00:04:0$k
    ip netns exec "$ns" ip addr add 10.9.4.$k/24 dev ${n}0
    ip netns exec "$ns" ip link set ${n}0 up
done
INA="ip netns exec $A"
INB="ip netns exec $B"

fail=0
ok() { echo "ok: $1"; }
bad() { echo "FAILED: $1"; fail=1; }
# count FILE [FILTER]: frames in a pcap, by tcpdump.
count() {
    f=$1; shift
    tcpdump -nr "$f" "$@" 2>/dev/null | wc -l | tr -d ' '
}
expect() {
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got $2, expected $3)"; fi
}

eth="eth(src=02:00:00:00:04:01,dst=02:00:00:00:04:02)"
cat > "$WORK/two.toml" <<EOF
[[stream]]
name = "nine"
packet = "$eth/ipv4(src=10.9.4.1,dst=10.9.4.2)/udp(sport=4000,dport=9)/raw(len=60)"
rate = "200pps"
loops = 0
limit = 40

[[stream]]
name = "ten"
packet = "$eth/ipv4(src=10.9.4.1,dst=10.9.4.2)/udp(sport=4000,dport=10)/raw(len=60)"
rate = "200pps"
loops = 0
limit = 40
EOF
send_two() {
    sleep "${1:-1}"
    $INA "$BIN" run "$WORK/two.toml" -i a0 -q >/dev/null 2>&1
}
# Waits for a background capture; fails the check if it does.
waitfor() {
    if ! wait "$1"; then
        bad "$2 exited with an error"
        cat "$WORK/err.txt" 2>/dev/null || true
    fi
}

echo "== 1. a BPF filter"
$INB "$BIN" capture -i b0 -f "udp dst port 9" -c 40 -d 10s -q -w "$WORK/nine.pcap" 2>"$WORK/err.txt" &
P=$!
send_two
waitfor $P "the capture"
expect "40 frames captured, all to port 9" "$(count "$WORK/nine.pcap")" 40
expect "tcpdump finds none to port 10 in it" "$(count "$WORK/nine.pcap" udp dst port 10)" 0

echo "== 2. pcap on standard output, read as it comes"
$INB sh -c "'$BIN' capture -i b0 -c 80 -d 10s -q -w - 'udp and src host 10.9.4.1' | tcpdump -nr - 2>/dev/null | wc -l" >"$WORK/stdout.txt" 2>"$WORK/err.txt" &
P=$!
send_two
waitfor $P "the capture to standard output"
expect "tcpdump read 80 frames from the pipe" "$(tr -d ' ' <"$WORK/stdout.txt")" 80

echo "== 3. a ring of files"
mkdir -p "$WORK/ring"
$INB "$BIN" capture -i b0 -c 80 -d 10s -q -w "$WORK/ring/r.pcap" --rotate 2K --files 3 udp 2>"$WORK/err.txt" &
P=$!
send_two
waitfor $P "the ring capture"
n=$(ls "$WORK/ring" | wc -l | tr -d ' ')
expect "three files left" "$n" 3
last=$(ls "$WORK/ring" | sort | tail -n 1)
case $last in r-0*.pcap) ok "named r-NNNNN.pcap ($last)" ;; *) bad "ring file name $last" ;; esac
total=0
for f in "$WORK"/ring/*.pcap; do
    c=$(count "$f")
    total=$((total + c))
    size=$(wc -c <"$f")
    [ "$size" -le 2048 ] || bad "$f is $size bytes, over 2K"
done
[ "$total" -gt 0 ] && [ "$total" -lt 80 ] && ok "the oldest frames went with the oldest files ($total kept)" || bad "kept $total frames"

echo "== 4. only what comes in"
$INB "$BIN" capture -i b0 --direction in -f icmp -c 3 -d 10s -q -w "$WORK/in.pcap" 2>"$WORK/err.txt" &
P=$!
sleep 1
$INB ping -c 3 -i 0.2 -W 1 10.9.4.1 >/dev/null 2>&1 || true
waitfor $P "the inbound capture"
expect "3 frames, all echo replies" "$(count "$WORK/in.pcap" 'icmp[icmptype] == icmp-echoreply')" 3

echo "== 5. a capture on a server, from another machine"
$INB "$BIN" serve --listen 10.9.4.2:4510 --insecure --data-dir "$WORK/server" 2>"$WORK/serve.log" &
SERVER=$!
i=0
until $INA "$BIN" ctl -c 10.9.4.2 info >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 100 ] || { cat "$WORK/serve.log"; echo "the server does not answer" >&2; exit 1; }
    sleep 0.1
done
# The control connection itself is TCP to 4510: the filter leaves it out.
$INA sh -c "'$BIN' ctl -c 10.9.4.2 capture -i b0 -c 40 -d 10s -q -w - udp dst port 9 | tcpdump -nr - 2>/dev/null | wc -l" >"$WORK/remote.txt" 2>"$WORK/err.txt" &
P=$!
send_two 1.5
waitfor $P "ferotrx ctl capture"
expect "40 frames from the server's capture, through the control connection" "$(tr -d ' ' <"$WORK/remote.txt")" 40
$INA "$BIN" ctl -c 10.9.4.2 capture-start -i b0 -w caps/ten.pcap -f "udp dst port 10" -c 40 -d 10s >/dev/null
send_two 0.5
sleep 1
$INA "$BIN" ctl -c 10.9.4.2 --json captures >"$WORK/captures.json"
if grep -q '"frames": *40' "$WORK/captures.json" || grep -q '"frames":40' "$WORK/captures.json"; then
    ok "the server's capture took 40 frames"
else
    bad "the server's capture: $(cat "$WORK/captures.json")"
fi
$INA "$BIN" ctl -c 10.9.4.2 fetch caps/ten.pcap -o "$WORK/ten.pcap" 2>/dev/null
expect "fetched it: 40 frames to port 10" "$(count "$WORK/ten.pcap" udp dst port 10)" 40
if $INA "$BIN" ctl -c 10.9.4.2 fetch ../etc/passwd -o "$WORK/no" 2>/dev/null; then
    bad "fetched a file outside the server's data directory"
else
    ok "files outside the data directory are refused"
fi

echo "== 6. --capture next to a run"
$INA "$BIN" run "$WORK/two.toml" -i a0 -q --capture "$WORK/run.pcap" --capture-filter udp >/dev/null 2>&1
expect "the run's 80 frames in its capture" "$(count "$WORK/run.pcap" udp and src host 10.9.4.1)" 80

echo "== 7. inspect -f"
n=$("$BIN" inspect "$WORK/run.pcap" -f "udp dst port 10" 2>&1 >/dev/null | sed -n 's/^\([0-9]*\) packets of.*/\1/p')
expect "inspect -f takes the 40 frames to port 10" "${n:-none}" 40

[ $fail -eq 0 ] && echo "all capture checks passed"
exit $fail
