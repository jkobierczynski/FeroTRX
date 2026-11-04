#!/bin/sh
# Runs the regression scenario examples/scenario-nat.toml against a real NAT
# router in a network namespace, then breaks the router's firewall and checks
# that the scenario notices.
#
#   ferotrx (this namespace)               router (namespace ferotrx-scn)
#   c0  clients 192.168.10.100-109 ------- rc 192.168.10.1/24
#       stream sender 192.168.10.2
#   s0  servers 192.168.20.80 (web) ------ rs 192.168.20.1/24, masquerade
#       .53 (DNS), .123 (NTP),             FORWARD: drop TCP 8080 and UDP 123
#       stream receiver .2
#
# 1. A run with the router as configured: every check must pass (web and DNS
#    get through, 8080 and NTP are blocked, the voice stream arrives). The
#    report goes to a history directory, with JUnit XML.
# 2. "A bad change": the router now resets TCP to port 80. The second run,
#    compared with the first (--baseline last), must fail, name
#    "web through NAT" as regressed, and leave the other checks passing.
# 3. `scenario compare --history` must say the same, and `scenario history`
#    must list both runs.
#
# Usage: sudo scripts/scenario-netns.sh [path/to/ferotrx] [extra `scenario run` options]
# Needs root, ip (iproute2) and iptables (or iptables-nft). Removes the lab
# when done. KEEP=DIR keeps the reports in DIR.
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
NS=ferotrx-scn
SCENARIO=$(cd "$(dirname "$0")/../examples" && pwd)/scenario-nat.toml
WORK=

cleanup() {
    for l in c0 s0; do ip link del $l 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    if [ -n "$WORK" ] && [ -z "${KEEP:-}" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
if [ -n "${KEEP:-}" ]; then
    mkdir -p "$KEEP"
    WORK=$KEEP
else
    WORK=$(mktemp -d)
fi

ip netns add $NS
r() { ip netns exec $NS "$@"; }
r ip link set lo up
r sysctl -qw net.ipv4.ip_forward=1
for side in c:1:10 s:2:20; do
    n=${side%%:*}; rest=${side#*:}; m=${rest%%:*}; net=${rest#*:}
    ip link add ${n}0 type veth peer name r$n
    ip link set r$n netns $NS
    # No IPv6: router solicitations would only add noise.
    sysctl -qw "net.ipv6.conf.${n}0.disable_ipv6=1" 2>/dev/null || true
    ip link set ${n}0 up
    r ip link set r$n address 02:00:00:00:0$m:01
    r ip addr add 192.168.$net.1/24 dev r$n
    r ip link set r$n up
done
# Packets the router makes itself (the resets of run 2) leave with the
# checksum left to the (virtual) NIC, which a veth never fills in: have the
# kernel fill it in, so the clients see the resets. Without ethtool the
# connections time out instead; the check fails either way.
if command -v ethtool >/dev/null 2>&1; then
    r ethtool -K rc tx off >/dev/null
fi
# The stream's receiver is ferotrx in promiscuous mode on s0, which answers
# no ARP: give the router its MAC.
r ip neigh replace 192.168.20.2 lladdr 02:00:00:00:02:02 dev rs nud permanent
r iptables -t nat -A POSTROUTING -o rs -j MASQUERADE
# The policy the scenario checks.
r iptables -A FORWARD -p tcp --dport 8080 -j DROP
r iptables -A FORWARD -p udp --dport 123 -j DROP

hist=$WORK/history
rm -rf "$hist" # a kept directory from an earlier run starts afresh
status=0
fail() {
    echo "FAIL: $*" >&2
    status=1
}

echo "== run 1: the router as configured"
set +e
"$BIN" scenario run "$SCENARIO" --history "$hist" --report "$WORK/before.json" \
    --junit "$WORK/before.xml" -q "$@"
rc=$?
set -e
[ $rc -eq 0 ] || fail "the first run should pass (exit $rc)"
grep -q 'tests="5" failures="0" errors="0" skipped="0"' "$WORK/before.xml" ||
    fail "JUnit report of the first run: $(grep '<testsuite ' "$WORK/before.xml")"

echo "== run 2: after a bad change, the router resets TCP to port 80"
r iptables -I FORWARD -p tcp --dport 80 -j REJECT --reject-with tcp-reset
set +e
"$BIN" scenario run "$SCENARIO" --history "$hist" --baseline last \
    --junit "$WORK/after.xml" -q "$@" >"$WORK/after.txt" 2>&1
rc=$?
set -e
cat "$WORK/after.txt"
[ $rc -eq 1 ] || fail "the second run should fail with exit 1 (exit $rc)"
grep -q '^FAIL   web through NAT' "$WORK/after.txt" || fail "web through NAT did not fail"
grep -q '^REGRESSED  web through NAT (tcp): pass -> fail' "$WORK/after.txt" ||
    fail "the comparison does not show web through NAT as regressed"
grep -q '^1 regressed, 0 fixed' "$WORK/after.txt" || fail "only web through NAT should regress"
for c in "port 8080 blocked" "DNS through NAT" "NTP blocked" "voice stream"; do
    grep -q "^PASS   $c" "$WORK/after.txt" || fail "$c should still pass"
done
grep -q 'tests="5" failures="1" errors="0"' "$WORK/after.xml" ||
    fail "JUnit report of the second run: $(grep '<testsuite ' "$WORK/after.xml")"

echo "== compare and history"
set +e
"$BIN" scenario compare --history "$hist" >"$WORK/compare.txt" 2>&1
rc=$?
set -e
cat "$WORK/compare.txt"
[ $rc -eq 1 ] || fail "scenario compare should exit 1 on a regression (exit $rc)"
grep -q 'REGRESSED  web through NAT' "$WORK/compare.txt" || fail "compare does not show the regression"
"$BIN" scenario history "$hist" | tee "$WORK/history.txt"
grep -q '^nat-router: 2 runs' "$WORK/history.txt" || fail "history should list two runs"
grep -q 'FAILED .*(web through NAT)' "$WORK/history.txt" || fail "history should name the failed check"

echo "router: packets dropped and rejected by the policy:"
r iptables -L FORWARD -v -n | sed -n '3,$p'
if [ $status -eq 0 ]; then
    echo "scenario-netns: all checks as expected"
fi
exit $status
