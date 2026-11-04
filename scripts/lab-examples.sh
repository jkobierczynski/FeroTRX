#!/bin/sh
# Plays the lab examples through the lab router the control server builds
# (`ferotrx serve --lab`, `lab.start`), as the GUI does: a TCP run of
# examples/lab-tcp.toml, a UDP run of examples/lab-udp-mix.toml and a replay
# of examples/lab-built-packets.toml (to the router's MAC 02:00:00:00:00:01)
# on ftrx-lab, then examples/lab-scenario.toml as a scenario run on the server
# (`scenario.start`), then `lab.stop`. Checks that connections complete and
# that transactions are answered, through NAT, that every check of the
# scenario passes, and that the lab is gone after.
#
# Usage: sudo scripts/lab-examples.sh [path/to/ferotrx]
# Needs root, ip (iproute2), iptables, jq, and VLAN support (8021q).
#
# BLOCK=1 also checks a lab whose router resets TCP to port 80: no
# connection of lab-tcp.toml may complete, and the scenario's web check (only
# that one) fails.
set -eu

BIN=${1:-}
if [ -z "$BIN" ]; then
    for b in ./target/debug/ferotrx ./target/release/ferotrx "$(command -v ferotrx || true)"; do
        if [ -n "$b" ] && [ -x "$b" ]; then BIN=$b; break; fi
    done
fi
if [ -z "$BIN" ] || ! [ -x "$BIN" ]; then
    echo "ferotrx not found: build it first (cargo build -p ferotrx-cli)" >&2
    exit 1
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
cd "$(dirname "$0")/.."
ADDR=127.0.0.1:4599
tmp=$(mktemp -d /tmp/ferotrx-lab.XXXXXX)
cleanup() {
    [ -z "${pid:-}" ] || kill "$pid" 2>/dev/null || true
    "$BIN" lab down >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

"$BIN" serve -l $ADDR --lab --data-dir . >"$tmp/serve.log" 2>&1 &
pid=$!
ctl() { "$BIN" ctl -c $ADDR "$@"; }
i=0
until ctl info >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 50 ] || { cat "$tmp/serve.log" >&2; exit 1; }
    sleep 0.1
done
[ "$(ctl call server.info --json | jq .lab)" = true ] || {
    echo "server.info says labs are off" >&2
    exit 1
}
status=0
fail() { echo "FAIL: $*" >&2; status=1; }

lab() { # params
    ctl call lab.start "$1" --json >"$tmp/lab.json" || { cat "$tmp/serve.log" >&2; exit 1; }
    jq -r '.summary[], (.notes[] | "note: " + .)' "$tmp/lab.json"
    ip link show ftrx-lab >/dev/null || fail "no ftrx-lab after lab.start"
}

# Waits for a run to end and prints its JSON.
wait_run() { # kind id
    i=0
    while [ "$(ctl call "$1.stats" "{\"id\": $2}" --json | jq -r .state)" = running ]; do
        i=$((i + 1))
        [ $i -lt 600 ] || { echo "$1 run $2 did not end" >&2; break; }
        sleep 0.1
    done
    ctl call "$1.stats" "{\"id\": $2}" --json
}

echo "== lab"
lab '{}'

echo "== TCP: examples/lab-tcp.toml"
id=$(ctl call tcp.start '{"path": "examples/lab-tcp.toml", "iface": "ftrx-lab", "connections": 200, "cps": 100}' --json | jq .id)
wait_run tcp "$id" >"$tmp/tcp.json"
jq -c '.client | {started, completed, reset, timed_out}' "$tmp/tcp.json"
[ "$(jq .client.completed "$tmp/tcp.json")" = 200 ] || fail "not all 200 TCP connections completed"

echo "== UDP: examples/lab-udp-mix.toml"
id=$(ctl call udp.start '{"path": "examples/lab-udp-mix.toml", "iface": "ftrx-lab", "duration": "4s"}' --json | jq .id)
wait_run udp "$id" >"$tmp/udp.json"
jq -c '.client | {sent, answered, timed_out}' "$tmp/udp.json"
jq -r '.templates[]? | "  " + .name + ": " + (.client.answered | tostring) + " answered"' "$tmp/udp.json" || true
sent=$(jq .client.sent "$tmp/udp.json")
answered=$(jq .client.answered "$tmp/udp.json")
[ "$sent" -gt 100 ] || fail "only $sent UDP transactions sent"
# Transactions still open when the duration ends are not answered.
[ $((answered * 100)) -ge $((sent * 95)) ] || fail "only $answered of $sent UDP transactions answered"

echo "== replay: examples/lab-built-packets.toml, routed to VLAN 20"
# Nothing answers ARP for the replay's destination: give the router a neighbor.
ip netns exec ferotrx-lab ip neigh replace 192.168.20.50 lladdr 02:00:00:00:00:50 dev rt.20
fwd() { ip netns exec ferotrx-lab cat /sys/class/net/rt.20/statistics/tx_packets; }
before=$(fwd)
"$BIN" run examples/lab-built-packets.toml -i ftrx-lab -d 4s >"$tmp/run.log" 2>&1 || { cat "$tmp/run.log" >&2; fail "ferotrx run failed"; }
routed=$(($(fwd) - before))
echo "the router sent $routed packets out of rt.20"
# 50 DNS packets per second from 2 s on, a ping a second: about 100.
[ "$routed" -ge 60 ] || fail "only $routed replayed packets were routed (router MAC $(ip netns exec ferotrx-lab cat /sys/class/net/ftrxlab-rt/address))"
# 192.168.20.50 is also the server of lab-tcp.toml: let the router find its
# emulated MAC again.
ip netns exec ferotrx-lab ip neigh del 192.168.20.50 dev rt.20 || true

# Waits for a scenario run to end and prints its JSON.
wait_scenario() { # id
    i=0
    while [ "$(ctl call scenario.get "{\"id\": $1}" --json | jq -r .state)" = running ]; do
        i=$((i + 1))
        [ $i -lt 1200 ] || { echo "scenario run $1 did not end" >&2; break; }
        sleep 0.1
    done
    ctl call scenario.get "{\"id\": $1}" --json
}

echo "== scenario: examples/lab-scenario.toml, run by the server on the lab it names"
id=$(ctl call scenario.start '{"path": "examples/lab-scenario.toml"}' --json | jq .id)
wait_scenario "$id" >"$tmp/scenario.json"
jq -r '.checks[] | "  " + .state + "  " + .name + ": " + (.report.summary // "")' "$tmp/scenario.json"
[ "$(jq -r '.report.summary | "\(.passed)/\(.checks)"' "$tmp/scenario.json")" = 6/6 ] ||
    fail "lab-scenario.toml: $(jq -c .report.summary "$tmp/scenario.json")"

if [ "${BLOCK:-}" = 1 ]; then
    echo "== lab with TCP port 80 reset"
    lab '{"block_tcp": [80, 8080], "block_udp": [123], "ipv6": false}'
    id=$(ctl call tcp.start '{"path": "examples/lab-tcp.toml", "iface": "ftrx-lab", "connections": 50, "cps": 50}' --json | jq .id)
    wait_run tcp "$id" >"$tmp/tcp.json"
    jq -c '.client | {started, completed, reset, timed_out}' "$tmp/tcp.json"
    [ "$(jq .client.completed "$tmp/tcp.json")" = 0 ] || fail "connections completed through a blocked port"
    echo "== scenario with TCP port 80 reset: only the web check fails"
    # On the lab as it is ("lab": false), not the one the scenario names.
    id=$(ctl call scenario.start '{"path": "examples/lab-scenario.toml", "lab": false}' --json | jq .id)
    wait_scenario "$id" >"$tmp/scenario.json"
    jq -r '.checks[] | "  " + .state + "  " + .name' "$tmp/scenario.json"
    [ "$(jq -r '[.checks[].state] | join(",")' "$tmp/scenario.json")" = fail,pass,pass,pass,pass,pass ] ||
        fail "lab-scenario.toml with port 80 reset: $(jq -c '[.checks[].state]' "$tmp/scenario.json")"
fi

echo "== lab.stop"
ctl call lab.stop --json | jq -c '{running}'
if ip link show ftrx-lab >/dev/null 2>&1 || ip netns list | grep -q ferotrx-lab; then
    fail "the lab is still there after lab.stop"
fi
[ $status = 0 ] && echo "all checks passed"
exit $status
