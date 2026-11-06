#!/bin/sh
# Builds a lab of three FeroTRX agents in Linux network namespaces and runs
# examples/fleet/fleet.toml across them, the way a controller drives agents
# on three machines:
#
#   controller (ns ftrx-lab)     10.99.0.1 on bridge fleet-m (management)
#     |
#     +-- east  (ns ftrx-east)  m0 10.99.0.11:4510   d0 web clients 10.98.0.100-104, probe
#     +-- west  (ns ftrx-west)  m0 10.99.0.12:4510   d0 web clients 10.98.0.110-114
#     +-- srv   (ns ftrx-srv)   m0 10.99.0.13:4510   d0 web server 10.98.0.80, probe receiver
#                                                    (every d0 on bridge fleet-d: the lab's LAN)
#
# Both bridges and the controller live in their own namespace, ftrx-lab, so
# nothing on the host (udev giving new links other MACs, Docker's bridge
# netfilter) touches them.
#
# Each agent is `ferotrx serve` with a token and its own data directory.
# `ferotrx fleet run` sends the profiles and http.pcap to the agents,
# starts the server, the clients on both client agents (500 ms later) and
# a probe stream from east received on srv at one instant, and adds up
# their counters:
#
# 1. Everything passes: 100 connections complete (50 per client agent),
#    the server saw them all, the runs started within SPREAD ms of their
#    planned times, the probe arrived on the other agent without loss, and
#    the files are on the agents. A second deploy sends nothing new.
# 2. With west cut off the LAN, the fleet fails: west's clients do not
#    complete, east's still do, and the sums show it.
#
# Usage: sudo scripts/fleet-netns.sh [path/to/ferotrx] [extra ferotrx fleet run options]
# Needs root, ip (iproute2) and jq. Removes the lab when done.
#
# SPREAD=100   most milliseconds between the planned and actual starts
# KEEP=DIR     keep the reports and the agents' data directories in DIR
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
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
echo "using $BIN"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PLAN=$HERE/examples/fleet/fleet.toml
SPREAD=${SPREAD:-100}
KEEP=${KEEP:-}
AGENTS="east:11 west:12 srv:13"
FEROTRX_TOKEN=fleet-lab-token-$$
export FEROTRX_TOKEN
WORK=
PIDS=

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for a in $AGENTS; do
        n=${a%%:*}
        ip netns del "ftrx-$n" 2>/dev/null || true
    done
    ip netns del ftrx-lab 2>/dev/null || true
    if [ -n "$WORK" ]; then
        if [ -n "$KEEP" ]; then
            mkdir -p "$KEEP" && cp -r "$WORK"/. "$KEEP"/ && echo "kept in $KEEP"
        fi
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

LAB="ip netns exec ftrx-lab"
ip netns add ftrx-lab
$LAB ip link set lo up
for br in fleet-m fleet-d; do
    $LAB ip link add $br type bridge
    $LAB sysctl -qw "net.ipv6.conf.$br.disable_ipv6=1" 2>/dev/null || true
    $LAB ip link set $br up
done
$LAB ip addr add 10.99.0.1/24 dev fleet-m
for a in $AGENTS; do
    n=${a%%:*}; host=${a##*:}; ns=ftrx-$n
    ip netns add $ns
    ip netns exec $ns ip link set lo up
    for link in m d; do
        $LAB ip link add "$link-$n" type veth peer name "${link}0" netns $ns
        $LAB sysctl -qw "net.ipv6.conf.$link-$n.disable_ipv6=1" 2>/dev/null || true
        ip netns exec $ns sysctl -qw "net.ipv6.conf.${link}0.disable_ipv6=1" 2>/dev/null || true
        $LAB ip link set "$link-$n" master fleet-$link
        $LAB ip link set "$link-$n" up
        ip netns exec $ns ip link set "${link}0" up
    done
    ip netns exec $ns ip addr add 10.99.0.$host/24 dev m0
    mkdir -p "$WORK/$n"
    ip netns exec $ns "$BIN" serve --listen 10.99.0.$host:4510 --token "$FEROTRX_TOKEN" \
        --data-dir "$WORK/$n" 2>"$WORK/$n.log" &
    PIDS="$PIDS $!"
done

# The agents are up once each answers.
for a in $AGENTS; do
    host=${a##*:}
    i=0
    until $LAB "$BIN" ctl -c 10.99.0.$host:4510 info >/dev/null 2>&1; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then
            echo "FAILED: agent at 10.99.0.$host:4510 does not answer" >&2
            cat "$WORK/${a%%:*}.log" >&2
            exit 1
        fi
        sleep 0.1
    done
done
echo "agents up: east, west, srv"

fail=0
check() {
    if jq -e "$2" "$3" >/dev/null; then
        echo "ok: $1"
    else
        echo "FAILED: $1"
        fail=1
    fi
}
run_of() { echo ".runs[] | select(.name == \"$1\")"; }

echo "== fleet check"
if $LAB "$BIN" fleet check "$PLAN"; then
    echo "ok: every agent answers and has its interfaces"
else
    echo "FAILED: ferotrx fleet check"
    fail=1
fi

echo "== 1. three agents together: everything passes"
set +e
$LAB "$BIN" fleet run "$PLAN" --duration 8s --report "$WORK/pass.json" "$@"
status=$?
set -e
[ $status -eq 0 ] && echo "ok: ferotrx fleet run passed" || { echo "FAILED: ferotrx fleet run exited with $status"; fail=1; }
j="$WORK/pass.json"
check "report: format, three agents, three runs" \
    '.format == "ferotrx-fleet-1" and (.agents | length) == 3 and (.runs | length) == 3' "$j"
check "100 connections completed, 50 on each client agent" \
    ".totals.tcp.completed == 100 and ([$(run_of "web clients") | .instances[].metrics.completed] == [50, 50])" "$j"
check "the server agent completed every connection" \
    "($(run_of "web server") | .metrics.server_completed) == 100" "$j"
check "every run started within $SPREAD ms of its planned time" \
    "[.runs[].instances[].start_late_ms | fabs] | max < $SPREAD" "$j"
check "the probe from east arrived on srv: 2500 sent, none lost" \
    "($(run_of probe) | .instances[0].rx_agent == \"srv\" and .metrics.tx_packets == 2500 and .metrics.lost == 0 and .metrics.rx_packets == 2500)" "$j"
check "the agents' clocks were read (same machine: within 5 ms)" \
    '[.agents[].offset_ms | fabs] | max < 5' "$j"
check "first deploy sent the pcap to each agent once per run" \
    '[.deployed[].files_sent] | add == 3' "$j"
if grep -q '10.98.0.110/24' "$WORK/west/fleet/web-lab/web-clients/fleet/web-clients.toml" &&
    [ -f "$WORK/west/fleet/web-lab/web-clients/http.pcap" ]; then
    echo "ok: west has its own copy of the profile, and the pcap where it looks for it"
else
    echo "FAILED: the deployed files on west"
    find "$WORK/west" -type f
    fail=1
fi
out=$($LAB "$BIN" fleet deploy "$PLAN" 2>&1)
if echo "$out" | grep -q '; 0 file(s) sent'; then
    echo "ok: a second deploy sends nothing new"
else
    echo "FAILED: a second deploy sent files again:"
    echo "$out"
    fail=1
fi

echo "== 2. west cut off the LAN: the fleet fails"
$LAB ip link set d-west nomaster
set +e
$LAB "$BIN" fleet run "$PLAN" --duration 4s --report "$WORK/fail.json" -q "$@" >/dev/null
status=$?
set -e
$LAB ip link set d-west master fleet-d
[ $status -ne 0 ] && echo "ok: ferotrx fleet run failed, as it should" || { echo "FAILED: ferotrx fleet run passed without west"; fail=1; }
j="$WORK/fail.json"
check "the web clients run failed" "($(run_of "web clients") | .passed) == false" "$j"
check "east's clients still completed, west's did not" \
    "[$(run_of "web clients") | .instances[] | {(.agent): .metrics.completed}] | add | .east == 50 and .west == 0" "$j"
check "the totals show it: 50 completed" '.totals.tcp.completed == 50' "$j"
check "west's part failed its own condition" \
    "[$(run_of "web clients") | .instances[] | select(.agent == \"west\") | .conditions[].pass] == [false]" "$j"

if [ $fail -ne 0 ]; then
    for a in $AGENTS; do
        echo "--- agent ${a%%:*} log:"
        cat "$WORK/${a%%:*}.log" || true
    done
    exit 1
fi
echo "all fleet checks passed"
