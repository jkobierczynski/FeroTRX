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
# Each agent is `ferotrx serve` over TLS (a lab CA from `ferotrx certs`)
# with a token and its own data directory; the controller uses a copy of
# the plan that names the CA (`ca = ...` per agent).
# `ferotrx fleet run` sends the profiles and http.pcap to the agents,
# starts the server, the clients on both client agents (500 ms later) and
# a probe stream from east received on srv at one instant, and adds up
# their counters:
#
# 1. Everything passes: 100 connections complete (50 per client agent),
#    the server saw them all, the runs started within SPREAD ms of their
#    planned times, the probe arrived on the other agent without loss, and
#    the files are on the agents. A second deploy sends nothing new.
#    Captures on east and srv (`[[capture]]`, BPF "tcp port 80") are
#    collected (`--collect`) and merged into one pcapng (`--merge`).
# 2. With west cut off the LAN, the fleet fails: west's clients do not
#    complete, east's still do, and the sums show it.
# 3. west's agent is killed (SIGKILL) in the middle of a run: the fleet
#    fails, the report names west as lost with the run it had, and east's
#    part still runs to its end. Then west's agent is started again.
# 4. east's control port refuses connections (TCP resets) for 2 s in the
#    middle of a run: the controller connects again, the runs went on, and
#    the fleet passes with east "reconnected".
# 5. examples/fleet/fleet-kinds.toml: emulated hosts, a scenario, an
#    RFC 2544 benchmark and a Y.1564 test on the three agents, started
#    together (each agent has a cable l0 - l1 of its own), with every
#    agent's capabilities and telemetry (CPU, clock) in the report.
#
# Usage: sudo scripts/fleet-netns.sh [path/to/ferotrx] [extra ferotrx fleet run options]
# Needs root, ip (iproute2), iptables, jq and tcpdump. Removes the lab when done.
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

# Tokens must travel over TLS beyond loopback: one server certificate for
# the three agent addresses, and a copy of the plan that trusts its CA.
"$BIN" certs "$WORK/pki" --server 10.99.0.11,10.99.0.12,10.99.0.13 >/dev/null
mkdir -p "$WORK/plan/fleet"
cp "$HERE"/examples/fleet/*.toml "$WORK/plan/fleet/"
# The other kinds' plan, with the CA too.
sed "s|^token_env = .*|&\nca = \"$WORK/pki/ca.pem\"|" "$HERE/examples/fleet/fleet-kinds.toml" \
    >"$WORK/plan/fleet/fleet-kinds.toml"
cp "$HERE/examples/http.pcap" "$WORK/plan/"
sed "s|^token_env = .*|&\nca = \"$WORK/pki/ca.pem\"|" "$HERE/examples/fleet/fleet.toml" \
    >"$WORK/plan/fleet/fleet.toml"
cat >>"$WORK/plan/fleet/fleet.toml" <<'EOT'

[[capture]]
agents = ["east", "srv"]
iface = "d0"
filter = "tcp port 80"
EOT
grep -q '^ca = ' "$WORK/plan/fleet/fleet.toml" || { echo "FAILED: no CA in the plan copy" >&2; exit 1; }
PLAN=$WORK/plan/fleet/fleet.toml

# Starts agent $1 (10.99.0.$2) in its namespace; its pid goes in PID_$1.
serve() {
    ip netns exec "ftrx-$1" "$BIN" serve --listen "10.99.0.$2:4510" --token "$FEROTRX_TOKEN" \
        --tls-cert "$WORK/pki/server.pem" --tls-key "$WORK/pki/server-key.pem" \
        --data-dir "$WORK/$1" 2>>"$WORK/$1.log" &
    PIDS="$PIDS $!"
    eval "PID_$1=$!"
}

# Waits until the agent at 10.99.0.$1 answers.
wait_agent() {
    i=0
    until $LAB "$BIN" ctl -c "10.99.0.$1:4510" --ca "$WORK/pki/ca.pem" info >/dev/null 2>&1; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then
            echo "FAILED: agent at 10.99.0.$1:4510 does not answer" >&2
            exit 1
        fi
        sleep 0.1
    done
}

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
    # A cable of the agent's own, l0 - l1, for fleet-kinds.toml.
    ip netns exec $ns ip link add l0 type veth peer name l1
    for l in l0 l1; do
        ip netns exec $ns sysctl -qw "net.ipv6.conf.$l.disable_ipv6=1" 2>/dev/null || true
        ip netns exec $ns ip link set $l up
    done
    mkdir -p "$WORK/$n"
    serve $n $host
done

# The agents are up once each answers.
for a in $AGENTS; do
    wait_agent "${a##*:}" || { cat "$WORK/${a%%:*}.log" >&2; exit 1; }
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
$LAB "$BIN" fleet run "$PLAN" --duration 8s --report "$WORK/pass.json" \
    --collect "$WORK/collected" --merge "$WORK/merged.pcapng" "$@"
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
check "two captures, both collected, no errors" \
    '(.captures | length) == 2 and all(.captures[]; .collected != null and .error == null)' "$j"
check "srv captured every web connection (at least 100 SYNs worth of frames)" \
    '.captures[] | select(.agent == "srv") | .frames >= 1000 and .dropped == 0' "$j"
check "the report names the merged file" '.merged != null' "$j"
for c in east srv; do
    f="$WORK/collected/$c-d0.pcap"
    n=$(tcpdump -nr "$f" 2>/dev/null | wc -l)
    want=$(jq ".captures[] | select(.agent == \"$c\") | .frames" "$j")
    if [ "$n" -gt 0 ] && [ "$n" -eq "$want" ]; then
        echo "ok: $c's capture was collected: $n frames, as counted"
    else
        echo "FAILED: $c's collected capture has $n frames, the agent counted $want"
        fail=1
    fi
done
all=$(jq '[.captures[].frames] | add' "$j")
n=$(tcpdump -nr "$WORK/merged.pcapng" 2>/dev/null | wc -l)
other=$(tcpdump -nr "$WORK/merged.pcapng" 'not tcp port 80' 2>/dev/null | wc -l)
if [ "$n" -eq "$all" ] && [ "$other" -eq 0 ]; then
    echo "ok: the merged pcapng has all $n frames, all tcp port 80"
else
    echo "FAILED: the merged pcapng has $n frames ($other not port 80), the captures $all"
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

echo "== 3. west's agent killed in the middle of a run: west is lost, east goes on"
# A copy of the plan that gives up on an agent after 3 s.
sed 's|^interval = .*|&\nreconnect = "3s"|' "$PLAN" >"$WORK/plan/fleet/fleet-lose.toml"
set +e
$LAB "$BIN" fleet run "$WORK/plan/fleet/fleet-lose.toml" --duration 8s \
    --report "$WORK/lost.json" -q "$@" >"$WORK/lost.out" 2>&1 &
fleet=$!
set -e
sleep 5
kill -9 "$PID_west"
set +e
wait $fleet
status=$?
set -e
[ $status -ne 0 ] && echo "ok: ferotrx fleet run failed, as it should" || { echo "FAILED: ferotrx fleet run passed without west"; fail=1; }
j="$WORK/lost.json"
check "the report names west as lost, with the run it had" \
    '[.failures[] | {agent, runs}] == [{"agent": "west", "runs": ["web clients"]}]' "$j"
check "west's record says lost, the others ok" \
    '[.agents[] | {(.name): .status}] | add == {"east": "ok", "west": "lost", "srv": "ok"}' "$j"
check "west was lost while the runs went, after its last answer" \
    '.failures[0] | .at_s > 1 and .at_s < 8 and .last_seen_s <= .at_s and .lost_at_s >= .at_s + 2.5' "$j"
check "east's clients still ran to their end and completed" \
    "[$(run_of "web clients") | .instances[] | select(.agent == \"east\") | .state, .metrics.completed] == [\"finished\", 50]" "$j"
check "west's part says it was lost" \
    "[$(run_of "web clients") | .instances[] | select(.agent == \"west\") | .error | test(\"lost\")] == [true]" "$j"
check "the samples show west lost at the end" \
    '[.samples[-1].agents[] | select(.agent == "west") | .status] == ["lost"]' "$j"
if grep -q "LOST: agent 'west' lost at" "$WORK/lost.out"; then
    echo "ok: the controller said so as it happened"
else
    echo "FAILED: no LOST line in the output:"
    cat "$WORK/lost.out"
    fail=1
fi
serve west 12
wait_agent 12

echo "== 4. east's control port resets connections for 2 s: the controller comes back"
set +e
$LAB "$BIN" fleet run "$PLAN" --duration 8s --report "$WORK/back.json" -q "$@" \
    >"$WORK/back.out" 2>&1 &
fleet=$!
set -e
sleep 4
EAST="ip netns exec ftrx-east"
$EAST iptables -I INPUT -p tcp --dport 4510 -j REJECT --reject-with tcp-reset
sleep 2
$EAST iptables -D INPUT -p tcp --dport 4510 -j REJECT --reject-with tcp-reset
set +e
wait $fleet
status=$?
set -e
[ $status -eq 0 ] && echo "ok: ferotrx fleet run passed" || { echo "FAILED: ferotrx fleet run exited with $status"; cat "$WORK/back.out"; fail=1; }
j="$WORK/back.json"
check "east reconnected once, nobody was lost" \
    '([.agents[] | select(.name == "east") | .status, .reconnects] == ["reconnected", 1]) and (.failures | length) == 0' "$j"
check "east's runs went on meanwhile: 50 completed" \
    "[$(run_of "web clients") | .instances[] | select(.agent == \"east\") | .metrics.completed] == [50]" "$j"
check "the report says how long east was out of reach" \
    '[.notes[] | select(test("agent .east. was out of reach"))] | length == 1' "$j"

echo "== 5. hosts, a scenario, a benchmark and a Y.1564 test across the agents"
KINDS=$WORK/plan/fleet/fleet-kinds.toml
if $LAB "$BIN" fleet check "$KINDS"; then
    echo "ok: the plan fits every agent (kinds, interfaces, backends)"
else
    echo "FAILED: ferotrx fleet check of fleet-kinds.toml"
    fail=1
fi
set +e
$LAB "$BIN" fleet run "$KINDS" --report "$WORK/kinds.json" "$@"
status=$?
set -e
[ $status -eq 0 ] && echo "ok: ferotrx fleet run passed" || { echo "FAILED: ferotrx fleet run of fleet-kinds.toml exited with $status"; fail=1; }
j="$WORK/kinds.json"
check "five hosts ready on west" '.totals.hosts.ready == 5 and .totals.hosts.failed == 0' "$j"
check "the scenario's check passed on east" '.totals.scenario.checks_passed == 1' "$j"
check "the benchmark ran to its end at full load" \
    '.totals.bench.passed == 1 and .totals.bench.throughput_pct > 90' "$j"
check "the Y.1564 test passed on west" '.totals.y1564.passed == 1 and .totals.y1564.steps_failed == 0' "$j"
check "all four started within $SPREAD ms of the shared start" \
    "[.runs[].instances[].start_late_ms | fabs] | max < $SPREAD" "$j"
check "every agent reported its CPUs and capabilities" \
    'all(.agents[]; .capabilities.cpus >= 1 and (.capabilities.kinds | index("y1564")) != null)' "$j"
check "every agent's health was read along the way (CPU, clock)" \
    'all(.agents[]; .telemetry.samples >= 2 and .telemetry.cpu_max_pct != null and .telemetry.offset_min_ms != null)' "$j"

if [ $fail -ne 0 ]; then
    for a in $AGENTS; do
        echo "--- agent ${a%%:*} log:"
        cat "$WORK/${a%%:*}.log" || true
    done
    exit 1
fi
echo "all fleet checks passed"
