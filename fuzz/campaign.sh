#!/usr/bin/env bash
# A fuzzing campaign over every target, 8 hours in total by default, with
# more time for the protocol targets that keep finding new paths.
#
#   fuzz/campaign.sh                  8 hours, one process per target
#   fuzz/campaign.sh -H 4 -j 4        4 hours, 4 processes per target
#   fuzz/campaign.sh -n               print the plan and exit
#
# Options:
#   -H, --hours N   total time in hours (default 8; may be a decimal, 0.5)
#   -j, --jobs N    libFuzzer processes per target (default 1; set it to the
#                   cores you can spare, the time stays the same)
#   -n, --dry-run   print each target's share and exit
#
# Targets run one after the other through fuzz/run.sh, so a crash in one
# does not stop the others. Corpora grow in fuzz/corpus/<target>/ (keep
# them: the next campaign starts there), crashes land in
# fuzz/artifacts/<target>/, and everything is logged to
# fuzz/campaign-<date>.log. See docs/fuzzing.md for what to do with a crash.
set -euo pipefail

cd "$(dirname "$0")/.."

# target:weight. The weights add up to 96, so for 8 hours one point is
# 5 minutes: app 80 min, tcp_engine/quic/ctl_server 60, udp_engine/ssh 45 ...
PLAN=(
  app:16 tcp_engine:12 quic:12 ctl_server:12 udp_engine:9 ssh:9
  host_engine:5 ctl_call:5 wire:4 packet:3 profile:3 pcap:3 text:3
)

hours=8
jobs=1
dry=""
while [ $# -gt 0 ]; do
  case "$1" in
    -H|--hours) hours=$2; shift 2 ;;
    -j|--jobs) jobs=$2; shift 2 ;;
    -n|--dry-run) dry=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done

total=$(awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }')
sum=0
for p in "${PLAN[@]}"; do sum=$((sum + ${p#*:})); done

log="fuzz/campaign-$(date +%Y%m%d-%H%M).log"
[ -n "$dry" ] && log=/dev/null
say() { echo "$*" | tee -a "$log"; }

say "Campaign: ${hours} h, ${jobs} process(es) per target, started $(date)"
for p in "${PLAN[@]}"; do
  t=${p%%:*}
  s=$((total * ${p#*:} / sum))
  say "$(printf '  %-12s %4d min' "$t" $((s / 60)))"
done
[ -n "$dry" ] && exit 0

failed=()
for p in "${PLAN[@]}"; do
  t=${p%%:*}
  s=$((total * ${p#*:} / sum))
  say "== $(date +%H:%M) $t for $((s / 60)) min"
  if fuzz/run.sh -t "$s" -j "$jobs" "$t" >>"$log" 2>&1; then
    say "   $t: no crashes"
  else
    failed+=("$t")
    say "   $t: FAILED, see fuzz/artifacts/$t/ and $log"
  fi
done

say "Finished $(date)."
if [ ${#failed[@]} -gt 0 ]; then
  say "Crashes in: ${failed[*]}. Minimize and report them as docs/fuzzing.md says."
  exit 1
fi
say "No crashes in any target."
