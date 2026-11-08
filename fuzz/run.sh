#!/usr/bin/env bash
# Runs FeroTRX's fuzz targets with cargo-fuzz (libFuzzer). See fuzz/README.md.
#
#   fuzz/run.sh                      every target, 60 s each
#   fuzz/run.sh -t 600 app ssh       these targets, 10 minutes each
#   fuzz/run.sh --changed origin/main   only targets whose code changed
#   fuzz/run.sh --list               the targets and the code each covers
#
# Options:
#   -t, --seconds N    time per target (default 60; FUZZ_SECONDS)
#   -j, --jobs N       libFuzzer processes per target (default 1)
#   --changed BASE     only the targets whose files differ from git BASE
#   --list             print the targets and exit
# Anything after `--` goes to libFuzzer, e.g. `-- -max_len=65536`.
#
# Needs a nightly toolchain (`rustup toolchain install nightly`) and
# cargo-fuzz (`cargo install cargo-fuzz`). Seeds are written to
# fuzz/seeds/<target>/ first (with the stable toolchain); new inputs go to
# fuzz/corpus/<target>/, crashes to fuzz/artifacts/<target>/.
set -euo pipefail

cd "$(dirname "$0")/.."

# target -> extended regex of the paths whose changes it covers
declare -A COVERS=(
  [app]='crates/ferotrx-core/src/app/'
  [tcp_engine]='crates/ferotrx-core/src/(tcp|app)/'
  [udp_engine]='crates/ferotrx-core/src/(udp|app)/'
  [host_engine]='crates/ferotrx-core/src/(host/|tcp/wire\.rs)'
  [wire]='crates/ferotrx-core/src/(tcp/wire\.rs|host/wire\.rs|latency/|net\.rs)'
  [packet]='crates/ferotrx-packet/'
  [pcap]='crates/ferotrx-core/src/capture\.rs|crates/ferotrx-packet/'
  [profile]='crates/ferotrx-core/src/(profile\.rs|check\.rs|scenario/|fleet|bench/|y1564/|[a-z]+/profile\.rs|traffic\.rs|impair\.rs|stream\.rs)'
  [text]='crates/ferotrx-packet/src/spec\.rs|crates/ferotrx-core/src/(impair|field_engine|size_mix|traffic|pacer)\.rs'
  [ssh]='crates/ferotrx-core/src/app/ssh/'
  [quic]='crates/ferotrx-core/src/app/quic/'
  [ctl_call]='crates/ferotrx-ctl/'
  [ctl_server]='crates/ferotrx-ctl/'
)
ALL=(app tcp_engine udp_engine host_engine wire packet pcap profile text ssh quic ctl_call ctl_server)
# Changes here touch every target.
EVERYTHING='^(fuzz/|crates/ferotrx-core/src/fuzzing/|crates/ferotrx-ctl/src/fuzzing\.rs|Cargo\.lock)'

seconds=${FUZZ_SECONDS:-60}
jobs=1
changed=""
targets=()
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--seconds) seconds=$2; shift 2 ;;
    -j|--jobs) jobs=$2; shift 2 ;;
    --changed) changed=$2; shift 2 ;;
    --list)
      for t in "${ALL[@]}"; do printf '%-12s %s\n' "$t" "${COVERS[$t]}"; done
      exit 0 ;;
    --) shift; extra=("$@"); break ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) targets+=("$1"); shift ;;
  esac
done
[ ${#targets[@]} -gt 0 ] || targets=("${ALL[@]}")

if [ -n "$changed" ]; then
  files=$(git diff --name-only "$changed"...HEAD)
  picked=()
  if grep -Eq "$EVERYTHING" <<<"$files"; then
    picked=("${targets[@]}")
  else
    for t in "${targets[@]}"; do
      if grep -Eq "^(${COVERS[$t]})" <<<"$files"; then picked+=("$t"); fi
    done
  fi
  targets=("${picked[@]+"${picked[@]}"}")
  if [ ${#targets[@]} -eq 0 ]; then
    echo "No fuzz target covers the files changed since $changed."
    exit 0
  fi
fi

echo "== seeds"
FEROTRX_FUZZ_CORPUS="$PWD/fuzz/seeds" cargo test -q -p ferotrx-core --features fuzzing --lib \
  fuzzing::tests::write_seed_corpora -- --ignored >/dev/null
FEROTRX_FUZZ_CORPUS="$PWD/fuzz/seeds" cargo test -q -p ferotrx-ctl --no-default-features --features fuzzing --lib \
  fuzzing::tests::write_seed_corpora -- --ignored >/dev/null

# More than one process: libFuzzer writes their logs to fuzz-<n>.log here.
par=()
[ "$jobs" -gt 1 ] && par=("-jobs=$jobs" "-workers=$jobs")

failed=()
for t in "${targets[@]}"; do
  echo "== $t: ${seconds}s"
  mkdir -p "fuzz/corpus/$t" "fuzz/artifacts/$t"
  dict=()
  [ -f "fuzz/dicts/$t.dict" ] && dict=("-dict=fuzz/dicts/$t.dict")
  # The live server's connection threads outlive an input: LeakSanitizer
  # takes their thread-local storage for leaks.
  [ "$t" = ctl_server ] && dict+=("-detect_leaks=0")
  if ! cargo +nightly fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- \
      -max_total_time="$seconds" -rss_limit_mb=2048 -timeout=10 -max_len=65536 \
      -print_final_stats=1 "${par[@]+"${par[@]}"}" \
      "${dict[@]+"${dict[@]}"}" "${extra[@]+"${extra[@]}"}"; then
    failed+=("$t")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo
  echo "Crashes in: ${failed[*]}; inputs in fuzz/artifacts/<target>/ (see fuzz/README.md)."
  exit 1
fi
echo "No crashes."
