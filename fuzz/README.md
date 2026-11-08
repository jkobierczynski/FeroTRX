# FeroTRX fuzz targets

cargo-fuzz (libFuzzer) targets for everything FeroTRX reads from the
network or a client. The manual is [docs/fuzzing.md](../docs/fuzzing.md):
the targets, how to run long campaigns, and what to do with a crash.

Quick start (nightly toolchain and `cargo install cargo-fuzz` once):

```sh
fuzz/run.sh                  # every target, 60 s each
fuzz/run.sh -t 3600 app      # one target for an hour
fuzz/run.sh --list           # the targets
fuzz/campaign.sh             # all of them, 8 hours in total
```

* `fuzz_targets/`: one file per target; each calls a function of
  `ferotrx_core::fuzzing` or `ferotrx_ctl::fuzzing`.
* `regressions/<target>/`: inputs that once crashed a target. Committed;
  the normal test suite runs every one of them.
* `seeds/`, `corpus/`, `artifacts/`: written by the runs (seeds from the
  code, the corpus libFuzzer grows, crashing inputs). Not committed.
