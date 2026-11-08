Inputs that once made a fuzz target panic, hang or run out of memory, one
folder per target, named after what they were. `cargo test` runs them all
(`fuzzing::tests::every_target_takes_its_regressions` in ferotrx-core and
ferotrx-ctl). Add the minimized input here when you fix a crash
(see docs/fuzzing.md).
