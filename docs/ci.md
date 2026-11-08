# CI: what runs when

`.github/workflows/ci.yml` runs on every pull request and every push to
`main`. Branch protection on `main` requires the checks `ubuntu-latest`,
`windows-latest` and `dpdk (ubuntu-latest)`; renaming those jobs means
updating the rule.

## Skipping work that already passed

The `ubuntu-latest`, `macos-latest`, `windows-latest` and `dpdk` jobs start
with `scripts/ci-gate.sh`. When the job already passed on the same git
tree, or on the tree of a parent or grandparent commit that differs only
trivially, every later step is skipped. The job itself still runs and ends
green in about a minute, so the required checks report and merges are not
blocked. (Skipping the job with a job-level `if` would not work: a skipped
matrix job reports one check named after the job, not `ubuntu-latest` and
`windows-latest`, and the required checks would wait forever.)

A trivial difference is:

- Markdown files (`*.md`) and files under `docs/` changed or added (not
  deleted or renamed: the installer packs some of them);
- version numbers bumped: the package version in `Cargo.toml`,
  `Cargo.lock`, `python/pyproject.toml` and `__version__`, and the
  version of the workspace's own path dependencies.

Anything else, including a dependency's version, code, examples, scripts
or workflows, gives a full run.

Each passing job uploads an artifact `ci-pass-JOB-TREE` (kept 30 days);
that is how a later run finds out. Only artifacts from runs in this
repository count, not from forks.

What this saves:

- the push to `main` after a merge (its tree is the tree the pull request's
  merge commit was tested on, as long as `main` did not move meanwhile);
- a stacked pull request retargeted or rebased onto `main` after the one
  below it merged, without conflicts (same tree);
- merging `main` into a stacked branch when the conflicts were only the
  version bump and `DEVELOPMENT.md`;
- documentation-only pull requests;
- "Re-run all jobs" after one job failed: the jobs that passed skip.

What it can't save:

- any change to code, tests, examples, scripts or workflows, however small;
- a stacked branch after `main` got other code meanwhile (another merged
  pull request): the tree is new;
- a base branch moving under a pull request with a merge conflict resolved
  in code.

A skip trusts the earlier run: a new stable Rust (with new clippy lints) or
runner image is only noticed on the next real run. To run everything
anyway, start the workflow by hand (Actions, CI, "Run workflow", with
"Run every job" ticked).

Try the decision locally: `scripts/ci-gate.sh --dry-run ubuntu-latest`
prints which earlier trees it would accept (without a token it can't look
the artifacts up, so it never skips).

## Cancelling superseded runs

A new push to a pull request cancels the CI and Fuzz runs still going for
the previous push. Runs on `main` are never cancelled.

## Retargeting

Changing a pull request's base branch (for instance GitHub retargeting the
pull request above a merged one) is an `edited` event, which CI does not
run on; the checks of the head commit still count. If GitHub instead
rebases the branch (native stacked pull requests do), the new head is a
`synchronize` event: the gate then finds the same tree and skips.
