#!/usr/bin/env bash
# Decides whether a CI job can skip its work because an equivalent tree
# already passed it. Used by .github/workflows/ci.yml; run it by hand with
# --dry-run to see what it would decide for HEAD.
#
#   scripts/ci-gate.sh [--dry-run] KEY
#
# KEY names the job (ubuntu-latest, windows-latest, macos-latest, dpdk).
# A job that passes uploads an artifact named ci-pass-KEY-TREE, TREE being
# the git tree it tested. This script looks for such an artifact for:
#
#   - the tree being tested (a retarget, a rebase without conflicts, the
#     push to main after a merge, a re-run of all jobs), or
#   - the tree of a parent or grandparent commit, when the difference is
#     trivial: documentation (*.md, docs/) changed or added, and version
#     numbers bumped (package versions in Cargo.toml, Cargo.lock,
#     pyproject.toml and __version__, and the versions of the workspace's
#     own path dependencies). That covers merging main into a stacked
#     branch when the conflicts were the version bump and DEVELOPMENT.md.
#
# Anything else (code, examples, scripts, workflows, a dependency's
# version, a deleted or renamed doc) means a full run. When the GitHub API
# can't be asked, the job runs too.
#
# In CI it writes CI_TREE (always) and CI_SKIP=true (when skipping) to
# $GITHUB_ENV. CI_FORCE=true runs everything regardless.
set -uo pipefail

dry=0
if [ "${1:-}" = --dry-run ]; then dry=1; shift; fi
key=${1:?usage: ci-gate.sh [--dry-run] KEY}

tree=$(git rev-parse 'HEAD^{tree}') || exit 0
env_out=${GITHUB_ENV:-/dev/null}
echo "CI_TREE=$tree" >>"$env_out"
# What the job's ci-pass artifact holds, if it ends up passing.
if [ -n "${RUNNER_TEMP:-}" ]; then
  printf 'tree %s\ncommit %s\nrun %s/%s/actions/runs/%s\n' "$tree" "$(git rev-parse HEAD)" \
    "${GITHUB_SERVER_URL:-}" "${GITHUB_REPOSITORY:-}" "${GITHUB_RUN_ID:-}" >"$RUNNER_TEMP/ci-pass.txt"
fi

if [ "${CI_FORCE:-}" = true ]; then
  echo "Full run requested."
  exit 0
fi

# Files whose only change may be a version number.
version_file() {
  case "$1" in
    Cargo.toml | */Cargo.toml | Cargo.lock | */Cargo.lock) return 0 ;;
    python/pyproject.toml | python/src/ferotrx/__init__.py) return 0 ;;
  esac
  return 1
}

# The file with its version numbers replaced by X: the package version (in
# [package], [workspace.package], [project] and Cargo.lock's [[package]]),
# __version__, and `version = "..."` on lines with a `path = "..."`.
# A registry crate's version can't change in Cargo.lock without its
# checksum, and a dependency requirement in Cargo.toml is left alone.
normalized() {
  git show "$1:$2" 2>/dev/null | awk '
    /^\[/ { sec = $0 }
    {
      line = $0
      if ((sec == "[package]" || sec == "[workspace.package]" || sec == "[project]" ||
           sec == "[[package]]") && line ~ /^version = "/)
        sub(/"[^"]*"/, "\"X\"", line)
      else if (line ~ /^__version__ = "/)
        sub(/"[^"]*"/, "\"X\"", line)
      else if (line ~ /path = "/ && line ~ /version = "/)
        sub(/version = "[^"]*"/, "version = \"X\"", line)
      print line
    }'
}

# Is going from tree $1 to the tested tree a trivial change?
trivial() {
  local changes status path
  changes=$(git diff --no-renames --name-status "$1" "$tree") || return 1
  [ -n "$changes" ] || return 0
  while IFS=$'\t' read -r status path; do
    case "$status:$path" in
      [MA]:*.md | [MA]:docs/*) continue ;;
    esac
    if [ "$status" = M ] && version_file "$path" &&
       [ "$(normalized "$1" "$path")" = "$(normalized "$tree" "$path")" ]; then
      continue
    fi
    echo "  $(git rev-parse --short "$1") differs in $path ($status)"
    return 1
  done <<<"$changes"
  return 0
}

# Did KEY pass on tree $1? Only artifacts made by runs in this repository
# count, not ones uploaded by a fork's pull request.
passed() {
  local name="ci-pass-$key-$1" repo_id=${GITHUB_REPOSITORY_ID:-} count
  [ -n "${GITHUB_REPOSITORY:-}" ] || return 1
  count=$(gh api -X GET "repos/$GITHUB_REPOSITORY/actions/artifacts" \
    -f name="$name" -f per_page=20 \
    --jq "[.artifacts[] | select(.expired == false and
           (\"$repo_id\" == \"\" or (.workflow_run.head_repository_id | tostring) == \"$repo_id\"))]
          | length" 2>/dev/null) || return 1
  [ "${count:-0}" -gt 0 ]
}

# The tested tree first, then its parents' and grandparents' (on a pull
# request HEAD is GitHub's merge commit: base, head, and the head's parents).
candidates=("$tree")
for rev in HEAD^1 HEAD^2 HEAD^1^1 HEAD^1^2 HEAD^2^1 HEAD^2^2; do
  t=$(git rev-parse -q --verify "$rev^{tree}" 2>/dev/null) || continue
  case " ${candidates[*]} " in *" $t "*) continue ;; esac
  candidates+=("$t")
done

for t in "${candidates[@]}"; do
  if [ "$t" != "$tree" ]; then
    trivial "$t" || continue
  fi
  if [ "$dry" = 1 ]; then
    echo "Would look for artifact ci-pass-$key-$t"
    passed "$t" || continue
  elif ! passed "$t"; then
    continue
  fi
  if [ "$t" = "$tree" ]; then
    echo "::notice::$key already passed on this tree ($tree); skipping the job's steps."
  else
    echo "::notice::$key passed on tree $t, which differs only in docs or version numbers; skipping the job's steps."
  fi
  echo "CI_SKIP=true" >>"$env_out"
  exit 0
done
echo "No passing run of $key on an equivalent tree; running everything."
