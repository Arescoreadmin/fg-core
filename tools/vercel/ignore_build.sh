#!/usr/bin/env bash
# P0-PORTAL-DEPLOY-RECOVERY-001 — fail-safe Vercel "Ignored Build Step".
#
# Vercel contract (docs: project-settings#ignored-build-step):
#   exit 0  -> build is aborted, deployment state CANCELED
#   exit 1  -> build continues
# The command runs from the project's Root Directory (e.g. apps/portal).
#
# Usage (from vercel.json):
#   bash ../../tools/vercel/ignore_build.sh <repo-root-relative path>...
#
# Design (each rule closes a way a required build could be skipped):
#   * Paths are resolved against the repository top level, never the cwd.
#     (#745 used repo-root paths from apps/portal, matched nothing, and
#     skipped every portal build from 2026-10-06.)
#   * The diff base is VERCEL_GIT_PREVIOUS_SHA — the last SUCCESSFUL deployment
#     for this project and branch — so a canceled or failed build can never
#     hide a change from the next one.  HEAD^ is only a fallback for a preview
#     branch's first deployment; production with no previous SHA builds.
#   * Every uncertain outcome builds: no paths, a path missing at HEAD, an
#     unresolvable HEAD or base, or any git error other than "no diff".
#   * The script exits only 0 or 1.
set -u

build() { echo "ignore-build: BUILD — $*"; exit 1; }
skip() { echo "ignore-build: SKIP — $*"; exit 0; }

[ "$#" -gt 0 ] || build "no watch paths given (refusing to skip)"

top=$(git rev-parse --show-toplevel 2>/dev/null) || build "not a git work tree"
head=$(git -C "$top" rev-parse --verify --quiet 'HEAD^{commit}') || build "HEAD unresolvable"

for p in "$@"; do
  case "$p" in
    /* | *..* | -*) build "invalid watch path '$p' (must be repo-root-relative)" ;;
  esac
  git -C "$top" cat-file -e "HEAD:$p" 2>/dev/null \
    || build "watch path '$p' does not exist at HEAD (a dead pathspec would skip forever)"
done

prev="${VERCEL_GIT_PREVIOUS_SHA:-}"
env="${VERCEL_ENV:-}"
if [ -n "$prev" ]; then
  base=$(git -C "$top" rev-parse --verify --quiet "${prev}^{commit}") \
    || build "last successful deployment ${prev:0:12} not in clone history"
  label="last successful deployment ${prev:0:12}"
elif [ "$env" = "production" ]; then
  build "production has no previous successful deployment SHA"
else
  base=$(git -C "$top" rev-parse --verify --quiet 'HEAD^1^{commit}') \
    || build "no previous deployment and no parent commit"
  label="parent commit (first deployment of this branch)"
fi

# Same SHA as the last successful deployment means an explicit redeploy.
[ "$base" = "$head" ] && build "explicit redeploy of ${head:0:12}"

git -C "$top" diff --quiet "$base" "$head" -- "$@"
rc=$?
case "$rc" in
  0) skip "no changes in [$*] since ${label}" ;;
  1) build "changes in [$*] since ${label}" ;;
  *) build "git diff failed (exit $rc); refusing to skip" ;;
esac
