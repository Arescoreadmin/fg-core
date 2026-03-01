#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# FrostGate CI Enforcement: PR Fix Log Required
#
# Fails if source files changed but docs/ai/PR_FIX_LOG.md was not modified.
# -----------------------------------------------------------------------------

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

BASE_REF="${GITHUB_BASE_REF:-origin/main}"

echo "[pr-fix-log] Comparing against base: ${BASE_REF}"

# Determine diff range
if git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  DIFF_RANGE="${BASE_REF}...HEAD"
else
  # Fallback for local runs
  DIFF_RANGE="HEAD~1...HEAD"
fi

CHANGED_FILES=$(git diff --name-only "$DIFF_RANGE")

if [[ -z "$CHANGED_FILES" ]]; then
  echo "[pr-fix-log] No changes detected."
  exit 0
fi

# Define source patterns that require fix log
SOURCE_PATTERNS='^(api/|admin_gateway/|scripts/|tools/|docker-compose|Makefile|.*\.py$|.*\.sh$)'

SOURCE_CHANGED=$(echo "$CHANGED_FILES" | grep -E "$SOURCE_PATTERNS" || true)
FIX_LOG_CHANGED=$(echo "$CHANGED_FILES" | grep -E '^docs/ai/PR_FIX_LOG\.md$' || true)

if [[ -n "$SOURCE_CHANGED" && -z "$FIX_LOG_CHANGED" ]]; then
  echo ""
  echo "❌ PR_FIX_LOG enforcement failure"
  echo ""
  echo "Source files were modified:"
  echo "$SOURCE_CHANGED"
  echo ""
  echo "But docs/ai/PR_FIX_LOG.md was not updated."
  echo ""
  echo "Enterprise policy requires an appended structured entry."
  echo ""
  exit 1
fi

echo "[pr-fix-log] OK"