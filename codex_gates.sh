#!/usr/bin/env bash
# codex_gates.sh — Enterprise gates Codex MUST run before claiming “done”
# Usage:
#   bash codex_gates.sh            # strict default
#   GATES_MODE=fast bash codex_gates.sh
#   GATES_MODE=offline bash codex_gates.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV_DIR="${VENV_DIR:-.venv}"
GATES_MODE="${GATES_MODE:-strict}"   # strict | fast | offline

[ -x "${VENV_DIR}/bin/python" ] || { echo "ERROR: venv missing at ${VENV_DIR}. Run setup_codex_env.sh" >&2; exit 1; }
# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

echo "==> Gates mode: ${GATES_MODE}"

echo "==> Gates: ruff (lint)"
ruff check .

if ruff --help | grep -q "format"; then
  echo "==> Gates: ruff (format check)"
  ruff format --check .
fi

echo "==> Gates: mypy"
# Strict by default. If you want optional, make it explicit in fast mode.
# mypy is not in requirements-dev.txt; skip with warning if not installed.
if command -v mypy >/dev/null 2>&1; then
  if [ "${GATES_MODE}" = "fast" ]; then
    mypy . || { echo "WARN: mypy failed in fast mode (non-blocking)"; }
  else
    mypy .
  fi
else
  echo "WARN: mypy not installed — skipping type checks (add mypy to requirements-dev.txt to enforce)"
fi

echo "==> Gates: pytest"
pytest -q

echo "==> Gates: pip check"
python -m pip check

echo "==> Gates: basic secret scan (cheap tripwire)"
# Prevent accidental key commits. Extend patterns over time.
#
# Two-pass approach: patterns are split by legitimacy of name-only references.
#
# Pass 1 — "never legitimate anywhere": PEM markers and Slack tokens are never
# correct to appear by name in infra or docs, so ALL paths are scanned.
# Excluded paths (apply to both passes):
# - codex_gates.sh itself: contains the detection patterns.
# - .claude/worktrees/**: Claude/Codex scratch worktrees may contain detector regexes.
# - services/ai_plane_extension/policy_engine.py: re.compile deny-list patterns, not secrets.
# - apps/**/node_modules/**: third-party JS libs (e.g. jose) contain PEM marker strings.
# - apps/**/.next/**: Next.js build artifacts bundle those strings via source maps.
# - docs/ai/**: PR fix log and audit notes quote env-var names as documentation.
# - .git/**: git internal files (COMMIT_EDITMSG, etc.) can quote detector patterns.
_SECRET_SCAN_BASE_GLOBS=(
  --glob '!codex_gates.sh'
  --glob '!.claude/worktrees/**'
  --glob '!services/ai_plane_extension/policy_engine.py'
  --glob '!.venv/**'
  --glob '!apps/**/node_modules/**'
  --glob '!apps/**/.next/**'
  --glob '!docs/ai/**'
  --glob '!.git/**'
)
rg -n --hidden --no-ignore-vcs \
  "${_SECRET_SCAN_BASE_GLOBS[@]}" \
  "(BEGIN( RSA)? PRIVATE KEY|xox[baprs]-|-----BEGIN PRIVATE KEY-----)" \
  . && { echo "ERROR: possible secret detected (see matches above)"; exit 1; } || true

# Pass 2 — "env-var names that are legitimate in infra/ops paths": OPENAI_API_KEY and
# AWS_SECRET_ACCESS_KEY appear by name (not as values) in backup scripts, operator runbooks,
# and the two backup workflow files that use ${{ secrets.FG_BACKUP_R2_SECRET_ACCESS_KEY }}.
# Those 4 infra paths are excluded here; they remain in scope for Pass 1.
# Additional exclusion:
# - apps/console/app/api/field-assessment/transcribe/route.ts: references process.env.OPENAI_API_KEY
#   by name to check if the var is set (not a value).
rg -n --hidden --no-ignore-vcs \
  "${_SECRET_SCAN_BASE_GLOBS[@]}" \
  --glob '!apps/console/app/api/field-assessment/transcribe/route.ts' \
  --glob '!docs/operators/**' \
  --glob '!scripts/backup/**' \
  --glob '!.github/workflows/backup-scheduled.yml' \
  --glob '!.github/workflows/restore-drill-monthly.yml' \
  "(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)" \
  . && { echo "ERROR: possible secret detected (see matches above)"; exit 1; } || true

echo "==> Gates: contract/authority checks (if Makefile exists)"
if [ -f Makefile ]; then
  # Prefer your existing contract lane if present.
  if grep -qE "fg-contract|contract" Makefile; then
    make fg-contract
  fi
fi

echo "==> Gates: authority integration (wiring completeness)"
PYTHONPATH=. python tools/ci/check_authority_integration.py

echo "Running PR fix log enforcement..."
scripts/ci/enforce_pr_fix_log.sh

echo "==> Gates: dependency audit"
if [ "${GATES_MODE}" = "offline" ]; then
  echo "SKIP: pip-audit (offline mode)"
elif [ -f Makefile ] && grep -qE "^pip-audit:" Makefile; then
  make pip-audit
else
  python -m pip install -q --upgrade pip-audit
  python -m pip_audit --ignore-vuln CVE-2026-4539 --ignore-vuln PYSEC-2025-183
fi

echo "==> Gates: canonical tester flow (skips if services unavailable)"
bash tools/auth/validate_tester_flow.sh

echo "==> All gates passed."
