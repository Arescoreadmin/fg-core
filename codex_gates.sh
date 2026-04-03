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
rg -n --hidden --no-ignore-vcs \
  "(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|BEGIN( RSA)? PRIVATE KEY|xox[baprs]-|-----BEGIN PRIVATE KEY-----)" \
  . && { echo "ERROR: possible secret detected (see matches above)"; exit 1; } || true

echo "==> Gates: contract/authority checks (if Makefile exists)"
if [ -f Makefile ]; then
  # Prefer your existing contract lane if present.
  if grep -qE "fg-contract|contract" Makefile; then
    make fg-contract
  fi
fi

echo "Running PR fix log enforcement..."
scripts/ci/enforce_pr_fix_log.sh

echo "==> Gates: dependency audit"
if [ "${GATES_MODE}" = "offline" ]; then
  echo "SKIP: pip-audit (offline mode)"
else
  pip-audit
fi

echo "==> All gates passed."