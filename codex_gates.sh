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
GATE_EXCEPTIONS_FILE="${ROOT}/docs/ai/CODEX_GATE_EXCEPTIONS.md"
mypy_exception_status() {
  # Returns:
  #   0 => exactly one valid active mypy exception line
  #   1 => no active mypy exception
  #   2 => malformed or ambiguous active mypy exception lines present
  [ -f "${GATE_EXCEPTIONS_FILE}" ] || return 1

  local active_count valid_count
  active_count="$(rg -n "^GATE_EXCEPTION\|mypy\|active\|" "${GATE_EXCEPTIONS_FILE}" | wc -l | tr -d ' ')"
  valid_count="$({
    rg -n "^GATE_EXCEPTION\|mypy\|active\|reason=[^|]+\|scope=[^|]+\|follow_up=[^|]+\|owner=[^|]+\|expires=[0-9]{4}-[0-9]{2}-[0-9]{2}$" "${GATE_EXCEPTIONS_FILE}" || true
  } | wc -l | tr -d ' ')"

  if [ "${active_count}" = "0" ]; then
    return 1
  fi

  if [ "${active_count}" = "1" ] && [ "${valid_count}" = "1" ]; then
    return 0
  fi

  return 2
}
# Strict by default. In strict mode, mypy may only be non-blocking if there is an explicit codex gate exception record.
if [ "${GATES_MODE}" = "fast" ]; then
  mypy . || { echo "WARN: mypy failed in fast mode (non-blocking)"; }
else
  if ! mypy .; then
    exception_status=0
    mypy_exception_status || exception_status=$?
    case "${exception_status}" in
      0)
        echo "WARN: mypy failed under active codex gate exception (see ${GATE_EXCEPTIONS_FILE})"
        ;;
      1)
        echo "ERROR: mypy failed and no codex gate exception is active"
        exit 1
        ;;
      *)
        echo "ERROR: malformed or ambiguous mypy exception entry in ${GATE_EXCEPTIONS_FILE}"
        exit 1
        ;;
    esac
  fi
fi

echo "==> Gates: pytest"
pytest -q

echo "==> Gates: pip check"
python -m pip check

echo "==> Gates: basic secret scan (cheap tripwire)"
# Prevent accidental key commits. Extend patterns over time.
# Exclusions are intentionally narrow: detector-source files that contain known-safe pattern literals.
rg -n --hidden --no-ignore-vcs \
  -g '!services/ai_plane_extension/policy_engine.py' \
  -g '!codex_gates.sh' \
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
  if ! command -v pip-audit >/dev/null 2>&1; then
    echo "pip-audit not found in PATH; installing into ${VENV_DIR}"
    python -m pip install --quiet pip-audit
  fi
  if [ -x "${VENV_DIR}/bin/pip-audit" ]; then
    "${VENV_DIR}/bin/pip-audit"
  else
    pip-audit
  fi
fi

echo "==> All gates passed."
