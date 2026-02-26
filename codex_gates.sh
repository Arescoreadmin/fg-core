#!/usr/bin/env bash
# codex_gates.sh — Enterprise gates Codex MUST run before claiming “done”
# Usage: bash codex_gates.sh
[ -d ".venv" ] || { echo "Missing .venv. Run setup_codex_env.sh"; exit 1; }

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV_DIR="${VENV_DIR:-.venv}"
if [ ! -x "${VENV_DIR}/bin/python" ]; then
  echo "ERROR: venv missing at ${VENV_DIR}. Run setup_codex_env.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

echo "==> Gates: ruff"
ruff check .

echo "==> Gates: mypy (if config exists)"
if [ -f pyproject.toml ] || [ -f mypy.ini ] || [ -f setup.cfg ]; then
  mypy .
else
  echo "mypy config not found; running in default mode"
  mypy . || true
fi

echo "==> Gates: pytest"
pytest -q

echo "==> Gates: pip check"
python -m pip check

echo "==> Gates: pip-audit"
pip-audit

echo "==> All gates passed."