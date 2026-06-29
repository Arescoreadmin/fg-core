#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${BASE_REF:-origin/main}"

echo "== FrostGate PR Preflight =="
echo "BASE_REF=${BASE_REF}"

echo
echo "== Changed Python files =="
CHANGED_PY="$(git diff --name-only "${BASE_REF}...HEAD" 2>/dev/null | grep -E '\.py$' || true)"

if [[ -n "${CHANGED_PY}" ]]; then
  echo "${CHANGED_PY}"
  echo
  echo "== Ruff changed files =="
  ruff check ${CHANGED_PY}
  ruff format --check ${CHANGED_PY}
else
  echo "No changed Python files detected."
fi

echo
echo "== Full mypy =="
mypy .

echo
echo "== Authority / privacy / registry gates =="
python tools/ci/check_cgin_privacy.py
python tools/ci/check_authority_integration.py
python tools/ci/check_plane_registry.py
python scripts/generate_platform_inventory.py

echo
echo "== Contract gate =="
make fg-contract

echo
echo "== Global pytest fast-fail =="
pytest -q -x --maxfail=5

echo
echo "== FrostGate PR Preflight: PASS =="
