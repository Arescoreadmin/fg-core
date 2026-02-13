#!/usr/bin/env bash
set -euo pipefail
VENV="${VENV:-.venv}"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Venv not found at $VENV. Create it first." >&2
  exit 1
fi

exec "$VENV/bin/python" -m "$@"
