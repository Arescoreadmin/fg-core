#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

echo "==> py_compile"
python -m py_compile api/main.py api/feed.py api/ui.py api/auth_scopes/__init__.py

echo "==> restart + ready"
make fg-restart >/dev/null
make -s fg-ready >/dev/null

echo "==> ui+sse smoke"
make -s fg-ui-sse-smoke

echo "✅ fg_doctor ok"
