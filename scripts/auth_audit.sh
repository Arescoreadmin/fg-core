#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

echo "[1/6] Checking repo root: $ROOT"
cd "$ROOT"

echo "[2/6] Ensure ripgrep exists"
command -v rg >/dev/null || { echo "ERROR: rg not found. Install ripgrep."; exit 1; }

echo "[3/6] Find OLD auth import usage (api.auth)"
rg -n --hidden --glob '!**/.venv/**' --glob '!**/__pycache__/**' \
  'from api\.auth import verify_api_key|api\.auth\.verify_api_key' api || true

echo
echo "[4/6] Find auth_scopes usage (expected)"
rg -n --hidden --glob '!**/.venv/**' --glob '!**/__pycache__/**' \
  'from api\.auth_scopes import verify_api_key|api\.auth_scopes\.verify_api_key' api || true

echo
echo "[5/6] Find references to deleted/legacy scopes modules (should be empty)"
rg -n --hidden --glob '!**/.venv/**' --glob '!**/__pycache__/**' \
  'api\.scopes|from api\.scopes|require_scope' api || true

echo
echo "[6/6] Inspect auth env usage in compose/.env"
rg -n --hidden --glob '!**/.venv/**' \
  'FG_API_KEY|FG_SCOPED_KEYS|FG_API_KEYS' docker-compose.yml .env 2>/dev/null || true

echo
echo "DONE: Review the output. Any 'api.auth' import means you missed a router."
