#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

command -v rg >/dev/null || { echo "ERROR: rg not found. Install ripgrep."; exit 1; }

echo "[1/5] Backing up current files (git recommended)"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git status --porcelain
  echo "Git repo detected. Good."
else
  echo "WARN: Not a git repo. Consider: git init && git add -A && git commit -m 'baseline'"
fi

echo "[2/5] Replace old verify_api_key import in api/*"
# Replace: from api.auth import verify_api_key  -> from api.auth_scopes import verify_api_key
FILES="$(rg -l --hidden --glob '!**/.venv/**' 'from api\.auth import verify_api_key' api || true)"
if [[ -n "${FILES}" ]]; then
  echo "$FILES" | while read -r f; do
    echo "Patching $f"
    perl -0777 -i -pe 's/from api\.auth import verify_api_key/from api.auth_scopes import verify_api_key/g' "$f"
  done
else
  echo "No old imports found. Nice."
fi

echo "[3/5] Ensure router objects exist (common faceplant)"
# Warn if any api/*.py uses @router but doesn't define router =
BAD="$(rg -n --hidden --glob '!**/.venv/**' '^@router\.' api | cut -d: -f1 | sort -u | while read -r f; do
  if ! rg -n '^\s*router\s*=\s*APIRouter' "$f" >/dev/null; then
    echo "$f"
  fi
done || true)"

if [[ -n "${BAD}" ]]; then
  echo "ERROR: These files use @router.* but do NOT define router = APIRouter(...)"
  echo "$BAD"
  echo "Fix them (define router) before continuing."
  exit 1
fi

echo "[4/5] Quick sanity: verify_api_key referenced?"
rg -n --hidden --glob '!**/.venv/**' 'verify_api_key' api || true

echo "[5/5] Done. Run: scripts/auth_audit.sh"
