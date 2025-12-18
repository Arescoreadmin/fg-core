#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
GOOD_URL='postgresql+psycopg://fg_user:STRONG_PASSWORD@postgres:5432/frostgate'

# Where we’ll look
FILES=()

# Compose files
while IFS= read -r -d '' f; do FILES+=("$f"); done < <(
  find "$ROOT" -maxdepth 2 -type f \( -name "docker-compose.yml" -o -name "docker-compose.*.yml" \) -print0 2>/dev/null || true
)

# Env files
while IFS= read -r -d '' f; do FILES+=("$f"); done < <(
  find "$ROOT" -maxdepth 2 -type f -name ".env*" -print0 2>/dev/null || true
)

# db.py (optional patch)
if [[ -f "$ROOT/api/db.py" ]]; then
  FILES+=("$ROOT/api/db.py")
fi

timestamp() { date +"%Y%m%d_%H%M%S"; }

backup_file() {
  local f="$1"
  local b="${f}.bak.$(timestamp)"
  cp -p "$f" "$b"
  echo "backup: $b"
}

patch_compose_fg_db_url() {
  local f="$1"
  perl -0777 -pe '
    s/^(\s*FG_DB_URL:\s*)(["'\'']?).*?\2\s*$/$1"postgresql+psycopg:\/\/fg_user:STRONG_PASSWORD@postgres:5432\/frostgate"/mg
  ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
}

patch_env_fg_db_url() {
  local f="$1"
  perl -0777 -pe '
    s/^(FG_DB_URL=).*?$/${1}postgresql+psycopg:\/\/fg_user:STRONG_PASSWORD@postgres:5432\/frostgate/mg
  ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
}

patch_db_py_default() {
  local f="$1"
  perl -0777 -pe '
    s/os\.getenv\("FG_DB_URL",\s*"[^\"]*"\)/os.getenv("FG_DB_URL", "postgresql+psycopg:\/\/fg_user:STRONG_PASSWORD@postgres:5432\/frostgate")/g
  ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
}


echo "Root: $ROOT"
echo "Setting FG_DB_URL to: $GOOD_URL"
echo

export GOOD_URL

changed=0

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || continue

  # Only touch files that mention FG_DB_URL (or db.py for default)
  if grep -q "FG_DB_URL" "$f" || [[ "$f" == */api/db.py ]]; then
    echo "patching: $f"
    backup_file "$f"

    if [[ "$f" == *docker-compose*.yml ]]; then
      patch_compose_fg_db_url "$f"
    elif [[ "$(basename "$f")" == .env* ]]; then
      patch_env_fg_db_url "$f"
    elif [[ "$f" == */api/db.py ]]; then
      patch_db_py_default "$f"
    fi

    changed=$((changed+1))
  fi
done

echo
echo "Patched files: $changed"
echo

echo "Sanity check: searching for the bad string 'fg_user frostgate'..."
if grep -R --line-number --no-messages -F "fg_user frostgate" "$ROOT" 2>/dev/null; then
  echo
  echo "FAIL: found remaining bad DB URL fragments above."
  exit 1
fi

echo "OK: no remaining bad fragments."
echo
echo "Next: restart stack"
echo "  docker compose down"
echo "  docker compose up -d --build"
