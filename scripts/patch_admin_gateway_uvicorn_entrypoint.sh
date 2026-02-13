#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FROM="admin_gateway.main:app"
TO="admin_gateway.asgi:app"

echo "==> Admin Gateway uvicorn entrypoint patch"
echo "    FROM: $FROM"
echo "    TO:   $TO"
echo

patch_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    echo "==> Skip (missing): $f"
    return 0
  fi

  if rg -n --fixed-strings "$FROM" "$f" >/dev/null; then
    echo "==> Patching: $f"
    tmp="$(mktemp)"
    sed "s|$FROM|$TO|g" "$f" > "$tmp"
    mv "$tmp" "$f"
    echo "✅ Patched $f"
  else
    echo "==> No '$FROM' found in $f (already patched or not applicable)"
  fi
}

# Patch ONLY known runtime command locations
patch_file "Makefile"
patch_file "admin_gateway/Dockerfile"

# Optional docs patch (best-effort)
for doc in docs/*.md admin_gateway/README.md README.md; do
  [[ -e "$doc" ]] || continue
  patch_file "$doc"
done

echo
echo "==> Verification"
echo "-> Makefile:"
rg -n "uvicorn.*admin_gateway\.(asgi|main):app" Makefile || true
echo "-> admin_gateway/Dockerfile:"
rg -n "uvicorn.*admin_gateway\.(asgi|main):app" admin_gateway/Dockerfile || true

echo "-> Confirm asgi module contains app:"
python - <<'PY'
from importlib import import_module
m = import_module("admin_gateway.asgi")
assert hasattr(m, "app"), "admin_gateway.asgi must export `app`"
print("✅ asgi exports app")
PY

echo
echo "==> Diff guard (refuse big diffs)"
allowed_re='^(Makefile|admin_gateway/Dockerfile|docs/.*\.md|admin_gateway/README\.md|README\.md)$'
bad="$(git diff --name-only | rg -v "$allowed_re" || true)"
if [[ -n "$bad" ]]; then
  echo "❌ Refusing: unexpected files modified:"
  echo "$bad"
  echo
  echo "Fix: reset working tree:"
  echo "  git restore . && git clean -fd"
  exit 1
fi

echo "✅ Diff guard passed"
git diff --stat
echo
echo '✅ Done. Next: RUN_CI=1 make ci && git commit -am "chore(admin-gateway): run uvicorn via asgi app"'
