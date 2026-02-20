#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="api/connectors_control_plane.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: missing $TARGET"
  exit 1
fi

echo "== Patch $TARGET to export a real module-level router =="

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re
import sys

p = Path("api/connectors_control_plane.py")
s = p.read_text(encoding="utf-8")

def has_router_symbol(src: str) -> bool:
    return bool(re.search(r'(?m)^\s*router\s*=\s*', src))

def ensure_fastapi_import(src: str) -> str:
    # If APIRouter already imported, good.
    if re.search(r'(?m)^\s*from\s+fastapi\s+import\s+.*\bAPIRouter\b', src):
        return src
    # If fastapi imported but not APIRouter, extend the import list.
    m = re.search(r'(?m)^(?P<indent>\s*)from\s+fastapi\s+import\s+(?P<names>.+)$', src)
    if m:
        names = m.group("names").strip()
        # naive split, but fine for our controlled import style
        if "APIRouter" not in names:
            new = f"from fastapi import APIRouter, {names}"
            src = src[: m.start()] + new + src[m.end() :]
        return src

    # Otherwise, insert a new import near the top, after __future__ import if present.
    lines = src.splitlines(True)
    insert_at = 0
    for i, line in enumerate(lines[:50]):  # only scan the top
        if line.startswith("from __future__ import"):
            insert_at = i + 1
            break
    # skip blank lines after future import
    while insert_at < len(lines) and lines[insert_at].strip() == "":
        insert_at += 1
    lines.insert(insert_at, "from fastapi import APIRouter\n")
    return "".join(lines)

def find_first_decorator_router_name(src: str) -> str | None:
    # Find something like:
    # @router.get(...)
    # @connectors_router.post(...)
    # We'll take the first one.
    m = re.search(r'(?m)^\s*@(?P<name>[A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch|options|head)\b', src)
    if not m:
        return None
    return m.group("name")

def find_apirouter_assignment(src: str, name: str) -> bool:
    # Check for "<name> = APIRouter("
    return bool(re.search(rf'(?m)^\s*{re.escape(name)}\s*=\s*APIRouter\s*\(', src))

def insert_router_block(src: str, *, primary_name: str, tags: str) -> str:
    """
    Insert:
      <primary_name> = APIRouter(tags=[...])
      router = <primary_name>
    near the top of module (after imports).
    """
    block = (
        "\n"
        "# ---------------------------------------------------------------------\n"
        "# Connectors control-plane router export\n"
        "# ---------------------------------------------------------------------\n"
        f"{primary_name} = APIRouter(tags={[tags]!r})\n"
        f"router = {primary_name}\n"
    )

    lines = src.splitlines(True)

    # Insert after import block. Heuristic: after the last top-level import in the first ~200 lines.
    last_import_idx = None
    for i, line in enumerate(lines[:200]):
        if re.match(r'^\s*(from|import)\s+', line):
            last_import_idx = i
            continue
        # Allow blank lines and comments within import block
        if last_import_idx is not None and (line.strip() == "" or line.lstrip().startswith("#")):
            continue
        if last_import_idx is not None:
            break

    if last_import_idx is None:
        # No imports? Insert at top.
        lines.insert(0, block)
        return "".join(lines)

    insert_at = last_import_idx + 1
    # Ensure at least one blank line before block
    if insert_at < len(lines) and lines[insert_at].strip() != "":
        block = "\n" + block
    lines.insert(insert_at, block)
    return "".join(lines)

def alias_router(src: str, name: str) -> str:
    # If router already exists, do nothing.
    if has_router_symbol(src):
        return src
    # Insert alias near the APIRouter assignment if possible; otherwise near top.
    lines = src.splitlines(True)
    assign_re = re.compile(rf'^\s*{re.escape(name)}\s*=\s*APIRouter\s*\(')
    for i, line in enumerate(lines):
        if assign_re.search(line):
            # Insert alias right after assignment line (not perfect if assignment spans multiple lines,
            # but safe and works because alias can appear anywhere after name exists).
            lines.insert(i + 1, f"router = {name}\n")
            return "".join(lines)
    # Fallback: insert near top after imports
    return insert_router_block(src, primary_name=name, tags="connectors-control-plane")

# ---- Patch logic ----

s2 = ensure_fastapi_import(s)

decor_name = find_first_decorator_router_name(s2)

# Case A: decorators exist -> align router name with them
if decor_name:
    # If decor_name isn't assigned to APIRouter, create it + alias router
    if not find_apirouter_assignment(s2, decor_name):
        # Insert a proper router object using the decorator name, so all existing decorators bind correctly.
        if not has_router_symbol(s2):
            s2 = insert_router_block(s2, primary_name=decor_name, tags="connectors-control-plane")
        else:
            # router exists but decor_name doesn't? Weird. Create decor_name and keep router.
            s2 = insert_router_block(s2, primary_name=decor_name, tags="connectors-control-plane")
    else:
        # decor_name exists as APIRouter: just ensure router alias points to it.
        s2 = alias_router(s2, decor_name)

# Case B: no decorators found -> just ensure router exists
else:
    if not has_router_symbol(s2):
        s2 = insert_router_block(s2, primary_name="router", tags="connectors-control-plane")

# Final sanity: router symbol must exist now
if not has_router_symbol(s2):
    raise SystemExit("ERROR: Patch failed to create/export router")

if s2 != s:
    p.write_text(s2, encoding="utf-8")
    print("Patched:", p)
else:
    print("No changes needed.")

PY

echo "== Verify module exports router =="
python - <<'PY'
from api.connectors_control_plane import router
assert router is not None
print("OK: imported router:", router)
PY

echo "== Optional: format and compile =="
ruff format api/connectors_control_plane.py >/dev/null 2>&1 || true
python -m compileall -q api services tests || true

echo "== Done =="