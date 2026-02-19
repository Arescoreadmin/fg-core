#!/usr/bin/env bash
set -euo pipefail

FILE="tools/ci/route_checks.py"

test -f "$FILE" || { echo "ERROR: $FILE not found (run from repo root)"; exit 2; }

# 1) Hard fail if the known-bad signature isn't present (so we don't patch the wrong thing).
if ! grep -q "tenant_explicit_unbound = _infer_tenant_unbound(" "$FILE"; then
  echo "ERROR: expected marker not found: tenant_explicit_unbound = _infer_tenant_unbound("
  exit 3
fi

# 2) Ensure helper to extract dependency names exists. If not, append it once.
if ! grep -q "^def _dependency_names_from_call(" "$FILE"; then
  cat >> "$FILE" <<'PY'

def _dependency_names_from_call(call: ast.Call) -> set[str]:
    """
    Extract dependency function names from a FastAPI dependencies=[Depends(...), ...] kwarg.
    Returns a set of best-effort names (e.g., "require_tenant_id", "api.auth.require_tenant_id").
    """
    dep_node = _keyword_value(call, "dependencies")
    if not isinstance(dep_node, (ast.List, ast.Tuple)):
        return set()
    out: set[str] = set()
    for dep in dep_node.elts:
        if not isinstance(dep, ast.Call):
            continue
        if _get_name(dep.func) != "Depends" or not dep.args:
            continue
        out.add(_get_name(dep.args[0]) or "")
        # Handle Depends(fn(...)) style
        if isinstance(dep.args[0], ast.Call):
            out.add(_get_name(dep.args[0].func) or "")
    return {x for x in out if x}
PY
fi

# 3) Patch the broken tenant_explicit_unbound block.
python - <<'PY'
from __future__ import annotations
from pathlib import Path
import re

path = Path("tools/ci/route_checks.py")
text = path.read_text(encoding="utf-8").splitlines(True)

# Locate the exact broken region by finding the line with the mangled call
start = None
for i, line in enumerate(text):
    if "tenant_explicit_unbound = _infer_tenant_unbound(" in line:
        start = i
        break

if start is None:
    raise SystemExit("ERROR: couldn't locate tenant_explicit_unbound assignment")

# Find the end of the broken call block by matching the closing paren line
end = None
for j in range(start, min(start + 30, len(text))):
    if re.match(r"^\s*\)\s*$", text[j]):
        end = j
        break

if end is None:
    raise SystemExit("ERROR: couldn't locate end of _infer_tenant_unbound(...) call")

block = "".join(text[start:end+1])

# If the block already looks fixed (has file_path= on same call line), bail out safely.
if "file_path=" in block and "tenant_explicit_unbound = tenant_explicit_unbound or" in text[end+1:end+5]:
    print("INFO: block already appears fixed; no changes made.")
    raise SystemExit(0)

indent = re.match(r"^(\s*)", text[start]).group(1)

replacement = (
    f"{indent}dep_names = _dependency_names_from_call(deco) | _extract_dep_names_from_function(node)\n"
    f"{indent}tenant_explicit_unbound = _infer_tenant_unbound(\n"
    f"{indent}    file_path=self.file_path,\n"
    f"{indent}    full_path=full_path,\n"
    f"{indent}    scopes=all_scopes,\n"
    f"{indent})\n"
    f"{indent}tenant_explicit_unbound = tenant_explicit_unbound or (\"require_tenant_id\" in dep_names)\n"
)

# Replace the whole broken call block (start..end) with our replacement lines
text[start:end+1] = [replacement]

path.write_text("".join(text), encoding="utf-8")
print("OK: patched tenant_explicit_unbound block")
PY

# 4) Add missing function helper for extracting dep names from function signature if needed.
if ! grep -q "^def _extract_dep_names_from_function(" "$FILE"; then
  cat >> "$FILE" <<'PY'

def _extract_dep_names_from_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """
    Extract dependency function names from Depends(...) defaults on function parameters.
    """
    out: set[str] = set()
    args = [*node.args.args, *node.args.kwonlyargs]
    if node.args.vararg:
        args.append(node.args.vararg)
    if node.args.kwarg:
        args.append(node.args.kwarg)

    for arg in args:
        default = _default_for_arg(node, arg.arg)
        if not isinstance(default, ast.Call):
            continue
        if _get_name(default.func) != "Depends" or not default.args:
            continue
        out.add(_get_name(default.args[0]) or "")
        if isinstance(default.args[0], ast.Call):
            out.add(_get_name(default.args[0].func) or "")
    return {x for x in out if x}
PY
fi

# 5) Reformat + lint + compile check so we fail here, not in CI.
ruff format "$FILE"
ruff check "$FILE"
python -m compileall -q "$FILE"

echo "DONE: $FILE parses, formats, and lints clean."
