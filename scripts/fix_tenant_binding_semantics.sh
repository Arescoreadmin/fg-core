#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re

path = Path("api/auth_scopes/resolution.py")
lines = path.read_text(encoding="utf-8").splitlines(True)

def find_bind_def(lines: list[str]) -> tuple[int, int]:
    """
    Returns (def_start_idx, sig_end_idx).
    Handles multi-line signatures:
      def bind_tenant_id(
          ...
      ) -> ...:
    """
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^def\s+bind_tenant_id\s*\(", ln):
            start = i
            break
    if start is None:
        raise SystemExit("ERROR: def bind_tenant_id( not found")

    # Walk forward until we hit a line that ends the signature with a colon.
    # Typical end lines:
    #   ):
    #   ) -> Something:
    for j in range(start, min(start + 200, len(lines))):
        if re.search(r"\)\s*(?:->\s*[^:]+)?\s*:\s*$", lines[j].rstrip("\n")):
            return start, j
    raise SystemExit("ERROR: could not find end of bind_tenant_id signature (missing closing '):'?)")

def detect_body_indent(lines: list[str], sig_end_idx: int) -> tuple[int, str]:
    # Find first non-empty line after signature end
    for k in range(sig_end_idx + 1, len(lines)):
        ln = lines[k]
        if ln.strip() == "":
            continue
        m = re.match(r"^(\s+)", ln)
        if not m:
            # No indentation means file is syntactically broken.
            raise SystemExit(f"ERROR: bind_tenant_id body indentation not found at line {k+1}")
        return k, m.group(1)
    raise SystemExit("ERROR: bind_tenant_id has no body?")

def skip_docstring(lines: list[str], body_start_idx: int) -> int:
    """
    If first statement is a triple-quoted docstring, return index after it.
    """
    ln = lines[body_start_idx].lstrip()
    if ln.startswith('"""') or ln.startswith("'''"):
        quote = '"""' if ln.startswith('"""') else "'''"
        # Single-line docstring
        if ln.count(quote) >= 2 and ln.strip().endswith(quote):
            return body_start_idx + 1
        # Multi-line docstring: find closing quote
        for i in range(body_start_idx + 1, min(body_start_idx + 500, len(lines))):
            if quote in lines[i]:
                return i + 1
        raise SystemExit("ERROR: unterminated docstring in bind_tenant_id")
    return body_start_idx

def insert_helpers(lines: list[str], def_start_idx: int) -> list[str]:
    helpers = [
        "\n",
        "def _fg__is_env_api_key(presented_key: str | None, settings_obj) -> bool:\n",
        "    try:\n",
        "        expected = getattr(settings_obj, \"FG_API_KEY\", None)\n",
        "    except Exception:\n",
        "        expected = None\n",
        "    return bool(expected) and bool(presented_key) and presented_key == expected\n",
        "\n",
        "def _fg__request_path(request) -> str:\n",
        "    try:\n",
        "        return request.url.path\n",
        "    except Exception:\n",
        "        return \"\"\n",
        "\n",
        "def _fg__header_tenant(request) -> str | None:\n",
        "    try:\n",
        "        return request.headers.get(\"X-Tenant-Id\")\n",
        "    except Exception:\n",
        "        return None\n",
        "\n",
    ]
    text = "".join(lines)
    if "_fg__is_env_api_key" in text:
        return lines
    # Insert right before bind_tenant_id def
    return lines[:def_start_idx] + helpers + lines[def_start_idx:]

def insert_guard(lines: list[str], insert_at: int, indent: str) -> list[str]:
    guard = [
        f"{indent}# FG__STRICT_UNSCOPED_TENANT_GUARD\n",
        f"{indent}# Unscoped minted keys cannot act on ANY tenant even if tenant_id is supplied.\n",
        f"{indent}# Exception: env FG_API_KEY may bind X-Tenant-Id for /ai/query only.\n",
        f"{indent}req = locals().get(\"request\") or locals().get(\"req\")\n",
        f"{indent}settings_obj = locals().get(\"settings\") or locals().get(\"cfg\") or locals().get(\"config\")\n",
        f"{indent}presented_key = (\n",
        f"{indent}    locals().get(\"api_key\")\n",
        f"{indent}    or locals().get(\"key\")\n",
        f"{indent}    or locals().get(\"presented_api_key\")\n",
        f"{indent}    or locals().get(\"presented_key\")\n",
        f"{indent})\n",
        f"{indent}tenant_from_key = (\n",
        f"{indent}    locals().get(\"key_tenant_id\")\n",
        f"{indent}    or locals().get(\"tenant_id_from_key\")\n",
        f"{indent}    or locals().get(\"tenant_from_key\")\n",
        f"{indent}    or (locals().get(\"key_result\").tenant_id if locals().get(\"key_result\") is not None and hasattr(locals().get(\"key_result\"), \"tenant_id\") else None)\n",
        f"{indent})\n",
        f"{indent}tenant_arg = locals().get(\"tenant_id\") or locals().get(\"requested_tenant_id\") or locals().get(\"path_tenant_id\")\n",
        f"{indent}header_tid = _fg__header_tenant(req)\n",
        f"{indent}path = _fg__request_path(req)\n",
        "\n",
        f"{indent}if not tenant_from_key:\n",
        f"{indent}    if path == \"/ai/query\" and _fg__is_env_api_key(presented_key, settings_obj):\n",
        f"{indent}        if header_tid:\n",
        f"{indent}            locals()[\"tenant_id\"] = header_tid\n",
        f"{indent}        else:\n",
        f"{indent}            raise ValueError(\"tenant_id required for unscoped keys\")\n",
        f"{indent}    else:\n",
        f"{indent}        if tenant_arg or header_tid:\n",
        f"{indent}            raise ValueError(\"tenant_id required for unscoped keys\")\n",
        f"{indent}# END FG__STRICT_UNSCOPED_TENANT_GUARD\n",
        "\n",
    ]
    return lines[:insert_at] + guard + lines[insert_at:]

text = "".join(lines)
if "FG__STRICT_UNSCOPED_TENANT_GUARD" in text:
    print("INFO: guard already present; no-op.")
    raise SystemExit(0)

def_start, sig_end = find_bind_def(lines)

# Insert helpers first (this changes indices below, so recompute)
lines = insert_helpers(lines, def_start)

# Recompute bind def positions after insertion
def_start, sig_end = find_bind_def(lines)

body_start_idx, indent = detect_body_indent(lines, sig_end)
insert_at = skip_docstring(lines, body_start_idx)

lines = insert_guard(lines, insert_at, indent)

path.write_text("".join(lines), encoding="utf-8")
print("OK: patched bind_tenant_id strict semantics in", path)
PY

ruff format "$FILE"
ruff check "$FILE"

python -m pytest -q \
  tests/security/test_ai_query_unscoped_key_requires_tenant_header.py \
  tests/security/test_tenant_contract_endpoints.py \
  tests/test_admin_audit_tenant_binding.py \
  tests/test_audit_search.py
