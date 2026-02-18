from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
BASE = REPO / "tools/ci/openapi_baseline.json"
CUR = REPO / "contracts/core/openapi.json"
OUT = REPO / "artifacts/OPENAPI_SECURITY_SUMMARY.md"


def _ops(spec):
    out = {}
    for p, body in (spec.get("paths") or {}).items():
        if not isinstance(body, dict):
            continue
        for m, op in body.items():
            mm = str(m).lower()
            if mm in {"get", "post", "put", "patch", "delete", "head", "options"} and isinstance(op, dict):
                out[(mm.upper(), p)] = op
    return out


def _auth(op):
    sec = op.get("security")
    return isinstance(sec, list) and len(sec) > 0


def main() -> int:
    b = json.loads(BASE.read_text(encoding="utf-8"))
    c = json.loads(CUR.read_text(encoding="utf-8"))
    bo = _ops(b)
    co = _ops(c)

    new = sorted(set(co) - set(bo))
    removed = sorted(set(bo) - set(co))
    changed_security = sorted(k for k in set(co) & set(bo) if _auth(co[k]) != _auth(bo[k]))
    missing_401_403 = sorted(k for k, op in co.items() if isinstance(op.get("responses"), dict) and ("401" not in op["responses"] or "403" not in op["responses"]))

    lines = [
        "# OpenAPI Security Summary",
        "",
        "non-cosmetic changes only",
        "",
        "## New routes",
    ]
    lines += [f"- {m} {p}" for m, p in new] or ["- none"]
    lines += ["", "## Removed routes (should be none)"]
    lines += [f"- {m} {p}" for m, p in removed] or ["- none"]
    lines += ["", "## Routes with changed security requirements"]
    lines += [f"- {m} {p}" for m, p in changed_security] or ["- none"]
    lines += ["", "## Routes missing 401/403"]
    lines += [f"- {m} {p}" for m, p in missing_401_403] or ["- none"]

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
