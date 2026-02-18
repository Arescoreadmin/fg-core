#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main() -> int:
    failures: list[str] = []
    inv = json.loads((REPO / "tools/ci/route_inventory.json").read_text(encoding="utf-8"))

    required = {
        ("POST", "/breakglass/sessions"),
        ("POST", "/exceptions/requests"),
        ("POST", "/exceptions/requests/{request_id}/approve"),
    }
    seen = {(str(r.get("method", "")).upper(), str(r.get("path", ""))) for r in inv}
    for key in required:
        if key not in seen:
            failures.append(f"missing governance endpoint: {key}")

    # immutable retention footgun guard: no delete endpoints for evidence anchors/runs
    for method, path in seen:
        if method == "DELETE" and (path.startswith("/evidence/anchors") or path.startswith("/evidence/runs")):
            failures.append("immutable retention footgun: delete endpoint exposed for evidence artifacts")

    # deterministic deny codes in routers
    ex_router = (REPO / "api/exception_breakglass.py").read_text(encoding="utf-8")
    if "error_code" not in ex_router:
        failures.append("exception_breakglass router missing deterministic error_code")

    if failures:
        print("governance invariants: FAILED")
        for f in failures:
            print(f" - {f}")
        return 1

    print("governance invariants: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
