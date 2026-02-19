#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = REPO / "contracts/core/openapi.json"
DEFAULT_BASELINE = REPO / "tools/ci/openapi_baseline.json"
DEFAULT_ALLOWLIST = REPO / "tools/ci/protected_routes_allowlist.json"
DEFAULT_ROUTE_INVENTORY = REPO / "tools/ci/route_inventory.json"

COSMETIC_KEYS = {"summary", "description", "tags"}
EXTENSION_PREFIXES = (
    "/compliance-cp/",
    "/enterprise-controls/",
    "/exceptions/",
    "/breakglass/",
    "/evidence/anchors",
    "/evidence/runs",
    "/auth/federation/",
    "/ai/",
    "/ai-plane/",
    "/planes",
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in sorted(obj.items()):
            if k in COSMETIC_KEYS:
                continue
            out[k] = _normalize(v)
        return out
    if isinstance(obj, list):
        if all(isinstance(x, (str, int, float, bool, type(None))) for x in obj):
            return sorted(obj, key=lambda x: str(x))
        return [_normalize(x) for x in obj]
    return obj


def _ops(spec: dict[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    out = {}
    for p, body in (spec.get("paths") or {}).items():
        if not isinstance(body, dict):
            continue
        for m, op in body.items():
            mm = str(m).lower()
            if mm in {"get", "post", "put", "patch", "delete", "head", "options"} and isinstance(op, dict):
                out[(mm, str(p))] = op
    return out


def _has_auth(inv: dict[str, object] | None) -> bool:
    return isinstance(inv, dict) and inv.get("scoped") is True


def _tenant_bound(inv: dict[str, object] | None) -> bool:
    return isinstance(inv, dict) and inv.get("tenant_bound") is True


def _responses_401_403(op: dict[str, object]) -> bool:
    r = op.get("responses")
    return isinstance(r, dict) and "401" in r and "403" in r


def _is_extension_route(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in EXTENSION_PREFIXES)


def main() -> int:
    baseline_path = Path(os.getenv("OPENAPI_BASELINE_PATH", str(DEFAULT_BASELINE)))
    target_path = Path(os.getenv("OPENAPI_TARGET_PATH", str(DEFAULT_TARGET)))
    allowlist_path = Path(os.getenv("OPENAPI_PROTECTED_ALLOWLIST_PATH", str(DEFAULT_ALLOWLIST)))
    route_inventory_path = Path(os.getenv("OPENAPI_ROUTE_INVENTORY_PATH", str(DEFAULT_ROUTE_INVENTORY)))

    baseline = _load(baseline_path)
    target = _load(target_path)
    allow = _load(allowlist_path)
    inv = _load(route_inventory_path)

    protected_prefixes = tuple(allow.get("protected_prefixes", []))
    waived = dict(allow.get("waived_401_403", {}))
    route_map = {(str(r.get("method", "")).lower(), str(r.get("path", ""))): r for r in inv}

    base_ops = _ops(baseline)
    tgt_ops = _ops(target)

    changed_keys = []
    for key, op in sorted(tgt_ops.items()):
        b = base_ops.get(key)
        if b is None:
            changed_keys.append(key)
            continue
        if _normalize(b) != _normalize(op):
            changed_keys.append(key)

    failures: list[str] = []

    allowed_ai = {"/ai/infer"}
    for _, path in tgt_ops:
        if path.startswith("/ai/") and path not in allowed_ai:
            failures.append(f"OPENAPI_SECURITY_UNEXPECTED_AI_ROUTE {path}")

    for method, path in changed_keys:
        op = tgt_ops[(method, path)]
        is_protected = any(path == p or path.startswith(p) for p in protected_prefixes)
        if not is_protected:
            continue
        inv_entry = route_map.get((method, path))
        if not _has_auth(inv_entry):
            failures.append(f"OPENAPI_SECURITY_AUTH_REQUIRED {method.upper()} {path}")
        if not _tenant_bound(inv_entry):
            failures.append(f"OPENAPI_SECURITY_TENANT_REQUIRED {method.upper()} {path}")

        key = f"{method.upper()} {path}"
        if not _responses_401_403(op) and key not in waived:
            failures.append(f"OPENAPI_SECURITY_401_403_REQUIRED {key}")

        if _is_extension_route(path):
            r = op.get("responses") if isinstance(op.get("responses"), dict) else {}
            has_4xx = any(str(code).startswith("4") for code in r.keys())
            if has_4xx:
                raw = json.dumps(op, sort_keys=True)
                if "error_code" not in raw:
                    failures.append(f"OPENAPI_SECURITY_ERROR_CODE_REQUIRED {key}")

    if failures:
        print("openapi security diff: FAILED")
        print(f"checked_changed_ops={len(changed_keys)} violations={len(failures)}")
        for f in sorted(failures):
            print(f" - {f}")
        return 1

    print("openapi security diff: OK")
    print(f"checked_changed_ops={len(changed_keys)} violations=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
