from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.ci.route_checks import iter_route_records, is_public_path

REPO = Path(__file__).resolve().parents[2]
INVENTORY = REPO / "tools/ci/route_inventory.json"

TRI_UNKNOWN = "unknown"
PROTECTED_UNKNOWN_PREFIXES = (
    "/decisions",
    "/feed",
    "/governance",
)

# Anything under these prefixes is treated as "not production API" and excluded
# from route inventory/security contract enforcement.
EXCLUDED_FILE_PREFIXES = ("api/_scratch/",)


def _scoped_state(rec) -> bool | str:
    if rec.route_has_scope_dependency:
        return True
    if is_public_path(rec.full_path):
        return False
    if rec.route_has_any_dependency:
        return TRI_UNKNOWN
    return False


def _tenant_state(rec) -> bool | str:
    if rec.tenant_bound:
        return True
    if getattr(rec, "tenant_explicit_unbound", False):
        return False
    if is_public_path(rec.full_path):
        return False
    if rec.route_has_any_dependency:
        return TRI_UNKNOWN
    return False


def _should_exclude_file(rel_path: str) -> bool:
    rel_path = rel_path.replace("\\", "/")
    return any(rel_path.startswith(prefix) for prefix in EXCLUDED_FILE_PREFIXES)


def current_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for rec in iter_route_records(REPO / "api"):
        rel = rec.file_path.relative_to(REPO).as_posix()

        # Exclude non-prod scratch space from security inventory.
        if _should_exclude_file(rel):
            continue

        rows.append(
            {
                "method": rec.method,
                "path": rec.full_path,
                "file": rel,
                "scoped": _scoped_state(rec),
                "scopes": list(rec.route_scopes),
                "tenant_bound": _tenant_state(rec),
            }
        )
    return sorted(
        rows,
        key=lambda r: (
            str(r["path"]),
            str(r["method"]),
            str(r["file"]),
            str(r["scoped"]),
            str(r["tenant_bound"]),
            ",".join(r["scopes"]),
        ),
    )


def write_inventory() -> None:
    INVENTORY.write_text(
        json.dumps(current_inventory(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _key(entry: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(entry["method"]),
        str(entry["path"]),
        str(entry["file"]),
    )


def _is_unknown(value: object) -> bool:
    return str(value).lower() == TRI_UNKNOWN


def _is_protected_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PROTECTED_UNKNOWN_PREFIXES)


def _validate_inventory(
    expected: list[dict[str, object]], cur: list[dict[str, object]]
) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []

    expected_map = {_key(item): item for item in expected}
    cur_map = {_key(item): item for item in cur}

    missing = sorted(set(expected_map) - set(cur_map))
    added = sorted(set(cur_map) - set(expected_map))
    if missing:
        failures.append(f"routes removed from inventory: {missing}")
    if added:
        failures.append(f"routes added to inventory: {added}")

    expected_unknown = 0
    current_unknown = 0
    unknown_routes: list[tuple[str, str, str]] = []

    for key in sorted(set(expected_map) & set(cur_map)):
        before = expected_map[key]
        after = cur_map[key]

        before_scoped = before.get("scoped")
        after_scoped = after.get("scoped")
        before_tenant = before.get("tenant_bound")
        after_tenant = after.get("tenant_bound")
        path = str(after.get("path", ""))
        method = str(after.get("method", "")).upper()

        if before_scoped is True and after_scoped is False:
            failures.append(f"{key} scoped regressed true->false")
        if before_tenant is True and after_tenant is False:
            failures.append(f"{key} tenant_bound regressed true->false")

        if _is_unknown(before_scoped) or _is_unknown(before_tenant):
            expected_unknown += 1
        if _is_unknown(after_scoped) or _is_unknown(after_tenant):
            current_unknown += 1
            unknown_routes.append((method, path, str(after.get("file", ""))))
            if _is_protected_path(path) and method != "HEAD":
                failures.append(
                    f"{key} has unknown scoped/tenant_bound on protected path {path}"
                )

    if current_unknown != 0:
        failures.append(
            f"unknown route classification count must be zero: {current_unknown}"
        )
        failures.append("unknown route entries (METHOD PATH (file)):")
        for method, path, file_path in unknown_routes:
            failures.append(f"  {method} {path} ({file_path})")
        failures.append("regenerate inventory with: make route-inventory-generate")
    elif expected_unknown != 0:
        warnings.append(
            f"unknown route classification improved: {expected_unknown} -> {current_unknown}"
        )

    return failures, warnings


def _validate_ai_plane_routes(
    cur: list[dict[str, object]], failures: list[str]
) -> None:
    # Only validate /ai/* endpoints that are part of the inventory scan.
    ai_routes = [r for r in cur if str(r.get("path", "")).startswith("/ai/")]
    expected_key = ("POST", "/ai/infer")

    found_expected = False
    for r in ai_routes:
        method = str(r.get("method", "")).upper()
        path = str(r.get("path", ""))
        if (method, path) == expected_key:
            found_expected = True
            if r.get("scoped") is not True:
                failures.append("/ai/infer must be scope-protected")
            if r.get("tenant_bound") is not True:
                failures.append("/ai/infer must be tenant-bound")
            scopes = set(str(x) for x in (r.get("scopes") or []))
            if "compliance:read" not in scopes:
                failures.append("/ai/infer must require compliance:read scope")
        else:
            failures.append(f"unexpected /ai/* route present: {method} {path}")

    if not found_expected:
        failures.append("missing required AI route: POST /ai/infer")

    main_py = (REPO / "api/main.py").read_text(encoding="utf-8")
    if "ai_plane_enabled()" not in main_py:
        failures.append("AI route mounting must be gated by FG_AI_PLANE_ENABLED")


def main() -> int:
    parser = argparse.ArgumentParser(description="Route inventory check/generator")
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate tools/ci/route_inventory.json",
    )
    args = parser.parse_args()

    if args.write:
        write_inventory()
        print(f"route inventory: wrote {INVENTORY.relative_to(REPO)}")
        return 0

    cur = current_inventory()
    if not INVENTORY.exists():
        print(f"route inventory missing: {INVENTORY.relative_to(REPO)}")
        return 1

    expected = json.loads(INVENTORY.read_text(encoding="utf-8"))
    failures, warnings = _validate_inventory(expected, cur)
    _validate_ai_plane_routes(cur, failures)

    if failures:
        print("route inventory: FAILED")
        for item in failures:
            print(f" - {item}")
        return 1

    for item in warnings:
        print(f"route inventory: WARNING - {item}")

    print("route inventory: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
