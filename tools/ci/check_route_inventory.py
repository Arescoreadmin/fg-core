#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.ci.route_checks import iter_route_records, is_public_path

INVENTORY = REPO / "tools/ci/route_inventory.json"
TRI_UNKNOWN = "unknown"
PROTECTED_UNKNOWN_PREFIXES = (
    "/decisions",
    "/feed",
    "/governance",
)


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
    if is_public_path(rec.full_path):
        return False
    if rec.route_has_any_dependency:
        return TRI_UNKNOWN
    return False


def current_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for rec in iter_route_records(REPO / "api"):
        rows.append(
            {
                "method": rec.method,
                "path": rec.full_path,
                "file": rec.file_path.relative_to(REPO).as_posix(),
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


def _validate_inventory(expected: list[dict[str, object]], cur: list[dict[str, object]]) -> tuple[list[str], list[str]]:
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
            if _is_protected_path(path) and method != "HEAD":
                failures.append(
                    f"{key} has unknown scoped/tenant_bound on protected path {path}"
                )

    if current_unknown > expected_unknown:
        warnings.append(
            f"unknown route classification count increased: {expected_unknown} -> {current_unknown}"
        )

    return failures, warnings


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
