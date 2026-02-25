from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from services.plane_registry import PLANE_REGISTRY
from tools.ci.plane_registry_checks import (
    contract_routes,
    match_plane,
    plane_coverage_summary,
    runtime_routes_ast,
)

REPO = Path(__file__).resolve().parents[2]
INVENTORY = REPO / "tools/ci/route_inventory.json"
SUMMARY = REPO / "tools/ci/route_inventory_summary.json"
REGISTRY_SNAPSHOT = REPO / "tools/ci/plane_registry_snapshot.json"
REGISTRY_HASH = REPO / "tools/ci/plane_registry_snapshot.sha256"
CONTRACT_ROUTES = REPO / "tools/ci/contract_routes.json"
BUILD_META = REPO / "tools/ci/build_meta.json"
BUNDLE_HASH = REPO / "tools/ci/attestation_bundle.sha256"
TOPOLOGY_HASH = REPO / "tools/ci/topology.sha256"
SCHEMA_VERSION = "v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dump_json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _wrap(routes: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_by": "tools/ci/check_route_inventory.py",
        "routes": routes,
    }


def _read_data(path: Path, *, label: str) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be an object")
    return data


def _inventory_from_data(data: dict[str, object]) -> list[dict[str, object]]:
    routes = data.get("routes")
    if routes is None and isinstance(data.get("items"), list):
        routes = data.get("items")
    if not isinstance(routes, list):
        raise ValueError("route_inventory.routes must be an array")
    for idx, item in enumerate(routes):
        if not isinstance(item, dict):
            raise ValueError(f"route_inventory.routes[{idx}] must be an object")
    return routes


def _inventory_payload(routes: list[dict[str, object]]) -> dict[str, object]:
    return _wrap(routes)


def current_inventory() -> list[dict[str, object]]:
    rows = []
    for route in runtime_routes_ast():
        planes = match_plane(str(route["path"]))
        rows.append({**route, "plane_id": planes[0] if len(planes) == 1 else "unmapped"})
    return sorted(rows, key=lambda r: (str(r["path"]), str(r["method"]), str(r["file"])))


def _key(entry: dict[str, object]) -> tuple[str, str, str]:
    return (str(entry["method"]), str(entry["path"]), str(entry.get("file", "")))


def _route_diff(expected: list[dict[str, object]], cur: list[dict[str, object]]) -> tuple[list[str], list[str], list[str]]:
    expected_map = {_key(e): e for e in expected}
    cur_map = {_key(e): e for e in cur}
    missing = sorted(set(expected_map) - set(cur_map))
    added = sorted(set(cur_map) - set(expected_map))

    changed: list[str] = []
    for key in sorted(set(expected_map) & set(cur_map)):
        before = expected_map[key]
        after = cur_map[key]
        tracked = ("scoped", "tenant_bound", "scopes", "plane_id", "dependency_categories")
        for field in tracked:
            if before.get(field) != after.get(field):
                changed.append(f"{key} changed {field}: {before.get(field)} -> {after.get(field)}")
    return [str(x) for x in missing], [str(x) for x in added], changed


def _write_registry_snapshot() -> None:
    payload = [p.to_dict() for p in sorted(PLANE_REGISTRY, key=lambda x: x.plane_id)]
    blob = _dump_json(payload)
    REGISTRY_SNAPSHOT.write_text(blob, encoding="utf-8")
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    REGISTRY_HASH.write_text(f"{digest}  {REGISTRY_SNAPSHOT.name}\n", encoding="utf-8")


def _write_attestation_bundle(cur: list[dict[str, object]]) -> None:
    contract = contract_routes()
    CONTRACT_ROUTES.write_text(_dump_json(contract), encoding="utf-8")

    git_sha = "unknown"
    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    except Exception:
        pass

    meta = {
        "git_sha": git_sha,
        "build_timestamp_utc": datetime.now(tz=UTC).isoformat(),
        "ci_runner_id": (
            Path("/proc/sys/kernel/hostname").read_text(encoding="utf-8").strip()
            if Path("/proc/sys/kernel/hostname").exists()
            else "unknown"
        ),
        "tool": "tools/ci/check_route_inventory.py",
        "tool_version": SCHEMA_VERSION,
        "inventory_sha256": hashlib.sha256(json.dumps(cur, sort_keys=True).encode("utf-8")).hexdigest(),
    }
    BUILD_META.write_text(_dump_json(meta), encoding="utf-8")

    bundle_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES, BUILD_META]
    lines = [f"{_sha256(f)}  {f.name}" for f in bundle_files]
    BUNDLE_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_topology_hash() -> None:
    topology_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES]
    lines = [f"{_sha256(f)}  {f.name}" for f in topology_files]
    TOPOLOGY_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_inventory() -> None:
    cur = current_inventory()
    INVENTORY.write_text(_dump_json(_inventory_payload(cur)), encoding="utf-8")
    _write_summary(cur, expected=None)
    _write_registry_snapshot()
    _write_attestation_bundle(cur)
    _write_topology_hash()


def _write_summary(cur: list[dict[str, object]], expected: list[dict[str, object]] | None) -> None:
    contract = contract_routes()
    runtime_keys = {(r["method"], r["path"]) for r in cur}
    contract_keys = {(r["method"], r["path"]) for r in contract}
    missing, added, changed = ([], [], [])
    if expected is not None:
        missing, added, changed = _route_diff(expected, cur)
    summary = {
        "plane_coverage": plane_coverage_summary(cur),
        "runtime_count": len(cur),
        "contract_count": len(contract),
        "runtime_only": sorted([f"{m} {p}" for m, p in (runtime_keys - contract_keys)]),
        "contract_only": sorted([f"{m} {p}" for m, p in (contract_keys - runtime_keys)]),
        "added": added,
        "removed": missing,
        "changed": changed,
    }
    SUMMARY.write_text(_dump_json(summary), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    cur = current_inventory()
    if args.write:
        write_inventory()
        print(f"route inventory: wrote {INVENTORY.relative_to(REPO)}")
        return 0

    if not INVENTORY.exists():
        print(f"route inventory missing: {INVENTORY.relative_to(REPO)}")
        return 1

    expected_data = _read_data(INVENTORY, label="route_inventory")
    expected = _inventory_from_data(expected_data)
    missing, added, changed = _route_diff(expected, cur)
    _write_summary(cur, expected)
    _write_registry_snapshot()
    _write_attestation_bundle(cur)
    _write_topology_hash()

    failures: list[str] = []
    if missing:
        failures.append(f"routes removed from inventory: {missing}")
    if added:
        failures.append(f"routes added to inventory: {added}")
    if changed:
        failures.extend(changed)

    summary_payload = _read_data(SUMMARY, label="route_inventory_summary")
    summary = summary_payload if summary_payload else {}
    if summary.get("runtime_only"):
        print(f"route inventory: WARNING runtime vs contract drift (runtime_only): {summary['runtime_only']}")
    if summary.get("contract_only"):
        failures.append(f"runtime vs contract drift (contract_only): {summary['contract_only']}")

    if failures:
        print("route inventory: FAILED")
        for item in failures:
            print(f" - {item}")
        print(" - regenerate inventory with: make route-inventory-generate")
        return 1

    print("route inventory: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
