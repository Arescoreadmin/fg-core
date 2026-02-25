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


def _dump_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _wrap(data: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "data": data,
    }


def _read_data(path: Path, *, label: str) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"{label}.schema_version expected {SCHEMA_VERSION}, got {payload.get('schema_version')}"
        )
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError(f"{label}.data must be a list")
    if not all(isinstance(item, dict) for item in data):
        raise ValueError(f"{label}.data entries must be objects")
    return data


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
    blob = _dump_json(_wrap(payload))
    REGISTRY_SNAPSHOT.write_text(blob, encoding="utf-8")
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    REGISTRY_HASH.write_text(f"{digest}  {REGISTRY_SNAPSHOT.name}\n", encoding="utf-8")


def _write_attestation_bundle(cur: list[dict[str, object]]) -> None:
    contract = contract_routes()
    CONTRACT_ROUTES.write_text(_dump_json(_wrap(contract)), encoding="utf-8")

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
    BUILD_META.write_text(_dump_json(_wrap([meta])), encoding="utf-8")

    bundle_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES, BUILD_META]
    lines = [f"{_sha256(f)}  {f.name}" for f in bundle_files]
    BUNDLE_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_topology_hash() -> None:
    topology_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES]
    lines = [f"{_sha256(f)}  {f.name}" for f in topology_files]
    TOPOLOGY_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_inventory() -> None:
    cur = current_inventory()
    INVENTORY.write_text(_dump_json(_wrap(cur)), encoding="utf-8")
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
    SUMMARY.write_text(_dump_json(_wrap([summary])), encoding="utf-8")


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

    expected = _read_data(INVENTORY, label="route_inventory")
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
    summary = summary_payload[0] if summary_payload else {}
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
