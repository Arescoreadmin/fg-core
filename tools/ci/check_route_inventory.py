from __future__ import annotations

import argparse
import hashlib
import json
import os
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
TOOL_NAME = "tools/ci/check_route_inventory.py"
CI_ENV = os.getenv("CI", "").strip().lower() in {"1", "true", "yes"}


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _stable_json_bytes(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _dump_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _v1_wrap(data: object, *, generated_by: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "data": data,
    }
    if generated_by:
        out["generated_by"] = generated_by
    return out


def _read_data(path: Path | str, label: str) -> object:
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"{label} must be valid JSON: {e}") from e


def _is_v1_wrapper(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and {"schema_version", "generated_at", "data"} <= set(obj.keys())
        and isinstance(obj.get("schema_version"), str)
        and bool(obj.get("schema_version"))
    )


def _unwrap_v1(obj: object) -> object:
    return obj["data"] if _is_v1_wrapper(obj) else obj


def _require_list_of_dicts(value: object, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{i}] must be an object")
        out.append(item)
    return out


def _inventory_from_doc(doc: object) -> list[dict[str, Any]]:
    payload = _unwrap_v1(doc)

    if isinstance(payload, dict) and "routes" in payload:
        return _require_list_of_dicts(
            payload.get("routes"), label="route_inventory.data.routes"
        )
    if isinstance(payload, dict) and "items" in payload:
        return _require_list_of_dicts(
            payload.get("items"), label="route_inventory.data.items"
        )

    if isinstance(doc, dict) and "routes" in doc:
        return _require_list_of_dicts(doc.get("routes"), label="route_inventory.routes")
    if isinstance(doc, dict) and "items" in doc:
        return _require_list_of_dicts(doc.get("items"), label="route_inventory.items")

    return _require_list_of_dicts(payload, label="route_inventory.data")


def _inventory_from_data(data: object) -> list[dict[str, Any]]:
    """
    Backwards-compatibility shim for older tests and tooling that still patch or
    call _inventory_from_data() directly.
    """
    return _inventory_from_doc(data)


def _key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(entry.get("method", "")),
        str(entry.get("path", "")),
        str(entry.get("file", "")),
    )


def _route_diff(
    expected: list[dict[str, Any]], cur: list[dict[str, Any]]
) -> tuple[list[str], list[str], list[str]]:
    expected_map = {_key(e): e for e in expected}
    cur_map = {_key(e): e for e in cur}
    missing = sorted(set(expected_map) - set(cur_map))
    added = sorted(set(cur_map) - set(expected_map))

    changed: list[str] = []
    tracked = (
        "scoped",
        "tenant_bound",
        "scopes",
        "plane_id",
        "plane",
        "dependency_categories",
    )
    for k in sorted(set(expected_map) & set(cur_map)):
        before = expected_map[k]
        after = cur_map[k]
        for field in tracked:
            if before.get(field) != after.get(field):
                changed.append(
                    f"{k} changed {field}: {before.get(field)} -> {after.get(field)}"
                )

    return [str(x) for x in missing], [str(x) for x in added], changed


def current_inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for route in runtime_routes_ast():
        path = str(route.get("path", ""))
        planes = match_plane(path)

        plane_id = "unmapped"
        if isinstance(planes, list) and len(planes) == 1:
            plane_id = str(planes[0])

        rows.append({**route, "plane_id": plane_id, "plane": plane_id})

    return sorted(
        rows,
        key=lambda r: (
            str(r.get("path", "")),
            str(r.get("method", "")),
            str(r.get("file", "")),
        ),
    )


def _registry_snapshot_doc() -> str:
    planes = [p.to_dict() for p in sorted(PLANE_REGISTRY, key=lambda x: x.plane_id)]
    return _dump_json(_v1_wrap(planes, generated_by=TOOL_NAME))


def _contract_routes_list() -> list[dict[str, Any]]:
    return _require_list_of_dicts(contract_routes(), label="contract_routes()")


def _contract_routes_doc() -> str:
    return _dump_json(_v1_wrap(_contract_routes_list(), generated_by=TOOL_NAME))


def _build_meta_doc(cur: list[dict[str, Any]]) -> str:
    git_sha = "unknown"
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
    except Exception:
        pass

    runner = "unknown"
    hn = Path("/proc/sys/kernel/hostname")
    if hn.exists():
        try:
            runner = hn.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    meta = {
        "git_sha": git_sha,
        "build_timestamp_utc": _now_iso(),
        "ci_runner_id": runner,
        "tool": TOOL_NAME,
        "tool_version": SCHEMA_VERSION,
        "inventory_sha256": _sha256_bytes(_stable_json_bytes(cur)),
    }

    return _dump_json(_v1_wrap([meta], generated_by=TOOL_NAME))


def _inventory_doc(cur: list[dict[str, Any]]) -> str:
    return _dump_json(_v1_wrap(cur, generated_by=TOOL_NAME))


def _summary_payload(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> dict[str, Any]:
    contract_list = _contract_routes_list()

    runtime_keys = {(str(r.get("method")), str(r.get("path"))) for r in cur}
    contract_keys = {(str(r.get("method")), str(r.get("path"))) for r in contract_list}

    removed: list[str] = []
    added: list[str] = []
    changed: list[str] = []
    if expected is not None:
        removed, added, changed = _route_diff(expected, cur)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": TOOL_NAME,
        "generated_at": _now_iso(),
        "plane_coverage": plane_coverage_summary(cur),
        "runtime_count": len(cur),
        "contract_count": len(contract_list),
        "runtime_only": sorted(f"{m} {p}" for (m, p) in (runtime_keys - contract_keys)),
        "contract_only": sorted(
            f"{m} {p}" for (m, p) in (contract_keys - runtime_keys)
        ),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_registry_snapshot() -> None:
    blob = _registry_snapshot_doc()
    _write_text(REGISTRY_SNAPSHOT, blob)
    digest = _sha256_bytes(blob.encode("utf-8"))
    _write_text(REGISTRY_HASH, f"{digest}  {REGISTRY_SNAPSHOT.name}\n")


def _write_contract_routes() -> None:
    _write_text(CONTRACT_ROUTES, _contract_routes_doc())


def _write_build_meta(cur: list[dict[str, Any]]) -> None:
    _write_text(BUILD_META, _build_meta_doc(cur))


def _write_attestation_bundle(cur: list[dict[str, Any]]) -> None:
    _write_contract_routes()
    _write_build_meta(cur)

    bundle_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES, BUILD_META]
    lines = [f"{_sha256(f)}  {f.name}" for f in bundle_files]
    _write_text(BUNDLE_HASH, "\n".join(lines) + "\n")


def _write_topology_hash() -> None:
    topology_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES]
    lines = [f"{_sha256(f)}  {f.name}" for f in topology_files]
    _write_text(TOPOLOGY_HASH, "\n".join(lines) + "\n")


def _write_summary(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> None:
    _write_text(SUMMARY, _dump_json(_summary_payload(cur, expected)))


def write_inventory() -> None:
    cur = current_inventory()
    _write_text(INVENTORY, _inventory_doc(cur))
    _write_summary(cur, expected=None)
    _write_registry_snapshot()
    _write_attestation_bundle(cur)
    _write_topology_hash()


def verify_inventory() -> int:
    cur = current_inventory()

    if not INVENTORY.exists():
        print(f"route inventory missing: {INVENTORY.relative_to(REPO)}")
        return 1

    expected_doc = _read_data(INVENTORY, "route_inventory")
    expected = _inventory_from_doc(expected_doc)

    removed, added, changed = _route_diff(expected, cur)
    summary = _summary_payload(cur, expected)

    failures: list[str] = []
    if removed:
        failures.append(f"routes removed from inventory: {removed}")
    if added:
        failures.append(f"routes added to inventory: {added}")
    if changed:
        failures.extend(changed)

    runtime_only = summary.get("runtime_only", [])
    contract_only = summary.get("contract_only", [])

    if runtime_only:
        print(
            "route inventory: WARNING runtime vs contract drift (runtime_only): "
            f"{runtime_only}"
        )
    if contract_only:
        failures.append(f"runtime vs contract drift (contract_only): {contract_only}")

    if failures:
        print("route inventory: FAILED")
        for item in failures:
            print(f" - {item}")
        print(" - regenerate inventory with: make route-inventory-generate")
        return 1

    print("route inventory: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate or regenerate FrostGate route inventory artifacts."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write route_inventory + governance snapshots",
    )
    args = parser.parse_args()

    if args.write:
        if CI_ENV:
            print("route inventory: write suppressed in CI")
            print(" - refusing to mutate tracked inventory artifacts when CI is set")
            print(" - run locally without CI=true: make route-inventory-generate")
            return 0
        write_inventory()
        print(f"route inventory: wrote {INVENTORY.relative_to(REPO)}")
        return 0

    return verify_inventory()


if __name__ == "__main__":
    raise SystemExit(main())
