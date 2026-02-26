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
TOOL_NAME = "tools/ci/check_route_inventory.py"


# -----------------------------
# small, boring, correct utils
# -----------------------------
def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_json_bytes(obj: object) -> bytes:
    # Deterministic bytes (for hashing), independent of pretty formatting
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _dump_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _v1_wrap(data: object, *, generated_by: str | None = None) -> dict[str, Any]:
    """
    Canonical wrapper expected by generate_platform_inventory.py:

      {
        "schema_version": "v1",
        "generated_at": "...",
        "data": <payload>,
        "generated_by": "..."
      }
    """
    out: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "data": data,
    }
    if generated_by:
        out["generated_by"] = generated_by
    return out


def _read_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
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
        raise ValueError(f"{label}.data must be a list")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}.data[{i}] must be an object")
        out.append(item)
    return out


def _inventory_from_doc(doc: object) -> list[dict[str, Any]]:
    """
    Accepts:
      - v1 wrapper: {schema_version, generated_at, data:[{...}]}
      - legacy: {routes:[{...}]}
      - legacy: {items:[{...}]}
      - legacy: [{...}]
    """
    if isinstance(doc, dict) and "routes" in doc:
        return _require_list_of_dicts(doc.get("routes"), label="route_inventory")
    if isinstance(doc, dict) and "items" in doc:
        return _require_list_of_dicts(doc.get("items"), label="route_inventory")

    payload = _unwrap_v1(doc)

    if isinstance(payload, dict) and "routes" in payload:
        return _require_list_of_dicts(payload.get("routes"), label="route_inventory")
    if isinstance(payload, dict) and "items" in payload:
        return _require_list_of_dicts(payload.get("items"), label="route_inventory")

    return _require_list_of_dicts(payload, label="route_inventory")


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


def _as_list_of_dicts(value: object, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{i}] must be an object")
        out.append(item)
    return out


# -----------------------------
# inventory building
# -----------------------------
def current_inventory() -> list[dict[str, Any]]:
    """
    IMPORTANT:
    - Emit BOTH `plane_id` (canonical) and `plane` (compat alias).
    - The platform inventory generator must be able to trust `plane_id` stamps.
    """
    rows: list[dict[str, Any]] = []
    for route in runtime_routes_ast():
        path = str(route.get("path", ""))
        planes = match_plane(path)

        plane_id = "unmapped"
        if isinstance(planes, list) and len(planes) == 1:
            try:
                plane_id = str(planes[0])
            except Exception:
                plane_id = "unmapped"

        rows.append({**route, "plane_id": plane_id, "plane": plane_id})

    return sorted(
        rows,
        key=lambda r: (
            str(r.get("path", "")),
            str(r.get("method", "")),
            str(r.get("file", "")),
        ),
    )


# -----------------------------
# artifact writers
# -----------------------------
def _write_registry_snapshot() -> None:
    planes = [p.to_dict() for p in sorted(PLANE_REGISTRY, key=lambda x: x.plane_id)]
    # data MUST be a list (of plane dicts)
    blob = _dump_json(_v1_wrap(planes, generated_by=TOOL_NAME))
    REGISTRY_SNAPSHOT.write_text(blob, encoding="utf-8")

    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    REGISTRY_HASH.write_text(f"{digest}  {REGISTRY_SNAPSHOT.name}\n", encoding="utf-8")


def _write_contract_routes() -> list[dict[str, Any]]:
    cr = contract_routes()
    cr_list = _as_list_of_dicts(cr, label="contract_routes()")
    CONTRACT_ROUTES.write_text(
        _dump_json(_v1_wrap(cr_list, generated_by=TOOL_NAME)), encoding="utf-8"
    )
    return cr_list


def _write_build_meta(cur: list[dict[str, Any]]) -> None:
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
        # Deterministic hash for the inventory payload list
        "inventory_sha256": hashlib.sha256(_stable_json_bytes(cur)).hexdigest(),
    }

    # build_meta MUST be v1 wrapper with data: [meta]
    BUILD_META.write_text(
        _dump_json(_v1_wrap([meta], generated_by=TOOL_NAME)), encoding="utf-8"
    )


def _write_attestation_bundle(cur: list[dict[str, Any]]) -> None:
    # Ensure dependent artifacts exist and are current
    _write_contract_routes()
    _write_build_meta(cur)

    bundle_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES, BUILD_META]
    lines = [f"{_sha256(f)}  {f.name}" for f in bundle_files]
    BUNDLE_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_topology_hash() -> None:
    topology_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES]
    lines = [f"{_sha256(f)}  {f.name}" for f in topology_files]
    TOPOLOGY_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_summary(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> None:
    contract = contract_routes()
    contract_list = _as_list_of_dicts(contract, label="contract_routes()")

    runtime_keys = {(str(r.get("method")), str(r.get("path"))) for r in cur}
    contract_keys = {(str(r.get("method")), str(r.get("path"))) for r in contract_list}

    removed: list[str] = []
    added: list[str] = []
    changed: list[str] = []
    if expected is not None:
        removed, added, changed = _route_diff(expected, cur)

    summary = {
        "plane_coverage": plane_coverage_summary(cur),
        "runtime_count": len(cur),
        "contract_count": len(contract_list),
        "runtime_only": sorted(
            [f"{m} {p}" for (m, p) in (runtime_keys - contract_keys)]
        ),
        "contract_only": sorted(
            [f"{m} {p}" for (m, p) in (contract_keys - runtime_keys)]
        ),
        "added": added,
        "removed": removed,
        "changed": changed,
    }

    # NOTE: summary is consumed by this tool and humans; platform inventory currently
    # only requires v1 wrappers for inventory/plane_registry/contract_routes/build_meta.
    SUMMARY.write_text(_dump_json(summary), encoding="utf-8")


def write_inventory() -> None:
    cur = current_inventory()

    # Inventory MUST be v1 wrapper with data as a LIST of route objects
    INVENTORY.write_text(
        _dump_json(_v1_wrap(cur, generated_by=TOOL_NAME)), encoding="utf-8"
    )

    _write_summary(cur, expected=None)
    _write_registry_snapshot()
    _write_attestation_bundle(cur)
    _write_topology_hash()


# -----------------------------
# main
# -----------------------------
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write route_inventory + governance snapshots",
    )
    args = parser.parse_args()

    cur = current_inventory()

    if args.write:
        write_inventory()
        print(f"route inventory: wrote {INVENTORY.relative_to(REPO)}")
        return 0

    if not INVENTORY.exists():
        print(f"route inventory missing: {INVENTORY.relative_to(REPO)}")
        return 1

    expected_doc = _read_json(INVENTORY, label="route_inventory")
    expected = _inventory_from_doc(expected_doc)

    removed, added, changed = _route_diff(expected, cur)

    _write_summary(cur, expected)
    _write_registry_snapshot()
    _write_attestation_bundle(cur)
    _write_topology_hash()

    failures: list[str] = []
    if removed:
        failures.append(f"routes removed from inventory: {removed}")
    if added:
        failures.append(f"routes added to inventory: {added}")
    if changed:
        failures.extend(changed)

    summary_payload = _read_json(SUMMARY, label="route_inventory_summary")
    summary = summary_payload if isinstance(summary_payload, dict) else {}

    if summary.get("runtime_only"):
        print(
            f"route inventory: WARNING runtime vs contract drift (runtime_only): {summary['runtime_only']}"
        )
    if summary.get("contract_only"):
        failures.append(
            f"runtime vs contract drift (contract_only): {summary['contract_only']}"
        )

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
