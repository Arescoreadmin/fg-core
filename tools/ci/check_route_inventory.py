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
SUMMARY = REPO / "artifacts" / "route_inventory_summary.json"
LEGACY_SUMMARY = REPO / "tools/ci/route_inventory_summary.json"
REGISTRY_SNAPSHOT = REPO / "tools/ci/plane_registry_snapshot.json"
REGISTRY_HASH = REPO / "tools/ci/plane_registry_snapshot.sha256"
CONTRACT_ROUTES = REPO / "tools/ci/contract_routes.json"
BUILD_META = REPO / "tools/ci/build_meta.json"
BUNDLE_HASH = REPO / "tools/ci/attestation_bundle.sha256"
TOPOLOGY_HASH = REPO / "tools/ci/topology.sha256"

ARTIFACT_REGISTRY_SNAPSHOT = REPO / "artifacts" / "plane_registry_snapshot.json"
ARTIFACT_REGISTRY_HASH = REPO / "artifacts" / "plane_registry_snapshot.sha256"
ARTIFACT_CONTRACT_ROUTES = REPO / "artifacts" / "contract_routes.json"
ARTIFACT_BUILD_META = REPO / "artifacts" / "build_meta.json"
ARTIFACT_BUNDLE_HASH = REPO / "artifacts" / "attestation_bundle.sha256"
ARTIFACT_TOPOLOGY_HASH = REPO / "artifacts" / "topology.sha256"

SCHEMA_VERSION = "v1"
TOOL_NAME = "tools/ci/check_route_inventory.py"


# -----------------------------
# small, boring, correct utils
# -----------------------------
def _ensure_artifact_dirs() -> None:
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_REGISTRY_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_REGISTRY_HASH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_CONTRACT_ROUTES.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_BUILD_META.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_BUNDLE_HASH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_TOPOLOGY_HASH.parent.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_json_bytes(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _dump_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write_text_if_changed(path: Path, text: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else None
    if existing == text:
        return False
    path.write_text(text, encoding="utf-8")
    return True


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


def _read_json(path: Path, *, label: str) -> object:
    return _read_data(path, label)


def _is_v1_wrapper(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and {"schema_version", "generated_at", "data"} <= set(obj.keys())
        and isinstance(obj.get("schema_version"), str)
        and bool(obj.get("schema_version"))
    )


def _unwrap_v1(obj: object) -> object:
    if _is_v1_wrapper(obj):
        assert isinstance(obj, dict)
        return obj["data"]
    return obj


def _write_wrapped_json_if_data_changed(
    path: Path,
    data: object,
    *,
    generated_by: str | None = None,
) -> bool:
    """
    Write wrapped tracked JSON only if logical payload changed.
    Prevents timestamp-only churn in tracked files.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            existing_data = _unwrap_v1(existing)
            if existing_data == data:
                return False
        except Exception:
            pass

    blob = _dump_json(_v1_wrap(data, generated_by=generated_by))
    path.write_text(blob, encoding="utf-8")
    return True


def _require_list_of_dicts(value: object, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label}.data must be a list")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}.data[{i}] must be an object")
        out.append(item)
    return out


def _inventory_from_data(data: object) -> list[dict[str, Any]]:
    return _inventory_from_doc(data)


def _inventory_from_doc(doc: object) -> list[dict[str, Any]]:
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
def _plane_id_for_path(path: str) -> str:
    planes = match_plane(path)
    if isinstance(planes, list) and len(planes) == 1:
        try:
            return str(planes[0])
        except Exception:
            return "unmapped"
    return "unmapped"


def current_inventory() -> list[dict[str, Any]]:
    """
    IMPORTANT:
    - Canonical route inventory is derived from AST (deterministic).
    - Emit BOTH `plane_id` (canonical) and `plane` (compat alias).
    """
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


# -----------------------------
# artifact writers
# -----------------------------
def _write_registry_snapshot_artifact() -> None:
    _ensure_artifact_dirs()
    planes = [p.to_dict() for p in sorted(PLANE_REGISTRY, key=lambda x: x.plane_id)]
    blob = _dump_json(_v1_wrap(planes, generated_by=TOOL_NAME))
    _write_text_if_changed(ARTIFACT_REGISTRY_SNAPSHOT, blob)
    digest = _sha256_bytes(blob.encode("utf-8"))
    _write_text_if_changed(
        ARTIFACT_REGISTRY_HASH,
        f"{digest}  {ARTIFACT_REGISTRY_SNAPSHOT.name}\n",
    )


def _write_contract_routes_artifact() -> list[dict[str, Any]]:
    cr = contract_routes()
    cr_list = _as_list_of_dicts(cr, label="contract_routes()")
    _write_text_if_changed(
        ARTIFACT_CONTRACT_ROUTES,
        _dump_json(_v1_wrap(cr_list, generated_by=TOOL_NAME)),
    )
    return cr_list


def _write_build_meta_artifact(cur: list[dict[str, Any]]) -> None:
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
        "inventory_sha256": hashlib.sha256(_stable_json_bytes(cur)).hexdigest(),
    }

    _write_text_if_changed(
        ARTIFACT_BUILD_META,
        _dump_json(_v1_wrap([meta], generated_by=TOOL_NAME)),
    )


def _write_attestation_bundle_artifact(cur: list[dict[str, Any]]) -> None:
    _write_contract_routes_artifact()
    _write_build_meta_artifact(cur)

    bundle_files = [
        ARTIFACT_REGISTRY_SNAPSHOT,
        INVENTORY,
        ARTIFACT_CONTRACT_ROUTES,
        ARTIFACT_BUILD_META,
    ]
    lines = [
        f"{_sha256(f)}  {f.name}" if f.exists() else f"MISSING  {f.name}"
        for f in bundle_files
    ]
    _write_text_if_changed(ARTIFACT_BUNDLE_HASH, "\n".join(lines) + "\n")


def _write_topology_hash_artifact() -> None:
    topology_files = [ARTIFACT_REGISTRY_SNAPSHOT, INVENTORY, ARTIFACT_CONTRACT_ROUTES]
    lines = [
        f"{_sha256(f)}  {f.name}" if f.exists() else f"MISSING  {f.name}"
        for f in topology_files
    ]
    _write_text_if_changed(ARTIFACT_TOPOLOGY_HASH, "\n".join(lines) + "\n")


def _summary_payload(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> dict[str, Any]:
    contract = contract_routes()
    contract_list = _as_list_of_dicts(contract, label="contract_routes()")

    runtime_keys = {(str(r.get("method")), str(r.get("path"))) for r in cur}
    contract_keys = {(str(r.get("method")), str(r.get("path"))) for r in contract_list}

    removed: list[str] = []
    added: list[str] = []
    changed: list[str] = []
    if expected is not None:
        removed, added, changed = _route_diff(expected, cur)

    return {
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


def _write_summary_artifact(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> None:
    _ensure_artifact_dirs()
    summary = _summary_payload(cur, expected)
    _write_text_if_changed(SUMMARY, _dump_json(summary))


def _write_summary_tracked(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> None:
    summary = _summary_payload(cur, expected)
    _write_text_if_changed(LEGACY_SUMMARY, _dump_json(summary))


def _write_registry_snapshot_tracked() -> bool:
    planes = [p.to_dict() for p in sorted(PLANE_REGISTRY, key=lambda x: x.plane_id)]
    changed = _write_wrapped_json_if_data_changed(
        REGISTRY_SNAPSHOT, planes, generated_by=TOOL_NAME
    )
    _write_text_if_changed(
        REGISTRY_HASH,
        f"{_sha256(REGISTRY_SNAPSHOT)}  {REGISTRY_SNAPSHOT.name}\n",
    )
    return changed


def _write_contract_routes_tracked() -> tuple[list[dict[str, Any]], bool]:
    cr = contract_routes()
    cr_list = _as_list_of_dicts(cr, label="contract_routes()")
    changed = _write_wrapped_json_if_data_changed(
        CONTRACT_ROUTES, cr_list, generated_by=TOOL_NAME
    )
    return cr_list, changed


def _write_build_meta_tracked(cur: list[dict[str, Any]]) -> None:
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
        "inventory_sha256": hashlib.sha256(_stable_json_bytes(cur)).hexdigest(),
    }

    _write_text_if_changed(
        BUILD_META,
        _dump_json(_v1_wrap([meta], generated_by=TOOL_NAME)),
    )


def _write_attestation_bundle_tracked() -> None:
    bundle_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES, BUILD_META]
    lines = [f"{_sha256(f)}  {f.name}" for f in bundle_files]
    _write_text_if_changed(BUNDLE_HASH, "\n".join(lines) + "\n")


def _write_topology_hash_tracked() -> None:
    topology_files = [REGISTRY_SNAPSHOT, INVENTORY, CONTRACT_ROUTES]
    lines = [f"{_sha256(f)}  {f.name}" for f in topology_files]
    _write_text_if_changed(TOPOLOGY_HASH, "\n".join(lines) + "\n")


def _write_artifacts_only(
    cur: list[dict[str, Any]], expected: list[dict[str, Any]] | None
) -> None:
    _write_summary_artifact(cur, expected)
    _write_registry_snapshot_artifact()
    _write_attestation_bundle_artifact(cur)
    _write_topology_hash_artifact()


def write_inventory() -> None:
    cur = current_inventory()

    inventory_changed = _write_wrapped_json_if_data_changed(
        INVENTORY, cur, generated_by=TOOL_NAME
    )
    _write_summary_tracked(cur, expected=None)
    registry_changed = _write_registry_snapshot_tracked()
    _, contract_changed = _write_contract_routes_tracked()

    # BUILD_META is intentionally volatile. Only rewrite it, and hashes that depend on it,
    # when logical tracked inputs actually changed.
    if (
        inventory_changed
        or registry_changed
        or contract_changed
        or not BUILD_META.exists()
    ):
        _write_build_meta_tracked(cur)
        _write_attestation_bundle_tracked()
        _write_topology_hash_tracked()

    # Always emit artifacts for CI/debugging.
    _write_artifacts_only(cur, expected=None)


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

    expected_doc = _read_data(INVENTORY, "route_inventory")
    expected = _inventory_from_data(expected_doc)

    removed, added, changed = _route_diff(expected, cur)

    _write_artifacts_only(cur, expected)

    failures: list[str] = []
    if removed:
        failures.append(f"routes removed from inventory: {removed}")
    if added:
        failures.append(f"routes added to inventory: {added}")
    if changed:
        failures.extend(changed)

    summary_payload = _read_data(SUMMARY, "route_inventory_summary")
    summary = summary_payload if isinstance(summary_payload, dict) else {}

    if summary.get("runtime_only"):
        print(
            "route inventory: WARNING runtime vs contract drift (runtime_only): "
            f"{summary['runtime_only']}"
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
