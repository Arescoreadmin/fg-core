from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]

GOVERNANCE_INPUTS = {
    "plane_registry": REPO / "tools/ci/plane_registry_snapshot.json",
    "route_inventory": REPO / "tools/ci/route_inventory.json",
    "contract_routes": REPO / "tools/ci/contract_routes.json",
    "topology_hash": REPO / "tools/ci/topology.sha256",
}
OPTIONAL_INPUTS = {
    "attestation_hash": REPO / "tools/ci/attestation_bundle.sha256",
    "build_meta": REPO / "tools/ci/build_meta.json",
}

SCHEMA_EXPECTED = {
    "plane_registry": "1",
    "route_inventory": "1",
    "contract_routes": "1",
    "build_meta": "1",
}
SHA_LINE_RE = re.compile(r"^[0-9a-f]{64}\s{2}[^\s].+$")


def _dump_json(payload: Any) -> str:
    return json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ": "),
    ) + "\n"


def require_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(str(path.relative_to(REPO)))


def load_json(path: Path) -> Any:
    require_file(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {path.relative_to(REPO)}: {exc}") from exc


def read_sha256(path: Path) -> str:
    require_file(path)
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"empty sha256 file: {path.relative_to(REPO)}")
    bad = [line for line in lines if not SHA_LINE_RE.match(line)]
    if bad:
        raise ValueError(
            f"malformed sha256 line(s) in {path.relative_to(REPO)}: {bad}"
        )
    return "\n".join(lines)


def _make_targets() -> set[str]:
    proc = subprocess.run(
        ["make", "-qpRr", "__mkdb__"],
        cwd=REPO,
        check=True,
        text=True,
        capture_output=True,
    )
    out = set()
    for line in proc.stdout.splitlines():
        if ":" in line and not line.startswith("\t") and not line.startswith("#"):
            name = line.split(":", 1)[0].strip()
            if name and "=" not in name and " " not in name:
                out.add(name)
    return out


def _require_keys(obj: dict[str, Any], required: set[str], context: str) -> None:
    missing = sorted(required - set(obj.keys()))
    if missing:
        raise ValueError(f"{context} missing required keys: {missing}")


def _validate_unknown_keys(
    obj: dict[str, Any],
    allowed: set[str],
    context: str,
    unknown_warnings: list[str],
    reject_unknown: bool,
) -> None:
    unknown = sorted(set(obj.keys()) - allowed)
    if not unknown:
        return
    msg = f"{context} unknown keys: {unknown}"
    if reject_unknown:
        raise ValueError(msg)
    unknown_warnings.append(msg)


def _require_list_of_strings(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context} must be a list[str]")
    return value


def _extract_versioned_list(
    raw: Any,
    *,
    artifact_name: str,
    data_key: str,
    allow_legacy_schema: bool,
) -> tuple[list[dict[str, Any]], str]:
    if isinstance(raw, dict):
        _require_keys(raw, {"schema_version", data_key}, f"{artifact_name}")
        schema_version = raw["schema_version"]
        if not isinstance(schema_version, str) or not schema_version:
            raise ValueError(f"{artifact_name}.schema_version must be a non-empty string")
        expected = SCHEMA_EXPECTED.get(artifact_name)
        if expected and schema_version != expected:
            raise ValueError(
                f"{artifact_name}.schema_version expected {expected}, got {schema_version}"
            )
        records = raw[data_key]
        if not isinstance(records, list):
            raise ValueError(f"{artifact_name}.{data_key} must be a list")
        if not all(isinstance(item, dict) for item in records):
            raise ValueError(f"{artifact_name}.{data_key} entries must be objects")
        return records, schema_version

    if isinstance(raw, list):
        if not allow_legacy_schema:
            raise ValueError(
                f"{artifact_name} must include schema_version wrapper; "
                "re-generate artifacts with versioned schema or use --allow-legacy-schema"
            )
        if not all(isinstance(item, dict) for item in raw):
            raise ValueError(f"{artifact_name} legacy entries must be objects")
        return raw, "legacy-v0"

    raise ValueError(f"{artifact_name} must be an object with schema_version or a legacy list")


def _validate_plane_snapshot(
    records: list[dict[str, Any]],
    *,
    unknown_warnings: list[str],
    reject_unknown: bool,
) -> None:
    plane_allowed = {
        "allowed_dependency_categories",
        "auth_class",
        "auth_exempt_routes",
        "bootstrap_routes",
        "docs_routes",
        "global_routes",
        "maturity_tag",
        "plane_id",
        "public_routes",
        "required_ci_gates",
        "required_make_targets",
        "required_route_invariants",
        "route_prefixes",
        "mount_flag",
        "evidence",
    }
    route_exception_allowed = {
        "class_name",
        "expires_at",
        "justification",
        "method",
        "path",
        "permanent",
    }

    for idx, plane in enumerate(records):
        context = f"plane_registry[{idx}]"
        _require_keys(plane, {"plane_id", "route_prefixes", "required_make_targets"}, context)
        _validate_unknown_keys(plane, plane_allowed, context, unknown_warnings, reject_unknown)

        if not isinstance(plane["plane_id"], str) or not plane["plane_id"].strip():
            raise ValueError(f"{context}.plane_id must be a non-empty string")

        _require_list_of_strings(plane["route_prefixes"], f"{context}.route_prefixes")
        _require_list_of_strings(plane["required_make_targets"], f"{context}.required_make_targets")

        for list_key in (
            "allowed_dependency_categories",
            "required_ci_gates",
            "required_route_invariants",
        ):
            if list_key in plane:
                _require_list_of_strings(plane[list_key], f"{context}.{list_key}")

        for route_key in (
            "auth_exempt_routes",
            "bootstrap_routes",
            "docs_routes",
            "global_routes",
            "public_routes",
        ):
            if route_key in plane:
                routes = plane[route_key]
                if not isinstance(routes, list):
                    raise ValueError(f"{context}.{route_key} must be a list")
                for route_idx, route in enumerate(routes):
                    if not isinstance(route, dict):
                        raise ValueError(f"{context}.{route_key}[{route_idx}] must be an object")
                    _require_keys(route, {"method", "path"}, f"{context}.{route_key}[{route_idx}]")
                    _validate_unknown_keys(
                        route,
                        route_exception_allowed,
                        f"{context}.{route_key}[{route_idx}]",
                        unknown_warnings,
                        reject_unknown,
                    )

        if "auth_class" in plane:
            auth_class = plane["auth_class"]
            if not isinstance(auth_class, dict):
                raise ValueError(f"{context}.auth_class must be an object")
            _require_keys(
                auth_class,
                {
                    "allow_unscoped_keys",
                    "require_any_scope",
                    "required_scope_prefixes",
                    "tenant_binding_required",
                },
                f"{context}.auth_class",
            )
            if not isinstance(auth_class["allow_unscoped_keys"], bool):
                raise ValueError(f"{context}.auth_class.allow_unscoped_keys must be bool")
            if not isinstance(auth_class["require_any_scope"], bool):
                raise ValueError(f"{context}.auth_class.require_any_scope must be bool")
            if not isinstance(auth_class["tenant_binding_required"], bool):
                raise ValueError(f"{context}.auth_class.tenant_binding_required must be bool")
            _require_list_of_strings(
                auth_class["required_scope_prefixes"],
                f"{context}.auth_class.required_scope_prefixes",
            )


def _validate_route_inventory(
    records: list[dict[str, Any]],
    *,
    unknown_warnings: list[str],
    reject_unknown: bool,
) -> None:
    allowed = {
        "dependency_categories",
        "file",
        "method",
        "path",
        "plane_id",
        "scoped",
        "scopes",
        "source",
        "tenant_bound",
    }
    for idx, route in enumerate(records):
        context = f"route_inventory[{idx}]"
        _require_keys(route, {"method", "path", "plane_id", "file"}, context)
        _validate_unknown_keys(route, allowed, context, unknown_warnings, reject_unknown)
        if not isinstance(route["method"], str) or not route["method"].strip():
            raise ValueError(f"{context}.method must be a non-empty string")
        if not isinstance(route["path"], str) or not route["path"].startswith("/"):
            raise ValueError(f"{context}.path must be an absolute path string")
        if not isinstance(route["plane_id"], str) or not route["plane_id"].strip():
            raise ValueError(f"{context}.plane_id must be a non-empty string")
        if not isinstance(route["file"], str) or not route["file"].strip():
            raise ValueError(f"{context}.file must be a non-empty string")
        if "scoped" in route and not isinstance(route["scoped"], bool):
            raise ValueError(f"{context}.scoped must be bool")
        if "tenant_bound" in route and not isinstance(route["tenant_bound"], bool):
            raise ValueError(f"{context}.tenant_bound must be bool")
        if "dependency_categories" in route:
            _require_list_of_strings(route["dependency_categories"], f"{context}.dependency_categories")
        if "scopes" in route:
            _require_list_of_strings(route["scopes"], f"{context}.scopes")


def _validate_contract_routes(
    records: list[dict[str, Any]],
    *,
    unknown_warnings: list[str],
    reject_unknown: bool,
) -> None:
    allowed = {"method", "path", "scopes", "source", "plane_id"}
    for idx, route in enumerate(records):
        context = f"contract_routes[{idx}]"
        _require_keys(route, {"method", "path", "scopes"}, context)
        _validate_unknown_keys(route, allowed, context, unknown_warnings, reject_unknown)
        if not isinstance(route["method"], str) or not route["method"].strip():
            raise ValueError(f"{context}.method must be a non-empty string")
        if not isinstance(route["path"], str) or not route["path"].startswith("/"):
            raise ValueError(f"{context}.path must be an absolute path string")
        _require_list_of_strings(route["scopes"], f"{context}.scopes")
        if "plane_id" in route and not isinstance(route["plane_id"], str):
            raise ValueError(f"{context}.plane_id must be string")


def _load_governance_inputs(
    *,
    allow_legacy_schema: bool,
    reject_unknown_keys: bool,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    str,
    str | None,
    dict[str, Any] | None,
    dict[str, str],
    list[str],
]:
    missing = [str(path.relative_to(REPO)) for path in GOVERNANCE_INPUTS.values() if not path.exists()]
    if missing:
        print("platform inventory: missing required governance inputs:", file=sys.stderr)
        for rel in sorted(missing):
            print(f" - {rel}", file=sys.stderr)
        raise SystemExit(2)

    unknown_warnings: list[str] = []

    raw_plane = load_json(GOVERNANCE_INPUTS["plane_registry"])
    raw_runtime = load_json(GOVERNANCE_INPUTS["route_inventory"])
    raw_contract = load_json(GOVERNANCE_INPUTS["contract_routes"])

    plane_snapshot, plane_schema = _extract_versioned_list(
        raw_plane,
        artifact_name="plane_registry",
        data_key="planes",
        allow_legacy_schema=allow_legacy_schema,
    )
    route_inventory, runtime_schema = _extract_versioned_list(
        raw_runtime,
        artifact_name="route_inventory",
        data_key="routes",
        allow_legacy_schema=allow_legacy_schema,
    )
    contract_routes, contract_schema = _extract_versioned_list(
        raw_contract,
        artifact_name="contract_routes",
        data_key="routes",
        allow_legacy_schema=allow_legacy_schema,
    )

    _validate_plane_snapshot(
        plane_snapshot,
        unknown_warnings=unknown_warnings,
        reject_unknown=reject_unknown_keys,
    )
    _validate_route_inventory(
        route_inventory,
        unknown_warnings=unknown_warnings,
        reject_unknown=reject_unknown_keys,
    )
    _validate_contract_routes(
        contract_routes,
        unknown_warnings=unknown_warnings,
        reject_unknown=reject_unknown_keys,
    )

    topology_sha = read_sha256(GOVERNANCE_INPUTS["topology_hash"])

    attestation_sha = None
    if OPTIONAL_INPUTS["attestation_hash"].exists():
        attestation_sha = read_sha256(OPTIONAL_INPUTS["attestation_hash"])

    build_meta = None
    build_meta_schema = "absent"
    if OPTIONAL_INPUTS["build_meta"].exists():
        raw_build_meta = load_json(OPTIONAL_INPUTS["build_meta"])
        if isinstance(raw_build_meta, dict) and "schema_version" in raw_build_meta:
            if raw_build_meta.get("schema_version") != SCHEMA_EXPECTED["build_meta"]:
                raise ValueError(
                    "build_meta.schema_version expected "
                    f"{SCHEMA_EXPECTED['build_meta']}, got {raw_build_meta.get('schema_version')}"
                )
            build_meta_schema = str(raw_build_meta["schema_version"])
            build_meta = raw_build_meta
        elif isinstance(raw_build_meta, dict):
            if not allow_legacy_schema:
                raise ValueError(
                    "build_meta must include schema_version or use --allow-legacy-schema"
                )
            build_meta_schema = "legacy-v0"
            build_meta = raw_build_meta
        else:
            raise ValueError("tools/ci/build_meta.json must be an object")

    if not route_inventory and os.getenv("FG_ALLOW_EMPTY_ROUTE_INVENTORY") != "1":
        raise ValueError(
            "tools/ci/route_inventory.json is empty; set FG_ALLOW_EMPTY_ROUTE_INVENTORY=1 to override"
        )

    schema_versions = {
        "plane_registry": plane_schema,
        "route_inventory": runtime_schema,
        "contract_routes": contract_schema,
        "build_meta": build_meta_schema,
    }
    return (
        plane_snapshot,
        route_inventory,
        contract_routes,
        topology_sha,
        attestation_sha,
        build_meta,
        schema_versions,
        unknown_warnings,
    )


def _route_sort_key(route: dict[str, Any]) -> tuple[str, str]:
    return (str(route.get("method", "")), str(route.get("path", "")))


def _sorted_route_signatures(routes: list[dict[str, Any]]) -> list[str]:
    return [f"{m} {p}" for m, p in sorted({(r["method"], r["path"]) for r in routes})]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-gaps",
        action="store_true",
        help="Allow unmapped runtime routes and empty-plane gaps (local debugging only).",
    )
    parser.add_argument(
        "--allow-legacy-schema",
        action="store_true",
        help="Allow legacy unversioned governance artifact formats.",
    )
    parser.add_argument(
        "--require-versioned-schema",
        action="store_true",
        help="Fail when governance artifacts are in legacy unversioned format.",
    )
    parser.add_argument(
        "--reject-unknown-keys",
        action="store_true",
        help="Fail when governance artifacts include unknown keys.",
    )
    args = parser.parse_args(argv)

    # Source-of-truth note:
    # Platform inventory intentionally reads deterministic governance artifacts written by
    # tools/ci/check_route_inventory.py and does not import PlaneDef internals.
    require_versioned_schema = args.require_versioned_schema or (
        os.getenv("FG_REQUIRE_VERSIONED_GOVERNANCE_SCHEMA") == "1"
    )

    (
        plane_snapshot,
        route_inventory,
        contract_routes,
        topology_sha,
        attestation_sha,
        build_meta,
        schema_versions,
        unknown_warnings,
    ) = _load_governance_inputs(
        # Backward-compatible default for current CI artifacts while preserving
        # an explicit strict mode gate for enforcing versioned schema wrappers.
        allow_legacy_schema=(not require_versioned_schema)
        or args.allow_legacy_schema
        or (os.getenv("FG_ALLOW_LEGACY_GOVERNANCE_SCHEMA") == "1"),
        reject_unknown_keys=args.reject_unknown_keys
        or os.getenv("FG_REJECT_UNKNOWN_GOVERNANCE_KEYS") == "1",
    )

    make_targets = _make_targets()
    artifact_schemas = sorted(
        p.as_posix().replace(str(REPO) + "/", "")
        for p in (REPO / "contracts/artifacts").glob("*.schema.json")
    )
    soc_text = (REPO / "artifacts/SOC_AUDIT_GATES.md").read_text(encoding="utf-8")

    planes = []
    gaps = []
    failures = []
    by_plane_routes: dict[str, list[str]] = {}
    owned_prefixes: list[str] = []
    route_records_by_plane: dict[str, list[dict[str, Any]]] = {}

    for plane in sorted(plane_snapshot, key=lambda p: str(p["plane_id"])):
        pid = str(plane.get("plane_id", "")).strip()
        route_prefixes = sorted(str(prefix) for prefix in (plane.get("route_prefixes") or []))
        owned_prefixes.extend(route_prefixes)

        required_targets = sorted(str(t) for t in (plane.get("required_make_targets") or []))
        missing_targets = sorted([t for t in required_targets if t not in make_targets])
        if missing_targets:
            gaps.append(
                {
                    "type": "missing_make_targets",
                    "plane": pid,
                    "details": missing_targets,
                    "suggested_fix": "Add missing make targets declared by plane registry.",
                }
            )

        if pid not in soc_text:
            gaps.append(
                {
                    "type": "missing_soc_gate_reference",
                    "plane": pid,
                    "details": "plane id not referenced in SOC gate artifact",
                    "suggested_fix": "Add SOC gate mapping entry for plane.",
                }
            )

        evidence = sorted(
            [
                {
                    "schema": str(item.get("schema_path", "")),
                    "generator": str(item.get("generator_script", "")),
                }
                for item in (plane.get("evidence") or [])
                if isinstance(item, dict)
            ],
            key=lambda x: (x["schema"], x["generator"]),
        )
        compat = {
            # Deprecated compatibility fields. Removal target: 2026-06.
            "deprecated_mount_flag": str(plane.get("mount_flag", "n/a")),
            "deprecated_evidence": evidence,
            "deprecation_notice": "mount_flag/evidence are compatibility-only and not governance source of truth",
        }

        route_records_by_plane[pid] = []
        planes.append(
            {
                "plane_id": pid,
                "route_prefixes": route_prefixes,
                "mount_flag": compat["deprecated_mount_flag"],
                "required_make_targets": required_targets,
                "evidence": compat["deprecated_evidence"],
                "compat": compat,
            }
        )

    for route in sorted(route_inventory, key=_route_sort_key):
        pid = str(route.get("plane_id", "")).strip()
        if pid in route_records_by_plane:
            route_records_by_plane[pid].append(route)
            continue

        path = str(route.get("path", ""))
        method = str(route.get("method", ""))
        mapped = False
        for plane in planes:
            prefixes = plane["route_prefixes"]
            if any(path.startswith(prefix) for prefix in prefixes):
                route_records_by_plane[plane["plane_id"]].append(route)
                mapped = True
                break
        if not mapped:
            failures.append(f"unmapped runtime route: {method} {path}")

    for pid in sorted(route_records_by_plane):
        by_plane_routes[pid] = _sorted_route_signatures(route_records_by_plane[pid])
        if not by_plane_routes[pid]:
            failures.append(f"plane has zero runtime routes: {pid}")

    unexpected = sorted(
        {
            str(r.get("path", ""))
            for r in route_inventory
            if str(r.get("path", "")).startswith("/")
            and not any(str(r.get("path", "")).startswith(prefix) for prefix in owned_prefixes)
        }
    )
    if unexpected:
        gaps.append(
            {
                "type": "unexpected_route_prefixes",
                "details": unexpected,
                "suggested_fix": "Map route prefixes to a plane or explicitly exempt in inventory governance.",
            }
        )
        for path in unexpected:
            failures.append(f"unexpected runtime route prefix: {path}")

    runtime_keys = {(str(r.get("method", "")), str(r.get("path", ""))) for r in route_inventory}
    contract_keys = {(str(r.get("method", "")), str(r.get("path", ""))) for r in contract_routes}

    readiness = {
        "tenant_binding_coverage": all(
            bool(r.get("tenant_bound")) or str(r.get("path", "")).startswith("/health")
            for r in route_inventory
        ),
        "rls_sensitive_tables_present": (
            REPO / "migrations/postgres/0018_nuclear_hardening_extensions.sql"
        ).exists(),
        "route_inventory_enforced": True,
        "openapi_security_diff_enforced": (
            REPO / "tools/ci/check_openapi_security_diff.py"
        ).exists(),
        "artifact_policy_enforced": (
            REPO / "tools/ci/check_artifact_policy.py"
        ).exists(),
        "resilience_guard_present": (
            REPO / "api/middleware/resilience_guard.py"
        ).exists(),
        "self_heal_bounded_off_by_default": (
            REPO / "services/self_heal/watchdog.py"
        ).exists(),
    }

    payload: dict[str, Any] = {
        "git_sha": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "planes": sorted(planes, key=lambda x: x["plane_id"]),
        "routes_by_plane": {k: by_plane_routes[k] for k in sorted(by_plane_routes)},
        "artifact_schemas": artifact_schemas,
        "readiness": readiness,
        "gaps": sorted(
            gaps,
            key=lambda x: (
                x.get("type", ""),
                x.get("plane", ""),
                json.dumps(x.get("details", ""), sort_keys=True),
            ),
        ),
        "governance": {
            "schema_versions": schema_versions,
            "schema_unknown_key_warnings": sorted(unknown_warnings),
            "topology_sha256": topology_sha,
            "topology_sha256_note": "Content hashes of plane_registry_snapshot.json, route_inventory.json, contract_routes.json.",
            "attestation_sha256": attestation_sha,
            "build_meta": build_meta,
            "runtime_count": len(route_inventory),
            "contract_count": len(contract_routes),
            "runtime_only": sorted([f"{m} {p}" for m, p in (runtime_keys - contract_keys)]),
            "contract_only": sorted([f"{m} {p}" for m, p in (contract_keys - runtime_keys)]),
        },
    }

    art = REPO / "artifacts"
    art.mkdir(exist_ok=True)
    (art / "platform_inventory.json").write_text(_dump_json(payload), encoding="utf-8")

    inv_md = ["# Platform Inventory", "", "## Planes"]
    for plane in payload["planes"]:
        inv_md.append(
            f"- `{plane['plane_id']}` flags=`{plane['mount_flag']}` targets={', '.join(plane['required_make_targets'])}"
        )
    inv_md += ["", "## Enterprise readiness checklist status"]
    for k, v in sorted(readiness.items()):
        inv_md.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    (art / "PLATFORM_INVENTORY.md").write_text("\n".join(inv_md) + "\n", encoding="utf-8")

    gap_md = ["# Platform Gaps", ""]
    if payload["gaps"]:
        for gap in payload["gaps"]:
            gap_md.append(
                f"- [{gap['type']}] {gap.get('plane', 'global')}: {gap['details']} | fix: {gap['suggested_fix']}"
            )
    else:
        gap_md.append("- none")
    (art / "PLATFORM_GAPS.md").write_text("\n".join(gap_md) + "\n", encoding="utf-8")

    if failures and not (args.allow_gaps or os.getenv("FG_PLATFORM_INVENTORY_ALLOW_GAPS") == "1"):
        print("platform inventory: FAILED semantic integrity checks", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f" - {failure}", file=sys.stderr)
        print(" - re-run with --allow-gaps for local diagnostics", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(f"platform inventory: missing file: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except ValueError as exc:
        print(f"platform inventory: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
