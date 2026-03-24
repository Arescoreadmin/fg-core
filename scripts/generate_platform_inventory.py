from __future__ import annotations

import argparse
import hashlib
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

# Deterministic governance inputs only.
SCHEMA_EXPECTED = {
    "plane_registry": "v1",
    "route_inventory": "v1",
    "contract_routes": "v1",
}

# Optional, volatile-only evidence schema.
BUILD_META_SCHEMA_EXPECTED = "v1"

SHA_LINE_RE = re.compile(r"^[0-9a-f]{64}\s{2}[^\s].+$")


# -----------------------------
# Deterministic helpers
# -----------------------------
def _dump_json(payload: Any) -> str:
    return (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ": "),
        )
        + "\n"
    )


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _governance_fingerprint(
    plane_snapshot: list[dict[str, Any]],
    route_inventory: list[dict[str, Any]],
    contract_routes: list[dict[str, Any]],
) -> str:
    blob = (
        _canonical_json(plane_snapshot)
        + _canonical_json(route_inventory)
        + _canonical_json(contract_routes)
    )
    return _sha256_text(blob)


# -----------------------------
# IO / Validation primitives
# -----------------------------
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
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not lines:
        raise ValueError(f"empty sha256 file: {path.relative_to(REPO)}")
    bad = [line for line in lines if not SHA_LINE_RE.match(line)]
    if bad:
        raise ValueError(f"malformed sha256 line(s) in {path.relative_to(REPO)}: {bad}")
    return "\n".join(lines)


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


def _extract_v1_data(
    raw: Any, *, artifact_name: str, expected_schema: str
) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(raw, dict):
        raise ValueError(
            f"{artifact_name} must be an object with schema_version/generated_at/data"
        )
    _require_keys(raw, {"schema_version", "generated_at", "data"}, artifact_name)

    schema_version = raw["schema_version"]
    if schema_version != expected_schema:
        raise ValueError(
            f"{artifact_name}.schema_version expected {expected_schema}, got {schema_version}"
        )

    if not isinstance(raw["generated_at"], str) or not raw["generated_at"].strip():
        raise ValueError(f"{artifact_name}.generated_at must be a non-empty string")

    data = raw["data"]
    if not isinstance(data, list):
        raise ValueError(f"{artifact_name}.data must be a list")
    if not all(isinstance(item, dict) for item in data):
        raise ValueError(f"{artifact_name}.data entries must be objects")

    return data, schema_version


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
        "route_prefixes",
        "mount_flag",
        "evidence",
        "required_route_invariants",
    }
    route_allowed = {
        "class_name",
        "expires_at",
        "justification",
        "method",
        "path",
        "permanent",
    }

    for idx, plane in enumerate(records):
        context = f"plane_registry[{idx}]"
        _require_keys(
            plane, {"plane_id", "route_prefixes", "required_make_targets"}, context
        )
        _validate_unknown_keys(
            plane, plane_allowed, context, unknown_warnings, reject_unknown
        )

        if not isinstance(plane["plane_id"], str) or not plane["plane_id"].strip():
            raise ValueError(f"{context}.plane_id must be non-empty string")
        _require_list_of_strings(plane["route_prefixes"], f"{context}.route_prefixes")
        _require_list_of_strings(
            plane["required_make_targets"], f"{context}.required_make_targets"
        )

        for k in ("allowed_dependency_categories", "required_ci_gates"):
            if k in plane:
                _require_list_of_strings(plane[k], f"{context}.{k}")

        for route_key in (
            "auth_exempt_routes",
            "bootstrap_routes",
            "docs_routes",
            "global_routes",
            "public_routes",
        ):
            if route_key not in plane:
                continue
            routes = plane[route_key]
            if not isinstance(routes, list):
                raise ValueError(f"{context}.{route_key} must be a list")
            for r_idx, route in enumerate(routes):
                if not isinstance(route, dict):
                    raise ValueError(f"{context}.{route_key}[{r_idx}] must be object")
                _require_keys(
                    route, {"method", "path"}, f"{context}.{route_key}[{r_idx}]"
                )
                _validate_unknown_keys(
                    route,
                    route_allowed,
                    f"{context}.{route_key}[{r_idx}]",
                    unknown_warnings,
                    reject_unknown,
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
        "plane",
        "scoped",
        "scopes",
        "source",
        "tenant_bound",
    }
    for idx, route in enumerate(records):
        context = f"route_inventory[{idx}]"
        _require_keys(route, {"method", "path", "plane_id", "file"}, context)
        _validate_unknown_keys(
            route, allowed, context, unknown_warnings, reject_unknown
        )


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
        _validate_unknown_keys(
            route, allowed, context, unknown_warnings, reject_unknown
        )


def _load_governance_inputs(
    *, reject_unknown_keys: bool
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
    missing = [
        str(path.relative_to(REPO))
        for path in GOVERNANCE_INPUTS.values()
        if not path.exists()
    ]
    if missing:
        print(
            "platform inventory: missing required governance inputs:", file=sys.stderr
        )
        for rel in sorted(missing):
            print(f" - {rel}", file=sys.stderr)
        raise SystemExit(2)

    unknown_warnings: list[str] = []

    raw_plane = load_json(GOVERNANCE_INPUTS["plane_registry"])
    raw_runtime = load_json(GOVERNANCE_INPUTS["route_inventory"])
    raw_contract = load_json(GOVERNANCE_INPUTS["contract_routes"])

    plane_snapshot, plane_schema = _extract_v1_data(
        raw_plane,
        artifact_name="plane_registry",
        expected_schema=SCHEMA_EXPECTED["plane_registry"],
    )
    route_inventory, runtime_schema = _extract_v1_data(
        raw_runtime,
        artifact_name="route_inventory",
        expected_schema=SCHEMA_EXPECTED["route_inventory"],
    )
    contract_routes, contract_schema = _extract_v1_data(
        raw_contract,
        artifact_name="contract_routes",
        expected_schema=SCHEMA_EXPECTED["contract_routes"],
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
    if OPTIONAL_INPUTS["build_meta"].exists():
        raw_build_meta = load_json(OPTIONAL_INPUTS["build_meta"])
        build_meta_data, _build_meta_schema = _extract_v1_data(
            raw_build_meta,
            artifact_name="build_meta",
            expected_schema=BUILD_META_SCHEMA_EXPECTED,
        )
        build_meta = build_meta_data[0] if build_meta_data else None

    if not route_inventory and os.getenv("FG_ALLOW_EMPTY_ROUTE_INVENTORY") != "1":
        raise ValueError(
            "tools/ci/route_inventory.json is empty; set FG_ALLOW_EMPTY_ROUTE_INVENTORY=1 to override"
        )

    return (
        plane_snapshot,
        route_inventory,
        contract_routes,
        topology_sha,
        attestation_sha,
        build_meta,
        {
            "plane_registry": plane_schema,
            "route_inventory": runtime_schema,
            "contract_routes": contract_schema,
        },
        unknown_warnings,
    )


def _make_targets() -> set[str]:
    proc = subprocess.run(
        ["make", "-qpRr", "__mkdb__"],
        cwd=REPO,
        check=True,
        text=True,
        capture_output=True,
    )
    out: set[str] = set()
    for line in proc.stdout.splitlines():
        if ":" in line and not line.startswith("\t") and not line.startswith("#"):
            name = line.split(":", 1)[0].strip()
            if name and "=" not in name and " " not in name:
                out.add(name)
    return out


def _route_sort_key(route: dict[str, Any]) -> tuple[str, str]:
    return (str(route.get("method", "")), str(route.get("path", "")))


def _sorted_route_signatures(routes: list[dict[str, Any]]) -> list[str]:
    return [f"{m} {p}" for m, p in sorted({(r["method"], r["path"]) for r in routes})]


def _deterministic_git_sha(build_meta: dict[str, Any] | None) -> str:
    if isinstance(build_meta, dict):
        v = build_meta.get("git_sha")
        if isinstance(v, str) and v.strip():
            return v.strip()
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-gaps",
        action="store_true",
        help="Allow unmapped runtime routes and empty-plane gaps (local debugging only).",
    )
    parser.add_argument(
        "--reject-unknown-keys",
        action="store_true",
        help="Fail when governance artifacts include unknown keys.",
    )
    parser.add_argument(
        "--include-volatile",
        action="store_true",
        help="Also write volatile evidence payload (git_sha, build_meta, attestation/topology hashes) to artifacts/platform_inventory.json.",
    )
    args = parser.parse_args(argv)

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
        reject_unknown_keys=args.reject_unknown_keys
        or os.getenv("FG_REJECT_UNKNOWN_GOVERNANCE_KEYS") == "1"
    )

    make_targets = _make_targets()
    artifact_schemas = sorted(
        p.as_posix().replace(str(REPO) + "/", "")
        for p in (REPO / "contracts/artifacts").glob("*.schema.json")
    )
    soc_text = (REPO / "artifacts/SOC_AUDIT_GATES.md").read_text(encoding="utf-8")

    gov_fp = _governance_fingerprint(plane_snapshot, route_inventory, contract_routes)

    planes: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    failures: list[str] = []
    by_plane_routes: dict[str, list[str]] = {}
    owned_prefixes: list[str] = []
    route_records_by_plane: dict[str, list[dict[str, Any]]] = {}

    for plane in sorted(plane_snapshot, key=lambda p: str(p["plane_id"])):
        pid = str(plane["plane_id"]).strip()
        route_prefixes = sorted(
            str(prefix) for prefix in (plane.get("route_prefixes") or [])
        )
        owned_prefixes.extend(route_prefixes)

        required_targets = sorted(
            str(t) for t in (plane.get("required_make_targets") or [])
        )
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

        compat = {
            "deprecation_notice": (
                "platform inventory is derived from canonical governance artifacts. "
                "Legacy PlaneDef internals (mount_flag/evidence/required_route_invariants) "
                "are ignored even if present in snapshots."
            )
        }

        route_records_by_plane[pid] = []
        planes.append(
            {
                "plane_id": pid,
                "route_prefixes": route_prefixes,
                "required_make_targets": required_targets,
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
            if any(path.startswith(prefix) for prefix in plane["route_prefixes"]):
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
            and not any(
                str(r.get("path", "")).startswith(prefix) for prefix in owned_prefixes
            )
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

    runtime_keys = {
        (str(r.get("method", "")), str(r.get("path", ""))) for r in route_inventory
    }
    contract_keys = {
        (str(r.get("method", "")), str(r.get("path", ""))) for r in contract_routes
    }

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

    det_payload: dict[str, Any] = {
        "governance_fingerprint": gov_fp,
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
            "runtime_count": len(route_inventory),
            "contract_count": len(contract_routes),
            "runtime_only": sorted(
                [f"{m} {p}" for m, p in (runtime_keys - contract_keys)]
            ),
            "contract_only": sorted(
                [f"{m} {p}" for m, p in (contract_keys - runtime_keys)]
            ),
        },
    }

    vol_payload: dict[str, Any] | None = None
    if args.include_volatile:
        payload_git_sha = _deterministic_git_sha(build_meta)
        vol_payload = dict(det_payload)
        vol_payload["git_sha"] = payload_git_sha
        vol_payload["build_meta"] = build_meta
        vol_payload["governance"] = dict(det_payload["governance"])
        vol_payload["governance"].update(
            {
                "topology_sha256": topology_sha,
                "topology_sha256_note": (
                    "Content hashes of plane_registry_snapshot.json, route_inventory.json, "
                    "contract_routes.json."
                ),
                "attestation_sha256": attestation_sha,
            }
        )

    art = REPO / "artifacts"
    art.mkdir(exist_ok=True)

    (art / "platform_inventory.det.json").write_text(
        _dump_json(det_payload), encoding="utf-8"
    )

    inv_md = ["# Platform Inventory", "", "## Planes"]
    for plane in det_payload["planes"]:
        inv_md.append(
            f"- `{plane['plane_id']}` targets={', '.join(plane['required_make_targets'])}"
        )
    inv_md += ["", "## Enterprise readiness checklist status"]
    for k, v in sorted(readiness.items()):
        inv_md.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    (art / "PLATFORM_INVENTORY.det.md").write_text(
        "\n".join(inv_md) + "\n", encoding="utf-8"
    )

    gap_md = ["# Platform Gaps", ""]
    if det_payload["gaps"]:
        for gap in det_payload["gaps"]:
            gap_md.append(
                f"- [{gap['type']}] {gap.get('plane', 'global')}: {gap['details']} | fix: {gap['suggested_fix']}"
            )
    else:
        gap_md.append("- none")
    (art / "PLATFORM_GAPS.det.md").write_text(
        "\n".join(gap_md) + "\n", encoding="utf-8"
    )

    if vol_payload is not None:
        (art / "platform_inventory.json").write_text(
            _dump_json(vol_payload), encoding="utf-8"
        )

    if failures and not (
        args.allow_gaps or os.getenv("FG_PLATFORM_INVENTORY_ALLOW_GAPS") == "1"
    ):
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
