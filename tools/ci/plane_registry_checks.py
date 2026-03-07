from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from services.plane_registry import PLANE_REGISTRY
from tools.ci.route_checks import iter_route_records

REPO = Path(__file__).resolve().parents[2]
CONTRACT_OPENAPI = REPO / "contracts/core/openapi.json"


def _route_tuple(method: str, path: str) -> tuple[str, str]:
    return (method.upper(), path)


# -----------------------------------------------------------
# Plane exception helpers
# -----------------------------------------------------------


def route_exception_classes(plane_id: str, method: str, path: str) -> set[str]:
    plane = next((p for p in PLANE_REGISTRY if p.plane_id == plane_id), None)
    if plane is None:
        return set()

    key = _route_tuple(method, path)
    classes: set[str] = set()

    for pool in (
        plane.global_routes,
        plane.public_routes,
        plane.bootstrap_routes,
        plane.auth_exempt_routes,
        plane.docs_routes,
    ):
        for e in pool:
            if _route_tuple(e.method, e.path) == key:
                classes.add(e.class_name)

    return classes


def route_has_exception(plane_id: str, method: str, path: str) -> bool:
    return bool(route_exception_classes(plane_id, method, path))


# -----------------------------------------------------------
# Dependency categorization
# -----------------------------------------------------------


def dependency_categories_for_record(rec) -> list[str]:
    categories: list[str] = []

    if rec.route_has_scope_dependency or rec.route_scopes:
        categories.append("auth")

    if rec.tenant_bound:
        categories.append("tenant")

    if rec.route_has_db_dependency:
        categories.append("db")

    if rec.full_path.startswith(
        ("/exceptions", "/breakglass", "/control-plane/terminal")
    ):
        categories.append("breakglass")

    if rec.full_path.startswith(
        (
            "/admin",
            "/control-plane",
            "/ui",
            "/auth",
            "/keys",
            "/evidence",
            "/approvals",
            "/audit",
        )
    ):
        categories.append("rate")

    return sorted(set(categories))


# -----------------------------------------------------------
# Runtime route discovery (AST)
# -----------------------------------------------------------


def runtime_routes_ast() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for rec in iter_route_records(REPO / "api"):
        base_row = {
            "source": "runtime-ast",
            "method": rec.method.upper(),
            "path": rec.full_path,
            "file": rec.file_path.relative_to(REPO).as_posix(),
            "scoped": bool(rec.route_has_scope_dependency),
            "scopes": list(rec.route_scopes),
            "tenant_bound": bool(rec.tenant_bound),
            "dependency_categories": dependency_categories_for_record(rec),
        }
        rows.append(base_row)

        # Canonical runtime alias: /defend is also mounted at /v1/defend in api.main
        if rec.full_path == "/defend":
            rows.append(
                {
                    **base_row,
                    "source": "runtime-app-alias",
                    "path": "/v1/defend",
                }
            )

    deduped = {
        (
            str(r["method"]),
            str(r["path"]),
            str(r["file"]),
        ): r
        for r in rows
    }

    return sorted(
        deduped.values(),
        key=lambda r: (str(r["path"]), str(r["method"]), str(r["file"])),
    )


# -----------------------------------------------------------
# Runtime route discovery (actual app)
# -----------------------------------------------------------


def runtime_routes_app() -> list[dict[str, object]] | None:
    try:
        from api.main import build_runtime_app
    except Exception:
        return None

    try:
        app = build_runtime_app(auth_enabled=True)
    except Exception:
        return None

    rows: list[dict[str, object]] = []

    for r in getattr(app, "routes", []) or []:
        path = getattr(r, "path", None)
        methods = getattr(r, "methods", None)

        if not path or not methods:
            continue

        ms = sorted(m for m in methods if m not in {"HEAD", "OPTIONS"})

        for m in ms:
            rows.append(
                {
                    "method": str(m).upper(),
                    "path": str(path),
                }
            )

    return sorted(rows, key=lambda x: (str(x["path"]), str(x["method"])))


# -----------------------------------------------------------
# Contract route discovery
# -----------------------------------------------------------


def contract_routes() -> list[dict[str, object]]:
    if not CONTRACT_OPENAPI.exists():
        return []

    doc = json.loads(CONTRACT_OPENAPI.read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []

    for path, ops in sorted((doc.get("paths") or {}).items()):
        if not isinstance(ops, dict):
            continue

        for method, op in sorted(ops.items()):
            m = str(method).upper()

            if m not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue

            scopes: list[str] = []

            sec = op.get("security") if isinstance(op, dict) else None
            if isinstance(sec, list):
                for entry in sec:
                    if isinstance(entry, dict):
                        for _, vals in entry.items():
                            if isinstance(vals, list):
                                scopes.extend(str(v) for v in vals)

            rows.append(
                {
                    "source": "contract",
                    "method": m,
                    "path": str(path),
                    "scopes": sorted(set(scopes)),
                }
            )

    return rows


# -----------------------------------------------------------
# Plane ownership matching (FIXED)
# -----------------------------------------------------------


def match_plane(path: str) -> list[str]:
    candidate_paths = [path]

    if path.startswith("/v1/"):
        candidate_paths.append(path[3:])

    best_len = -1
    best_planes: set[str] = set()

    for candidate in candidate_paths:
        matches: list[tuple[int, str]] = []

        for plane in PLANE_REGISTRY:
            for prefix in plane.route_prefixes:
                if candidate == prefix or candidate.startswith(prefix + "/"):
                    matches.append((len(prefix), plane.plane_id))

        if not matches:
            continue

        candidate_best_len = max(length for length, _ in matches)

        candidate_best_planes = {
            plane_id for length, plane_id in matches if length == candidate_best_len
        }

        if candidate_best_len > best_len:
            best_len = candidate_best_len
            best_planes = set(candidate_best_planes)

        elif candidate_best_len == best_len:
            best_planes.update(candidate_best_planes)

    return sorted(best_planes)


# -----------------------------------------------------------
# Coverage summary
# -----------------------------------------------------------


def plane_coverage_summary(routes: list[dict[str, object]]) -> dict[str, int]:
    c: dict[str, int] = defaultdict(int)

    for r in routes:
        plane_id = str(r.get("plane_id", "unmapped"))
        c[plane_id] += 1

    return dict(sorted(c.items()))
