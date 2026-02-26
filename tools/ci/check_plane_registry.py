#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

ADMIN_PREFIX_POLICY = "control_only"


def _exception_health(
    route_ex, *, plane_id: str, pool_name: str, warnings: list[str], failures: list[str]
) -> None:
    if not route_ex.justification.strip():
        failures.append(
            f"plane {plane_id} has unjustified exception in {pool_name}: {route_ex.method} {route_ex.path}"
        )

    if not route_ex.permanent and not route_ex.expires_at.strip():
        failures.append(
            f"plane {plane_id} non-permanent exception missing expires_at in {pool_name}: {route_ex.method} {route_ex.path}"
        )
        return

    if route_ex.permanent:
        return

    try:
        expires = datetime.strptime(route_ex.expires_at.strip(), "%Y-%m-%d").replace(
            tzinfo=UTC
        )
    except ValueError:
        failures.append(
            f"plane {plane_id} exception has invalid expires_at (YYYY-MM-DD required) in {pool_name}: {route_ex.method} {route_ex.path} -> {route_ex.expires_at}"
        )
        return

    now = datetime.now(tz=UTC)
    delta_days = (expires - now).days
    if delta_days > 90:
        failures.append(
            f"plane {plane_id} exception exceeds maximum 90-day horizon in {pool_name}: {route_ex.method} {route_ex.path} expires {route_ex.expires_at}"
        )
    elif delta_days < 0:
        failures.append(
            f"plane {plane_id} exception exceeded 90-day expiry window in {pool_name}: {route_ex.method} {route_ex.path} expired {route_ex.expires_at}"
        )
    elif delta_days <= 30:
        warnings.append(
            f"plane {plane_id} exception expires within 30 days in {pool_name}: {route_ex.method} {route_ex.path} expires {route_ex.expires_at}"
        )


def main() -> int:
    from services.plane_registry import PLANE_REGISTRY
    from tools.ci.plane_registry_checks import (
        contract_routes,
        match_plane,
        route_exception_classes,
        runtime_routes_app,
        runtime_routes_ast,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--use-runtime-app", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []
    warnings: list[str] = []
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    runtime = runtime_routes_ast()
    contract = contract_routes()

    for plane in PLANE_REGISTRY:
        if not plane.route_prefixes:
            failures.append(f"plane {plane.plane_id} missing route prefixes")
        for target in plane.required_make_targets:
            if f"{target}:" not in makefile:
                failures.append(f"plane {plane.plane_id} missing make target {target}")
        for pool_name in (
            "global_routes",
            "public_routes",
            "bootstrap_routes",
            "auth_exempt_routes",
            "docs_routes",
        ):
            for route_ex in getattr(plane, pool_name):
                _exception_health(
                    route_ex,
                    plane_id=plane.plane_id,
                    pool_name=pool_name,
                    warnings=warnings,
                    failures=failures,
                )

    runtime_keys = {(r["method"], r["path"]) for r in runtime}
    contract_keys = {(r["method"], r["path"]) for r in contract}
    missing_from_runtime = sorted(contract_keys - runtime_keys)
    missing_from_contract = sorted(runtime_keys - contract_keys)

    if missing_from_runtime:
        failures.append(f"contract-only routes detected: {missing_from_runtime}")
    if missing_from_contract:
        warnings.append(f"runtime-only routes detected: {missing_from_contract}")

    prod_like = os.getenv("PROD_LIKE", "0") == "1"

    for route in runtime:
        method = str(route["method"])
        path = str(route["path"])
        planes = match_plane(path)
        if not planes:
            failures.append(f"unexpected-route gap: {method} {path}")
            continue
        if len(planes) != 1:
            failures.append(f"multi-plane route ownership: {method} {path} -> {planes}")
            continue

        plane_id = planes[0]
        plane = next(p for p in PLANE_REGISTRY if p.plane_id == plane_id)
        exception_classes = route_exception_classes(plane_id, method, path)
        has_exception = bool(exception_classes)

        if path.startswith("/admin") and plane_id != "control":
            failures.append(
                f"admin-surface ownership violation under {ADMIN_PREFIX_POLICY}: {method} {path} owned by {plane_id}, expected control"
            )

        if prod_like and path.startswith(("/dev", "/_debug", "/_legacy")):
            failures.append(f"prod-like forbidden debug/legacy route: {method} {path}")

        if (
            plane.auth_class.require_any_scope
            and not route.get("scoped")
            and "public" not in exception_classes
            and "bootstrap" not in exception_classes
            and "auth_exempt" not in exception_classes
            and "docs" not in exception_classes
        ):
            failures.append(f"{method} {path} plane={plane_id} missing scoped auth")

        if (
            plane.auth_class.tenant_binding_required
            and not route.get("tenant_bound")
            and not has_exception
        ):
            failures.append(
                f"{method} {path} plane={plane_id} missing tenant binding without exact exception"
            )

        scopes = set(str(s) for s in (route.get("scopes") or []))
        prefixes = tuple(plane.auth_class.required_scope_prefixes)
        if (
            prefixes
            and scopes
            and not any(any(scope.startswith(p) for p in prefixes) for scope in scopes)
        ):
            failures.append(
                f"{method} {path} plane={plane_id} scopes violate policy: {sorted(scopes)}"
            )

        categories = set(str(c) for c in (route.get("dependency_categories") or []))
        allowed = set(plane.allowed_dependency_categories)
        if not categories.issubset(allowed):
            failures.append(
                f"{method} {path} plane={plane_id} dependency categories not allowed: {sorted(categories - allowed)}"
            )

    if args.use_runtime_app:
        runtime_app = runtime_routes_app()
        if runtime_app is None:
            in_ci = os.getenv("CI", "").strip().lower() in {"1", "true", "yes"}
            allow_missing = os.getenv("ALLOW_RUNTIME_APP_DEPS_MISSING", "0") == "1"
            if in_ci and not allow_missing:
                failures.append(
                    "runtime app route extraction unavailable in CI (set ALLOW_RUNTIME_APP_DEPS_MISSING=1 only for dev override)"
                )
            else:
                warnings.append(
                    "runtime app route extraction unavailable (dependency/import issue)"
                )
        else:
            app_keys = {(r["method"], r["path"]) for r in runtime_app}
            ast_only = sorted(runtime_keys - app_keys)
            app_only = sorted(app_keys - runtime_keys)
            if app_only:
                failures.append(f"runtime-app-only routes detected: {app_only}")
            if ast_only:
                warnings.append(f"ast-only routes detected: {ast_only}")

    if failures:
        print("plane registry check: FAILED")
        for f in sorted(set(failures)):
            print(f" - {f}")
        return 1

    for w in sorted(set(warnings)):
        print(f"plane registry check: WARNING {w}")

    print("plane registry check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
