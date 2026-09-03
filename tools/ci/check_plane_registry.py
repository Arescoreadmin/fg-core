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

# FastAPI framework-generated documentation/runtime surfaces.
# These may exist at runtime even when they are intentionally excluded from
# contract-plane ownership checks.
FRAMEWORK_ROUTE_ALLOWLIST: set[tuple[str, str]] = {
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/redoc"),
}

# Explicitly approved runtime compatibility aliases.
RUNTIME_ROUTE_ALIAS_ALLOWLIST: set[tuple[str, str]] = {
    ("POST", "/v1/defend"),
}

# Explicit public verification endpoints.
# These are intentionally public, read-only integrity verification surfaces.
EXACT_PUBLIC_ROUTE_EXCEPTIONS: set[tuple[str, str]] = {
    ("GET", "/field-assessment/reports/verify/{report_hash}"),
    # Invitation acceptance is intentionally unauthenticated — the pni1. token IS
    # the authorization. No service-account scope required.
    ("POST", "/portal/invitations/{token}/accept"),
    # Named-session revocation authorizes via the session's own pnu1. token in
    # X-FG-Portal-Session; no separate service-account scope dependency.
    ("DELETE", "/portal/named-sessions/{session_id}"),
    # Self-revocation variant: same auth pattern as /{session_id} — the pnu1.
    # token in X-FG-Portal-Session IS the credential; no service-account scope.
    ("DELETE", "/portal/named-sessions/self"),
    # pnu1. auth pattern: X-FG-Portal-Session token is the credential. Tenant
    # resolved via SECURITY DEFINER lookup_portal_session_by_fingerprint()
    # (migration 0171). validate_session() enforces auth_version, membership
    # state, and sets RLS context. Standard require_scopes dependency does not
    # apply to named-user session flows.
    ("GET", "/portal/named-users/me"),
}

EXACT_TENANT_BINDING_EXCEPTIONS: set[tuple[str, str]] = {
    # Internal admin-gateway validation of configured Console operator authority;
    # tenant_id is the candidate authority under review, not the caller tenant.
    ("GET", "/admin/tenants/{tenant_id}/operator-authority"),
    # IA-1 identity binding provisioning: tenant_id in path identifies the target
    # tenant being provisioned, not the caller. Caller authenticates via admin:write
    # scope; isolation enforced by provision_tenant_organization, not auth context.
    ("POST", "/admin/tenants/{tenant_id}/identity-bindings"),
    ("GET", "/field-assessment/reports/verify/{report_hash}"),
    # C7 portal grant/session routes enforce tenant isolation through
    # PortalGrantSession validation and PortalScopeMiddleware rather than
    # standard tenant-bound route parameters.
    ("POST", "/portal/authenticate"),
    ("GET", "/portal/me"),
    ("DELETE", "/portal/sessions/{session_id}"),
    # PR A named-user routes: tenant is resolved via _resolve_tenant(request) which
    # reads request.state.tenant_id — enforced by AuthGateMiddleware, not a
    # Depends() parameter the AST scanner recognises.
    ("POST", "/portal/named-users/enroll"),
    ("POST", "/portal/invitations"),
    ("POST", "/portal/invitations/{token}/accept"),
    ("DELETE", "/portal/named-sessions/{session_id}"),
    # Self-revocation: tenant is resolved server-side from the session record via
    # the SECURITY DEFINER function; no Depends() tenant parameter for the scanner.
    ("DELETE", "/portal/named-sessions/self"),
    # pnu1. auth pattern: tenant resolved via SECURITY DEFINER
    # lookup_portal_session_by_fingerprint() (migration 0171); validate_session()
    # calls _set_tenant_rls() before any tenant-scoped query. The standard
    # Depends() tenant parameter does not apply to named-user session flows.
    ("GET", "/portal/named-users/me"),
    # R4.9 retirement stub: POST /admin/keys always raises HTTP 410 Gone and
    # performs no tenant-scoped queries. Tenant binding is irrelevant — the
    # handler unconditionally rejects every request before touching any data.
    ("POST", "/admin/keys"),
    # TENANT-ADMIN-001 delegated admin routes: tenant_id in path identifies the
    # target tenant being managed, not the caller's auth-context tenant.
    # Bootstrap uses platform.admin + set_tenant_context(db, tenant_id).
    # Delegated routes use DB-canonical check_tenant_admin_authority which
    # enforces same-tenant via resolve_authoritative_tenant inside _dep.
    ("POST", "/admin/tenants/{tenant_id}/bootstrap-admin"),
    ("POST", "/admin/tenants/{tenant_id}/users/invite"),
    ("PATCH", "/admin/tenants/{tenant_id}/users/{user_id}"),
    ("GET", "/admin/tenants/{tenant_id}/portal-access"),
    ("POST", "/admin/tenants/{tenant_id}/portal-access/invite"),
    ("DELETE", "/admin/tenants/{tenant_id}/portal-access/{grant_id}"),
    # P-113.4 tenant service credential administration: same authority pattern as
    # other TENANT-ADMIN-001 routes above. require_tenant_admin() enforces same-tenant
    # isolation via resolve_authoritative_tenant + DB-canonical check_tenant_admin_authority.
    # credential_id parameter scopes within the already-verified tenant.
    ("GET", "/admin/tenants/{tenant_id}/credential-administration"),
    ("POST", "/admin/tenants/{tenant_id}/credential-administration"),
    ("GET", "/admin/tenants/{tenant_id}/credential-administration/rbac"),
    ("GET", "/admin/tenants/{tenant_id}/credential-administration/{credential_id}"),
    (
        "GET",
        "/admin/tenants/{tenant_id}/credential-administration/{credential_id}/events",
    ),
    (
        "POST",
        "/admin/tenants/{tenant_id}/credential-administration/{credential_id}/rotate",
    ),
    ("DELETE", "/admin/tenants/{tenant_id}/credential-administration/{credential_id}"),
    (
        "POST",
        "/admin/tenants/{tenant_id}/credential-administration/{credential_id}/suspend",
    ),
    (
        "POST",
        "/admin/tenants/{tenant_id}/credential-administration/{credential_id}/resume",
    ),
    (
        "PUT",
        "/admin/tenants/{tenant_id}/credential-administration/{credential_id}/role",
    ),
    # P-113.5 workforce membership lifecycle: revoke is an action sub-route on
    # /workforce/users/{user_id}/revoke. Tenant isolation is enforced by
    # require_bound_tenant(request) which reads request.state.tenant_id set by
    # AuthGateMiddleware — the same pattern as other workforce/users routes.
    ("POST", "/workforce/users/{user_id}/revoke"),
    # P-113.6 platform_admin credential authority: these routes operate on the
    # frostgate-internal tenant's platform_admin credential — a fixed, platform-level
    # identity that has no caller-tenant binding by design. Access is gated by
    # require_internal_admin_gateway() (X-FG-Internal-Token) + require_permission
    # ("platform.admin"). There is no per-caller tenant context to bind.
    ("GET", "/admin/system/platform-admin"),
    ("POST", "/admin/system/platform-admin/bootstrap"),
    ("POST", "/admin/system/platform-admin/rotate"),
    ("POST", "/admin/system/platform-admin/suspend"),
    ("POST", "/admin/system/platform-admin/resume"),
    ("POST", "/admin/system/platform-admin/revoke"),
}


def _exception_health(
    route_ex, *, plane_id: str, pool_name: str, warnings: list[str], failures: list[str]
) -> None:
    if not route_ex.justification.strip():
        failures.append(
            f"plane {plane_id} has unjustified exception in {pool_name}: "
            f"{route_ex.method} {route_ex.path}"
        )

    if not route_ex.permanent and not route_ex.expires_at.strip():
        failures.append(
            f"plane {plane_id} non-permanent exception missing expires_at in {pool_name}: "
            f"{route_ex.method} {route_ex.path}"
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
            "plane "
            f"{plane_id} exception has invalid expires_at (YYYY-MM-DD required) in "
            f"{pool_name}: {route_ex.method} {route_ex.path} -> {route_ex.expires_at}"
        )
        return

    now = datetime.now(tz=UTC)
    delta_days = (expires - now).days
    if delta_days > 90:
        failures.append(
            f"plane {plane_id} exception exceeds maximum 90-day horizon in {pool_name}: "
            f"{route_ex.method} {route_ex.path} expires {route_ex.expires_at}"
        )
    elif delta_days < 0:
        failures.append(
            f"plane {plane_id} exception exceeded 90-day expiry window in {pool_name}: "
            f"{route_ex.method} {route_ex.path} expired {route_ex.expires_at}"
        )
    elif delta_days <= 30:
        warnings.append(
            f"plane {plane_id} exception expires within 30 days in {pool_name}: "
            f"{route_ex.method} {route_ex.path} expires {route_ex.expires_at}"
        )


def _normalize_route_key(method: str, path: str) -> tuple[str, str]:
    return (str(method).upper().strip(), str(path).strip())


def _filter_runtime_app_only(
    routes: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    ignored = FRAMEWORK_ROUTE_ALLOWLIST | RUNTIME_ROUTE_ALIAS_ALLOWLIST
    normalized = {_normalize_route_key(method, path) for method, path in routes}
    return sorted(route for route in normalized if route not in ignored)


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

    runtime_keys = {_normalize_route_key(r["method"], r["path"]) for r in runtime}
    contract_keys = {_normalize_route_key(r["method"], r["path"]) for r in contract}
    missing_from_runtime = sorted(contract_keys - runtime_keys)
    missing_from_contract = sorted(runtime_keys - contract_keys)

    if missing_from_runtime:
        failures.append(f"contract-only routes detected: {missing_from_runtime}")
    if missing_from_contract:
        warnings.append(f"runtime-only routes detected: {missing_from_contract}")

    prod_like = os.getenv("PROD_LIKE", "0") == "1"

    for route in runtime:
        method = str(route["method"]).upper().strip()
        path = str(route["path"]).strip()
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
                f"admin-surface ownership violation under {ADMIN_PREFIX_POLICY}: "
                f"{method} {path} owned by {plane_id}, expected control"
            )

        if prod_like and path.startswith(("/dev", "/_debug", "/_legacy")):
            failures.append(f"prod-like forbidden debug/legacy route: {method} {path}")

        route_key = (method, path)

        if (
            plane.auth_class.require_any_scope
            and not route.get("scoped")
            and route_key not in EXACT_PUBLIC_ROUTE_EXCEPTIONS
            and "public" not in exception_classes
            and "bootstrap" not in exception_classes
            and "auth_exempt" not in exception_classes
            and "allowed_internal" not in exception_classes
            and "docs" not in exception_classes
        ):
            failures.append(f"{method} {path} plane={plane_id} missing scoped auth")

        if (
            plane.auth_class.tenant_binding_required
            and not route.get("tenant_bound")
            and route_key not in EXACT_TENANT_BINDING_EXCEPTIONS
            and not has_exception
        ):
            failures.append(
                f"{method} {path} plane={plane_id} missing tenant binding "
                "without exact exception"
            )

        scopes = {str(s) for s in (route.get("scopes") or [])}
        prefixes = tuple(plane.auth_class.required_scope_prefixes)
        if (
            prefixes
            and scopes
            and not any(any(scope.startswith(p) for p in prefixes) for scope in scopes)
        ):
            failures.append(
                f"{method} {path} plane={plane_id} scopes violate policy: "
                f"{sorted(scopes)}"
            )

        categories = {str(c) for c in (route.get("dependency_categories") or [])}
        allowed = set(plane.allowed_dependency_categories)
        if not categories.issubset(allowed):
            failures.append(
                f"{method} {path} plane={plane_id} dependency categories not allowed: "
                f"{sorted(categories - allowed)}"
            )

    if args.use_runtime_app:
        runtime_app = runtime_routes_app()
        if runtime_app is None:
            in_ci = os.getenv("CI", "").strip().lower() in {"1", "true", "yes"}
            allow_missing = os.getenv("ALLOW_RUNTIME_APP_DEPS_MISSING", "0") == "1"
            if in_ci and not allow_missing:
                failures.append(
                    "runtime app route extraction unavailable in CI "
                    "(set ALLOW_RUNTIME_APP_DEPS_MISSING=1 only for dev override)"
                )
            else:
                warnings.append(
                    "runtime app route extraction unavailable (dependency/import issue)"
                )
        else:
            app_keys = {
                _normalize_route_key(r["method"], r["path"]) for r in runtime_app
            }
            ast_only = sorted(runtime_keys - app_keys)
            app_only = _filter_runtime_app_only(list(app_keys - runtime_keys))

            if app_only:
                failures.append(f"runtime-app-only routes detected: {app_only}")
            if ast_only:
                warnings.append(f"ast-only routes detected: {ast_only}")

    if failures:
        print("plane registry check: FAILED")
        for failure in sorted(set(failures)):
            print(f" - {failure}")
        return 1

    for warning in sorted(set(warnings)):
        print(f"plane registry check: WARNING {warning}")

    print("plane registry check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
