#!/usr/bin/env python3
"""tools/testing/production/auth_harness_001.py — MODE-B-PROOF-HARDENING-001 Mode B.

Fail-closed, actor-aware, authenticated production verification using Playwright.
DISABLED BY DEFAULT. Requires explicit operator opt-in.

Activation (all three must be set):
  FG_PROD_AUTH_TEST_ENABLED=true          — operator opt-in (cannot be set in CI automatically)
  FG_PROD_TEST_EMAIL=<synthetic-identity> — dedicated test account email
  FG_PROD_TEST_PASSWORD=<password>        — dedicated test account password

Actor profiles (select with --actor-profile):
  internal_operator  — FrostGate operator; positive test on /dashboard (default)
  client_executive   — Client identity; positive test on /dashboard/executive;
                       /dashboard and admin routes must be denied

Checks — internal_operator:
  AUTH-001  Auth0 login page rendered (pre-credential)
  AUTH-002  Auth.js session established after login
  AUTH-003  Session cookie security attributes (Secure, HttpOnly, SameSite)
  AUTH-004  Authenticated access to /dashboard succeeds (internal-only route)
  AUTH-005  Unauthorized admin route fails closed
  AUTH-006  Logout clears Auth.js session cookie
  AUTH-007  Post-logout session endpoint returns empty user
  AUTH-008  Post-logout protected route redirects to /login
  AUTH-009  Auth0 SLO redirect issued on logout

Checks — client_executive (additional / replacement):
  AUTH-001  Auth0 login page rendered
  AUTH-002  Auth.js session established
  AUTH-003  Session cookie security attributes
  CLIENT-001  /dashboard/executive accessible to client_executive
  CLIENT-002  Tenant-scoped BFF read succeeds for bound synthetic tenant
  CLIENT-003  /dashboard denied to client_executive (→ /unauthorized)
  CLIENT-004  Platform-administration UI denied (→ /unauthorized)
  CLIENT-005  Platform-admin API denied (401/403)
  CLIENT-006  Cross-tenant Core API access denied (403)
  CLIENT-007  Forged/duplicate tenant context denied (422/403)
  AUTH-006  Logout clears session cookie
  AUTH-007  Post-logout session endpoint returns empty user
  AUTH-008  Post-logout protected route redirects to /login
  AUTH-009  Auth0 SLO redirect issued on logout

Required check manifests drive the acceptance decision — if any required check is
not PASS (whether FAIL, NOT_PROVEN, or BLOCKED), the run does not ACCEPT.

Exit codes:
  0 — ACCEPTED: all required checks PASS
  1 — REJECTED_FAIL: one or more checks FAIL
  2 — BLOCKED: activation guard not satisfied or harness prerequisite blocked
  3 — REJECTED_INCOMPLETE: NOT_PROVEN checks, missing checks, or empty evidence
  4 — Unrecoverable error (browser crash, unexpected exception)

MFA behavior:
  If Auth0 requires MFA and the automation cannot complete it, AUTH-002 and
  all downstream checks are marked BLOCKED. The overall result is REJECTED_INCOMPLETE
  (exit 3). Operator-assisted verification via the runbook is the authoritative fallback.

Never prints passwords, tokens, cookies, or authorization headers to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.testing.production.evidence import (  # noqa: E402
    AcceptanceDecision,
    CANONICAL_CHECK_MANIFESTS,
    CheckResult,
    EvidenceRecord,
    EvidenceResult,
    VALID_PROFILES,
    finalize,
    now_iso,
    repo_sha,
    write_evidence,
)

DEFAULT_CONSOLE_URL = "https://console.frostgate.ai"

_EVIDENCE_PATHS: dict[str, Path] = {
    "internal_operator": (
        _REPO_ROOT
        / "contracts"
        / "artifacts"
        / "identity"
        / "prod-auth-automation-001-auth-evidence.json"
    ),
    "client_executive": (
        _REPO_ROOT
        / "contracts"
        / "artifacts"
        / "identity"
        / "prod-auth-client-executive-evidence.json"
    ),
}

# Auth0 Universal Login form field selectors
_AUTH0_EMAIL_SELECTOR = 'input[name="username"], input[type="email"]'
_AUTH0_PASSWORD_SELECTOR = 'input[name="password"], input[type="password"]'
_AUTH0_SUBMIT_SELECTOR = 'button[type="submit"], button[name="action"]'

# Auth.js cookie names (production uses __Secure- prefix)
_SESSION_COOKIE_NAMES = (
    "__Secure-authjs.session-token",
    "authjs.session-token",
)

PLAYWRIGHT_TIMEOUT_MS = 30_000

# Canonical required check manifests live in evidence.py (CANONICAL_CHECK_MANIFESTS).
# Re-export as _REQUIRED_CHECKS for local use; harness and verifier share the same source.
_REQUIRED_CHECKS: dict[str, list[str]] = CANONICAL_CHECK_MANIFESTS


# ---------------------------------------------------------------------------
# Activation guard
# ---------------------------------------------------------------------------


def _activation_guard() -> tuple[bool, str]:
    """Check all activation conditions. Returns (ok, reason)."""
    enabled = os.environ.get("FG_PROD_AUTH_TEST_ENABLED", "").strip()
    if enabled != "true":
        return False, (
            "FG_PROD_AUTH_TEST_ENABLED is not set to 'true'. "
            "Mode B requires explicit operator opt-in. "
            "See docs/deployment/runbook-prod-auth-automation-001.md."
        )
    email = os.environ.get("FG_PROD_TEST_EMAIL", "").strip()
    if not email:
        return (
            False,
            "FG_PROD_TEST_EMAIL is not set. Provide a dedicated synthetic test identity.",
        )
    password = os.environ.get("FG_PROD_TEST_PASSWORD", "").strip()
    if not password:
        return False, "FG_PROD_TEST_PASSWORD is not set."
    return True, ""


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Shared auth helpers
# ---------------------------------------------------------------------------


def _blocked(cid: str, description: str, reason: str) -> CheckResult:
    """Produce a BLOCKED check result."""
    return CheckResult(
        id=cid,
        description=description,
        expected="N/A",
        observed=f"BLOCKED: {reason}",
        result=EvidenceResult.BLOCKED,
        timestamp=now_iso(),
        diagnostic=reason,
    )


def _not_proven(cid: str, description: str, reason: str) -> CheckResult:
    return CheckResult(
        id=cid,
        description=description,
        expected="N/A",
        observed=f"NOT_PROVEN: {reason}",
        result=EvidenceResult.NOT_PROVEN,
        timestamp=now_iso(),
        diagnostic=reason,
    )


def _remaining_blocked(
    check_ids: list[tuple[str, str]], blocking_reason: str
) -> list[CheckResult]:
    """Mark a list of (id, description) checks as BLOCKED due to a prerequisite failure."""
    return [_blocked(cid, desc, blocking_reason) for cid, desc in check_ids]


# ---------------------------------------------------------------------------
# AUTH checks (shared by all profiles)
# ---------------------------------------------------------------------------


def check_auth0_login_page(page: Any, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        page.goto(f"{base_url}/login", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        is_auth0 = "auth0.com" in current_url or "auth0" in current_url.lower()
        has_email_field = page.locator(_AUTH0_EMAIL_SELECTOR).count() > 0
        if is_auth0 or has_email_field:
            return CheckResult(
                id="AUTH-001",
                description="Auth0 login page rendered and interactive",
                expected="Auth0 Universal Login page with email input",
                observed=f"Auth0 page detected, email_field={has_email_field}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        has_auth0_button = (
            page.locator(
                'button:has-text("Auth0"), button:has-text("Sign in with Auth0")'
            ).count()
            > 0
        )
        if has_auth0_button:
            return CheckResult(
                id="AUTH-001",
                description="Auth0 login page rendered and interactive",
                expected="Auth0 sign-in button or Universal Login page",
                observed="FrostGate login page with Auth0 button",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        return CheckResult(
            id="AUTH-001",
            description="Auth0 login page rendered and interactive",
            expected="Auth0 Universal Login page with email input",
            observed=f"URL={current_url[:80]}",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic="Could not confirm Auth0 login page. May require operator inspection.",
        )
    except Exception as exc:
        return CheckResult(
            id="AUTH-001",
            description="Auth0 login page rendered and interactive",
            expected="Auth0 Universal Login page",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def _perform_login(
    page: Any, email: str, password: str, base_url: str
) -> tuple[bool, str, bool]:
    """Attempt Auth0 login. Returns (success, diagnostic, mfa_blocked)."""
    try:
        page.goto(
            f"{base_url}/api/auth/signin/auth0?prompt=login",
            timeout=PLAYWRIGHT_TIMEOUT_MS,
        )
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)

        email_field = page.locator(_AUTH0_EMAIL_SELECTOR).first
        if not email_field.is_visible(timeout=5000):
            continue_btn = page.locator('button:has-text("Continue")').first
            if continue_btn.is_visible(timeout=2000):
                continue_btn.click()
                page.wait_for_load_state("networkidle", timeout=10000)
            email_field = page.locator(_AUTH0_EMAIL_SELECTOR).first

        email_field.fill(email)

        continue_btn = page.locator('button:has-text("Continue")').first
        if continue_btn.is_visible(timeout=2000):
            continue_btn.click()
            page.wait_for_load_state("networkidle", timeout=10000)

        password_field = page.locator(_AUTH0_PASSWORD_SELECTOR).first
        if not password_field.is_visible(timeout=10000):
            diag = "Password field not visible after email entry — MFA challenge or CAPTCHA active"
            return False, diag, True

        password_field.fill(password)
        submit_btn = page.locator(_AUTH0_SUBMIT_SELECTOR).first
        submit_btn.click()

        page.wait_for_url(f"{base_url}/**", timeout=PLAYWRIGHT_TIMEOUT_MS)
        return True, "", False
    except Exception as exc:
        diag = f"{type(exc).__name__}: {str(exc)[:200]}"
        is_mfa = any(
            kw in diag.lower()
            for kw in ("mfa", "captcha", "bot", "challenge", "otp", "authenticat")
        )
        return False, diag, is_mfa


def check_session_established(
    page: Any, base_url: str, email: str, password: str
) -> tuple[CheckResult, bool]:
    """Attempt login and verify Auth.js session cookie. Returns (check, logged_in)."""
    ts = now_iso()
    login_ok, diag, mfa_blocked = _perform_login(page, email, password, base_url)
    if not login_ok:
        if mfa_blocked:
            return (
                CheckResult(
                    id="AUTH-002",
                    description="Auth.js session cookie established after login",
                    expected="Session cookie set, user signed in",
                    observed="BLOCKED (MFA or bot-detection active)",
                    result=EvidenceResult.BLOCKED,
                    timestamp=ts,
                    diagnostic=(
                        f"Login blocked by identity provider protection: {diag}. "
                        "Use operator-assisted verification (see runbook)."
                    ),
                ),
                False,
            )
        return (
            CheckResult(
                id="AUTH-002",
                description="Auth.js session cookie established after login",
                expected="Session cookie set after successful login",
                observed="Login failed",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=diag,
            ),
            False,
        )

    cookies = page.context.cookies()
    session_cookie = next(
        (c for c in cookies if c.get("name", "") in _SESSION_COOKIE_NAMES),
        None,
    )
    if not session_cookie:
        return (
            CheckResult(
                id="AUTH-002",
                description="Auth.js session cookie established after login",
                expected=f"Cookie named {_SESSION_COOKIE_NAMES[0]} or {_SESSION_COOKIE_NAMES[1]}",
                observed=f"No session cookie found (cookies={[c.get('name') for c in cookies]})",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic="Login appeared to succeed but no Auth.js session cookie was set",
            ),
            False,
        )
    return (
        CheckResult(
            id="AUTH-002",
            description="Auth.js session cookie established after login",
            expected="Session cookie set after successful login",
            observed=f"Cookie {session_cookie['name']} present",
            result=EvidenceResult.PASS,
            timestamp=ts,
        ),
        True,
    )


def check_cookie_security_attributes(page: Any) -> CheckResult:
    ts = now_iso()
    cookies = page.context.cookies()
    session_cookie = next(
        (c for c in cookies if c.get("name", "") in _SESSION_COOKIE_NAMES),
        None,
    )
    if not session_cookie:
        return _not_proven(
            "AUTH-003",
            "Session cookie has Secure, HttpOnly, SameSite attributes",
            "Session cookie not found (AUTH-002 may have failed)",
        )

    is_secure = session_cookie.get("secure", False)
    is_httponly = session_cookie.get("httpOnly", False)
    samesite = (session_cookie.get("sameSite", "") or "").lower()
    samesite_ok = samesite in ("lax", "strict")

    failures = []
    if not is_secure:
        failures.append("Secure=false")
    if not is_httponly:
        failures.append("HttpOnly=false")
    if not samesite_ok:
        failures.append(f"SameSite={samesite!r} (expected Lax or Strict)")

    observed = f"Secure={is_secure}, HttpOnly={is_httponly}, SameSite={samesite!r}"

    if failures:
        return CheckResult(
            id="AUTH-003",
            description="Session cookie has Secure, HttpOnly, SameSite attributes",
            expected="Secure=true, HttpOnly=true, SameSite in (Lax, Strict)",
            observed=observed,
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Missing security attributes: {', '.join(failures)}",
        )
    return CheckResult(
        id="AUTH-003",
        description="Session cookie has Secure, HttpOnly, SameSite attributes",
        expected="Secure=true, HttpOnly=true, SameSite in (Lax, Strict)",
        observed=observed,
        result=EvidenceResult.PASS,
        timestamp=ts,
    )


# ---------------------------------------------------------------------------
# Session data helper
# ---------------------------------------------------------------------------


def _get_session_data(page: Any, base_url: str) -> dict[str, Any]:
    """Fetch session data from /api/auth/session. Returns parsed body or {}."""
    try:
        import requests as req_lib

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        r = req_lib.get(
            f"{base_url}/api/auth/session",
            timeout=10,
            cookies=cookies,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            return r.json() or {}
    except Exception:
        pass
    return {}


def _extract_tenant_id(session_data: dict[str, Any]) -> Optional[str]:
    """Extract tenantId from Auth.js session data (user or token sub-objects)."""
    for obj in (
        session_data,
        session_data.get("user", {}),
        session_data.get("token", {}),
    ):
        if not isinstance(obj, dict):
            continue
        for key in ("tenantId", "tenant_id", "https://frostgate.ai/tenant_id"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


# ---------------------------------------------------------------------------
# internal_operator checks
# ---------------------------------------------------------------------------


def check_dashboard_access(page: Any, base_url: str) -> CheckResult:
    """AUTH-004: /dashboard accessible to internal_operator."""
    ts = now_iso()
    try:
        response = page.goto(f"{base_url}/dashboard", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        on_dashboard = "/dashboard" in current_url
        status = response.status if response else 0
        if on_dashboard and status == 200:
            return CheckResult(
                id="AUTH-004",
                description="Authenticated access to /dashboard succeeds (internal operator)",
                expected="HTTP 200, browser on /dashboard",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        return CheckResult(
            id="AUTH-004",
            description="Authenticated access to /dashboard succeeds (internal operator)",
            expected="HTTP 200, browser on /dashboard",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic="Dashboard not accessible after authentication",
        )
    except Exception as exc:
        return CheckResult(
            id="AUTH-004",
            description="Authenticated access to /dashboard succeeds (internal operator)",
            expected="HTTP 200, browser on /dashboard",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_unauthorized_route_rejected(page: Any, base_url: str) -> CheckResult:
    """AUTH-005: Protected admin route not accessible to the test identity."""
    ts = now_iso()
    try:
        response = page.goto(
            f"{base_url}/api/admin/provision-tenant",
            timeout=PLAYWRIGHT_TIMEOUT_MS,
        )
        page.wait_for_load_state("load", timeout=10000)
        status = response.status if response else 0
        current_url = page.url
        is_rejected = (
            status in (401, 403, 405)
            or "/unauthorized" in current_url
            or "/login" in current_url
        )
        if is_rejected:
            return CheckResult(
                id="AUTH-005",
                description="Unauthorized admin route fails closed",
                expected="401/403/405 or redirect to /unauthorized",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        return CheckResult(
            id="AUTH-005",
            description="Unauthorized admin route fails closed",
            expected="401/403/405 or redirect to /unauthorized",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Admin route accessible with test identity (status={status})",
        )
    except Exception as exc:
        return CheckResult(
            id="AUTH-005",
            description="Unauthorized admin route fails closed",
            expected="401/403/405 or redirect to /unauthorized",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# client_executive checks
# ---------------------------------------------------------------------------


def check_client_executive_route(page: Any, base_url: str) -> CheckResult:
    """CLIENT-001: /dashboard/executive accessible to client_executive."""
    ts = now_iso()
    try:
        response = page.goto(
            f"{base_url}/dashboard/executive", timeout=PLAYWRIGHT_TIMEOUT_MS
        )
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        on_route = "/dashboard/executive" in current_url
        status = response.status if response else 0
        if on_route and status == 200:
            return CheckResult(
                id="CLIENT-001",
                description="/dashboard/executive accessible to client_executive",
                expected="HTTP 200, browser on /dashboard/executive",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        # May redirect to /unauthorized or /login on access failure
        if "/unauthorized" in current_url or "/login" in current_url:
            return CheckResult(
                id="CLIENT-001",
                description="/dashboard/executive accessible to client_executive",
                expected="HTTP 200, browser on /dashboard/executive",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic="client_executive denied access to /dashboard/executive",
            )
        return CheckResult(
            id="CLIENT-001",
            description="/dashboard/executive accessible to client_executive",
            expected="HTTP 200, browser on /dashboard/executive",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Expected /dashboard/executive, landed on {current_url[:80]}",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-001",
            description="/dashboard/executive accessible to client_executive",
            expected="HTTP 200, browser on /dashboard/executive",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_client_bff_read(
    page: Any, base_url: str, tenant_id: Optional[str]
) -> CheckResult:
    """CLIENT-002: Tenant-scoped BFF read succeeds for bound synthetic tenant."""
    ts = now_iso()
    if not tenant_id:
        return _blocked(
            "CLIENT-002",
            "Tenant-scoped BFF read succeeds for bound synthetic tenant",
            "tenant_id not found in session — principal-tenant binding not established; "
            "ensure the synthetic test identity has a tenant binding via Core API.",
        )
    try:
        import requests as req_lib

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        # Probe a client-accessible read-only BFF endpoint with the session tenant
        r = req_lib.get(
            f"{base_url}/api/core/api/executive/summary",
            timeout=15,
            cookies=cookies,
            headers={"Accept": "application/json"},
            params={"tenant_id": tenant_id},
        )
        # 200: PASS; 404 may mean route doesn't exist (NOT_PROVEN); 401/403: FAIL
        if r.status_code == 200:
            return CheckResult(
                id="CLIENT-002",
                description="Tenant-scoped BFF read succeeds for bound synthetic tenant",
                expected="HTTP 200 for client-accessible BFF endpoint",
                observed=f"HTTP {r.status_code}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        if r.status_code == 404:
            # Route may not exist — try decisions endpoint as fallback
            r2 = req_lib.get(
                f"{base_url}/api/core/decisions",
                timeout=15,
                cookies=cookies,
                headers={"Accept": "application/json"},
                params={"tenant_id": tenant_id},
            )
            if r2.status_code == 200:
                return CheckResult(
                    id="CLIENT-002",
                    description="Tenant-scoped BFF read succeeds for bound synthetic tenant",
                    expected="HTTP 200 for client-accessible BFF endpoint",
                    observed=f"HTTP {r2.status_code} (decisions endpoint)",
                    result=EvidenceResult.PASS,
                    timestamp=ts,
                )
            if r2.status_code == 404:
                return _not_proven(
                    "CLIENT-002",
                    "Tenant-scoped BFF read succeeds for bound synthetic tenant",
                    "Client-accessible BFF endpoint returned 404 — route may not exist "
                    "in this deployment; verify BFF routes are present.",
                )
            return CheckResult(
                id="CLIENT-002",
                description="Tenant-scoped BFF read succeeds for bound synthetic tenant",
                expected="HTTP 200",
                observed=f"HTTP {r2.status_code}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=f"BFF read denied: {r2.status_code}",
            )
        return CheckResult(
            id="CLIENT-002",
            description="Tenant-scoped BFF read succeeds for bound synthetic tenant",
            expected="HTTP 200",
            observed=f"HTTP {r.status_code}",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"BFF read denied: {r.status_code}",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-002",
            description="Tenant-scoped BFF read succeeds for bound synthetic tenant",
            expected="HTTP 200",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_internal_dashboard_denied(page: Any, base_url: str) -> CheckResult:
    """CLIENT-003: /dashboard denied to client_executive (redirect to /unauthorized)."""
    ts = now_iso()
    try:
        response = page.goto(f"{base_url}/dashboard", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        status = response.status if response else 0
        # Authenticated client_executive is NOT redirected to /login (they ARE logged in).
        # Console middleware redirects them to /unauthorized.
        is_denied = "/unauthorized" in current_url
        if is_denied:
            return CheckResult(
                id="CLIENT-003",
                description="/dashboard denied to client_executive",
                expected="Redirect to /unauthorized (internal-only route)",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        if "/dashboard" in current_url and status == 200:
            return CheckResult(
                id="CLIENT-003",
                description="/dashboard denied to client_executive",
                expected="Redirect to /unauthorized (internal-only route)",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=(
                    "client_executive was ALLOWED to access /dashboard — "
                    "internal-only route not properly restricted"
                ),
            )
        # Also accept /login redirect as denial (session may have been invalidated)
        if "/login" in current_url:
            return CheckResult(
                id="CLIENT-003",
                description="/dashboard denied to client_executive",
                expected="Redirect to /unauthorized (internal-only route)",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
                diagnostic="Redirected to /login (acceptable denial; session may have expired)",
            )
        return CheckResult(
            id="CLIENT-003",
            description="/dashboard denied to client_executive",
            expected="Redirect to /unauthorized (internal-only route)",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=f"Unexpected landing URL: {current_url[:80]}",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-003",
            description="/dashboard denied to client_executive",
            expected="Redirect to /unauthorized",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_platform_admin_ui_denied(page: Any, base_url: str) -> CheckResult:
    """CLIENT-004: Platform-administration UI denied to client_executive."""
    ts = now_iso()
    try:
        response = page.goto(f"{base_url}/admin/tenants", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        status = response.status if response else 0
        is_denied = "/unauthorized" in current_url or "/login" in current_url
        if is_denied:
            return CheckResult(
                id="CLIENT-004",
                description="Platform-administration UI denied to client_executive",
                expected="Redirect to /unauthorized or /login",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        if "/admin/tenants" in current_url and status == 200:
            return CheckResult(
                id="CLIENT-004",
                description="Platform-administration UI denied to client_executive",
                expected="Redirect to /unauthorized",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=(
                    "client_executive was ALLOWED to access /admin/tenants — "
                    "platform-admin route not properly restricted"
                ),
            )
        return CheckResult(
            id="CLIENT-004",
            description="Platform-administration UI denied to client_executive",
            expected="Redirect to /unauthorized",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=f"Unexpected URL: {current_url[:80]}",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-004",
            description="Platform-administration UI denied to client_executive",
            expected="Redirect to /unauthorized",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_platform_admin_api_denied(page: Any, base_url: str) -> CheckResult:
    """CLIENT-005: Platform-admin API denied to client_executive (401/403)."""
    ts = now_iso()
    try:
        import requests as req_lib

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        # Probe an internal-only read-only Core API endpoint via Console BFF.
        # stats/summary and health/ready are INTERNAL_ONLY_ROLES in CORE_API_POLICIES.
        for probe_path in ("stats/summary", "health/ready"):
            r = req_lib.get(
                f"{base_url}/api/core/{probe_path}",
                timeout=15,
                cookies=cookies,
                headers={"Accept": "application/json"},
            )
            if r.status_code in (401, 403):
                return CheckResult(
                    id="CLIENT-005",
                    description="Platform-admin API denied to client_executive",
                    expected="401 or 403 for internal-only Core API endpoint",
                    observed=f"HTTP {r.status_code} (/{probe_path})",
                    result=EvidenceResult.PASS,
                    timestamp=ts,
                )
            if r.status_code == 200:
                return CheckResult(
                    id="CLIENT-005",
                    description="Platform-admin API denied to client_executive",
                    expected="401 or 403 for internal-only Core API endpoint",
                    observed=f"HTTP {r.status_code} (/{probe_path}) — NOT DENIED",
                    result=EvidenceResult.FAIL,
                    timestamp=ts,
                    diagnostic=(
                        f"client_executive received HTTP 200 on internal-only endpoint "
                        f"/api/core/{probe_path} — BFF authorization not enforced"
                    ),
                )
            # 404 or other: endpoint may not exist in BFF — try next probe
        return _not_proven(
            "CLIENT-005",
            "Platform-admin API denied to client_executive",
            "All probed internal-only BFF endpoints returned 404 or unexpected status — "
            "routes may not exist in this deployment; verify /api/core/* BFF routes.",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-005",
            description="Platform-admin API denied to client_executive",
            expected="401 or 403 for internal-only endpoint",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_cross_tenant_denied(
    page: Any, base_url: str, session_tenant_id: Optional[str]
) -> CheckResult:
    """CLIENT-006: Cross-tenant Core API access denied (403 TENANT_AUTHORITY_DENIED)."""
    ts = now_iso()
    if not session_tenant_id:
        return _blocked(
            "CLIENT-006",
            "Cross-tenant Core API access denied",
            "Session tenant_id not available — cannot construct a cross-tenant request; "
            "ensure the synthetic test identity has a tenant binding.",
        )
    try:
        import requests as req_lib

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        # Attempt to read a tenant-scoped endpoint with a fabricated different tenant_id.
        # resolveTenantRequestAuthority() must return TENANT_AUTHORITY_DENIED (403).
        fabricated_tenant_id = f"synthetic-cross-tenant-probe-{uuid.uuid4().hex[:8]}"
        r = req_lib.get(
            f"{base_url}/api/core/decisions",
            timeout=15,
            cookies=cookies,
            headers={"Accept": "application/json"},
            params={"tenant_id": fabricated_tenant_id},
        )
        if r.status_code == 403:
            return CheckResult(
                id="CLIENT-006",
                description="Cross-tenant Core API access denied",
                expected="HTTP 403 (TENANT_AUTHORITY_DENIED)",
                observed=f"HTTP {r.status_code}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        if r.status_code == 200:
            return CheckResult(
                id="CLIENT-006",
                description="Cross-tenant Core API access denied",
                expected="HTTP 403 (TENANT_AUTHORITY_DENIED)",
                observed=f"HTTP {r.status_code} — cross-tenant access NOT denied",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=(
                    "BFF allowed cross-tenant read with fabricated tenant_id — "
                    "tenant boundary enforcement failed"
                ),
            )
        if r.status_code == 404:
            return _not_proven(
                "CLIENT-006",
                "Cross-tenant Core API access denied",
                "Decisions endpoint returned 404 — route may not exist; "
                "verify /api/core/decisions BFF route.",
            )
        return _not_proven(
            "CLIENT-006",
            "Cross-tenant Core API access denied",
            f"Unexpected HTTP {r.status_code} from decisions endpoint",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-006",
            description="Cross-tenant Core API access denied",
            expected="HTTP 403",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_forged_tenant_denied(page: Any, base_url: str) -> CheckResult:
    """CLIENT-007: Forged or ambiguous tenant context denied (422/403)."""
    ts = now_iso()
    try:
        import requests as req_lib

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        # Duplicate tenant_id query params → resolveTenantRequestAuthority()
        # returns TENANT_CONTEXT_AMBIGUOUS (422) when queryTenantIds.length > 1.
        # requests library joins duplicate keys correctly.
        r = req_lib.get(
            f"{base_url}/api/core/decisions",
            timeout=15,
            cookies=cookies,
            headers={"Accept": "application/json"},
            params=[
                ("tenant_id", "forge-tenant-alpha"),
                ("tenant_id", "forge-tenant-beta"),
            ],
        )
        if r.status_code in (422, 403):
            return CheckResult(
                id="CLIENT-007",
                description="Forged/duplicate tenant context denied",
                expected="HTTP 422 (TENANT_CONTEXT_AMBIGUOUS) or 403",
                observed=f"HTTP {r.status_code}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        if r.status_code == 200:
            return CheckResult(
                id="CLIENT-007",
                description="Forged/duplicate tenant context denied",
                expected="HTTP 422 or 403",
                observed=f"HTTP {r.status_code} — ambiguous context NOT rejected",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=(
                    "BFF accepted a request with duplicate tenant_id query params — "
                    "TENANT_CONTEXT_AMBIGUOUS not enforced"
                ),
            )
        if r.status_code == 404:
            return _not_proven(
                "CLIENT-007",
                "Forged/duplicate tenant context denied",
                "Decisions endpoint returned 404 — verify /api/core/decisions BFF route.",
            )
        return _not_proven(
            "CLIENT-007",
            "Forged/duplicate tenant context denied",
            f"Unexpected HTTP {r.status_code} from decisions endpoint",
        )
    except Exception as exc:
        return CheckResult(
            id="CLIENT-007",
            description="Forged/duplicate tenant context denied",
            expected="HTTP 422 or 403",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Shared logout / session lifecycle checks
# ---------------------------------------------------------------------------


def check_logout_clears_session(
    page: Any, base_url: str
) -> tuple[CheckResult, CheckResult, CheckResult]:
    """AUTH-006/007/008: Logout and session invalidation."""
    ts6 = now_iso()

    try:
        page.goto(f"{base_url}/api/auth/logout", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
    except Exception as exc:
        blocked = "BLOCKED (logout navigation failed)"
        reason = type(exc).__name__
        return (
            CheckResult(
                id="AUTH-006",
                description="Logout clears Auth.js session cookie",
                expected="Session cookie deleted after logout",
                observed=blocked,
                result=EvidenceResult.FAIL,
                timestamp=ts6,
                diagnostic=reason,
            ),
            _not_proven(
                "AUTH-007",
                "Post-logout session endpoint returns empty user",
                "logout failed",
            ),
            _not_proven(
                "AUTH-008",
                "Post-logout protected route redirects to /login",
                "logout failed",
            ),
        )

    # AUTH-006: session cookie should be gone
    ts6b = now_iso()
    cookies = page.context.cookies()
    session_cookie = next(
        (c for c in cookies if c.get("name", "") in _SESSION_COOKIE_NAMES),
        None,
    )
    if session_cookie:
        check6 = CheckResult(
            id="AUTH-006",
            description="Logout clears Auth.js session cookie",
            expected="Session cookie deleted after logout",
            observed=f"Session cookie {session_cookie['name']} still present",
            result=EvidenceResult.FAIL,
            timestamp=ts6b,
            diagnostic="Auth.js cookie not cleared after logout",
        )
    else:
        check6 = CheckResult(
            id="AUTH-006",
            description="Logout clears Auth.js session cookie",
            expected="Session cookie deleted after logout",
            observed="No session cookie found (cleared)",
            result=EvidenceResult.PASS,
            timestamp=ts6b,
        )

    # AUTH-007: session endpoint should return empty/null user
    ts7 = now_iso()
    try:
        import requests as req_lib

        r = req_lib.get(
            f"{base_url}/api/auth/session",
            timeout=10,
            cookies={c["name"]: c["value"] for c in page.context.cookies()},
        )
        body = r.json() if r.status_code == 200 else {}
        user = body.get("user")
        has_user = user is not None and user != {} and user != ""
        check7 = CheckResult(
            id="AUTH-007",
            description="Post-logout session endpoint returns empty user",
            expected="{}  or  no user field",
            observed=f"status={r.status_code}, user={'present' if has_user else 'absent/null'}",
            result=EvidenceResult.PASS if not has_user else EvidenceResult.FAIL,
            timestamp=ts7,
            diagnostic="Session still active after logout" if has_user else None,
        )
    except Exception as exc:
        check7 = _not_proven(
            "AUTH-007",
            "Post-logout session endpoint returns empty user",
            type(exc).__name__,
        )

    # AUTH-008: /dashboard post-logout should redirect to /login
    ts8 = now_iso()
    try:
        response = page.goto(f"{base_url}/dashboard", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        on_login = "/login" in current_url
        status = response.status if response else 0
        check8 = CheckResult(
            id="AUTH-008",
            description="Post-logout protected route redirects to /login",
            expected="Redirect to /login after session invalidation",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.PASS if on_login else EvidenceResult.FAIL,
            timestamp=ts8,
            diagnostic=(
                None
                if on_login
                else "Route accessible after logout — session not invalidated"
            ),
        )
    except Exception as exc:
        check8 = _not_proven(
            "AUTH-008",
            "Post-logout protected route redirects to /login",
            type(exc).__name__,
        )

    return check6, check7, check8


def check_auth0_slo_redirect(page: Any, base_url: str) -> CheckResult:
    """AUTH-009: Logout issues a redirect to Auth0 /v2/logout (application-layer logout)."""
    ts = now_iso()
    redirected_urls: list[str] = []

    def on_request(request: Any) -> None:
        if "auth0.com" in request.url and "/v2/logout" in request.url:
            redirected_urls.append(request.url)

    page.on("request", on_request)
    try:
        page.goto(f"{base_url}/api/auth/logout", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
    except Exception:
        pass

    if redirected_urls:
        return CheckResult(
            id="AUTH-009",
            description="Logout issues Auth0 SLO redirect (/v2/logout)",
            expected="Request to Auth0 /v2/logout",
            observed="Auth0 /v2/logout request observed",
            result=EvidenceResult.PASS,
            timestamp=ts,
        )
    # Not observable: server-side redirect or SSO managed outside browser
    return CheckResult(
        id="AUTH-009",
        description="Logout issues Auth0 SLO redirect (/v2/logout)",
        expected="Request to Auth0 /v2/logout",
        observed="NOT_PROVEN (redirect may be server-side)",
        result=EvidenceResult.NOT_PROVEN,
        timestamp=ts,
        diagnostic=(
            "Auth0 SLO may occur server-side. Verify via Auth0 Dashboard session logs. "
            "Upstream SSO session termination requires independent manual proof."
        ),
    )


# ---------------------------------------------------------------------------
# Profile runners
# ---------------------------------------------------------------------------


def _run_internal_operator(
    page: Any, base_url: str, email: str, password: str
) -> list[CheckResult]:
    checks: list[CheckResult] = []

    checks.append(check_auth0_login_page(page, base_url))

    session_check, logged_in = check_session_established(
        page, base_url, email, password
    )
    checks.append(session_check)

    if not logged_in:
        # AUTH-002 may be BLOCKED (MFA) or FAIL — propagate as BLOCKED for remaining
        block_reason = (
            "AUTH-002 BLOCKED by MFA"
            if session_check.result == EvidenceResult.BLOCKED
            else "AUTH-002 login FAIL"
        )
        block_status = (
            EvidenceResult.BLOCKED
            if session_check.result == EvidenceResult.BLOCKED
            else EvidenceResult.NOT_PROVEN
        )
        remaining = [
            ("AUTH-003", "Session cookie security attributes"),
            ("AUTH-004", "Authenticated access to /dashboard"),
            ("AUTH-005", "Unauthorized admin route fails closed"),
            ("AUTH-006", "Logout clears session cookie"),
            ("AUTH-007", "Post-logout session empty"),
            ("AUTH-008", "Post-logout protected route redirects"),
            ("AUTH-009", "Auth0 SLO redirect"),
        ]
        for cid, cdesc in remaining:
            checks.append(
                CheckResult(
                    id=cid,
                    description=cdesc,
                    expected="N/A",
                    observed=f"{'BLOCKED' if block_status == EvidenceResult.BLOCKED else 'NOT_PROVEN'}: {block_reason}",
                    result=block_status,
                    timestamp=now_iso(),
                    diagnostic=block_reason,
                )
            )
        return checks

    checks.append(check_cookie_security_attributes(page))
    checks.append(check_dashboard_access(page, base_url))
    checks.append(check_unauthorized_route_rejected(page, base_url))
    c6, c7, c8 = check_logout_clears_session(page, base_url)
    checks.extend([c6, c7, c8])
    checks.append(check_auth0_slo_redirect(page, base_url))
    return checks


def _run_client_executive(
    page: Any, base_url: str, email: str, password: str
) -> list[CheckResult]:
    checks: list[CheckResult] = []

    checks.append(check_auth0_login_page(page, base_url))

    session_check, logged_in = check_session_established(
        page, base_url, email, password
    )
    checks.append(session_check)

    if not logged_in:
        block_reason = (
            "AUTH-002 BLOCKED by MFA"
            if session_check.result == EvidenceResult.BLOCKED
            else "AUTH-002 login FAIL"
        )
        block_status = (
            EvidenceResult.BLOCKED
            if session_check.result == EvidenceResult.BLOCKED
            else EvidenceResult.NOT_PROVEN
        )
        remaining = [
            ("AUTH-003", "Session cookie security attributes"),
            ("CLIENT-001", "/dashboard/executive accessible to client_executive"),
            ("CLIENT-002", "Tenant-scoped BFF read succeeds"),
            ("CLIENT-003", "/dashboard denied to client_executive"),
            ("CLIENT-004", "Platform-administration UI denied"),
            ("CLIENT-005", "Platform-admin API denied"),
            ("CLIENT-006", "Cross-tenant Core API access denied"),
            ("CLIENT-007", "Forged/duplicate tenant context denied"),
            ("AUTH-006", "Logout clears session cookie"),
            ("AUTH-007", "Post-logout session empty"),
            ("AUTH-008", "Post-logout protected route redirects"),
            ("AUTH-009", "Auth0 SLO redirect"),
        ]
        for cid, cdesc in remaining:
            checks.append(
                CheckResult(
                    id=cid,
                    description=cdesc,
                    expected="N/A",
                    observed=f"{'BLOCKED' if block_status == EvidenceResult.BLOCKED else 'NOT_PROVEN'}: {block_reason}",
                    result=block_status,
                    timestamp=now_iso(),
                    diagnostic=block_reason,
                )
            )
        return checks

    checks.append(check_cookie_security_attributes(page))

    # Retrieve session data to extract tenant_id for tenant-aware checks
    session_data = _get_session_data(page, base_url)
    tenant_id = _extract_tenant_id(session_data)

    checks.append(check_client_executive_route(page, base_url))
    checks.append(check_client_bff_read(page, base_url, tenant_id))
    checks.append(check_internal_dashboard_denied(page, base_url))
    checks.append(check_platform_admin_ui_denied(page, base_url))
    checks.append(check_platform_admin_api_denied(page, base_url))
    checks.append(check_cross_tenant_denied(page, base_url, tenant_id))
    checks.append(check_forged_tenant_denied(page, base_url))

    c6, c7, c8 = check_logout_clears_session(page, base_url)
    checks.extend([c6, c7, c8])
    checks.append(check_auth0_slo_redirect(page, base_url))
    return checks


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_auth_harness(
    base_url: str,
    headless: bool = True,
    actor_profile: str = "internal_operator",
    workflow_run_id: str = "",
) -> EvidenceRecord:
    run_id = str(uuid.uuid4())
    start_ts = now_iso()
    email = os.environ["FG_PROD_TEST_EMAIL"].strip()
    # Password is used but never stored, printed, or included in evidence
    password = os.environ["FG_PROD_TEST_PASSWORD"].strip()

    record = EvidenceRecord(
        timestamp=start_ts,
        run_id=run_id,
        repo_sha=repo_sha(),
        verification_profile=actor_profile,
        environment="production",
        console_origin=base_url,
        verification_environment="authenticated_playwright",
        test_execution_mode="automated",
        evidence_provenance=f"Playwright browser automation; actor_profile={actor_profile}",
        workflow_run_id=workflow_run_id or os.environ.get("GITHUB_RUN_ID", ""),
        test_identity_ref=f"synthetic:{email.split('@')[0]}@[domain-redacted]",
        required_check_manifest=_REQUIRED_CHECKS.get(actor_profile, []),
    )

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(base_url=base_url)
        page = context.new_page()
        page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)

        try:
            if actor_profile == "client_executive":
                checks = _run_client_executive(page, base_url, email, password)
            else:
                checks = _run_internal_operator(page, base_url, email, password)
        finally:
            context.close()
            browser.close()

    record.checks = checks
    finalize(record)
    return record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_RESULT_SYMBOLS: dict[str, str] = {
    "PASS": "[PASS]",
    "FAIL": "[FAIL]",
    "NOT_PROVEN": "[????]",
    "BLOCKED": "[BLKD]",
}


def _print_summary(record: EvidenceRecord, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(record.to_dict(), indent=2, ensure_ascii=False))
        return

    profile = record.verification_profile
    print("=" * 64)
    print("MODE-B-PROOF-HARDENING-001 — Mode B: Authenticated Playwright")
    print(f"Actor profile: {profile}")
    print("=" * 64)
    print(f"Run ID:        {record.run_id}")
    print(f"Timestamp:     {record.timestamp}")
    print(f"Repo SHA:      {record.repo_sha}")
    print(f"Console:       {record.console_origin}")
    print(f"Identity:      {record.test_identity_ref}")
    print()

    for check in record.checks:
        symbol = _RESULT_SYMBOLS.get(check.result.value, "[????]")
        print(f"  {symbol} {check.id}: {check.description}")
        if check.result != EvidenceResult.PASS:
            print(f"           expected: {check.expected}")
            print(f"           observed: {check.observed}")
        if check.diagnostic:
            print(f"           note:     {check.diagnostic}")

    print()
    print(f"Overall:            {record.overall_result.value}")
    print(f"Acceptance:         {record.acceptance_decision}")
    print(f"Fingerprint:        {record.evidence_fingerprint}")
    manifest = record.required_check_manifest
    if manifest:
        print(f"Required manifest:  {manifest}")
    print("=" * 64)


def _exit_code_for_acceptance(decision: str) -> int:
    if decision == AcceptanceDecision.ACCEPTED.value:
        return 0
    if decision == AcceptanceDecision.REJECTED_FAIL.value:
        return 1
    if decision == AcceptanceDecision.REJECTED_EMPTY.value:
        return 3
    # REJECTED_INCOMPLETE covers NOT_PROVEN and BLOCKED
    return 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MODE-B-PROOF-HARDENING-001 Mode B — fail-closed authenticated verification"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("FG_PROD_SMOKE_URL", DEFAULT_CONSOLE_URL),
        help="Console base URL",
    )
    parser.add_argument(
        "--headless",
        default="true",
        choices=["true", "false"],
        help="Run browser headless (default: true)",
    )
    parser.add_argument(
        "--actor-profile",
        default=os.environ.get("FG_PROD_ACTOR_PROFILE", "internal_operator"),
        choices=VALID_PROFILES,
        dest="actor_profile",
        help=f"Actor profile to verify ({', '.join(VALID_PROFILES)})",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="Write evidence JSON to the profile-specific path",
    )
    parser.add_argument(
        "--evidence-path",
        default="",
        help="Override evidence output path",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print evidence JSON to stdout",
    )
    args = parser.parse_args(argv)

    # Activation guard — exit 2 (BLOCKED) on failure
    ok, reason = _activation_guard()
    if not ok:
        print(
            f"ERROR: Mode B activation guard not satisfied: {reason}", file=sys.stderr
        )
        print(
            "See docs/deployment/runbook-prod-auth-automation-001.md for operator-assisted fallback.",
            file=sys.stderr,
        )
        return 2

    if not _playwright_available():
        print(
            "ERROR: 'playwright' package is not installed. "
            "Run: pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 2

    base_url = args.url.rstrip("/")
    headless = args.headless == "true"
    print(f"Running authenticated harness against: {base_url}", file=sys.stderr)
    print(f"Actor profile: {args.actor_profile}", file=sys.stderr)
    print(
        f"Identity: {os.environ.get('FG_PROD_TEST_EMAIL', '').split('@')[0]}@[domain-redacted]",
        file=sys.stderr,
    )

    try:
        record = run_auth_harness(
            base_url,
            headless=headless,
            actor_profile=args.actor_profile,
        )
    except KeyboardInterrupt:
        return 4
    except Exception as exc:
        print(f"ERROR: Unrecoverable error: {exc}", file=sys.stderr)
        return 4

    if args.write_evidence or args.evidence_path:
        evidence_path = (
            Path(args.evidence_path)
            if args.evidence_path
            else _EVIDENCE_PATHS.get(
                args.actor_profile, _EVIDENCE_PATHS["internal_operator"]
            )
        )
        write_evidence(record, evidence_path)
        print(f"Evidence written: {evidence_path}", file=sys.stderr)

    _print_summary(record, output_json=args.output_json)

    return _exit_code_for_acceptance(record.acceptance_decision)


if __name__ == "__main__":
    sys.exit(main())
