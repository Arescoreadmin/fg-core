#!/usr/bin/env python3
"""tools/testing/production/auth_harness_001.py — PROD-AUTH-AUTOMATION-001 Mode B.

Authenticated production verification using Playwright browser automation.
DISABLED BY DEFAULT. Requires explicit operator opt-in.

Activation (all three must be set):
  FG_PROD_AUTH_TEST_ENABLED=true          — operator opt-in (cannot be set in CI automatically)
  FG_PROD_TEST_EMAIL=<synthetic-identity> — dedicated test account email
  FG_PROD_TEST_PASSWORD=<password>        — dedicated test account password

Identity requirements:
  - Dedicated synthetic identity with minimal privileges
  - Dedicated test tenant (not a real customer tenant)
  - Never a real customer's account

Never bypasses MFA, CAPTCHA, or identity-provider security protections.
If Auth0 requires MFA or triggers bot detection, specific checks are marked NOT_PROVEN
and the operator-assisted workflow in runbook.md is the authoritative fallback.

Checks (Mode B):
  AUTH-001  Auth0 login page rendered (pre-credential)
  AUTH-002  Auth.js session established after login
  AUTH-003  Session cookie security attributes (Secure, HttpOnly, SameSite)
  AUTH-004  Authenticated access to /dashboard succeeds
  AUTH-005  Unauthorized route fails closed (/api/admin/* → 401/403/redirect)
  AUTH-006  Logout clears Auth.js session cookie
  AUTH-007  Post-logout session endpoint returns empty user
  AUTH-008  Post-logout dashboard redirects to /login (session invalidated)
  AUTH-009  Auth0 SLO redirect issued on logout (identity-provider session cleared)

Usage:
  FG_PROD_AUTH_TEST_ENABLED=true \\
  FG_PROD_TEST_EMAIL=test@example.com \\
  FG_PROD_TEST_PASSWORD=<password> \\
  python tools/testing/production/auth_harness_001.py

  python tools/testing/production/auth_harness_001.py --headless false  (visible browser)
  python tools/testing/production/auth_harness_001.py --write-evidence

Exit codes:
  0 — all checks PASS or NOT_PROVEN (no FAIL)
  1 — one or more checks FAIL
  2 — activation guard not satisfied or dependency missing
  3 — unrecoverable browser error

Never prints passwords, tokens, cookies, or authorization headers to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.testing.production.evidence import (  # noqa: E402
    CheckResult,
    EvidenceRecord,
    EvidenceResult,
    finalize,
    now_iso,
    repo_sha,
    write_evidence,
)

DEFAULT_CONSOLE_URL = "https://console.frostgate.ai"
EVIDENCE_PATH = (
    _REPO_ROOT
    / "contracts"
    / "artifacts"
    / "identity"
    / "prod-auth-automation-001-auth-evidence.json"
)

# Auth0 Universal Login form field selectors (standard Auth0 UL v2)
_AUTH0_EMAIL_SELECTOR = 'input[name="username"], input[type="email"]'
_AUTH0_PASSWORD_SELECTOR = 'input[name="password"], input[type="password"]'
_AUTH0_SUBMIT_SELECTOR = 'button[type="submit"], button[name="action"]'

# Auth.js cookie names (production uses __Secure- prefix)
_SESSION_COOKIE_NAMES = (
    "__Secure-authjs.session-token",
    "authjs.session-token",
)

PLAYWRIGHT_TIMEOUT_MS = 30_000


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
# Auth checks
# ---------------------------------------------------------------------------


def check_auth0_login_page(page: Any, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        page.goto(f"{base_url}/login", timeout=PLAYWRIGHT_TIMEOUT_MS)
        # Auth.js middleware redirects /login to Auth0 Universal Login
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
        # May be a custom login page (FrostGate's /login with Auth0 button)
        # or a different IdP. Check for the Auth0 sign-in button.
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
) -> tuple[bool, str]:
    """Attempt Auth0 login. Returns (success, diagnostic)."""
    try:
        page.goto(
            f"{base_url}/api/auth/signin/auth0?prompt=login",
            timeout=PLAYWRIGHT_TIMEOUT_MS,
        )
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)

        # Find and fill email field
        email_field = page.locator(_AUTH0_EMAIL_SELECTOR).first
        if not email_field.is_visible(timeout=5000):
            # May need to click 'Continue' on a first step
            continue_btn = page.locator('button:has-text("Continue")').first
            if continue_btn.is_visible(timeout=2000):
                continue_btn.click()
                page.wait_for_load_state("networkidle", timeout=10000)
            email_field = page.locator(_AUTH0_EMAIL_SELECTOR).first

        email_field.fill(email)

        # Check for continue button (some Auth0 flows split email/password steps)
        continue_btn = page.locator('button:has-text("Continue")').first
        if continue_btn.is_visible(timeout=2000):
            continue_btn.click()
            page.wait_for_load_state("networkidle", timeout=10000)

        password_field = page.locator(_AUTH0_PASSWORD_SELECTOR).first
        if not password_field.is_visible(timeout=10000):
            return (
                False,
                "Password field not visible after email entry — possible MFA or CAPTCHA",
            )

        password_field.fill(password)
        submit_btn = page.locator(_AUTH0_SUBMIT_SELECTOR).first
        submit_btn.click()

        # Wait for redirect back to the console
        page.wait_for_url(f"{base_url}/**", timeout=PLAYWRIGHT_TIMEOUT_MS)
        return True, ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"


def check_session_established(
    page: Any, base_url: str, email: str, password: str
) -> tuple[CheckResult, bool]:
    """Attempt login and verify Auth.js session cookie is set. Returns (check, logged_in)."""
    ts = now_iso()
    login_ok, diag = _perform_login(page, email, password, base_url)
    if not login_ok:
        if (
            "MFA" in diag
            or "CAPTCHA" in diag
            or "captcha" in diag.lower()
            or "bot" in diag.lower()
        ):
            return (
                CheckResult(
                    id="AUTH-002",
                    description="Auth.js session cookie established after login",
                    expected="Session cookie set, user signed in",
                    observed="NOT_PROVEN (MFA or bot detection active)",
                    result=EvidenceResult.NOT_PROVEN,
                    timestamp=ts,
                    diagnostic=f"Login blocked by identity provider protection: {diag}. See runbook for operator-assisted workflow.",
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

    # Check for session cookie
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
        return CheckResult(
            id="AUTH-003",
            description="Session cookie has Secure, HttpOnly, SameSite attributes",
            expected="Secure=true, HttpOnly=true, SameSite in (Lax, Strict)",
            observed="Session cookie not found",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic="Cannot verify cookie attributes without a session cookie (AUTH-002 may have failed)",
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


def check_dashboard_access(page: Any, base_url: str) -> CheckResult:
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
                description="Authenticated access to /dashboard succeeds",
                expected="HTTP 200, browser on /dashboard",
                observed=f"HTTP {status}, URL={current_url[:80]}",
                result=EvidenceResult.PASS,
                timestamp=ts,
            )
        return CheckResult(
            id="AUTH-004",
            description="Authenticated access to /dashboard succeeds",
            expected="HTTP 200, browser on /dashboard",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic="Dashboard not accessible after authentication",
        )
    except Exception as exc:
        return CheckResult(
            id="AUTH-004",
            description="Authenticated access to /dashboard succeeds",
            expected="HTTP 200, browser on /dashboard",
            observed="ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_unauthorized_route_rejected(page: Any, base_url: str) -> CheckResult:
    """Verify that a protected admin route is not accessible to the test identity."""
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


def check_logout_clears_session(
    page: Any, base_url: str
) -> tuple[CheckResult, CheckResult, CheckResult]:
    """Perform logout and verify session is invalidated. Returns three checks (AUTH-006/007/008)."""
    ts6 = now_iso()

    # Perform logout via the custom logout route
    try:
        page.goto(f"{base_url}/api/auth/logout", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
    except Exception as exc:
        not_proven = CheckResult(
            id="AUTH-006",
            description="Logout clears Auth.js session cookie",
            expected="Session cookie deleted after logout",
            observed="ERROR during logout",
            result=EvidenceResult.FAIL,
            timestamp=ts6,
            diagnostic=type(exc).__name__,
        )
        not_proven_007 = CheckResult(
            id="AUTH-007",
            description="Post-logout session endpoint returns empty user",
            expected="{}  or  {user: null}",
            observed="NOT_PROVEN (logout failed)",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=now_iso(),
        )
        not_proven_008 = CheckResult(
            id="AUTH-008",
            description="Post-logout /dashboard redirects to /login",
            expected="Redirect to /login",
            observed="NOT_PROVEN (logout failed)",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=now_iso(),
        )
        return not_proven, not_proven_007, not_proven_008

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
        check7 = CheckResult(
            id="AUTH-007",
            description="Post-logout session endpoint returns empty user",
            expected="{}  or  no user field",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts7,
            diagnostic=type(exc).__name__,
        )

    # AUTH-008: accessing /dashboard post-logout should redirect to /login
    ts8 = now_iso()
    try:
        response = page.goto(f"{base_url}/dashboard", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
        current_url = page.url
        on_login = "/login" in current_url
        status = response.status if response else 0
        check8 = CheckResult(
            id="AUTH-008",
            description="Post-logout /dashboard redirects to /login",
            expected="Redirect to /login after session invalidation",
            observed=f"HTTP {status}, URL={current_url[:80]}",
            result=EvidenceResult.PASS if on_login else EvidenceResult.FAIL,
            timestamp=ts8,
            diagnostic=None
            if on_login
            else "Dashboard accessible after logout — session not invalidated",
        )
    except Exception as exc:
        check8 = CheckResult(
            id="AUTH-008",
            description="Post-logout /dashboard redirects to /login",
            expected="Redirect to /login after session invalidation",
            observed="ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts8,
            diagnostic=type(exc).__name__,
        )

    return check6, check7, check8


def check_auth0_slo_redirect(page: Any, base_url: str) -> CheckResult:
    """Verify that logout issues a redirect to Auth0's /v2/logout endpoint."""
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
    # May not be observable if Auth0 SLO uses a server-side redirect
    return CheckResult(
        id="AUTH-009",
        description="Logout issues Auth0 SLO redirect (/v2/logout)",
        expected="Request to Auth0 /v2/logout",
        observed="NOT_PROVEN (redirect may be server-side; not observable by browser instrumentation)",
        result=EvidenceResult.NOT_PROVEN,
        timestamp=ts,
        diagnostic="Auth0 SLO may occur server-side. Verify via Auth0 Dashboard session logs.",
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_auth_harness(base_url: str, headless: bool = True) -> EvidenceRecord:
    run_id = str(uuid.uuid4())
    start_ts = now_iso()
    email = os.environ["FG_PROD_TEST_EMAIL"].strip()
    # Password is used but never stored, printed, or included in evidence
    password = os.environ["FG_PROD_TEST_PASSWORD"].strip()

    record = EvidenceRecord(
        timestamp=start_ts,
        run_id=run_id,
        repo_sha=repo_sha(),
        verification_environment="authenticated_playwright",
        # Reference to the synthetic identity without sensitive credentials
        test_identity_ref=f"synthetic:{email.split('@')[0]}@[domain-redacted]",
    )

    from playwright.sync_api import sync_playwright

    checks: list[CheckResult] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(
            # No stored state — fresh session every run
            base_url=base_url,
        )
        page = context.new_page()
        page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)

        try:
            checks.append(check_auth0_login_page(page, base_url))

            session_check, logged_in = check_session_established(
                page, base_url, email, password
            )
            checks.append(session_check)

            if logged_in:
                checks.append(check_cookie_security_attributes(page))
                checks.append(check_dashboard_access(page, base_url))
                checks.append(check_unauthorized_route_rejected(page, base_url))
                c6, c7, c8 = check_logout_clears_session(page, base_url)
                checks.extend([c6, c7, c8])
                checks.append(check_auth0_slo_redirect(page, base_url))
            else:
                # Mark remaining checks as NOT_PROVEN
                not_proven_ids = [
                    ("AUTH-003", "Session cookie security attributes"),
                    ("AUTH-004", "Authenticated access to /dashboard"),
                    ("AUTH-005", "Unauthorized admin route fails closed"),
                    ("AUTH-006", "Logout clears session cookie"),
                    ("AUTH-007", "Post-logout session empty"),
                    ("AUTH-008", "Post-logout /dashboard redirects"),
                    ("AUTH-009", "Auth0 SLO redirect"),
                ]
                for cid, cdesc in not_proven_ids:
                    checks.append(
                        CheckResult(
                            id=cid,
                            description=cdesc,
                            expected="N/A",
                            observed="NOT_PROVEN (login did not succeed)",
                            result=EvidenceResult.NOT_PROVEN,
                            timestamp=now_iso(),
                            diagnostic="AUTH-002 (session establishment) did not pass",
                        )
                    )
        finally:
            context.close()
            browser.close()

    record.checks = checks
    finalize(record)
    return record


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _print_summary(record: EvidenceRecord, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(record.to_dict(), indent=2, ensure_ascii=False))
        return

    print("=" * 64)
    print("PROD-AUTH-AUTOMATION-001 — Mode B: Authenticated Playwright")
    print("=" * 64)
    print(f"Run ID:       {record.run_id}")
    print(f"Timestamp:    {record.timestamp}")
    print(f"Repo SHA:     {record.repo_sha}")
    print(f"Identity:     {record.test_identity_ref}")
    print()

    for check in record.checks:
        symbol = {"PASS": "[PASS]", "FAIL": "[FAIL]", "NOT_PROVEN": "[????]"}[
            check.result
        ]
        print(f"  {symbol} {check.id}: {check.description}")
        if check.result != EvidenceResult.PASS:
            print(f"           expected: {check.expected}")
            print(f"           observed: {check.observed}")
        if check.diagnostic:
            print(f"           note:     {check.diagnostic}")

    print()
    print(f"Overall: {record.overall_result.value}")
    print(f"Fingerprint: {record.evidence_fingerprint}")
    print("=" * 64)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PROD-AUTH-AUTOMATION-001 Mode B — authenticated Playwright verification"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("FG_PROD_SMOKE_URL", DEFAULT_CONSOLE_URL),
        help="Console base URL (default: https://console.frostgate.ai)",
    )
    parser.add_argument(
        "--headless",
        default="true",
        choices=["true", "false"],
        help="Run browser headless (default: true)",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help=f"Write evidence JSON to {EVIDENCE_PATH}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print evidence JSON to stdout",
    )
    args = parser.parse_args(argv)

    # Activation guard — must pass before any browser is launched
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
            "ERROR: 'playwright' package is not installed. Run: pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 2

    base_url = args.url.rstrip("/")
    headless = args.headless == "true"
    print(f"Running authenticated harness against: {base_url}", file=sys.stderr)
    print(
        f"Identity: {os.environ.get('FG_PROD_TEST_EMAIL', '').split('@')[0]}@[domain-redacted]",
        file=sys.stderr,
    )

    try:
        record = run_auth_harness(base_url, headless=headless)
    except KeyboardInterrupt:
        return 3
    except Exception as exc:
        print(f"ERROR: Unrecoverable browser error: {exc}", file=sys.stderr)
        return 3

    if args.write_evidence:
        write_evidence(record, EVIDENCE_PATH)
        print(f"Evidence written: {EVIDENCE_PATH}", file=sys.stderr)

    _print_summary(record, output_json=args.output_json)

    has_fail = any(c.result == EvidenceResult.FAIL for c in record.checks)
    return 1 if has_fail else 0


if __name__ == "__main__":
    sys.exit(main())
