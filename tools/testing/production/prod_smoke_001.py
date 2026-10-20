#!/usr/bin/env python3
"""tools/testing/production/prod_smoke_001.py — PROD-AUTH-AUTOMATION-001 Mode A.

Public production smoke verification. No credentials, no session state, no mutations.
Safe to run automatically after an approved deployment.

Checks:
  SMOKE-001  Console root accessible (HTTP 200)
  SMOKE-002  Login page accessible (HTTP 200)
  SMOKE-003  Unauthenticated session endpoint returns 200 JSON
  SMOKE-004  Dashboard redirects to /login when unauthenticated
  SMOKE-005  Direct deployment SHA resolution via Vercel API (if credentials present)
  SMOKE-006  No sensitive data leaked in unauthenticated session response

Usage:
  python tools/testing/production/prod_smoke_001.py
  FG_PROD_SMOKE_URL=https://console.frostgate.ai python tools/testing/production/prod_smoke_001.py
  python tools/testing/production/prod_smoke_001.py --write-evidence
  python tools/testing/production/prod_smoke_001.py --json

Exit codes:
  0 — all checks PASS or NOT_PROVEN (no FAIL)
  1 — one or more checks FAIL
  2 — configuration or connectivity error

Never prints tokens, cookies, authorization headers, or credentials.
Never mutates production state.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Guard: requests must be available (it is in requirements.txt)
# ---------------------------------------------------------------------------
try:
    import requests
    from requests import Session
except ImportError:
    print(
        "ERROR: 'requests' is not installed. Run: pip install requests",
        file=sys.stderr,
    )
    sys.exit(2)

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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONSOLE_URL = "https://console.frostgate.ai"
REQUEST_TIMEOUT_SECONDS = 15
EVIDENCE_PATH = (
    _REPO_ROOT
    / "contracts"
    / "artifacts"
    / "identity"
    / "prod-auth-automation-001-smoke-evidence.json"
)

# Sensitive field names that must never appear in the unauthenticated session response.
_SENSITIVE_FIELDS = frozenset(
    {
        "secret",
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "password",
        "credential",
        "cookie",
        "authorization",
    }
)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_root_accessible(session: Session, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        r = session.get(
            f"{base_url}/", timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=True
        )
        ok = r.status_code == 200
        return CheckResult(
            id="SMOKE-001",
            description="Console root path accessible (HTTP 200)",
            expected="200",
            observed=str(r.status_code),
            result=EvidenceResult.PASS if ok else EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=None if ok else f"Unexpected status {r.status_code}",
        )
    except requests.Timeout:
        return CheckResult(
            id="SMOKE-001",
            description="Console root path accessible (HTTP 200)",
            expected="200",
            observed="TIMEOUT",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except requests.ConnectionError as exc:
        return CheckResult(
            id="SMOKE-001",
            description="Console root path accessible (HTTP 200)",
            expected="200",
            observed="CONNECTION_ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_login_accessible(session: Session, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        r = session.get(
            f"{base_url}/login", timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=True
        )
        ok = r.status_code == 200
        return CheckResult(
            id="SMOKE-002",
            description="Login page accessible (HTTP 200)",
            expected="200",
            observed=str(r.status_code),
            result=EvidenceResult.PASS if ok else EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=None if ok else f"Unexpected status {r.status_code}",
        )
    except requests.Timeout:
        return CheckResult(
            id="SMOKE-002",
            description="Login page accessible (HTTP 200)",
            expected="200",
            observed="TIMEOUT",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except requests.ConnectionError as exc:
        return CheckResult(
            id="SMOKE-002",
            description="Login page accessible (HTTP 200)",
            expected="200",
            observed="CONNECTION_ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_session_endpoint(session: Session, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        r = session.get(
            f"{base_url}/api/auth/session",
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        if r.status_code != 200:
            return CheckResult(
                id="SMOKE-003",
                description="Unauthenticated session endpoint returns 200 JSON",
                expected="200",
                observed=str(r.status_code),
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=f"Expected 200, got {r.status_code}",
            )
        content_type = r.headers.get("content-type", "")
        if "json" not in content_type.lower():
            return CheckResult(
                id="SMOKE-003",
                description="Unauthenticated session endpoint returns 200 JSON",
                expected="200 application/json",
                observed=f"200 {content_type}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic="Response is not JSON",
            )
        return CheckResult(
            id="SMOKE-003",
            description="Unauthenticated session endpoint returns 200 JSON",
            expected="200 application/json",
            observed=f"200 {content_type.split(';')[0].strip()}",
            result=EvidenceResult.PASS,
            timestamp=ts,
        )
    except requests.Timeout:
        return CheckResult(
            id="SMOKE-003",
            description="Unauthenticated session endpoint returns 200 JSON",
            expected="200",
            observed="TIMEOUT",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except requests.ConnectionError as exc:
        return CheckResult(
            id="SMOKE-003",
            description="Unauthenticated session endpoint returns 200 JSON",
            expected="200",
            observed="CONNECTION_ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_dashboard_redirect(session: Session, base_url: str) -> CheckResult:
    ts = now_iso()
    try:
        r = session.get(
            f"{base_url}/dashboard",
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        # Auth.js middleware redirects unauthenticated requests to /login.
        # May be 302, 307, or 308 depending on implementation.
        is_redirect = r.status_code in (301, 302, 307, 308)
        if not is_redirect:
            return CheckResult(
                id="SMOKE-004",
                description="Dashboard redirects unauthenticated requests to /login",
                expected="3xx redirect to /login",
                observed=str(r.status_code),
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=f"Expected redirect, got {r.status_code}",
            )
        location = r.headers.get("location", "")
        path = urlparse(location).path
        to_login = "/login" in path or path == "/login"
        if not to_login:
            return CheckResult(
                id="SMOKE-004",
                description="Dashboard redirects unauthenticated requests to /login",
                expected="3xx redirect to /login",
                observed=f"{r.status_code} Location: {path or location}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic=f"Redirect destination is not /login: {path}",
            )
        return CheckResult(
            id="SMOKE-004",
            description="Dashboard redirects unauthenticated requests to /login",
            expected="3xx redirect to /login",
            observed=f"{r.status_code} Location: {path}",
            result=EvidenceResult.PASS,
            timestamp=ts,
        )
    except requests.Timeout:
        return CheckResult(
            id="SMOKE-004",
            description="Dashboard redirects unauthenticated requests to /login",
            expected="3xx redirect to /login",
            observed="TIMEOUT",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except requests.ConnectionError as exc:
        return CheckResult(
            id="SMOKE-004",
            description="Dashboard redirects unauthenticated requests to /login",
            expected="3xx redirect to /login",
            observed="CONNECTION_ERROR",
            result=EvidenceResult.FAIL,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def check_vercel_deployment(base_url: str) -> tuple[CheckResult, str]:
    """Attempt to resolve deployment ID and SHA via Vercel API.

    Returns (check_result, deployed_sha).
    Does not use the session object — Vercel API uses its own auth header.
    Never prints the Vercel token value.
    """
    ts = now_iso()
    token = os.environ.get("VERCEL_TOKEN", "")
    project_id = os.environ.get("VERCEL_PROJECT_ID", "")

    if not token or not project_id:
        return (
            CheckResult(
                id="SMOKE-005",
                description="Vercel deployment SHA resolution via API",
                expected="Vercel deployment with gitSource.sha",
                observed="NOT_PROVEN (VERCEL_TOKEN or VERCEL_PROJECT_ID not set)",
                result=EvidenceResult.NOT_PROVEN,
                timestamp=ts,
                diagnostic="Set VERCEL_TOKEN and VERCEL_PROJECT_ID to enable",
            ),
            "NOT_PROVEN",
        )

    try:
        import requests as req_lib

        team_id = os.environ.get("VERCEL_TEAM_ID", "")
        params: dict[str, str] = {
            "projectId": project_id,
            "limit": "1",
            "target": "production",
        }
        if team_id:
            params["teamId"] = team_id
        r = req_lib.get(
            "https://api.vercel.com/v6/deployments",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=15,
        )
        if r.status_code != 200:
            return (
                CheckResult(
                    id="SMOKE-005",
                    description="Vercel deployment SHA resolution via API",
                    expected="200 from Vercel deployments API",
                    observed=str(r.status_code),
                    result=EvidenceResult.FAIL,
                    timestamp=ts,
                    diagnostic=f"Vercel API returned {r.status_code}",
                ),
                "NOT_PROVEN",
            )
        data = r.json()
        deployments = data.get("deployments", [])
        if not deployments:
            return (
                CheckResult(
                    id="SMOKE-005",
                    description="Vercel deployment SHA resolution via API",
                    expected="At least one production deployment",
                    observed="0 deployments returned",
                    result=EvidenceResult.NOT_PROVEN,
                    timestamp=ts,
                    diagnostic="No production deployments found for project",
                ),
                "NOT_PROVEN",
            )
        latest = deployments[0]
        deploy_id = latest.get("uid", "UNKNOWN")
        git_source = latest.get("gitSource", {})
        sha = git_source.get("sha", "NOT_PROVEN")
        state = latest.get("readyState", "UNKNOWN")
        ready = state == "READY"
        return (
            CheckResult(
                id="SMOKE-005",
                description="Vercel deployment SHA resolution via API",
                expected="READY deployment with gitSource.sha",
                observed=f"state={state} sha={sha[:12] if sha not in ('NOT_PROVEN', 'UNKNOWN') else sha} id={deploy_id}",
                result=EvidenceResult.PASS
                if (sha != "NOT_PROVEN" and ready)
                else EvidenceResult.NOT_PROVEN,
                timestamp=ts,
                diagnostic=None if ready else f"Latest deployment state is {state!r}",
            ),
            sha,
        )
    except Exception as exc:
        return (
            CheckResult(
                id="SMOKE-005",
                description="Vercel deployment SHA resolution via API",
                expected="READY deployment with gitSource.sha",
                observed="ERROR",
                result=EvidenceResult.NOT_PROVEN,
                timestamp=ts,
                diagnostic=type(exc).__name__,
            ),
            "NOT_PROVEN",
        )


def check_session_no_secrets(session: Session, base_url: str) -> CheckResult:
    """Verify the unauthenticated session response does not leak sensitive fields."""
    ts = now_iso()
    try:
        r = session.get(
            f"{base_url}/api/auth/session",
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        if r.status_code != 200:
            return CheckResult(
                id="SMOKE-006",
                description="Unauthenticated session response contains no sensitive fields",
                expected="200 with no sensitive field names",
                observed=f"HTTP {r.status_code}",
                result=EvidenceResult.NOT_PROVEN,
                timestamp=ts,
                diagnostic="Cannot inspect session body (non-200 response)",
            )
        try:
            body = r.json()
        except ValueError:
            return CheckResult(
                id="SMOKE-006",
                description="Unauthenticated session response contains no sensitive fields",
                expected="JSON body with no sensitive field names",
                observed="Non-JSON body",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic="Session endpoint returned non-JSON for unauthenticated request",
            )
        leaked = _find_sensitive_keys(body)
        if leaked:
            return CheckResult(
                id="SMOKE-006",
                description="Unauthenticated session response contains no sensitive fields",
                expected="No sensitive field names in unauthenticated session",
                observed=f"Found sensitive fields: {sorted(leaked)}",
                result=EvidenceResult.FAIL,
                timestamp=ts,
                diagnostic="Unauthenticated session response contains credential-adjacent fields",
            )
        return CheckResult(
            id="SMOKE-006",
            description="Unauthenticated session response contains no sensitive fields",
            expected="No sensitive field names in unauthenticated session",
            observed=f"No sensitive fields found (keys={sorted(_flatten_keys(body))})",
            result=EvidenceResult.PASS,
            timestamp=ts,
        )
    except requests.Timeout:
        return CheckResult(
            id="SMOKE-006",
            description="Unauthenticated session response contains no sensitive fields",
            expected="200 JSON with no sensitive fields",
            observed="TIMEOUT",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
        )
    except requests.ConnectionError as exc:
        return CheckResult(
            id="SMOKE-006",
            description="Unauthenticated session response contains no sensitive fields",
            expected="200 JSON with no sensitive fields",
            observed="CONNECTION_ERROR",
            result=EvidenceResult.NOT_PROVEN,
            timestamp=ts,
            diagnostic=type(exc).__name__,
        )


def _flatten_keys(obj: Any, prefix: str = "") -> set[str]:
    """Recursively collect all JSON keys, lowercased."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.add(k.lower())
            keys.update(_flatten_keys(v, full))
    elif isinstance(obj, list):
        for item in obj:
            keys.update(_flatten_keys(item, prefix))
    return keys


def _find_sensitive_keys(obj: Any) -> set[str]:
    all_keys = _flatten_keys(obj)
    return all_keys & _SENSITIVE_FIELDS


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_smoke(base_url: str) -> EvidenceRecord:
    run_id = str(uuid.uuid4())
    start_ts = now_iso()

    record = EvidenceRecord(
        timestamp=start_ts,
        run_id=run_id,
        repo_sha=repo_sha(),
        verification_environment="public_smoke",
        test_identity_ref="NOT_APPLICABLE",
    )

    # Unverified production checks (require authenticated Mode B)
    record.unverified_production_checks = [
        "AUTH-001: Auth0 login form rendered and interactive",
        "AUTH-002: Auth.js session cookie established after successful login",
        "AUTH-003: Session cookie has Secure, HttpOnly, SameSite=Lax/Strict attributes",
        "AUTH-004: Authenticated user can access /dashboard",
        "AUTH-005: Unauthorized routes fail closed (403/redirect)",
        "AUTH-006: Logout clears Auth.js session cookie",
        "AUTH-007: Post-logout session endpoint returns empty/null user",
        "AUTH-008: Auth0 SLO (identity-provider logout) completes",
        "AUTH-009: Tenant isolation — synthetic user cannot access other tenant routes",
        "AUTH-010: Re-use of invalidated session cookie is rejected",
    ]

    # Create a session with no cookies, no auth headers
    session = requests.Session()
    session.headers.update(
        {"User-Agent": "FrostGate-ProdSmoke/1.0 PROD-AUTH-AUTOMATION-001"}
    )

    checks: list[CheckResult] = []

    checks.append(check_root_accessible(session, base_url))
    checks.append(check_login_accessible(session, base_url))
    checks.append(check_session_endpoint(session, base_url))
    checks.append(check_dashboard_redirect(session, base_url))

    # Vercel deployment check returns (check_result, deployed_sha)
    deploy_check, deployed_sha = check_vercel_deployment(base_url)
    checks.append(deploy_check)
    record.deployed_sha = deployed_sha

    checks.append(check_session_no_secrets(session, base_url))

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
    print("PROD-AUTH-AUTOMATION-001 — Mode A: Public Production Smoke")
    print("=" * 64)
    print(f"Run ID:       {record.run_id}")
    print(f"Timestamp:    {record.timestamp}")
    print(f"Repo SHA:     {record.repo_sha}")
    print(f"Deployed SHA: {record.deployed_sha}")
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
    print()

    if record.unverified_production_checks:
        print(
            f"NOT_PROVEN — {len(record.unverified_production_checks)} checks require Mode B (authenticated):"
        )
        for item in record.unverified_production_checks:
            print(f"  {item}")
    print("=" * 64)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PROD-AUTH-AUTOMATION-001 Mode A — public production smoke"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("FG_PROD_SMOKE_URL", DEFAULT_CONSOLE_URL),
        help="Console base URL (default: https://console.frostgate.ai)",
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

    base_url = args.url.rstrip("/")
    print(f"Running production smoke against: {base_url}", file=sys.stderr)

    record = run_smoke(base_url)

    if args.write_evidence:
        write_evidence(record, EVIDENCE_PATH)
        print(f"Evidence written: {EVIDENCE_PATH}", file=sys.stderr)

    _print_summary(record, output_json=args.output_json)

    has_fail = any(c.result == EvidenceResult.FAIL for c in record.checks)
    return 1 if has_fail else 0


if __name__ == "__main__":
    sys.exit(main())
