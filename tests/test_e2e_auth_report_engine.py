"""
E2E: PR 16 auth authority validation + PR 15 report engine lifecycle.

Validates the complete runtime path that manual testing exposed as broken:

  Auth (PR 16)
    health/ready → invalid key rejected → scoped key accepted → scope enforced

  Report engine (PR 15)
    create engagement → generate signed report → list → get →
    verify Ed25519 signature → export

Gate: FG_E2E_HTTP=1

Required env:
  FG_BASE_URL    — running server, default http://127.0.0.1:8000
  FG_SCOPED_KEY  — key with governance:read + governance:write bound to
                   FG_E2E_TENANT (falls back to FG_API_KEY)
  FG_E2E_TENANT  — tenant the key is bound to, default local-tenant-001

  The running container must have FG_REPORT_SIGNING_KEY set for the
  verify assertion to pass. If it is absent the report creation step
  returns 503 and the test fails with a clear message.

Run:
  FG_E2E_HTTP=1 FG_SCOPED_KEY=fgk.xxx.yyy pytest tests/test_e2e_auth_report_engine.py -v

Note: this test writes a real engagement + report into the running database.
Test objects can be identified by client_name prefix "E2E-TEST-".
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

import pytest
import requests

# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

E2E_ENABLED = os.getenv("FG_E2E_HTTP", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "y",
    "on",
)

BASE_URL = os.getenv("FG_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
SCOPED_KEY = os.getenv("FG_SCOPED_KEY") or os.getenv("FG_API_KEY", "")
E2E_TENANT = os.getenv("FG_E2E_TENANT", "local-tenant-001")

pytestmark = [pytest.mark.e2e_http, pytest.mark.integration]

_SKIP = pytest.mark.skipif(not E2E_ENABLED, reason="FG_E2E_HTTP not enabled")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _headers(key: Optional[str] = None) -> Dict[str, str]:
    k = key or SCOPED_KEY
    if k:
        return {"X-API-Key": k}
    return {}


def _req(
    method: str,
    path: str,
    *,
    key: Optional[str] = None,
    no_key: bool = False,
    json: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
) -> requests.Response:
    url = f"{BASE_URL}{path}"
    hdrs = {} if no_key else _headers(key)
    return requests.request(method, url, headers=hdrs, json=json, timeout=timeout)


def _json_or_fail(r: requests.Response, context: str = "") -> Any:
    try:
        return r.json()
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"Expected JSON{' (' + context + ')' if context else ''}: "
            f"status={r.status_code} body={r.text[:400]}"
        ) from exc


def _wait_ready(timeout_s: float = 30.0) -> None:
    t0 = time.time()
    last: Optional[str] = None
    while time.time() - t0 < timeout_s:
        try:
            r = requests.get(f"{BASE_URL}/health/ready", timeout=2.0)
            if r.status_code == 200:
                return
            last = f"status={r.status_code}"
        except Exception as exc:  # noqa: BLE001
            last = repr(exc)
        time.sleep(0.5)
    raise AssertionError(
        f"Server not ready at {BASE_URL} after {timeout_s}s. Last: {last}\n"
        f"Start the stack: docker compose --profile core up -d\n"
        f"Then: FG_E2E_HTTP=1 FG_SCOPED_KEY=<key> pytest tests/test_e2e_auth_report_engine.py -v"
    )


# ---------------------------------------------------------------------------
# Auth validation (PR 16 — auth authority gap)
# ---------------------------------------------------------------------------


@_SKIP
def test_e2e_auth_health_and_ready() -> None:
    """Server is up and readiness probe passes before testing anything else."""
    _wait_ready()

    r = _req("GET", "/health", no_key=True)
    assert r.status_code == 200, f"/health: {r.status_code} {r.text[:200]}"

    r = _req("GET", "/health/ready", no_key=True)
    assert r.status_code == 200, f"/health/ready: {r.status_code} {r.text[:200]}"


@_SKIP
def test_e2e_auth_invalid_key_rejected() -> None:
    """A clearly invalid key must be rejected on a protected route.

    This is the exact failure mode that blocked PR 15 manual validation:
    the container booted healthy but every key was rejected.
    """
    _wait_ready()

    r = _req("GET", "/field-assessment/engagements", key="invalid.key.value")
    assert r.status_code in (401, 403), (
        f"Expected 401/403 for invalid key, got {r.status_code}: {r.text[:200]}"
    )


@_SKIP
def test_e2e_auth_no_key_rejected() -> None:
    """Protected routes must reject requests with no API key."""
    _wait_ready()

    r = _req("GET", "/field-assessment/engagements", no_key=True)
    assert r.status_code in (401, 403), (
        f"Expected 401/403 for missing key, got {r.status_code}: {r.text[:200]}"
    )


@_SKIP
def test_e2e_auth_scoped_key_accepted() -> None:
    """The scoped key from FG_SCOPED_KEY / FG_API_KEY is accepted on a read route."""
    if not SCOPED_KEY:
        pytest.skip("FG_SCOPED_KEY / FG_API_KEY not set")

    _wait_ready()

    r = _req("GET", "/field-assessment/engagements")
    assert r.status_code == 200, (
        f"Scoped key rejected on /field-assessment/engagements: "
        f"{r.status_code} {r.text[:400]}\n\n"
        f"This means FG_SQLITE_PATH in the container is still pointing at the wrong "
        f"path (no auth store reachable). Fix: set FG_SQLITE_PATH="
        f"/var/lib/frostgate/state/frostgate.db in .env and recreate the container."
    )


@_SKIP
def test_e2e_auth_read_only_key_cannot_create() -> None:
    """A key without governance:write is rejected on a write route (scope enforcement)."""
    if not SCOPED_KEY:
        pytest.skip("FG_SCOPED_KEY / FG_API_KEY not set")

    read_only_key = os.getenv("FG_READ_ONLY_KEY", "")
    if not read_only_key:
        pytest.skip("FG_READ_ONLY_KEY not set — skipping scope enforcement check")

    _wait_ready()

    r = _req(
        "POST",
        "/field-assessment/engagements",
        key=read_only_key,
        json={
            "client_name": "E2E-SCOPE-CHECK",
            "assessor_id": "e2e-probe",
            "assessment_type": "ai_governance",
        },
    )
    assert r.status_code in (401, 403), (
        f"Expected scope rejection (401/403), got {r.status_code}: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Report engine lifecycle (PR 15)
# ---------------------------------------------------------------------------


@_SKIP
def test_e2e_report_engine_full_lifecycle() -> None:
    """Full engagement + governance report lifecycle against the live stack.

    Sequence:
      1.  POST /field-assessment/engagements           — create engagement
      2.  POST .../reports                             — generate signed report (v1)
      3.  GET  .../reports                             — list → version 1 present
      4.  GET  .../reports/1                           — full report document
      5.  POST .../reports/1/verify                   — Ed25519 signature valid=true
      6.  GET  .../reports/1/export                   — export returns report payload

    A 503 at step 2 means FG_REPORT_SIGNING_KEY is not set in the container.
    """
    if not SCOPED_KEY:
        pytest.skip("FG_SCOPED_KEY / FG_API_KEY not set")

    _wait_ready()

    run_id = uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------
    # Step 1: create engagement
    # ------------------------------------------------------------------
    r = _req(
        "POST",
        "/field-assessment/engagements",
        json={
            "client_name": f"E2E-TEST-{run_id}",
            "client_domain": "e2e.test.local",
            "assessor_id": f"e2e-assessor-{run_id}",
            "assessment_type": "ai_governance",
        },
    )
    assert r.status_code == 201, (
        f"[step 1] create engagement failed: {r.status_code} {r.text[:400]}"
    )
    eng = _json_or_fail(r, "step 1 create engagement")
    engagement_id = eng.get("engagement_id") or eng.get("id")
    assert engagement_id, f"[step 1] no engagement_id in response: {eng}"

    base = f"/field-assessment/engagements/{engagement_id}"

    # ------------------------------------------------------------------
    # Step 2: generate signed governance report
    # ------------------------------------------------------------------
    r = _req(
        "POST",
        f"{base}/reports",
        json={"report_type": "full_assessment"},
    )
    assert r.status_code != 503, (
        "[step 2] 503 REPORT_SIGNING_KEY_MISSING — "
        "FG_REPORT_SIGNING_KEY is not set in the running container.\n"
        "Set it in .env and recreate: docker compose --profile core up -d --force-recreate frostgate-core"
    )
    assert r.status_code == 201, (
        f"[step 2] create report failed: {r.status_code} {r.text[:400]}"
    )
    report = _json_or_fail(r, "step 2 create report")

    assert report.get("version") == 1, (
        f"[step 2] expected version=1, got: {report.get('version')}"
    )
    assert report.get("manifest_hash"), "[step 2] manifest_hash missing from report"
    assert report.get("report_type") == "full_assessment", (
        f"[step 2] unexpected report_type: {report.get('report_type')}"
    )
    report_version = report["version"]

    # ------------------------------------------------------------------
    # Step 3: list reports — version must appear
    # ------------------------------------------------------------------
    r = _req("GET", f"{base}/reports")
    assert r.status_code == 200, (
        f"[step 3] list reports failed: {r.status_code} {r.text[:400]}"
    )
    listing = _json_or_fail(r, "step 3 list reports")
    items = listing.get("items", [])
    assert any(item.get("version") == report_version for item in items), (
        f"[step 3] version {report_version} not found in listing: {items}"
    )

    # ------------------------------------------------------------------
    # Step 4: get report by version — full document
    # ------------------------------------------------------------------
    r = _req("GET", f"{base}/reports/{report_version}")
    assert r.status_code == 200, (
        f"[step 4] get report/{report_version} failed: {r.status_code} {r.text[:400]}"
    )
    doc = _json_or_fail(r, f"step 4 get report/{report_version}")
    assert doc.get("version") == report_version, (
        f"[step 4] version mismatch in document: {doc.get('version')}"
    )
    assert doc.get("manifest_hash") == report.get("manifest_hash"), (
        "[step 4] manifest_hash changed between create and get"
    )

    # ------------------------------------------------------------------
    # Step 5: verify Ed25519 signature — must return valid=true
    # ------------------------------------------------------------------
    r = _req("POST", f"{base}/reports/{report_version}/verify")
    assert r.status_code == 200, (
        f"[step 5] verify failed: {r.status_code} {r.text[:400]}"
    )
    verification = _json_or_fail(r, f"step 5 verify report/{report_version}")
    assert verification.get("valid") is True, (
        f"[step 5] Ed25519 verification returned valid=false.\n"
        f"This means the canonical JSON at verify-time does not match the canonical "
        f"JSON that was signed at create-time. Check that version is stamped into "
        f"report_json BEFORE canonical_str is computed (PR 15 P1 fix).\n"
        f"Response: {verification}"
    )

    # ------------------------------------------------------------------
    # Step 6: export — report payload returned
    # ------------------------------------------------------------------
    r = _req("GET", f"{base}/reports/{report_version}/export")
    assert r.status_code == 200, (
        f"[step 6] export failed: {r.status_code} {r.text[:400]}"
    )
    export_body = _json_or_fail(r, f"step 6 export report/{report_version}")
    assert export_body, "[step 6] export returned empty body"


@_SKIP
def test_e2e_report_cross_tenant_returns_404() -> None:
    """A second tenant must not be able to read reports from the first tenant.

    Requires FG_TENANT_B_KEY — a valid key bound to a different tenant.
    Skipped if not provided; not blocking for local dev but required before prod.
    """
    if not SCOPED_KEY:
        pytest.skip("FG_SCOPED_KEY / FG_API_KEY not set")

    tenant_b_key = os.getenv("FG_TENANT_B_KEY", "")
    if not tenant_b_key:
        pytest.skip("FG_TENANT_B_KEY not set — skipping cross-tenant isolation check")

    _wait_ready()

    # create an engagement as tenant A
    run_id = uuid.uuid4().hex[:8]
    r = _req(
        "POST",
        "/field-assessment/engagements",
        json={
            "client_name": f"E2E-TENANT-ISO-{run_id}",
            "assessor_id": "e2e-iso",
            "assessment_type": "ai_governance",
        },
    )
    assert r.status_code == 201, (
        f"setup: create engagement: {r.status_code} {r.text[:200]}"
    )
    engagement_id = (_json_or_fail(r, "iso setup")).get("engagement_id") or (
        _json_or_fail(r, "iso setup")
    ).get("id")

    # tenant B trying to read tenant A's reports must get 404
    r = _req(
        "GET",
        f"/field-assessment/engagements/{engagement_id}/reports",
        key=tenant_b_key,
    )
    assert r.status_code == 404, (
        f"[cross-tenant] expected 404, got {r.status_code}: {r.text[:200]}\n"
        "Tenant B must not see Tenant A's engagements."
    )
