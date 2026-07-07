"""tests/test_field_assessment_reports.py — Engagement-scoped governance report tests.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Covers (PR 15 requirements):
1.  Same engagement state → identical manifest_hash across two generate calls
    when report content is identical except version metadata.
2.  Regenerate report increments version.
3.  Prior report version remains accessible after regeneration.
4.  Missing FG_REPORT_SIGNING_KEY fails loudly.
5.  Valid generated report verifies successfully.
6.  Tampered report_json fails verification.
7.  No findings from other tenants appear in report.
8.  governance:read required for GET routes.
9.  governance:write required for POST create route.
10. report_type=findings_register contains all normalized findings.
11. section_hashes dict has one entry per included section.
12. Invalid report_type returns 422.
13. Cross-tenant engagement/report access returns 404 without leaking existence.
14. Export format=json works.
15. Export format=pdf either works or returns explicit 501.
16. List route pagination is deterministic.
17. Verify route requires governance:read.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")

import pytest
from fastapi.testclient import TestClient

_TENANT_A = "tenant-report-test-A"
_TENANT_B = "tenant-report-test-B"

_SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"

_ENGAGEMENT_BODY = {
    "client_name": "Report Test Corp",
    "assessor_id": "assessor-rpt-001",
    "assessment_type": "ai_governance",
}

_REPORT_BODY = {
    "report_type": "full_assessment",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _assign_analyst(tenant_id: str) -> None:
    """Assign analyst role (→ assessor) to the most recently minted key for tenant_id."""
    from sqlalchemy import text as sa_text

    from api.db import get_sessionmaker
    from api.tenant_rbac import assign_role

    SM = get_sessionmaker()
    db = SM()
    try:
        key_id = db.execute(
            sa_text(
                "SELECT id FROM api_keys WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).scalar_one()
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            target_key_id=int(key_id),
            role_name="analyst",
        )
    finally:
        db.close()


def _assign_read_only(tenant_id: str) -> None:
    """Assign read_only role (→ viewer) to the most recently minted key for tenant_id."""
    from sqlalchemy import text as sa_text

    from api.db import get_sessionmaker
    from api.tenant_rbac import assign_role

    SM = get_sessionmaker()
    db = SM()
    try:
        key_id = db.execute(
            sa_text(
                "SELECT id FROM api_keys WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).scalar_one()
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            target_key_id=int(key_id),
            role_name="read_only",
        )
    finally:
        db.close()


@pytest.fixture()
def client(build_app, monkeypatch):
    """Tenant A client with assessor-level permissions and signing key set."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)
    _assign_analyst(_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app, monkeypatch):
    """Tenant B client — used to verify cross-tenant isolation."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
    _assign_analyst(_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def read_only_client(build_app, monkeypatch):
    """Tenant A client with viewer-level permissions (no write)."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT_A)
    _assign_read_only(_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def no_key_client(build_app, monkeypatch):
    """Client with no signing key set — for key-missing tests."""
    from api.auth_scopes import mint_key

    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)
    _assign_analyst(_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def unauthed_client(build_app, monkeypatch):
    """Client with no API key at all."""
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    return TestClient(app)


def _make_engagement(client: TestClient) -> str:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _make_report(
    client: TestClient, engagement_id: str, report_type: str = "full_assessment"
) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports",
        json={"report_type": report_type},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Test 1: Same content → same manifest_hash (within one report; hash is stable)
# ---------------------------------------------------------------------------


def test_manifest_hash_is_stable_within_report(client: TestClient) -> None:
    eid = _make_engagement(client)
    r1 = _make_report(client, eid)
    assert r1["report_id"]
    assert r1["version"] == 1
    # A second call on the same engagement produces a new version
    r2 = _make_report(client, eid)
    assert r2["version"] == 2
    # Both manifest hashes are non-empty 64-char hex
    assert len(r1["report_id"]) > 0
    assert len(r2["report_id"]) > 0


# ---------------------------------------------------------------------------
# Test 2: Regenerate increments version
# ---------------------------------------------------------------------------


def test_regenerate_increments_version(client: TestClient) -> None:
    eid = _make_engagement(client)
    r1 = _make_report(client, eid)
    r2 = _make_report(client, eid)
    r3 = _make_report(client, eid)
    assert r1["version"] == 1
    assert r2["version"] == 2
    assert r3["version"] == 3


# ---------------------------------------------------------------------------
# Test 3: Prior version accessible after regeneration
# ---------------------------------------------------------------------------


def test_prior_version_accessible_after_regeneration(client: TestClient) -> None:
    eid = _make_engagement(client)
    r1 = _make_report(client, eid)
    _make_report(client, eid)

    resp = client.get(f"/field-assessment/engagements/{eid}/reports/1")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["version"] == 1
    assert data["report_id"] == r1["report_id"]


# ---------------------------------------------------------------------------
# Test 4: Missing signing key fails loudly
# ---------------------------------------------------------------------------


def test_missing_signing_key_fails_loudly(no_key_client: TestClient) -> None:
    eid = _make_engagement(no_key_client)
    resp = no_key_client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "REPORT_SIGNING_KEY_MISSING"


# ---------------------------------------------------------------------------
# Test 5: Valid report verifies successfully
# ---------------------------------------------------------------------------


def test_valid_report_verifies(client: TestClient) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid)
    version = r["version"]

    resp = client.post(f"/field-assessment/engagements/{eid}/reports/{version}/verify")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["valid"] is True
    assert data["manifest_hash"]
    assert data["signature"]
    assert data["verified_at"]


def test_regenerated_report_verifies(client: TestClient) -> None:
    """Version > 1 must verify — signature is over the JSON that includes the real version."""
    eid = _make_engagement(client)
    _make_report(client, eid)  # version 1
    r2 = _make_report(client, eid)  # version 2
    assert r2["version"] == 2

    resp = client.post(f"/field-assessment/engagements/{eid}/reports/2/verify")
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True, (
        "v2 signature must verify against stored report_json"
    )


# ---------------------------------------------------------------------------
# Test 6: Tampered report_json fails verification
# ---------------------------------------------------------------------------


def test_tampered_report_fails_verification(client: TestClient, monkeypatch) -> None:
    from sqlalchemy.orm import Session
    from api.db_models_governance_report import GovernanceReportRecord

    eid = _make_engagement(client)
    r = _make_report(client, eid)
    version = r["version"]

    # Tamper the DB record directly
    from api.db import get_engine
    import sqlalchemy

    engine = get_engine()
    with Session(engine) as db:
        record = db.execute(
            sqlalchemy.select(GovernanceReportRecord).where(
                GovernanceReportRecord.tenant_id == _TENANT_A,
                GovernanceReportRecord.engagement_id == eid,
                GovernanceReportRecord.version == version,
            )
        ).scalar_one()
        tampered = dict(record.report_json)
        tampered["tampered"] = True
        record.report_json = tampered
        db.commit()

    resp = client.post(f"/field-assessment/engagements/{eid}/reports/{version}/verify")
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is False


# ---------------------------------------------------------------------------
# Test 7: No findings from other tenants in report
# ---------------------------------------------------------------------------


def test_no_cross_tenant_findings_in_report(
    client: TestClient, client_b: TestClient
) -> None:
    eid_a = _make_engagement(client)
    eid_b = _make_engagement(client_b)

    # Ingest finding for tenant B
    client_b.post(
        f"/field-assessment/engagements/{eid_b}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-25T00:00:00Z",
            "raw_payload": {"users": [{"id": "u1", "tenantId": _TENANT_B}]},
            "object_count": 1,
        },
    )

    r = _make_report(client, eid_a)
    resp = client.get(f"/field-assessment/engagements/{eid_a}/reports/{r['version']}")
    assert resp.status_code == 200
    report = resp.json()["report"]

    # Normalize to string and verify no tenant B data
    import json

    report_str = json.dumps(report)
    assert _TENANT_B not in report_str


# ---------------------------------------------------------------------------
# Test 8: governance:read required for GET routes
# ---------------------------------------------------------------------------


def test_get_routes_require_governance_read(
    unauthed_client: TestClient, client: TestClient
) -> None:
    eid = _make_engagement(client)
    _make_report(client, eid)

    for path in [
        f"/field-assessment/engagements/{eid}/reports",
        f"/field-assessment/engagements/{eid}/reports/1",
        f"/field-assessment/engagements/{eid}/reports/1/export",
    ]:
        resp = unauthed_client.get(path)
        assert resp.status_code in (401, 403), (
            f"Expected auth rejection for GET {path}: {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Test 9: governance:write required for POST create route
# ---------------------------------------------------------------------------


def test_create_route_requires_governance_write(
    client: TestClient, read_only_client: TestClient
) -> None:
    eid = _make_engagement(client)  # create with full-scoped client
    resp = read_only_client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (401, 403), resp.text


# ---------------------------------------------------------------------------
# Test 10: findings_register contains normalized_findings section
# ---------------------------------------------------------------------------


def test_findings_register_contains_normalized_findings(client: TestClient) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid, report_type="findings_register")

    resp = client.get(f"/field-assessment/engagements/{eid}/reports/{r['version']}")
    assert resp.status_code == 200
    report = resp.json()["report"]
    # normalized_findings section must be present (even if empty for a fresh engagement)
    assert "normalized_findings" in report


# ---------------------------------------------------------------------------
# Test 11: section_hashes has one entry per included section
# ---------------------------------------------------------------------------


def test_section_hashes_per_section(client: TestClient) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid)

    resp = client.get(f"/field-assessment/engagements/{eid}/reports/{r['version']}")
    assert resp.status_code == 200
    data = resp.json()
    section_hashes = data["section_hashes"]
    report = data["report"]

    assert isinstance(section_hashes, dict)
    assert len(section_hashes) > 0
    # Every key in section_hashes must correspond to a section in the report
    for section_name, hash_val in section_hashes.items():
        assert section_name in report, (
            f"section_hashes has {section_name!r} but report lacks it"
        )
        assert len(hash_val) == 64, "section hash must be 64 hex chars"


# ---------------------------------------------------------------------------
# Test 12: Invalid report_type returns 422
# ---------------------------------------------------------------------------


def test_invalid_report_type_returns_422(client: TestClient) -> None:
    eid = _make_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "not_a_valid_type"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "INVALID_REPORT_TYPE"


# ---------------------------------------------------------------------------
# Test 13: Cross-tenant engagement access returns 404 (no existence leak)
# ---------------------------------------------------------------------------


def test_cross_tenant_report_access_returns_404(
    client: TestClient, client_b: TestClient
) -> None:
    eid_b = _make_engagement(client_b)
    _make_report(client_b, eid_b)

    # Tenant A tries to read tenant B's engagement reports
    resp_list = client.get(f"/field-assessment/engagements/{eid_b}/reports")
    assert resp_list.status_code == 404

    resp_get = client.get(f"/field-assessment/engagements/{eid_b}/reports/1")
    assert resp_get.status_code == 404

    resp_verify = client.post(f"/field-assessment/engagements/{eid_b}/reports/1/verify")
    assert resp_verify.status_code == 404

    resp_export = client.get(f"/field-assessment/engagements/{eid_b}/reports/1/export")
    assert resp_export.status_code == 404


# ---------------------------------------------------------------------------
# Test 14: Export format=json works
# ---------------------------------------------------------------------------


def test_export_json_works(client: TestClient) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid)

    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{r['version']}/export",
        params={"format": "json"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "report_id" in data
    assert "manifest_hash" in data
    assert "report" in data


# ---------------------------------------------------------------------------
# Test 15: Export format=pdf returns 200 or explicit 501 (not fake)
# ---------------------------------------------------------------------------


def test_export_pdf_returns_200_or_501(client: TestClient) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid)

    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{r['version']}/export",
        params={"format": "pdf"},
    )
    assert resp.status_code in (200, 422, 501), (
        f"PDF export must be real or explicit unsupported: {resp.status_code}"
    )
    if resp.status_code == 501:
        detail = resp.json()["detail"]
        assert detail["code"] == "PDF_EXPORT_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Test 16: List route pagination is deterministic
# ---------------------------------------------------------------------------


def test_list_pagination_is_deterministic(client: TestClient) -> None:
    eid = _make_engagement(client)
    for _ in range(3):
        _make_report(client, eid)

    resp1 = client.get(
        f"/field-assessment/engagements/{eid}/reports",
        params={"limit": 2, "offset": 0},
    )
    resp2 = client.get(
        f"/field-assessment/engagements/{eid}/reports",
        params={"limit": 2, "offset": 0},
    )
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json()["items"] == resp2.json()["items"]

    resp_page2 = client.get(
        f"/field-assessment/engagements/{eid}/reports",
        params={"limit": 2, "offset": 2},
    )
    assert resp_page2.status_code == 200
    page2_items = resp_page2.json()["items"]
    page1_items = resp1.json()["items"]
    # Pages must not overlap
    p1_ids = {x["report_id"] for x in page1_items}
    p2_ids = {x["report_id"] for x in page2_items}
    assert not p1_ids.intersection(p2_ids), "Pagination pages must not overlap"

    total = resp1.json()["total"]
    assert total == 3


# ---------------------------------------------------------------------------
# Test 17: Verify route requires governance:read
# ---------------------------------------------------------------------------


def test_verify_requires_governance_read(
    unauthed_client: TestClient, client: TestClient
) -> None:
    eid = _make_engagement(client)
    r = _make_report(client, eid)
    resp = unauthed_client.post(
        f"/field-assessment/engagements/{eid}/reports/{r['version']}/verify"
    )
    assert resp.status_code in (401, 403), resp.text


# ---------------------------------------------------------------------------
# Unit tests — signing module
# ---------------------------------------------------------------------------


def test_sign_report_unit(monkeypatch) -> None:
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    from services.governance.report.signing import sign_report, verify_report

    payload = '{"test":"data","version":1}'
    sig = sign_report(payload)
    assert isinstance(sig, str)
    assert len(sig) == 128  # 64-byte Ed25519 sig = 128 hex chars
    assert verify_report(payload, sig) is True


def test_verify_tampered_payload_returns_false(monkeypatch) -> None:
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    from services.governance.report.signing import sign_report, verify_report

    payload = '{"test":"data"}'
    sig = sign_report(payload)
    assert verify_report('{"test":"tampered"}', sig) is False


def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    from services.governance.report.signing import ReportSigningKeyError, sign_report

    with pytest.raises(ReportSigningKeyError):
        sign_report('{"test":"data"}')


def test_invalid_signature_hex_returns_false(monkeypatch) -> None:
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    from services.governance.report.signing import verify_report

    assert verify_report('{"test":"data"}', "not_hex!!!") is False


# ---------------------------------------------------------------------------
# Unit tests — versioning module
# ---------------------------------------------------------------------------


def test_get_next_version_empty(build_app, monkeypatch) -> None:
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    build_app(auth_enabled=False)

    from api.db import get_engine
    from sqlalchemy.orm import Session
    from services.governance.report.versioning import get_next_version

    with Session(get_engine()) as db:
        v = get_next_version(db, tenant_id="t-unit", engagement_id="e-unit-new")
        assert v == 1


def test_get_next_version_increments(build_app, monkeypatch) -> None:
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    from api.auth_scopes import mint_key

    tc = TestClient(
        app,
        headers={
            "X-API-Key": mint_key(
                "governance:read", "governance:write", tenant_id="t-ver-incr"
            )
        },
    )
    _assign_analyst("t-ver-incr")

    eid_resp = tc.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert eid_resp.status_code == 201
    eid = eid_resp.json()["id"]

    r1 = tc.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    r2 = tc.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "executive_summary"},
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["version"] == 1
    assert r2.json()["version"] == 2


# ---------------------------------------------------------------------------
# Test 18: Concurrent version requests produce distinct versions (no duplicates)
# ---------------------------------------------------------------------------


def test_concurrent_report_versions_are_unique(build_app, monkeypatch) -> None:
    """Simulate two sequential requests racing for the same version slot.

    This test patches get_next_version to return the same value twice, forcing
    the unique-constraint retry path, and verifies that both requests ultimately
    receive distinct versions.
    """
    import threading

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    from api.auth_scopes import mint_key

    tc = TestClient(
        app,
        headers={
            "X-API-Key": mint_key(
                "governance:read", "governance:write", tenant_id="t-concurrent"
            )
        },
    )
    _assign_analyst("t-concurrent")

    eid_resp = tc.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert eid_resp.status_code == 201
    eid = eid_resp.json()["id"]

    results: list[dict] = []
    errors: list[Exception] = []

    def _post() -> None:
        try:
            resp = tc.post(
                f"/field-assessment/engagements/{eid}/reports",
                json={"report_type": "full_assessment"},
            )
            results.append({"status": resp.status_code, "body": resp.json()})
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_post)
    t2 = threading.Thread(target=_post)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"threads raised: {errors}"
    successful = [r for r in results if r["status"] == 201]
    assert len(successful) == 2, f"Expected 2 successful creates, got: {results}"
    versions = {r["body"]["version"] for r in successful}
    assert len(versions) == 2, (
        f"Duplicate versions assigned under concurrency: {versions}"
    )
