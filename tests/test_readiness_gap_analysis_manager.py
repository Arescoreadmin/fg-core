"""Tests for the Readiness Gap Analysis API.

Covers:
- GET /control-plane/readiness/assessments/{id}/gap-analysis
  - Tenant isolation (403 when no tenant context)
  - Cross-tenant isolation (404 on foreign tenant's assessment)
  - Assessment-not-found (404)
  - Successful computation with a complete assessment
  - Empty assessment returns valid result with no gaps of certain types
  - Export-safety (no secrets, stack traces, or topology in response)
  - Response schema stability
  - Deterministic ordering (stable gap ordering across calls)
- GET /control-plane/readiness/domains/{domain_id}
- GET /control-plane/readiness/controls/{control_id}
- GET /control-plane/readiness/maturity-tiers/{tier_id}
  - Success, 404, tenant isolation

All tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_readiness_gap_api.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_gap_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def read_only_client(tmp_path, monkeypatch):
    """Client with only control-plane:read scope."""
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_gap_ro_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def tenant_client(tmp_path, monkeypatch):
    """Client scoped to tenant-alpha."""
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_gap_tenant_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read", "control-plane:admin", tenant_id="tenant-alpha"
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def other_tenant_client(tmp_path, monkeypatch, tenant_client):
    """Client scoped to tenant-beta, sharing the same DB as tenant_client."""
    from api.auth_scopes import mint_key
    from api.main import build_app

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id="tenant-beta")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_draft_framework(client: TestClient, slug: str = "fw-gap-draft") -> str:
    resp = client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "Gap Test FW",
            "framework_slug": slug,
            "framework_version": "1.0",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["framework_id"]


def _activate_framework(client: TestClient, fw_id: str) -> None:
    resp = client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/transition",
        json={"to_status": "active"},
    )
    assert resp.status_code == 200, resp.text


def _create_active_framework(client: TestClient, slug: str = "fw-gap-test") -> str:
    fw_id = _create_draft_framework(client, slug=slug)
    _activate_framework(client, fw_id)
    return fw_id


def _create_assessment(client: TestClient, fw_id: str, version_tag: str = "1.0") -> str:
    resp = client.post(
        "/control-plane/readiness/assessments",
        json={"framework_id": fw_id, "framework_version_tag": version_tag},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["assessment_id"]


def _create_domain(client: TestClient, fw_id: str, slug: str = "gov") -> str:
    resp = client.post(
        "/control-plane/readiness/domains",
        json={
            "framework_id": fw_id,
            "domain_name": "Governance",
            "domain_slug": slug,
            "domain_description": "test domain",
            "domain_order": 1,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["domain_id"]


def _create_control(
    client: TestClient, fw_id: str, domain_id: str, identifier: str = "GV-1"
) -> str:
    resp = client.post(
        "/control-plane/readiness/controls",
        json={
            "framework_id": fw_id,
            "domain_id": domain_id,
            "control_identifier": identifier,
            "control_name": f"Control {identifier}",
            "control_description": "test control",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["control_id"]


def _create_maturity_tier(
    client: TestClient, fw_id: str, identifier: str = "T1"
) -> str:
    resp = client.post(
        "/control-plane/readiness/maturity-tiers",
        json={
            "framework_id": fw_id,
            "tier_identifier": identifier,
            "tier_name": f"Tier {identifier}",
            "tier_order": 1,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["tier_id"]


# ---------------------------------------------------------------------------
# Gap analysis: tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_gap_analysis_requires_tenant_context(api_client):
    """Platform-scoped key (no tenant_id) must be rejected with 403."""
    resp = api_client.get("/control-plane/readiness/assessments/any-id/gap-analysis")
    assert resp.status_code == 403
    body = resp.json()
    assert "detail" in body
    assert "code" in body["detail"]


@pytest.mark.contract
def test_gap_analysis_assessment_not_found(tenant_client):
    resp = tenant_client.get(
        "/control-plane/readiness/assessments/nonexistent-assessment-id/gap-analysis"
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["code"] == "READY-API-005"


@pytest.mark.contract
def test_gap_analysis_cross_tenant_isolation(tenant_client, other_tenant_client):
    """tenant-alpha's assessment must not be visible to tenant-beta."""
    fw_id = _create_active_framework(tenant_client, slug="fw-cross-tenant-gap")
    assessment_id = _create_assessment(tenant_client, fw_id)

    # tenant-beta cannot see tenant-alpha's assessment
    resp = other_tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 404
    # Must not reveal tenant-alpha's existence
    detail = resp.json().get("detail", {})
    assert "tenant-alpha" not in str(detail)


@pytest.mark.contract
def test_gap_analysis_no_info_disclosure_on_cross_tenant(
    tenant_client, other_tenant_client
):
    """404 detail must not expose the owning tenant's identity."""
    fw_id = _create_active_framework(tenant_client, slug="fw-no-disclose-gap")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = other_tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 404
    body_str = str(resp.json())
    assert "tenant-alpha" not in body_str


# ---------------------------------------------------------------------------
# Gap analysis: successful computation
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_gap_analysis_empty_assessment_returns_valid_result(tenant_client):
    """An assessment with no results should yield a valid result with gaps."""
    fw_id = _create_active_framework(tenant_client, slug="fw-gap-empty")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body = resp.json()

    # Top-level structure
    assert "result_id" in body
    assert "framework_id" in body
    assert "framework_version" in body
    assert "analysis_version" in body
    assert "analyzed_at" in body
    assert "gaps" in body
    assert "readiness_blockers" in body
    assert "maturity_blockers" in body
    assert "dependency_chains" in body
    assert "remediation_recommendations" in body
    assert "impact_estimates" in body
    assert "evidence_freshness_records" in body
    assert "replay_contract" in body

    # assessment_id pinned in result
    assert body["assessment_id"] == assessment_id


@pytest.mark.contract
def test_gap_analysis_with_non_compliant_control(tenant_client):
    """Non-compliant result should surface a gap."""
    fw_id = _create_draft_framework(tenant_client, slug="fw-gap-noncompliant")
    domain_id = _create_domain(tenant_client, fw_id, slug="gov-nc")
    ctrl_id = _create_control(tenant_client, fw_id, domain_id, identifier="NC-1")
    _activate_framework(tenant_client, fw_id)
    assessment_id = _create_assessment(tenant_client, fw_id)

    # Record a non-compliant result
    resp = tenant_client.post(
        f"/control-plane/readiness/assessments/{assessment_id}/results",
        json={"control_id": ctrl_id, "outcome": "non_compliant"},
    )
    assert resp.status_code == 201

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body = resp.json()

    # Should have at least one gap related to this control
    gap_ids_str = str(body["gaps"])
    assert ctrl_id in gap_ids_str or len(body["gaps"]) > 0


@pytest.mark.contract
def test_gap_analysis_result_id_format(tenant_client):
    """result_id should begin with 'gap::'."""
    fw_id = _create_active_framework(tenant_client, slug="fw-gap-rid")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    assert resp.json()["result_id"].startswith("gap::")


@pytest.mark.contract
def test_gap_analysis_replay_contract_present(tenant_client):
    fw_id = _create_active_framework(tenant_client, slug="fw-gap-replay")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    rc = resp.json()["replay_contract"]
    assert "contract_id" in rc
    assert "result_id" in rc
    assert "framework_version" in rc
    assert "analysis_version" in rc


@pytest.mark.contract
def test_gap_analysis_lists_are_lists(tenant_client):
    """All list fields must be lists, not None."""
    fw_id = _create_active_framework(tenant_client, slug="fw-gap-lists")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body = resp.json()

    for field in (
        "gaps",
        "readiness_blockers",
        "maturity_blockers",
        "dependency_chains",
        "remediation_recommendations",
        "impact_estimates",
        "policy_exceptions",
        "compensating_controls",
        "governance_overrides",
        "evidence_freshness_records",
    ):
        assert isinstance(body[field], list), f"{field!r} must be a list"


# ---------------------------------------------------------------------------
# Gap analysis: export safety
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_gap_analysis_export_safe_no_secrets(tenant_client):
    """Response must not contain secret-like patterns."""
    fw_id = _create_active_framework(tenant_client, slug="fw-gap-safe")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body_str = str(resp.text).lower()

    forbidden = (
        "traceback",
        "sqlalchemy",
        "sqlite",
        "stack trace",
        "password",
        "secret",
        "private_key",
        "bearer ",
        "access_token",
        "inputs_canonical",
    )
    for word in forbidden:
        assert word not in body_str, f"Response contains forbidden token: {word!r}"


@pytest.mark.contract
def test_gap_analysis_no_tenant_id_in_gaps(tenant_client):
    """Individual gap records must not expose tenant_id."""
    fw_id = _create_draft_framework(tenant_client, slug="fw-gap-no-tid")
    domain_id = _create_domain(tenant_client, fw_id, slug="gov-ntid")
    ctrl_id = _create_control(tenant_client, fw_id, domain_id, identifier="TID-1")
    _activate_framework(tenant_client, fw_id)
    assessment_id = _create_assessment(tenant_client, fw_id)

    tenant_client.post(
        f"/control-plane/readiness/assessments/{assessment_id}/results",
        json={"control_id": ctrl_id, "outcome": "non_compliant"},
    )

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body = resp.json()

    # Individual gap records must not leak tenant_id in the response
    for gap in body["gaps"]:
        assert "tenant_id" not in gap, "Gap response must not expose tenant_id"


# ---------------------------------------------------------------------------
# Gap analysis: deterministic ordering
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_gap_analysis_stable_ordering(tenant_client):
    """Two calls to gap analysis for the same assessment must return same gap order."""
    fw_id = _create_draft_framework(tenant_client, slug="fw-gap-order")
    domain_id = _create_domain(tenant_client, fw_id, slug="gov-ord")
    for i in range(3):
        _create_control(tenant_client, fw_id, domain_id, identifier=f"ORD-{i}")
    _activate_framework(tenant_client, fw_id)
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp1 = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    resp2 = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    gaps1 = [g["gap_id"] for g in resp1.json()["gaps"]]
    gaps2 = [g["gap_id"] for g in resp2.json()["gaps"]]
    assert gaps1 == gaps2, "Gap ordering must be deterministic across calls"


# ---------------------------------------------------------------------------
# GET /domains/{domain_id}
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_get_domain_by_id(api_client):
    fw_id = _create_draft_framework(api_client, slug="fw-domain-get")
    domain_id = _create_domain(api_client, fw_id, slug="gov-get")
    _activate_framework(api_client, fw_id)

    resp = api_client.get(f"/control-plane/readiness/domains/{domain_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["domain_id"] == domain_id
    assert body["framework_id"] == fw_id


@pytest.mark.contract
def test_get_domain_not_found(api_client):
    resp = api_client.get("/control-plane/readiness/domains/nonexistent-domain-id")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "READY-API-002"


@pytest.mark.contract
def test_get_domain_requires_read_scope(tmp_path, monkeypatch):
    """Request without valid key must be rejected."""
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_domain_noauth.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/control-plane/readiness/domains/any-id")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /controls/{control_id}
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_get_control_by_id(api_client):
    fw_id = _create_draft_framework(api_client, slug="fw-ctrl-get")
    domain_id = _create_domain(api_client, fw_id, slug="gov-ctrl")
    ctrl_id = _create_control(api_client, fw_id, domain_id, identifier="GET-1")
    _activate_framework(api_client, fw_id)

    resp = api_client.get(f"/control-plane/readiness/controls/{ctrl_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["control_id"] == ctrl_id
    assert body["framework_id"] == fw_id
    assert body["control_identifier"] == "GET-1"


@pytest.mark.contract
def test_get_control_not_found(api_client):
    resp = api_client.get("/control-plane/readiness/controls/nonexistent-control-id")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "READY-API-003"


@pytest.mark.contract
def test_get_control_no_secrets_in_response(api_client):
    fw_id = _create_draft_framework(api_client, slug="fw-ctrl-safe")
    domain_id = _create_domain(api_client, fw_id, slug="gov-ctrl-safe")
    ctrl_id = _create_control(api_client, fw_id, domain_id, identifier="SAFE-1")
    _activate_framework(api_client, fw_id)

    resp = api_client.get(f"/control-plane/readiness/controls/{ctrl_id}")
    assert resp.status_code == 200
    body_str = resp.text.lower()
    assert "traceback" not in body_str
    assert "sqlalchemy" not in body_str


# ---------------------------------------------------------------------------
# GET /maturity-tiers/{tier_id}
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_get_maturity_tier_by_id(api_client):
    fw_id = _create_draft_framework(api_client, slug="fw-tier-get")
    tier_id = _create_maturity_tier(api_client, fw_id, identifier="T1-GET")
    _activate_framework(api_client, fw_id)

    resp = api_client.get(f"/control-plane/readiness/maturity-tiers/{tier_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier_id"] == tier_id
    assert body["framework_id"] == fw_id
    assert body["tier_identifier"] == "T1-GET"


@pytest.mark.contract
def test_get_maturity_tier_not_found(api_client):
    resp = api_client.get("/control-plane/readiness/maturity-tiers/nonexistent-tier-id")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "READY-API-004"


@pytest.mark.contract
def test_get_maturity_tier_requires_read_scope(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_tier_noauth.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/control-plane/readiness/maturity-tiers/any-id")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Red-team / negative tests
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_gap_analysis_rejects_invalid_assessment_id_format(tenant_client):
    """Arbitrary strings as assessment_id must not expose internal state."""
    for probe in ("' OR 1=1--", "../../../etc/passwd", "a" * 512):
        resp = tenant_client.get(
            f"/control-plane/readiness/assessments/{probe}/gap-analysis"
        )
        assert resp.status_code in (404, 400, 422)
        body_str = str(resp.json())
        assert "traceback" not in body_str.lower()
        assert "sqlalchemy" not in body_str.lower()


@pytest.mark.contract
def test_gap_analysis_no_stack_trace_on_error(api_client):
    """Error responses must not contain stack traces or ORM details."""
    resp = api_client.get(
        "/control-plane/readiness/assessments/bad-id-no-tenant/gap-analysis"
    )
    # Platform key has no tenant — expect 403
    assert resp.status_code in (403, 404)
    body_str = str(resp.json()).lower()
    assert "traceback" not in body_str
    assert "file " not in body_str
    assert "line " not in body_str


@pytest.mark.contract
def test_gap_analysis_no_internal_topology(tenant_client):
    """Response must not expose internal service hostnames or paths."""
    fw_id = _create_active_framework(tenant_client, slug="fw-topo-safe")
    assessment_id = _create_assessment(tenant_client, fw_id)

    resp = tenant_client.get(
        f"/control-plane/readiness/assessments/{assessment_id}/gap-analysis"
    )
    assert resp.status_code == 200
    body_str = resp.text.lower()
    assert "localhost" not in body_str
    assert "/home/" not in body_str
    assert "sqlite:///" not in body_str
