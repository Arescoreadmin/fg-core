"""Tests for services.field_assessment.executive_summary.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Covers:
  - ProviderResponse.text JSON is parsed and used
  - ProviderResponse without content still works when text is present
  - Invalid provider JSON falls back to deterministic template
  - Empty provider response falls back deterministically
  - Provider exception falls back deterministically
  - Deterministic fallback is stable and export-safe
  - No raw provider dataclass repr leaks into client output
  - Executive summary section appears in generated report response
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from services.field_assessment.executive_summary import (
    generate_executive_summary,
    _template_summary,
    _severity_counts,
    _risk_posture_from_counts,
    _GENERATION_NOTE,
)

_TENANT = "tenant-exec-summary"
_ENG = "eng-exec-001"

_VALID_PROVIDER_JSON = json.dumps(
    {
        "narrative": "This organization has a high-risk AI governance posture. Two critical gaps in data governance and security posture require immediate attention. Addressing these items will meaningfully reduce exposure.",
        "risk_posture": "high",
        "key_concerns": [
            "Data governance controls require immediate remediation",
            "Security posture gap identified across two domains",
        ],
    }
)

_FINDINGS = [
    {"severity": "high", "domain": "data_governance", "gap_classification": "high_gap"},
    {
        "severity": "medium",
        "domain": "security_posture",
        "gap_classification": "moderate_gap",
    },
]

_FRAMEWORK_SUMMARY = {"NIST_AI_RMF": ["data_governance", "security_posture"]}


def _make_provider_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    # Intentionally do NOT set resp.content — tests must work without it
    del resp.content
    return resp


# ---------------------------------------------------------------------------
# Unit: _severity_counts + _risk_posture_from_counts
# ---------------------------------------------------------------------------


def test_severity_counts_empty():
    assert _severity_counts([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_severity_counts_mixed():
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
    ]
    counts = _severity_counts(findings)
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 0


def test_risk_posture_critical_takes_precedence():
    counts = {"critical": 1, "high": 2, "medium": 3, "low": 0}
    assert _risk_posture_from_counts(counts) == "critical"


def test_risk_posture_low_when_no_gaps():
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert _risk_posture_from_counts(counts) == "low"


# ---------------------------------------------------------------------------
# Unit: _template_summary — deterministic fallback
# ---------------------------------------------------------------------------


def test_template_summary_structure():
    result = _template_summary(
        severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        framework_names=["NIST_AI_RMF"],
        finding_count=1,
        risk_posture="critical",
    )
    assert "narrative" in result
    assert "risk_posture" in result
    assert "key_concerns" in result
    assert "generation_note" in result
    assert result["risk_posture"] == "critical"
    assert result["generation_note"] == _GENERATION_NOTE


def test_template_summary_no_secrets():
    result = _template_summary(
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
        framework_names=["SOC2"],
        finding_count=1,
        risk_posture="high",
    )
    narrative = result["narrative"]
    assert "sk-" not in narrative
    assert "password" not in narrative.lower()
    assert "secret" not in narrative.lower()


def test_template_summary_no_raw_prompt_or_provider_metadata():
    result = _template_summary(
        severity_counts={"critical": 0, "high": 0, "medium": 1, "low": 0},
        framework_names=[],
        finding_count=1,
        risk_posture="medium",
    )
    narrative = result["narrative"]
    assert "anthropic" not in narrative.lower()
    assert "claude" not in narrative.lower()
    assert "ProviderResponse" not in narrative
    assert "dataclass" not in narrative


def test_template_summary_key_concerns_capped_at_3():
    result = _template_summary(
        severity_counts={"critical": 2, "high": 3, "medium": 4, "low": 0},
        framework_names=["NIST_AI_RMF", "SOC2", "HIPAA"],
        finding_count=9,
        risk_posture="critical",
    )
    assert len(result["key_concerns"]) <= 3


# ---------------------------------------------------------------------------
# test_executive_summary_uses_provider_response_text
# ---------------------------------------------------------------------------


def test_executive_summary_uses_provider_response_text():
    """ProviderResponse.text JSON is parsed and used; no fallback to dataclass repr."""
    resp = _make_provider_response(_VALID_PROVIDER_JSON)

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.72,
        )

    assert result["narrative"] == json.loads(_VALID_PROVIDER_JSON)["narrative"]
    assert result["risk_posture"] == "high"
    assert len(result["key_concerns"]) == 2
    assert result["generation_note"] == _GENERATION_NOTE


# ---------------------------------------------------------------------------
# test_executive_summary_does_not_parse_provider_dataclass_repr
# ---------------------------------------------------------------------------


def test_executive_summary_does_not_parse_provider_dataclass_repr():
    """str(ProviderResponse) is a dataclass repr, not JSON — must fall back deterministically."""
    resp = MagicMock()
    resp.text = None
    # Simulate what str(resp) looks like for a dataclass
    resp.__str__ = lambda self: (
        "ProviderResponse(provider_id='anthropic', text=None, model='claude-...')"
    )
    del resp.content

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.5,
        )

    # Must have fallen back to deterministic template — not the dataclass repr
    assert "ProviderResponse" not in result["narrative"]
    assert "provider_id" not in result["narrative"]
    assert result["generation_note"] == _GENERATION_NOTE


# ---------------------------------------------------------------------------
# test_executive_summary_invalid_provider_json_falls_back
# ---------------------------------------------------------------------------


def test_executive_summary_invalid_provider_json_falls_back():
    """Non-JSON provider response falls back to deterministic template."""
    resp = _make_provider_response("This is not JSON at all.")

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.6,
        )

    assert "narrative" in result
    assert "risk_posture" in result
    # Template fallback narrative is a plain string, not provider garbage
    assert "not JSON" not in result["narrative"]


# ---------------------------------------------------------------------------
# test_executive_summary_empty_provider_response_falls_back
# ---------------------------------------------------------------------------


def test_executive_summary_empty_provider_response_falls_back():
    """Empty text field falls back deterministically without raising."""
    resp = _make_provider_response("")

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.4,
        )

    assert result["narrative"]
    assert result["generation_note"] == _GENERATION_NOTE


# ---------------------------------------------------------------------------
# test_executive_summary_provider_exception_falls_back
# ---------------------------------------------------------------------------


def test_executive_summary_provider_exception_falls_back():
    """Provider exception does not propagate; falls back deterministically."""
    from services.ai.providers.base import ProviderCallError, AI_PROVIDER_CALL_FAILED

    with patch(
        "services.ai.dispatch.call_provider",
        side_effect=ProviderCallError(AI_PROVIDER_CALL_FAILED, "timeout"),
    ):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=[
                {
                    "severity": "critical",
                    "domain": "data_governance",
                    "gap_classification": "critical_gap",
                }
            ],
            framework_summary={"NIST_AI_RMF": ["data_governance"]},
            confidence_overall=0.3,
        )

    assert result["narrative"]
    assert result["risk_posture"] == "critical"
    assert result["generation_note"] == _GENERATION_NOTE


# ---------------------------------------------------------------------------
# test_executive_summary_narrative_blank_falls_back
# ---------------------------------------------------------------------------


def test_executive_summary_narrative_blank_falls_back():
    """Provider returns JSON but narrative is blank — fall back to template."""
    empty_narrative = json.dumps(
        {"narrative": "", "risk_posture": "high", "key_concerns": []}
    )
    resp = _make_provider_response(empty_narrative)

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.5,
        )

    assert result["narrative"]  # template fallback is non-empty


# ---------------------------------------------------------------------------
# test_executive_summary_invalid_risk_posture_clamped
# ---------------------------------------------------------------------------


def test_executive_summary_invalid_risk_posture_clamped():
    """Provider returns invalid risk_posture — clamped to deterministic value."""
    bad_posture = json.dumps(
        {
            "narrative": "Some narrative text here.",
            "risk_posture": "severe",  # not a valid value
            "key_concerns": [],
        }
    )
    resp = _make_provider_response(bad_posture)

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.6,
        )

    assert result["risk_posture"] in ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# test_executive_summary_markdown_fences_stripped
# ---------------------------------------------------------------------------


def test_executive_summary_markdown_fences_stripped():
    """Provider wraps JSON in markdown fences — still parsed correctly."""
    fenced = f"```json\n{_VALID_PROVIDER_JSON}\n```"
    resp = _make_provider_response(fenced)

    with patch("services.ai.dispatch.call_provider", return_value=resp):
        result = generate_executive_summary(
            engagement_id=_ENG,
            tenant_id=_TENANT,
            findings=_FINDINGS,
            framework_summary=_FRAMEWORK_SUMMARY,
            confidence_overall=0.7,
        )

    assert result["narrative"] == json.loads(_VALID_PROVIDER_JSON)["narrative"]


# ---------------------------------------------------------------------------
# Integration tests — HTTP create-and-readback for executive_summary reports
# ---------------------------------------------------------------------------

_TENANT_ES = "tenant-es-integration"
_TENANT_ES_B = "tenant-es-integration-b"

_ES_ENGAGEMENT_BODY = {
    "client_name": "ES Integration Corp",
    "assessor_id": "assessor-es-001",
    "assessment_type": "ai_governance",
}

_ES_SUMMARY_STUB = {
    "narrative": "Integration test narrative for executive summary.",
    "risk_posture": "medium",
    "key_concerns": ["Integration test concern"],
    "generation_note": _GENERATION_NOTE,
}


def _issue_key_es(tenant_id: str, *scopes: str) -> tuple[str, str]:
    import uuid as _uuid

    from api.credential_authority import issue_credential
    from api.db import get_engine
    from sqlalchemy import text as sa_text

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            sa_text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state)"
                " VALUES (:tid, 'active')"
            ),
            {"tid": tenant_id},
        )
    result = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"test:{_uuid.uuid4()}",
        scopes=list(scopes),
    )
    plaintext_secret = result.plaintext_secret
    assert plaintext_secret is not None
    return plaintext_secret, result.record.credential_id


def _assign_analyst_es(tenant_id: str, credential_id: str) -> None:
    from api.db import get_engine
    from api.tenant_rbac import assign_role
    from sqlalchemy.orm import Session

    with Session(get_engine()) as db:
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            credential_id=credential_id,
            role_name="analyst",
        )
        db.commit()


@pytest.fixture()
def client_es(build_app, monkeypatch):
    """Tenant ES-A client with analyst permissions; TrustBindingFake active via FG_ENV=test."""
    app = build_app(auth_enabled=True)
    key, cred_id = _issue_key_es(_TENANT_ES, "governance:read", "governance:write")
    _assign_analyst_es(_TENANT_ES, cred_id)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def read_only_client_es(build_app, monkeypatch):
    """Tenant ES-A client with governance:read only (no write)."""
    app = build_app(auth_enabled=True)
    key, cred_id = _issue_key_es(_TENANT_ES, "governance:read")
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def no_signing_key_client_es(build_app, monkeypatch):
    """Analyst-scoped client whose signing authority always raises VaultTransitError."""
    app = build_app(auth_enabled=True)
    key, cred_id = _issue_key_es(_TENANT_ES, "governance:read", "governance:write")
    _assign_analyst_es(_TENANT_ES, cred_id)

    import api.field_assessment as _fa_module
    from services.cgin.key_management.vault_transit import VaultTransitError

    def _unavailable_authority():
        raise VaultTransitError("Signing authority not configured (test: key missing)")

    monkeypatch.setattr(
        _fa_module, "_get_trust_binding_authority", _unavailable_authority
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def unauthed_client_es(build_app):
    """Client with no API key."""
    app = build_app(auth_enabled=True)
    return TestClient(app)


@pytest.fixture()
def client_b_es(build_app):
    """Tenant ES-B client — for cross-tenant isolation."""
    app = build_app(auth_enabled=True)
    key, cred_id = _issue_key_es(_TENANT_ES_B, "governance:read", "governance:write")
    _assign_analyst_es(_TENANT_ES_B, cred_id)
    return TestClient(app, headers={"X-API-Key": key})


def _make_es_engagement(client: TestClient) -> str:
    resp = client.post("/field-assessment/engagements", json=_ES_ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_exec_summary_post_receipt_shape(client_es: TestClient) -> None:
    """POST returns a 201 receipt with report_id, version, status, and compiled_at.

    POST /engagements/{id}/reports returns ONLY a metadata receipt — the full
    report (including executive_summary) lives in the GET response.
    """
    eid = _make_es_engagement(client_es)
    with patch(
        "services.field_assessment.executive_summary.generate_executive_summary",
        return_value=_ES_SUMMARY_STUB,
    ):
        resp = client_es.post(
            f"/field-assessment/engagements/{eid}/reports",
            json={"report_type": "executive_summary"},
        )
    assert resp.status_code == 201, resp.text
    receipt = resp.json()
    assert "report_id" in receipt, "receipt must include report_id"
    assert receipt["version"] == 1, (
        f"first report must be version 1, got {receipt['version']}"
    )
    assert receipt["status"] == "finalized", (
        f"status must be 'finalized', got {receipt['status']!r}"
    )
    assert "compiled_at" in receipt, "receipt must include compiled_at"
    assert "executive_summary" not in receipt, (
        "POST receipt must NOT include executive_summary — that field lives in the GET response"
    )


def test_exec_summary_readback_contains_section(client_es: TestClient) -> None:
    """GET /engagements/{id}/reports/{version} returns report.executive_summary with grounded content."""
    eid = _make_es_engagement(client_es)
    with patch(
        "services.field_assessment.executive_summary.generate_executive_summary",
        return_value=_ES_SUMMARY_STUB,
    ):
        post_resp = client_es.post(
            f"/field-assessment/engagements/{eid}/reports",
            json={"report_type": "executive_summary"},
        )
    assert post_resp.status_code == 201, post_resp.text
    version = post_resp.json()["version"]

    get_resp = client_es.get(f"/field-assessment/engagements/{eid}/reports/{version}")
    assert get_resp.status_code == 200, get_resp.text
    body = get_resp.json()

    assert "report" in body, "GET response must include a 'report' field"
    report = body["report"]
    assert "executive_summary" in report, (
        "report.executive_summary must be present for report_type=executive_summary"
    )
    es = report["executive_summary"]
    assert isinstance(es.get("narrative"), str) and es["narrative"], (
        "executive_summary.narrative must be a non-empty string"
    )
    assert isinstance(es.get("risk_posture"), str), (
        "executive_summary.risk_posture must be a string"
    )
    assert isinstance(es.get("key_concerns"), list), (
        "executive_summary.key_concerns must be a list"
    )
    assert es["narrative"] == _ES_SUMMARY_STUB["narrative"], (
        "executive_summary.narrative must match the stubbed value"
    )


def test_exec_summary_unauthenticated_rejected(unauthed_client_es: TestClient) -> None:
    """POST without an API key must be rejected (fail closed)."""
    resp = unauthed_client_es.post(
        "/field-assessment/engagements/eng-fake/reports",
        json={"report_type": "executive_summary"},
    )
    assert resp.status_code in (401, 403), (
        f"unauthenticated POST must be rejected, got {resp.status_code}"
    )


def test_exec_summary_read_only_scope_rejected(read_only_client_es: TestClient) -> None:
    """POST with governance:read but not governance:write must be rejected."""
    resp = read_only_client_es.post(
        "/field-assessment/engagements/eng-fake/reports",
        json={"report_type": "executive_summary"},
    )
    assert resp.status_code in (401, 403), (
        f"read-only scope must be rejected for POST, got {resp.status_code}"
    )


def test_exec_summary_no_signing_key_fails_loudly(
    no_signing_key_client_es: TestClient,
) -> None:
    """POST when signing authority is unavailable must return 503 (fail closed)."""
    eid = _make_es_engagement(no_signing_key_client_es)
    resp = no_signing_key_client_es.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "executive_summary"},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["code"] == "REPORT_SIGNING_KEY_MISSING"


def test_exec_summary_cross_tenant_engagement_not_found(
    client_b_es: TestClient, client_es: TestClient
) -> None:
    """Tenant B cannot generate a report for Tenant A's engagement (returns 404)."""
    with patch(
        "services.field_assessment.executive_summary.generate_executive_summary",
        return_value=_ES_SUMMARY_STUB,
    ):
        eid = _make_es_engagement(client_es)
        resp = client_b_es.post(
            f"/field-assessment/engagements/{eid}/reports",
            json={"report_type": "executive_summary"},
        )
    assert resp.status_code == 404, (
        f"cross-tenant engagement access must return 404, got {resp.status_code}"
    )


def test_exec_summary_missing_version_not_found(client_es: TestClient) -> None:
    """GET for a non-existent version must return 404 without leaking existence."""
    eid = _make_es_engagement(client_es)
    resp = client_es.get(f"/field-assessment/engagements/{eid}/reports/999")
    assert resp.status_code == 404, (
        f"missing version must return 404, got {resp.status_code}"
    )
