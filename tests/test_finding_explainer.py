"""Tests for services.field_assessment.finding_explainer.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Covers:
  - PRIV finding with linked scan → counts appear in explanation
  - MFA finding with linked scan → admin_no_mfa count reflected
  - No linked evidence → generic fallback, confidence=0.4, no error
  - Wrong tenant → 404 on /explain route (tenant isolation)
  - plain_summary never contains raw payloads or credentials
  - All 7 prefix templates render without error on empty summary input
  - TTL cache: second call returns cached result
  - OAUTH finding → score_3_critical count in affected_entities
  - explanation_confidence=1.0 for known type + evidence + fresh scan
  - AI finding template renders with shadow_ai and dlp signal counts
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from fastapi.testclient import TestClient

from services.field_assessment import finding_explainer as _mod
from services.field_assessment.finding_explainer import (
    FindingExplanation,
    explain_finding,
    _explain_mfa,
    _explain_ca,
    _explain_app,
    _explain_oauth,
    _explain_ai,
    _explain_guest,
    _explain_priv,
    _explain_generic,
)

_TENANT = "tenant-explainer"


def _make_finding(
    finding_id: str = "find-001",
    finding_type: str = "msgraph.PRIV-002",
    severity: str = "high",
    title: str = "More than 5 Global Administrator accounts",
    description: str = "6 Global Admin accounts detected.",
) -> MagicMock:
    f = MagicMock()
    f.id = finding_id
    f.finding_type = finding_type
    f.severity = severity
    f.title = title
    f.description = description
    return f


def _make_scan(
    scan_id: str = "scan-001",
    collected_at: str = "2026-05-01T00:00:00Z",
    summary: dict[str, Any] | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = scan_id
    s.collected_at = collected_at
    s.normalized_payload = {"summary": summary or {}}
    return s


def _make_link(scan_id: str = "scan-001") -> MagicMock:
    lnk = MagicMock()
    lnk.evidence_entity_type = "scan_result"
    lnk.evidence_entity_id = scan_id
    return lnk


# ─── Unit tests — pure template functions ────────────────────────────────────


def test_priv_template_uses_global_admin_count() -> None:
    finding = _make_finding(finding_type="msgraph.PRIV-002")
    summary = {
        "privileged_roles": {"global_admin_count": 7, "permanent_assignments": 3}
    }
    plain, what, entities = _explain_priv(finding, None, summary)
    assert "7" in plain
    assert any(e.entity_type == "admin_user" for e in entities)
    assert any(e.count == 7 for e in entities)


def test_mfa_template_uses_admin_no_mfa_count() -> None:
    finding = _make_finding(
        finding_type="msgraph.MFA-001", title="Admin account(s) with no MFA registered"
    )
    summary = {
        "mfa": {
            "admin_no_mfa": 2,
            "total_enabled_users": 50,
            "coverage_pct": 96.0,
            "no_mfa": 2,
            "weak_mfa_only": 0,
        }
    }
    plain, what, entities = _explain_mfa(finding, None, summary)
    assert "2" in plain
    assert "administrator" in plain.lower()
    assert any(e.entity_type == "admin_user" and e.count == 2 for e in entities)


def test_oauth_template_uses_score_3_critical() -> None:
    finding = _make_finding(
        finding_type="msgraph.OAUTH-001", title="Critical OAuth grant"
    )
    summary = {
        "oauth_consent": {
            "score_3_critical": 4,
            "total_grants": 20,
            "user_consented": 15,
            "stale_grants_180d": 2,
            "unverified_publisher_grants": 4,
            "score_2_high": 1,
        }
    }
    plain, what, entities = _explain_oauth(finding, None, summary)
    assert "4" in plain
    assert any(e.count == 4 for e in entities)


def test_ai_template_uses_shadow_and_dlp_counts() -> None:
    finding = _make_finding(finding_type="msgraph.AI-001", title="AI DLP critical")
    summary = {
        "ai_signals": {
            "shadow_ai_apps": 3,
            "dlp_score_3_critical": 2,
            "dlp_score_2_high": 1,
            "unapproved_ai_apps": 5,
            "copilot_active_users": 10,
            "user_consented_ai": 8,
        }
    }
    plain, what, entities = _explain_ai(finding, None, summary)
    assert "2" in plain
    assert any(e.entity_type == "app" and e.count == 2 for e in entities)


def test_all_templates_render_on_empty_summary() -> None:
    finding = _make_finding()
    empty: dict[str, Any] = {}
    for fn in (
        _explain_mfa,
        _explain_ca,
        _explain_app,
        _explain_oauth,
        _explain_ai,
        _explain_guest,
        _explain_priv,
    ):
        plain, what, entities = fn(finding, None, empty)
        assert isinstance(plain, str) and plain
        assert isinstance(what, str) and what
        assert isinstance(entities, list)


def test_generic_fallback_uses_finding_title() -> None:
    finding = _make_finding(
        title="Custom finding type", description="Some description."
    )
    plain, what, entities = _explain_generic(finding, None, {})
    assert "Custom finding type" in plain
    assert entities == []


# ─── Unit tests — explain_finding with mocked DB ─────────────────────────────


def _clear_cache() -> None:
    _mod._CACHE.clear()


def test_explain_finding_with_linked_scan() -> None:
    _clear_cache()
    finding = _make_finding(finding_type="msgraph.PRIV-002")
    scan = _make_scan(
        summary={
            "privileged_roles": {"global_admin_count": 8, "permanent_assignments": 5}
        }
    )
    link = _make_link(scan.id)

    db = MagicMock()
    with (
        patch.object(_mod, "get_finding", return_value=finding),
        patch.object(_mod, "list_evidence_links", return_value=[link]),
        patch.object(_mod, "get_scan_result", return_value=scan),
    ):
        result = explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-x", finding_id="find-001"
        )

    assert isinstance(result, FindingExplanation)
    assert "8" in result.plain_summary
    assert result.evidence_count == 1
    assert scan.id in result.source_scan_ids
    assert result.explanation_confidence >= 0.7


def test_explain_finding_no_evidence_fallback() -> None:
    _clear_cache()
    finding = _make_finding(finding_type="msgraph.PRIV-002")
    db = MagicMock()
    with (
        patch.object(_mod, "get_finding", return_value=finding),
        patch.object(_mod, "list_evidence_links", return_value=[]),
    ):
        result = explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-x", finding_id="find-002"
        )

    assert isinstance(result, FindingExplanation)
    assert result.evidence_count == 0
    assert result.source_scan_ids == []
    assert result.explanation_confidence == 0.7


def test_explain_finding_unknown_type_confidence_low() -> None:
    _clear_cache()
    finding = _make_finding(
        finding_type="custom.UNKNOWN-999", title="Unknown type", description="Desc."
    )
    db = MagicMock()
    with (
        patch.object(_mod, "get_finding", return_value=finding),
        patch.object(_mod, "list_evidence_links", return_value=[]),
    ):
        result = explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-x", finding_id="find-003"
        )

    assert result.explanation_confidence == 0.4


def test_explain_finding_ttl_cache() -> None:
    _clear_cache()
    finding = _make_finding(finding_type="msgraph.MFA-001")
    db = MagicMock()

    call_count = {"n": 0}

    def counting_get_finding(*args: Any, **kwargs: Any) -> Any:
        call_count["n"] += 1
        return finding

    with (
        patch.object(_mod, "get_finding", side_effect=counting_get_finding),
        patch.object(_mod, "list_evidence_links", return_value=[]),
    ):
        explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-cache", finding_id="find-cache"
        )
        explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-cache", finding_id="find-cache"
        )

    assert call_count["n"] == 1, "second call should use TTL cache"


def test_plain_summary_contains_no_credentials_or_raw_payload() -> None:
    _clear_cache()
    sensitive_payload = {
        "raw_payload": "password=secret&token=abc123",
        "userPrincipalName": "admin@corp.com",
        "export_safe": False,
    }
    scan = _make_scan(summary={"privileged_roles": {"global_admin_count": 3}})
    scan.normalized_payload = {
        "summary": {"privileged_roles": {"global_admin_count": 3}},
        "raw": sensitive_payload,
    }
    link = _make_link(scan.id)
    finding = _make_finding(finding_type="msgraph.PRIV-005")
    db = MagicMock()

    with (
        patch.object(_mod, "get_finding", return_value=finding),
        patch.object(_mod, "list_evidence_links", return_value=[link]),
        patch.object(_mod, "get_scan_result", return_value=scan),
    ):
        result = explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-x", finding_id="find-cred"
        )

    assert "password" not in result.plain_summary
    assert "token" not in result.plain_summary
    assert "admin@corp.com" not in result.plain_summary
    assert "secret" not in result.plain_summary


def test_high_confidence_fresh_scan() -> None:
    _clear_cache()
    finding = _make_finding(finding_type="msgraph.MFA-001")
    from services.canonical import utc_iso8601_z_now

    recent_ts = utc_iso8601_z_now()
    scan = _make_scan(
        collected_at=recent_ts,
        summary={
            "mfa": {
                "admin_no_mfa": 1,
                "total_enabled_users": 20,
                "coverage_pct": 95.0,
                "no_mfa": 1,
                "weak_mfa_only": 0,
            }
        },
    )
    link = _make_link(scan.id)
    db = MagicMock()

    with (
        patch.object(_mod, "get_finding", return_value=finding),
        patch.object(_mod, "list_evidence_links", return_value=[link]),
        patch.object(_mod, "get_scan_result", return_value=scan),
    ):
        result = explain_finding(
            db, tenant_id=_TENANT, engagement_id="eng-x", finding_id="find-hc"
        )

    assert result.explanation_confidence == 1.0


# ─── Integration tests — HTTP route ──────────────────────────────────────────


@pytest.fixture()
def client(build_app: Any) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-ID": _TENANT})


def _create_engagement(client: TestClient) -> dict[str, Any]:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Explainer Test Corp",
            "assessor_id": "assessor-explain",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_finding(client: TestClient, engagement_id: str) -> dict[str, Any]:
    """Ingest a scan with a PRIV-002 finding, then return the normalized finding row."""
    scan_resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-01T00:00:00Z",
            "raw_payload": {"users": []},
            "object_count": 0,
            "normalized_payload": {
                "findings": [
                    {
                        "finding_type": "msgraph.PRIV-002",
                        "severity": "high",
                        "title": "More than 5 Global Administrator accounts",
                        "description": "6 Global Admin accounts detected.",
                    }
                ]
            },
        },
    )
    assert scan_resp.status_code == 201, scan_resp.text
    list_resp = client.get(f"/field-assessment/engagements/{engagement_id}/findings")
    assert list_resp.status_code == 200, list_resp.text
    items = list_resp.json()["items"]
    assert items, "no findings created by scan ingest"
    return items[0]


def test_explain_route_returns_explanation(client: TestClient) -> None:
    _clear_cache()
    eng = _create_engagement(client)
    finding = _create_finding(client, eng["id"])
    resp = client.get(
        f"/field-assessment/engagements/{eng['id']}/findings/{finding['id']}/explain"
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["finding_id"] == finding["id"]
    assert isinstance(body["plain_summary"], str) and body["plain_summary"]
    assert isinstance(body["what_it_means"], str)
    assert isinstance(body["affected_entities"], list)
    assert isinstance(body["explanation_confidence"], float)
    assert "source_scan_ids" in body
    assert body["schema_version"] == "1.0"


def test_explain_route_wrong_tenant_returns_404(build_app: Any) -> None:
    _clear_cache()
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    owner_key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
    owner_client = TestClient(
        app, headers={"X-API-Key": owner_key, "X-Tenant-ID": _TENANT}
    )
    eng = _create_engagement(owner_client)
    finding = _create_finding(owner_client, eng["id"])

    other_tenant = "tenant-other-explainer"
    other_key = mint_key("governance:read", tenant_id=other_tenant)
    other_client = TestClient(
        app, headers={"X-API-Key": other_key, "X-Tenant-ID": other_tenant}
    )
    resp = other_client.get(
        f"/field-assessment/engagements/{eng['id']}/findings/{finding['id']}/explain"
    )
    assert resp.status_code == 404
