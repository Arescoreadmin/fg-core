"""Tests for NIST AI RMF questionnaire — mapping normalization, engagement isolation,
evidence linking, and deterministic lineage."""

from __future__ import annotations

import json
import os
from typing import Any

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from fastapi.testclient import TestClient

from services.field_assessment.questionnaire_store import normalize_nist_control

_TENANT_ID = "tenant-questionnaire-tests"


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> dict[str, Any]:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Coverage Corp",
            "assessor_id": "assessor-q",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _init_questionnaire(client: TestClient, engagement_id: str) -> dict[str, Any]:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/questionnaires",
        json={"framework": "nist_ai_rmf"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Unit tests — normalize_nist_control
# ---------------------------------------------------------------------------


class TestNormalizeNistControl:
    def test_string_with_prefix(self) -> None:
        assert normalize_nist_control("NIST-AI-RMF-GOVERN-1.2") == "GOVERN-1.2"

    def test_string_without_prefix(self) -> None:
        assert normalize_nist_control("GOVERN-1.2") == "GOVERN-1.2"

    def test_string_manage(self) -> None:
        assert normalize_nist_control("NIST-AI-RMF-MANAGE-2.2") == "MANAGE-2.2"

    def test_dict_control_id_with_prefix(self) -> None:
        assert (
            normalize_nist_control({"control_id": "NIST-AI-RMF-GOVERN-1.2"})
            == "GOVERN-1.2"
        )

    def test_dict_control_id_without_prefix(self) -> None:
        assert normalize_nist_control({"control_id": "GOVERN-1.2"}) == "GOVERN-1.2"

    def test_dict_function_category(self) -> None:
        assert (
            normalize_nist_control(
                {"function": "GOVERN", "category": "GOVERN-1.2", "description": "x"}
            )
            == "GOVERN-1.2"
        )

    def test_dict_function_category_manage(self) -> None:
        assert (
            normalize_nist_control({"function": "MANAGE", "category": "MANAGE-2.2"})
            == "MANAGE-2.2"
        )

    def test_empty_string_returns_none(self) -> None:
        assert normalize_nist_control("") is None

    def test_none_returns_none(self) -> None:
        assert normalize_nist_control(None) is None

    def test_integer_returns_none(self) -> None:
        assert normalize_nist_control(42) is None

    def test_empty_dict_returns_none(self) -> None:
        assert normalize_nist_control({}) is None


# ---------------------------------------------------------------------------
# Evidence linking — three supported mapping shapes
# ---------------------------------------------------------------------------


def _import_scan_with_mapping(
    client: TestClient,
    engagement_id: str,
    mapping: Any,
) -> None:
    """Import a normalized finding with the given nist_ai_rmf_mappings via scan result.

    Uses the mapping as a marker in raw_payload so each distinct mapping produces a
    distinct evidence_hash (create_scan_result is idempotent by hash).
    """
    marker = json.dumps(mapping, sort_keys=True)
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-27T10:00:00Z",
            "raw_payload": {"users": [{"_mapping_marker": marker}]},
            "normalized_payload": {
                "findings": [
                    {
                        "finding_type": "mfa_gap",
                        "title": "Test finding",
                        "description": "Test description for NIST mapping test",
                        "severity": "high",
                        "framework_mappings": ["NIST-AI-RMF"],
                        "nist_ai_rmf_mappings": [mapping],
                    }
                ]
            },
        },
    )
    assert resp.status_code in (200, 201), resp.text


def _submit_with_control(
    client: TestClient,
    engagement_id: str,
    questionnaire_id: str,
    control_id: str,
) -> None:
    resp = client.patch(
        f"/field-assessment/engagements/{engagement_id}/questionnaires/{questionnaire_id}/responses/{control_id}",
        json={"response_status": "implemented", "evidence_text": "Policy in place"},
    )
    assert resp.status_code == 200, resp.text

    resp2 = client.post(
        f"/field-assessment/engagements/{engagement_id}/questionnaires/{questionnaire_id}/submit"
    )
    assert resp2.status_code == 200, resp2.text


def test_questionnaire_links_string_control_ids(client: TestClient) -> None:
    """String mapping 'NIST-AI-RMF-GOVERN-1.2' creates evidence link."""
    eng = _create_engagement(client)
    _import_scan_with_mapping(client, eng["id"], "NIST-AI-RMF-GOVERN-1.2")
    q = _init_questionnaire(client, eng["id"])
    _submit_with_control(client, eng["id"], q["id"], "GOVERN-1.2")

    links = client.get(f"/field-assessment/engagements/{eng['id']}/evidence-links")
    assert links.status_code == 200
    body = links.json()
    q_links = [
        lk for lk in body if lk.get("evidence_entity_type") == "questionnaire_response"
    ]
    assert len(q_links) >= 1
    meta = q_links[0]["link_metadata"]
    assert meta["matched_control_id"] == "GOVERN-1.2"
    assert meta["link_reason"] == "nist_control_match"


def test_questionnaire_links_control_id_objects(client: TestClient) -> None:
    """Object mapping {"control_id": "NIST-AI-RMF-GOVERN-1.4"} creates evidence link."""
    eng = _create_engagement(client)
    _import_scan_with_mapping(
        client, eng["id"], {"control_id": "NIST-AI-RMF-GOVERN-1.4"}
    )
    q = _init_questionnaire(client, eng["id"])
    _submit_with_control(client, eng["id"], q["id"], "GOVERN-1.4")

    links = client.get(f"/field-assessment/engagements/{eng['id']}/evidence-links")
    assert links.status_code == 200
    q_links = [
        lk
        for lk in links.json()
        if lk.get("evidence_entity_type") == "questionnaire_response"
    ]
    assert len(q_links) >= 1
    meta = q_links[0]["link_metadata"]
    assert meta["matched_control_id"] == "GOVERN-1.4"
    assert meta["link_reason"] == "nist_control_match"


def test_questionnaire_links_function_category_objects(client: TestClient) -> None:
    """MS Graph shape {"function": "GOVERN", "category": "GOVERN-1.2"} creates link."""
    eng = _create_engagement(client)
    _import_scan_with_mapping(
        client,
        eng["id"],
        {"function": "GOVERN", "category": "GOVERN-1.2", "description": "OAuth risk"},
    )
    q = _init_questionnaire(client, eng["id"])
    _submit_with_control(client, eng["id"], q["id"], "GOVERN-1.2")

    links = client.get(f"/field-assessment/engagements/{eng['id']}/evidence-links")
    assert links.status_code == 200
    q_links = [
        lk
        for lk in links.json()
        if lk.get("evidence_entity_type") == "questionnaire_response"
    ]
    assert len(q_links) >= 1
    meta = q_links[0]["link_metadata"]
    assert meta["matched_control_id"] == "GOVERN-1.2"
    assert meta["link_reason"] == "nist_control_match"
    assert meta["source_type"] == "questionnaire"
    assert meta["source_response_id"] is not None


def test_questionnaire_creates_evidence_links_from_msgraph_findings(
    client: TestClient,
) -> None:
    """Full end-to-end: MS Graph mapping shape produces evidence links on submit."""
    eng = _create_engagement(client)
    # MS Graph bridge stores {"function": ..., "category": ..., "description": ...}
    for ctrl in ["GOVERN-1.2", "GOVERN-1.4", "MANAGE-2.2"]:
        func = ctrl.split("-")[0]
        _import_scan_with_mapping(
            client,
            eng["id"],
            {"function": func, "category": ctrl, "description": "scan finding"},
        )

    q = _init_questionnaire(client, eng["id"])
    for ctrl in ["GOVERN-1.2", "GOVERN-1.4", "MANAGE-2.2"]:
        client.patch(
            f"/field-assessment/engagements/{eng['id']}/questionnaires/{q['id']}/responses/{ctrl}",
            json={"response_status": "partial"},
        )

    submit = client.post(
        f"/field-assessment/engagements/{eng['id']}/questionnaires/{q['id']}/submit"
    )
    assert submit.status_code == 200

    links = client.get(f"/field-assessment/engagements/{eng['id']}/evidence-links")
    assert links.status_code == 200
    q_links = [
        lk
        for lk in links.json()
        if lk.get("evidence_entity_type") == "questionnaire_response"
    ]
    assert len(q_links) == 3
    for lk in q_links:
        meta = lk["link_metadata"]
        assert meta["link_reason"] == "nist_control_match"
        assert meta["source_type"] == "questionnaire"
        assert meta["source_response_id"] is not None
        assert meta["source_question_id"] is not None
        assert meta["matched_control_id"] in {"GOVERN-1.2", "GOVERN-1.4", "MANAGE-2.2"}


# ---------------------------------------------------------------------------
# Engagement isolation (Blocker 2)
# ---------------------------------------------------------------------------


@pytest.fixture()
def two_engagements(client: TestClient) -> tuple[dict, dict, dict]:
    """Returns (engagement_a, engagement_b, questionnaire_a)."""
    eng_a = _create_engagement(client)
    eng_b = _create_engagement(client)
    q_a = _init_questionnaire(client, eng_a["id"])
    return eng_a, eng_b, q_a


def test_get_questionnaire_wrong_engagement_returns_404(
    client: TestClient, two_engagements: tuple
) -> None:
    eng_a, eng_b, q_a = two_engagements
    resp = client.get(
        f"/field-assessment/engagements/{eng_b['id']}/questionnaires/{q_a['id']}"
    )
    assert resp.status_code == 404


def test_patch_questionnaire_wrong_engagement_returns_404(
    client: TestClient, two_engagements: tuple
) -> None:
    eng_a, eng_b, q_a = two_engagements
    resp = client.patch(
        f"/field-assessment/engagements/{eng_b['id']}/questionnaires/{q_a['id']}/responses/GOVERN-1.1",
        json={"response_status": "implemented"},
    )
    assert resp.status_code == 404


def test_submit_questionnaire_wrong_engagement_returns_404(
    client: TestClient, two_engagements: tuple
) -> None:
    eng_a, eng_b, q_a = two_engagements
    # Mark one control so submit would succeed if engagement isolation were absent
    client.patch(
        f"/field-assessment/engagements/{eng_a['id']}/questionnaires/{q_a['id']}/responses/GOVERN-1.1",
        json={"response_status": "implemented"},
    )
    resp = client.post(
        f"/field-assessment/engagements/{eng_b['id']}/questionnaires/{q_a['id']}/submit"
    )
    assert resp.status_code == 404


def test_submit_event_written_to_correct_engagement(
    client: TestClient, two_engagements: tuple
) -> None:
    eng_a, eng_b, q_a = two_engagements
    client.patch(
        f"/field-assessment/engagements/{eng_a['id']}/questionnaires/{q_a['id']}/responses/GOVERN-1.1",
        json={"response_status": "implemented"},
    )
    submit = client.post(
        f"/field-assessment/engagements/{eng_a['id']}/questionnaires/{q_a['id']}/submit"
    )
    assert submit.status_code == 200

    audit_a = client.get(f"/field-assessment/engagements/{eng_a['id']}/audit-events")
    audit_b = client.get(f"/field-assessment/engagements/{eng_b['id']}/audit-events")
    assert audit_a.status_code == 200
    assert audit_b.status_code == 200

    events_a = [e["event_type"] for e in audit_a.json()]
    events_b = [e["event_type"] for e in audit_b.json()]
    assert "questionnaire.submitted" in events_a
    assert "questionnaire.submitted" not in events_b


# ---------------------------------------------------------------------------
# Evidence lineage — deterministic metadata
# ---------------------------------------------------------------------------


def test_evidence_link_metadata_is_deterministic(client: TestClient) -> None:
    eng = _create_engagement(client)
    _import_scan_with_mapping(
        client,
        eng["id"],
        {"function": "MAP", "category": "MAP-1.1", "description": "risk context"},
    )
    q = _init_questionnaire(client, eng["id"])
    client.patch(
        f"/field-assessment/engagements/{eng['id']}/questionnaires/{q['id']}/responses/MAP-1.1",
        json={
            "response_status": "implemented",
            "evidence_text": "Risk register maintained",
        },
    )
    client.post(
        f"/field-assessment/engagements/{eng['id']}/questionnaires/{q['id']}/submit"
    )

    links = client.get(f"/field-assessment/engagements/{eng['id']}/evidence-links")
    assert links.status_code == 200
    q_links = [
        lk
        for lk in links.json()
        if lk.get("evidence_entity_type") == "questionnaire_response"
    ]
    assert len(q_links) == 1
    meta = q_links[0]["link_metadata"]

    # Deterministic lineage fields
    assert meta["source_type"] == "questionnaire"
    assert meta["matched_control_id"] == "MAP-1.1"
    assert meta["source_question_id"] == "MAP-1.1"
    assert meta["link_reason"] == "nist_control_match"
    assert meta["questionnaire_id"] == q["id"]
    assert meta["response_status"] == "implemented"
    # source_response_id and evidence_entity_id must agree
    assert meta["source_response_id"] == q_links[0]["evidence_entity_id"]
