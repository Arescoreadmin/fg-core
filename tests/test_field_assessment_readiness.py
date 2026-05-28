"""Tests for deterministic field-assessment playbooks and execution state."""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

os.environ.setdefault("FG_ENV", "test")

import pytest
from fastapi.testclient import TestClient

from services.field_assessment.playbooks import get_playbook
from services.field_assessment.readiness import build_execution_state

_TENANT_ID = "tenant-fa-readiness"


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
            "client_name": "Readiness Corp",
            "assessor_id": "assessor-readiness",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _get_gate(state: dict[str, Any], gate_id: str) -> dict[str, Any]:
    for gate in state["gates"]:
        if gate["gate_id"] == gate_id:
            return gate
    raise AssertionError(f"gate not found: {gate_id}")


def test_playbook_selection_by_assessment_type() -> None:
    ai_playbook = get_playbook("ai_governance")
    comprehensive = get_playbook("comprehensive")
    hipaa = get_playbook("hipaa")

    assert ai_playbook.playbook_id == "field_assessment.ai_governance.v1"
    assert comprehensive.playbook_id == "field_assessment.comprehensive.v1"
    assert hipaa.playbook_id == "field_assessment.hipaa.v1"
    assert hipaa.playbook_id != comprehensive.playbook_id


def test_execution_state_output_is_deterministic_for_same_inputs() -> None:
    engagement = SimpleNamespace(
        id="eng-1",
        assessment_type="ai_governance",
        status="in_progress",
    )
    scans = [
        SimpleNamespace(
            id="scan-b",
            source_type="oauth_inventory",
            object_count=1,
            collected_at="2026-05-19T00:00:00Z",
        ),
        SimpleNamespace(
            id="scan-a",
            source_type="microsoft_graph",
            object_count=1,
            collected_at="2026-05-19T00:00:00Z",
        ),
    ]
    docs = [
        SimpleNamespace(
            id="doc-ai",
            document_classification="ai_policy",
            freshness_date="2026-05-01T00:00:00Z",
        ),
        SimpleNamespace(
            id="doc-data",
            document_classification="data_governance",
            freshness_date="2026-05-01T00:00:00Z",
        ),
        SimpleNamespace(
            id="doc-vendor",
            document_classification="vendor_risk",
            freshness_date="2026-05-01T00:00:00Z",
        ),
    ]
    observations = [
        SimpleNamespace(
            id="obs-ai",
            domain="ai_governance",
            observation_type="gap",
            severity="medium",
            title="AI governance review",
            description="Policy reviewed.",
            interview_role=None,
            structured_evidence={},
        ),
        SimpleNamespace(
            id="int-ai",
            domain="ai_governance",
            observation_type="interview",
            severity="info",
            title="AI owner interview",
            description="Interview captured.",
            interview_role="ai_system_owner",
            structured_evidence={},
        ),
    ]
    findings = [
        SimpleNamespace(
            id="finding-1",
            severity="high",
            evidence_ref_ids=["scan-a"],
            remediation_hint="Define AI owner control.",
            confidence_score=85,
        )
    ]
    evidence_links = [
        SimpleNamespace(
            id="link-1",
            source_entity_type="finding",
            source_entity_id="finding-1",
            evidence_entity_type="scan_result",
            evidence_entity_id="scan-a",
        )
    ]
    first = build_execution_state(
        engagement=engagement,
        playbook=get_playbook("ai_governance"),
        scan_results=scans,
        document_analyses=docs,
        observations=observations,
        findings=findings,
        evidence_links=evidence_links,
        generated_at="2026-05-20T00:00:00Z",
    ).to_dict()
    second = build_execution_state(
        engagement=engagement,
        playbook=get_playbook("ai_governance"),
        scan_results=scans,
        document_analyses=docs,
        observations=observations,
        findings=findings,
        evidence_links=evidence_links,
        generated_at="2026-05-20T00:00:00Z",
    ).to_dict()

    assert first == second
    assert [gate["gate_id"] for gate in first["gates"]] == [
        gate["gate_id"] for gate in second["gates"]
    ]


def test_missing_required_scan_produces_blocked_gate(client: TestClient) -> None:
    engagement = _create_engagement(client)

    resp = client.get(
        f"/field-assessment/engagements/{engagement['id']}/execution-state"
    )

    assert resp.status_code == 200
    state = resp.json()
    gate = _get_gate(state, "scan.microsoft_graph.required")
    assert gate["status"] == "blocked"
    assert gate["recommended_action_id"] == "action.import_scan.microsoft_graph"
    assert state["schema_version"] == "1.0"


def test_imported_scan_clears_corresponding_gate(client: TestClient) -> None:
    engagement = _create_engagement(client)
    scan_resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-19T00:00:00Z",
            "raw_payload": {"users": [], "client_secret": "redact-me"},
            "object_count": 1,
        },
    )
    assert scan_resp.status_code == 201, scan_resp.text

    resp = client.get(
        f"/field-assessment/engagements/{engagement['id']}/execution-state"
    )

    assert resp.status_code == 200
    body = resp.json()
    gate = _get_gate(body, "scan.microsoft_graph.required")
    assert gate["status"] == "passed"
    assert "raw_payload" not in resp.text
    assert "redact-me" not in resp.text


def test_missing_and_stale_document_gates_are_reported(client: TestClient) -> None:
    engagement = _create_engagement(client)
    doc_resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/document-analyses",
        json={
            "document_name": "AI Policy 2020.pdf",
            "document_classification": "ai_policy",
            "freshness_date": "2020-01-01T00:00:00Z",
        },
    )
    assert doc_resp.status_code == 201, doc_resp.text

    resp = client.get(
        f"/field-assessment/engagements/{engagement['id']}/execution-state"
    )

    assert resp.status_code == 200
    state = resp.json()
    assert _get_gate(state, "document.ai_policy.required")["status"] == "passed"
    assert _get_gate(state, "document.data_governance.required")["status"] == "blocked"
    stale_gates = [
        gate for gate in state["gates"] if gate["gate_type"] == "document_freshness"
    ]
    assert stale_gates
    assert stale_gates[0]["status"] == "warning"


def test_missing_interview_produces_guided_next_action(client: TestClient) -> None:
    engagement = _create_engagement(client)

    resp = client.get(
        f"/field-assessment/engagements/{engagement['id']}/execution-state"
    )

    assert resp.status_code == 200
    state = resp.json()
    gate = _get_gate(state, "interview.ai_system_owner.required")
    assert gate["status"] == "blocked"
    actions = {action["action_id"]: action for action in state["next_actions"]}
    action = actions["action.capture_interview.ai_system_owner"]
    assert action["target_ui_section"] == "interviews"
    assert action["safe_for_junior_assessor"] is True


def test_unlinked_high_risk_finding_blocks_report_and_escalates() -> None:
    engagement = SimpleNamespace(
        id="eng-2",
        assessment_type="ai_governance",
        status="evidence_collected",
    )
    finding = SimpleNamespace(
        id="finding-high",
        severity="high",
        evidence_ref_ids=[],
        remediation_hint=None,
        confidence_score=40,
    )

    state = build_execution_state(
        engagement=engagement,
        playbook=get_playbook("ai_governance"),
        scan_results=[],
        document_analyses=[],
        observations=[],
        findings=[finding],
        evidence_links=[],
        generated_at="2026-05-20T00:00:00Z",
    ).to_dict()

    assert _get_gate(state, "finding.evidence.required")["status"] == "blocked"
    assert _get_gate(state, "finding.remediation.required")["status"] == "blocked"
    assert any(item["must_block_progression"] for item in state["escalation_items"])
    assert any(
        blocker["target_status"] == "report_generation"
        for blocker in state["transition_blockers"]
    )


def test_ambiguous_shadow_observation_produces_escalation_and_asset_candidate() -> None:
    engagement = SimpleNamespace(
        id="eng-3",
        assessment_type="ai_governance",
        status="in_progress",
    )
    observation = SimpleNamespace(
        id="obs-shadow",
        domain="ai_governance",
        observation_type="concern",
        severity="high",
        title="Shadow AI app discovered",
        description="Owner is unknown and usage is unclear.",
        interview_role=None,
        structured_evidence={"owner": "unknown"},
    )

    state = build_execution_state(
        engagement=engagement,
        playbook=get_playbook("ai_governance"),
        scan_results=[],
        document_analyses=[],
        observations=[observation],
        findings=[],
        evidence_links=[],
        generated_at="2026-05-20T00:00:00Z",
    ).to_dict()

    assert state["asset_candidate_actions"][0]["source_entity_id"] == "obs-shadow"
    assert any(
        item["ambiguity_type"] == "ambiguous_observation"
        for item in state["escalation_items"]
    )


def test_execution_state_tenant_isolation_returns_404(build_app: object) -> None:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key_a = mint_key("governance:read", "governance:write", tenant_id="tenant-a")
    key_b = mint_key("governance:read", "governance:write", tenant_id="tenant-b")
    client_a = TestClient(app, headers={"X-API-Key": key_a})
    client_b = TestClient(app, headers={"X-API-Key": key_b})
    created = client_a.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Tenant A",
            "assessor_id": "assessor-a",
            "assessment_type": "ai_governance",
        },
    )
    assert created.status_code == 201, created.text

    resp = client_b.get(
        f"/field-assessment/engagements/{created.json()['id']}/execution-state"
    )

    assert resp.status_code == 404
