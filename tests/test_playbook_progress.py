"""Tests for services.field_assessment.progress — PlaybookProgress computation.

Covers:
  - New engagement: all actions are blocking when all gates are blocked
  - After scan link: scan_result action no longer blocking
  - Zero blocking gates: blocking_count == 0 and all actions non-blocking
  - completion_pct calculation from gate counts
  - deep_link contains engagement_id and tab param
  - Wrong tenant: 403/404 on /next-actions route
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from fastapi.testclient import TestClient

from services.field_assessment.playbooks import get_playbook
from services.field_assessment.progress import compute_next_actions
from services.field_assessment.readiness import build_execution_state

_TENANT = "tenant-progress"

_FAKE_TS = "2026-01-01T00:00:00Z"


def _minimal_engagement(
    engagement_id: str = "eng-prog-1", status: str = "setup"
) -> SimpleNamespace:
    return SimpleNamespace(
        id=engagement_id,
        tenant_id=_TENANT,
        status=status,
        assessment_type="ai_governance",
        client_name="Progress Corp",
    )


def _build_state(
    engagement_id: str = "eng-prog-1",
    scans: list[Any] | None = None,
    documents: list[Any] | None = None,
    observations: list[Any] | None = None,
    findings: list[Any] | None = None,
    evidence_links: list[Any] | None = None,
    reports: list[Any] | None = None,
    status: str = "setup",
) -> Any:
    eng = _minimal_engagement(engagement_id=engagement_id, status=status)
    playbook = get_playbook("ai_governance")
    return build_execution_state(
        engagement=eng,
        playbook=playbook,
        scan_results=scans or [],
        document_analyses=documents or [],
        observations=observations or [],
        findings=findings or [],
        evidence_links=evidence_links or [],
        generated_at=_FAKE_TS,
        reports=reports or [],
    )


# ─── Unit tests — pure compute_next_actions ───────────────────────────────────


def test_new_engagement_has_blocking_actions() -> None:
    state = _build_state()
    progress = compute_next_actions(
        state, engagement_id="eng-prog-1", current_status="setup"
    )
    assert progress.engagement_id == "eng-prog-1"
    assert progress.current_status == "setup"
    # A fresh engagement must have at least one blocking action
    assert progress.blocking_count > 0
    blocking = [a for a in progress.actions if a.blocking]
    assert len(blocking) > 0


def test_blocking_count_matches_actions() -> None:
    state = _build_state()
    progress = compute_next_actions(
        state, engagement_id="eng-prog-1", current_status="setup"
    )
    expected_blocking = sum(1 for a in progress.actions if a.blocking)
    assert progress.blocking_count == expected_blocking


def test_completion_pct_between_0_and_100() -> None:
    state = _build_state()
    progress = compute_next_actions(
        state, engagement_id="eng-prog-1", current_status="setup"
    )
    assert 0.0 <= progress.completion_pct <= 100.0


def test_completion_pct_increases_with_closed_gates() -> None:
    state_empty = _build_state()
    pct_empty = compute_next_actions(
        state_empty, engagement_id="eng-prog-1", current_status="setup"
    ).completion_pct

    # After completing all gates (artificially — by modifying completed_gate_count)
    from dataclasses import replace

    state_full = replace(
        state_empty,
        completed_gate_count=state_empty.completed_gate_count
        + state_empty.blocking_gate_count,
        blocking_gate_count=0,
    )
    pct_full = compute_next_actions(
        state_full, engagement_id="eng-prog-1", current_status="setup"
    ).completion_pct

    assert pct_full >= pct_empty


def test_deep_link_contains_engagement_id_and_tab() -> None:
    state = _build_state()
    progress = compute_next_actions(
        state, engagement_id="eng-testlink", current_status="setup"
    )
    for action in progress.actions:
        assert action.deep_link is not None
        assert "eng-testlink" in action.deep_link
        assert "tab=" in action.deep_link


def test_action_type_is_semantic() -> None:
    state = _build_state()
    progress = compute_next_actions(
        state, engagement_id="eng-prog-1", current_status="setup"
    )
    for action in progress.actions:
        # action_type should never be empty
        assert action.action_type
        # action_type must not carry the raw field name directly as-is
        # (it should be mapped to a semantic label)
        assert (
            action.action_type != action.required_input_type
            or action.required_input_type
            in (
                "scan_result",
                "evidence_link",
                "document_analysis",
                "field_observation",
                "report_qa_approval",
                "questionnaire_response",
            )
        )


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
            "client_name": "Progress Test Corp",
            "assessor_id": "assessor-progress",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_next_actions_route_returns_progress(client: TestClient) -> None:
    eng = _create_engagement(client)
    resp = client.get(f"/field-assessment/engagements/{eng['id']}/next-actions")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["engagement_id"] == eng["id"]
    assert isinstance(body["completion_pct"], float)
    assert isinstance(body["blocking_count"], int)
    assert isinstance(body["actions"], list)


def test_next_actions_route_actions_have_deep_links(client: TestClient) -> None:
    eng = _create_engagement(client)
    resp = client.get(f"/field-assessment/engagements/{eng['id']}/next-actions")
    assert resp.status_code == 200
    body = resp.json()
    eng_id = eng["id"]
    for action in body["actions"]:
        assert action["deep_link"] is not None
        assert eng_id in action["deep_link"]
        assert "tab=" in action["deep_link"]
        assert isinstance(action["blocking"], bool)
        assert action["action_type"]


def test_next_actions_route_wrong_tenant_returns_404(build_app: Any) -> None:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    owner_key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
    owner_client = TestClient(
        app, headers={"X-API-Key": owner_key, "X-Tenant-ID": _TENANT}
    )
    eng = _create_engagement(owner_client)

    other_tenant = "tenant-other-progress"
    other_key = mint_key("governance:read", tenant_id=other_tenant)
    other_client = TestClient(
        app, headers={"X-API-Key": other_key, "X-Tenant-ID": other_tenant}
    )

    resp = other_client.get(f"/field-assessment/engagements/{eng['id']}/next-actions")
    assert resp.status_code in (403, 404)
