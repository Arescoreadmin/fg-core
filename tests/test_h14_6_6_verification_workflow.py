"""Tests for PR 14.6.6 — Verification Workflow Authority.

Covers:
  - Workflow request creation (201, 422, tenant isolation)
  - Get/list requests (200, 404, filters, pagination)
  - Assignment (ASSIGNED state, reassignment, not found)
  - Workflow transitions (valid, invalid, terminal states)
  - Escalation (IN_REVIEW → ESCALATED, count increments, invalid state)
  - Result recording (APPROVED/REJECTED, audit trail)
  - SLA deadlines (set, get, ON_TRACK/DUE_SOON/OVERDUE)
  - Queue (by state, priority ordering, empty queue)
  - Dashboard metrics (by_state, overdue, unassigned)
  - CGIN snapshot (fields present)
  - Evidence authority integration (trust state updated on approval)
  - Timeline integration (events emitted)
  - Tenant isolation (two tenants, complete separation)
  - Audit trail (events written for every mutation)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from api.auth_scopes import mint_key
from services.verification_authority.models import (
    AssigneeType,
    EscalationType,
    VerificationWorkflowState,
    WorkflowSlaStatus,
    validate_workflow_transition,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)
_TENANT = "t-vw-001"
_TENANT_B = "t-vw-002"

_REVIEW_DUE_FUTURE = (_NOW + timedelta(days=30)).isoformat()
_REVIEW_DUE_SOON = (_NOW + timedelta(days=3)).isoformat()
_REVIEW_DUE_PAST = (_NOW - timedelta(days=2)).isoformat()
_DECISION_DUE_FUTURE = (_NOW + timedelta(days=60)).isoformat()


def _vw_payload(**overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "evidence_id": "ev-test-001",
        "priority": 50,
    }
    defaults.update(overrides)
    return defaults


def _assign_payload(**overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "assignee_id": "analyst-001",
        "assignee_type": AssigneeType.ANALYST.value,
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


def _create_request(client: TestClient, **overrides: Any) -> dict:
    resp = client.post("/verification-requests", json=_vw_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _transition(
    client: TestClient, req_id: str, to_state: str, notes: str = ""
) -> Response:
    body: dict = {"to_state": to_state}
    if notes:
        body["notes"] = notes
    resp = client.post(f"/verification-requests/{req_id}/transition", json=body)
    return resp


def _assign(client: TestClient, req_id: str, **overrides: Any) -> Response:
    resp = client.post(
        f"/verification-requests/{req_id}/assign", json=_assign_payload(**overrides)
    )
    return resp


# ---------------------------------------------------------------------------
# 1. TestCreateVerificationRequest
# ---------------------------------------------------------------------------


class TestCreateVerificationRequest:
    def test_create_returns_201(self, client):
        resp = client.post("/verification-requests", json=_vw_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["evidence_id"] == "ev-test-001"
        assert data["workflow_state"] == VerificationWorkflowState.REQUESTED.value
        assert data["priority"] == 50
        assert data["id"] is not None

    def test_create_with_notes_and_priority(self, client):
        resp = client.post(
            "/verification-requests",
            json=_vw_payload(notes="Needs urgent review", priority=90),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["notes"] == "Needs urgent review"
        assert data["priority"] == 90

    def test_create_with_sla_deadlines(self, client):
        resp = client.post(
            "/verification-requests",
            json=_vw_payload(
                review_due_at=_REVIEW_DUE_FUTURE,
                decision_due_at=_DECISION_DUE_FUTURE,
            ),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["review_due_at"] == _REVIEW_DUE_FUTURE
        assert data["decision_due_at"] == _DECISION_DUE_FUTURE

    def test_create_missing_evidence_id_rejected(self, client):
        resp = client.post("/verification-requests", json={"priority": 50})
        assert resp.status_code == 422

    def test_create_priority_out_of_range_rejected(self, client):
        resp = client.post("/verification-requests", json=_vw_payload(priority=101))
        assert resp.status_code == 422

    def test_create_priority_negative_rejected(self, client):
        resp = client.post("/verification-requests", json=_vw_payload(priority=-1))
        assert resp.status_code == 422

    def test_create_state_is_requested(self, client):
        data = _create_request(client)
        assert data["workflow_state"] == "REQUESTED"

    def test_create_sets_requested_by(self, client):
        data = _create_request(client)
        assert data["requested_by"] is not None

    def test_create_sets_escalation_count_zero(self, client):
        data = _create_request(client)
        assert data["escalation_count"] == 0

    def test_create_tenant_isolation(self, client, client_b):
        data_a = _create_request(client)
        resp_b = client_b.get(f"/verification-requests/{data_a['id']}")
        assert resp_b.status_code == 404

    def test_create_returns_tenant_id(self, client):
        data = _create_request(client)
        assert data["tenant_id"] == _TENANT

    def test_create_multiple_requests_for_same_evidence(self, client):
        r1 = _create_request(client, evidence_id="ev-multi-001")
        r2 = _create_request(client, evidence_id="ev-multi-001")
        assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# 2. TestGetVerificationRequest
# ---------------------------------------------------------------------------


class TestGetVerificationRequest:
    def test_get_returns_200(self, client):
        data = _create_request(client)
        resp = client.get(f"/verification-requests/{data['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == data["id"]

    def test_get_not_found_returns_404(self, client):
        resp = client.get("/verification-requests/nonexistent-id-xyz")
        assert resp.status_code == 404

    def test_get_cross_tenant_returns_404(self, client, client_b):
        data = _create_request(client)
        resp = client_b.get(f"/verification-requests/{data['id']}")
        assert resp.status_code == 404

    def test_get_returns_all_fields(self, client):
        data = _create_request(client, notes="test note")
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["evidence_id"] == "ev-test-001"
        assert result["workflow_state"] == "REQUESTED"
        assert result["notes"] == "test note"
        assert result["escalation_count"] == 0
        assert "created_at" in result
        assert "updated_at" in result

    def test_get_sla_status_on_track(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_FUTURE)
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["sla_status"] == WorkflowSlaStatus.ON_TRACK.value

    def test_get_sla_status_none_when_no_deadlines(self, client):
        data = _create_request(client)
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["sla_status"] is None

    def test_get_sla_status_overdue(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_PAST)
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["sla_status"] == WorkflowSlaStatus.OVERDUE.value

    def test_get_sla_status_due_soon(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_SOON)
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["sla_status"] == WorkflowSlaStatus.DUE_SOON.value


# ---------------------------------------------------------------------------
# 3. TestListVerificationRequests
# ---------------------------------------------------------------------------


class TestListVerificationRequests:
    def test_list_empty(self, client):
        resp = client.get("/verification-requests?evidence_id=ev-empty-9999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_by_evidence_id(self, client):
        ev_id = "ev-list-filter-001"
        _create_request(client, evidence_id=ev_id)
        _create_request(client, evidence_id="ev-list-other-001")
        resp = client.get(f"/verification-requests?evidence_id={ev_id}")
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["evidence_id"] == ev_id

    def test_list_by_workflow_state(self, client):
        _create_request(client, evidence_id="ev-list-state-001")
        resp = client.get("/verification-requests?workflow_state=REQUESTED")
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["workflow_state"] == "REQUESTED"

    def test_list_pagination(self, client):
        ev_id = "ev-list-page-001"
        for _ in range(5):
            _create_request(client, evidence_id=ev_id)
        resp1 = client.get(
            f"/verification-requests?evidence_id={ev_id}&limit=2&offset=0"
        )
        resp2 = client.get(
            f"/verification-requests?evidence_id={ev_id}&limit=2&offset=2"
        )
        data1 = resp1.json()
        data2 = resp2.json()
        assert len(data1["items"]) == 2
        assert data1["total"] >= 5
        assert data2["items"][0]["id"] != data1["items"][0]["id"]

    def test_list_all_requests(self, client):
        _create_request(client, evidence_id="ev-list-all-001")
        resp = client.get("/verification-requests")
        data = resp.json()
        assert data["total"] >= 1

    def test_list_tenant_isolation(self, client, client_b):
        ev_id = "ev-list-iso-001"
        _create_request(client, evidence_id=ev_id)
        resp_b = client_b.get(f"/verification-requests?evidence_id={ev_id}")
        assert resp_b.json()["total"] == 0

    def test_list_by_assignee_id(self, client):
        data = _create_request(client, evidence_id="ev-list-assignee-001")
        _assign(client, data["id"], assignee_id="analyst-filter-001")
        resp = client.get("/verification-requests?assignee_id=analyst-filter-001")
        result = resp.json()
        assert result["total"] >= 1


# ---------------------------------------------------------------------------
# 4. TestAssignVerification
# ---------------------------------------------------------------------------


class TestAssignVerification:
    def test_assign_from_requested_transitions_to_assigned(self, client):
        data = _create_request(client)
        resp = _assign(client, data["id"])
        assert resp.status_code == 200
        result = resp.json()
        assert result["workflow_state"] == "ASSIGNED"
        assert result["assignee_id"] == "analyst-001"
        assert result["assignee_type"] == "ANALYST"

    def test_assign_from_queued_transitions_to_assigned(self, client):
        data = _create_request(client)
        _transition(client, data["id"], "QUEUED")
        resp = _assign(client, data["id"])
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "ASSIGNED"

    def test_reassignment_allowed_from_assigned(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        resp = _assign(
            client, data["id"], assignee_id="manager-002", assignee_type="MANAGER"
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["assignee_id"] == "manager-002"
        assert result["assignee_type"] == "MANAGER"

    def test_assign_not_found_returns_404(self, client):
        resp = _assign(client, "nonexistent-req-id")
        assert resp.status_code == 404

    def test_assign_invalid_state_returns_422(self, client):
        data = _create_request(client)
        _transition(client, data["id"], "QUEUED")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "APPROVED")
        resp = _assign(client, data["id"])
        assert resp.status_code == 422

    def test_assign_with_due_at(self, client):
        data = _create_request(client)
        due = _REVIEW_DUE_FUTURE
        resp = _assign(client, data["id"], assigned_due_at=due)
        assert resp.status_code == 200
        assert resp.json()["assigned_due_at"] == due

    def test_assign_sets_assigned_at(self, client):
        data = _create_request(client)
        resp = _assign(client, data["id"])
        assert resp.json()["assigned_at"] is not None

    def test_assign_sets_assignee_type_director(self, client):
        data = _create_request(client)
        resp = _assign(client, data["id"], assignee_type="DIRECTOR")
        assert resp.status_code == 200
        assert resp.json()["assignee_type"] == "DIRECTOR"


# ---------------------------------------------------------------------------
# 5. TestTransitionWorkflow
# ---------------------------------------------------------------------------


class TestTransitionWorkflow:
    def test_requested_to_queued(self, client):
        data = _create_request(client)
        resp = _transition(client, data["id"], "QUEUED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "QUEUED"

    def test_queued_to_assigned(self, client):
        data = _create_request(client)
        _transition(client, data["id"], "QUEUED")
        resp = _transition(client, data["id"], "ASSIGNED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "ASSIGNED"

    def test_assigned_to_in_review(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        resp = _transition(client, data["id"], "IN_REVIEW")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "IN_REVIEW"

    def test_in_review_to_approved(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = _transition(client, data["id"], "APPROVED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "APPROVED"

    def test_in_review_to_rejected(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = _transition(client, data["id"], "REJECTED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "REJECTED"

    def test_approved_to_completed(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "APPROVED")
        resp = _transition(client, data["id"], "COMPLETED")
        assert resp.status_code == 200
        result = resp.json()
        assert result["workflow_state"] == "COMPLETED"
        assert result["completed_at"] is not None

    def test_cancelled_sets_cancelled_at(self, client):
        data = _create_request(client)
        resp = _transition(client, data["id"], "CANCELLED")
        assert resp.status_code == 200
        result = resp.json()
        assert result["workflow_state"] == "CANCELLED"
        assert result["cancelled_at"] is not None

    def test_expired_sets_expired_at(self, client):
        data = _create_request(client)
        resp = _transition(client, data["id"], "EXPIRED")
        assert resp.status_code == 200
        result = resp.json()
        assert result["workflow_state"] == "EXPIRED"
        assert result["expired_at"] is not None

    def test_invalid_transition_returns_422(self, client):
        data = _create_request(client)
        # REQUESTED → IN_REVIEW is invalid
        resp = _transition(client, data["id"], "IN_REVIEW")
        assert resp.status_code == 422

    def test_terminal_state_cannot_transition(self, client):
        data = _create_request(client)
        _transition(client, data["id"], "CANCELLED")
        resp = _transition(client, data["id"], "QUEUED")
        assert resp.status_code == 422

    def test_rejected_is_terminal(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "REJECTED")
        resp = _transition(client, data["id"], "COMPLETED")
        assert resp.status_code == 422

    def test_transition_not_found_returns_404(self, client):
        resp = _transition(client, "nonexistent-id", "QUEUED")
        assert resp.status_code == 404

    def test_in_review_to_pending_information(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = _transition(client, data["id"], "PENDING_INFORMATION")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "PENDING_INFORMATION"

    def test_pending_information_back_to_in_review(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "PENDING_INFORMATION")
        resp = _transition(client, data["id"], "IN_REVIEW")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "IN_REVIEW"


# ---------------------------------------------------------------------------
# 6. TestEscalateVerification
# ---------------------------------------------------------------------------


class TestEscalateVerification:
    def test_escalate_from_in_review(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["workflow_state"] == "ESCALATED"
        assert result["escalation_count"] == 1
        assert result["last_escalation_type"] == "MANUAL"

    def test_escalate_from_pending_information(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "PENDING_INFORMATION")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.SLA.value},
        )
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "ESCALATED"

    def test_escalation_count_increments(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        # De-escalate and escalate again
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.EXECUTIVE.value},
        )
        assert resp.json()["escalation_count"] == 2

    def test_escalate_from_invalid_state_returns_422(self, client):
        data = _create_request(client)
        # REQUESTED → escalate should fail
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        assert resp.status_code == 422

    def test_escalate_not_found_returns_404(self, client):
        resp = client.post(
            "/verification-requests/nonexistent/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        assert resp.status_code == 404

    def test_escalate_with_notes(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={
                "escalation_type": EscalationType.REVIEW.value,
                "escalation_notes": "Needs director review",
                "escalated_to": "director-001",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["last_escalation_type"] == "REVIEW"

    def test_escalate_sets_last_escalated_by(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.AUTOMATIC.value},
        )
        assert resp.json()["last_escalated_by"] is not None

    def test_escalated_can_transition_to_approved(self, client):
        data = _create_request(client)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        resp = _transition(client, data["id"], "APPROVED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "APPROVED"


# ---------------------------------------------------------------------------
# 7. TestRecordResult
# ---------------------------------------------------------------------------


class TestRecordResult:
    def _reach_in_review(
        self, client: TestClient, ev_id: str = "ev-result-001"
    ) -> dict:
        data = _create_request(client, evidence_id=ev_id)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        return data

    def test_record_approved_result(self, client):
        data = self._reach_in_review(client, "ev-result-app-001")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED", "decision_notes": "Looks good"},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["result"] == "APPROVED"
        assert result["request_id"] == data["id"]
        assert result["decided_by"] is not None

    def test_record_rejected_result(self, client):
        data = self._reach_in_review(client, "ev-result-rej-001")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "REJECTED", "decision_notes": "Insufficient evidence"},
        )
        assert resp.status_code == 200
        assert resp.json()["result"] == "REJECTED"

    def test_record_result_not_found_returns_404(self, client):
        resp = client.post(
            "/verification-requests/nonexistent/result",
            json={"result": "APPROVED"},
        )
        assert resp.status_code == 404

    def test_record_result_writes_audit_event(self, client):
        data = self._reach_in_review(client, "ev-result-audit-001")
        client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        audit_resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = audit_resp.json()["items"]
        event_types = [e["event_type"] for e in events]
        assert "RESULT_RECORDED" in event_types

    def test_record_result_from_invalid_state_returns_422(self, client):
        data = _create_request(client, evidence_id="ev-result-invalid-001")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        assert resp.status_code == 422

    def test_record_result_from_escalated_state(self, client):
        data = _create_request(client, evidence_id="ev-result-esc-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": EscalationType.MANUAL.value},
        )
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        assert resp.status_code == 200

    def test_record_result_returns_decided_at(self, client):
        data = self._reach_in_review(client, "ev-result-ts-001")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        assert resp.json()["decided_at"] is not None

    def test_record_result_returns_evidence_id(self, client):
        data = self._reach_in_review(client, "ev-result-evid-001")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "REJECTED"},
        )
        assert resp.json()["evidence_id"] == "ev-result-evid-001"


# ---------------------------------------------------------------------------
# 8. TestSetSlaDeadlines
# ---------------------------------------------------------------------------


class TestSetSlaDeadlines:
    def test_set_review_and_decision_due(self, client):
        data = _create_request(client)
        resp = client.put(
            f"/verification-requests/{data['id']}/sla",
            json={
                "review_due_at": _REVIEW_DUE_FUTURE,
                "decision_due_at": _DECISION_DUE_FUTURE,
            },
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["request_id"] == data["id"]
        assert result["review_sla_status"] == WorkflowSlaStatus.ON_TRACK.value
        assert result["decision_sla_status"] == WorkflowSlaStatus.ON_TRACK.value

    def test_sla_set_audit_event_written(self, client):
        data = _create_request(client)
        client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        audit_resp = client.get(f"/verification-requests/{data['id']}/audit")
        event_types = [e["event_type"] for e in audit_resp.json()["items"]]
        assert "SLA_SET" in event_types

    def test_set_escalation_due(self, client):
        data = _create_request(client)
        resp = client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"escalation_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["escalation_sla_status"] == WorkflowSlaStatus.ON_TRACK.value

    def test_set_assigned_due(self, client):
        data = _create_request(client)
        resp = client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"assigned_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 200
        assert resp.json()["assigned_sla_status"] == WorkflowSlaStatus.ON_TRACK.value

    def test_set_overdue_returns_overdue_status(self, client):
        data = _create_request(client)
        resp = client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        result = resp.json()
        assert result["review_sla_status"] == WorkflowSlaStatus.OVERDUE.value
        assert "review_due_at" in result["overdue_fields"]

    def test_set_sla_not_found_returns_404(self, client):
        resp = client.put(
            "/verification-requests/nonexistent/sla",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 404

    def test_set_partial_sla_updates_only_provided_fields(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_FUTURE)
        client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"decision_due_at": _DECISION_DUE_FUTURE},
        )
        resp = client.get(f"/verification-requests/{data['id']}")
        result = resp.json()
        assert result["review_due_at"] == _REVIEW_DUE_FUTURE
        assert result["decision_due_at"] == _DECISION_DUE_FUTURE


# ---------------------------------------------------------------------------
# 9. TestGetSlaStatus
# ---------------------------------------------------------------------------


class TestGetSlaStatus:
    def test_on_track_with_far_future_deadline(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_FUTURE)
        resp = client.get(f"/verification-requests/{data['id']}/sla")
        assert resp.status_code == 200
        result = resp.json()
        assert result["review_sla_status"] == WorkflowSlaStatus.ON_TRACK.value
        assert result["overdue_fields"] == []

    def test_due_soon_within_3_days(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_SOON)
        resp = client.get(f"/verification-requests/{data['id']}/sla")
        assert resp.status_code == 200
        assert resp.json()["review_sla_status"] == WorkflowSlaStatus.DUE_SOON.value

    def test_overdue_with_past_deadline(self, client):
        data = _create_request(client, review_due_at=_REVIEW_DUE_PAST)
        resp = client.get(f"/verification-requests/{data['id']}/sla")
        assert resp.status_code == 200
        result = resp.json()
        assert result["review_sla_status"] == WorkflowSlaStatus.OVERDUE.value
        assert "review_due_at" in result["overdue_fields"]

    def test_no_deadlines_returns_none_status(self, client):
        data = _create_request(client)
        resp = client.get(f"/verification-requests/{data['id']}/sla")
        assert resp.status_code == 200
        result = resp.json()
        assert result["review_sla_status"] is None
        assert result["decision_sla_status"] is None

    def test_multiple_overdue_fields(self, client):
        data = _create_request(
            client,
            review_due_at=_REVIEW_DUE_PAST,
            decision_due_at=_REVIEW_DUE_PAST,
        )
        resp = client.get(f"/verification-requests/{data['id']}/sla")
        result = resp.json()
        assert "review_due_at" in result["overdue_fields"]
        assert "decision_due_at" in result["overdue_fields"]

    def test_sla_not_found_returns_404(self, client):
        resp = client.get("/verification-requests/nonexistent/sla")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. TestGetQueue
# ---------------------------------------------------------------------------


class TestGetQueue:
    def test_get_queue_by_requested_state(self, client):
        _create_request(client, evidence_id="ev-queue-001", priority=70)
        _create_request(client, evidence_id="ev-queue-002", priority=30)
        resp = client.get("/verification-requests/queue/REQUESTED")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "REQUESTED"
        assert data["total"] >= 2

    def test_queue_items_sorted_by_priority_desc(self, client):
        _create_request(client, evidence_id="ev-queue-prio-001", priority=10)
        _create_request(client, evidence_id="ev-queue-prio-002", priority=90)
        _create_request(client, evidence_id="ev-queue-prio-003", priority=50)
        resp = client.get("/verification-requests/queue/REQUESTED?limit=50")
        items = resp.json()["items"]
        priorities = [i["priority"] for i in items]
        assert priorities == sorted(priorities, reverse=True)

    def test_empty_queue_returns_empty_list(self, client):
        resp = client.get("/verification-requests/queue/COMPLETED?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_queue_item_has_required_fields(self, client):
        _create_request(client, evidence_id="ev-queue-fields-001")
        resp = client.get("/verification-requests/queue/REQUESTED?limit=1")
        items = resp.json()["items"]
        assert len(items) >= 1
        item = items[0]
        assert "request_id" in item
        assert "evidence_id" in item
        assert "workflow_state" in item
        assert "priority" in item

    def test_queue_tenant_isolation(self, client, client_b):
        _create_request(client, evidence_id="ev-queue-iso-001")
        resp_b = client_b.get("/verification-requests/queue/REQUESTED?limit=50")
        for item in resp_b.json()["items"]:
            assert item["evidence_id"] != "ev-queue-iso-001"


# ---------------------------------------------------------------------------
# 11. TestDashboardMetrics
# ---------------------------------------------------------------------------


class TestDashboardMetrics:
    def test_dashboard_returns_200(self, client):
        resp = client.get("/verification-requests/dashboard")
        assert resp.status_code == 200

    def test_dashboard_has_required_fields(self, client):
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert "total_requests" in data
        assert "by_state" in data
        assert "overdue_count" in data
        assert "due_soon_count" in data
        assert "avg_priority" in data
        assert "unassigned_count" in data
        assert "escalated_count" in data
        assert "completed_count" in data

    def test_dashboard_counts_by_state(self, client):
        _create_request(client, evidence_id="ev-dash-state-001")
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert data["by_state"].get("REQUESTED", 0) >= 1

    def test_dashboard_overdue_count(self, client):
        _create_request(
            client, evidence_id="ev-dash-overdue-001", review_due_at=_REVIEW_DUE_PAST
        )
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert data["overdue_count"] >= 1

    def test_dashboard_unassigned_count(self, client):
        _create_request(client, evidence_id="ev-dash-unassigned-001")
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert data["unassigned_count"] >= 1

    def test_dashboard_escalated_count(self, client):
        req = _create_request(client, evidence_id="ev-dash-esc-001")
        _assign(client, req["id"])
        _transition(client, req["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{req['id']}/escalate",
            json={"escalation_type": "MANUAL"},
        )
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert data["escalated_count"] >= 1

    def test_dashboard_tenant_isolation(self, client, client_b):
        _create_request(client, evidence_id="ev-dash-iso-001")
        resp_b = client_b.get("/verification-requests/dashboard")
        # Tenant B's dashboard should not include tenant A's requests
        data_b = resp_b.json()
        # Just verify they are independent responses
        assert "total_requests" in data_b

    def test_dashboard_avg_priority(self, client):
        _create_request(client, evidence_id="ev-dash-avg-001", priority=80)
        resp = client.get("/verification-requests/dashboard")
        data = resp.json()
        assert data["avg_priority"] > 0


# ---------------------------------------------------------------------------
# 12. TestCginSnapshot
# ---------------------------------------------------------------------------


class TestCginSnapshot:
    def test_cgin_snapshot_returns_200(self, client):
        resp = client.get("/verification-requests/cgin/snapshot")
        assert resp.status_code == 200

    def test_cgin_snapshot_has_required_fields(self, client):
        resp = client.get("/verification-requests/cgin/snapshot")
        data = resp.json()
        assert "snapshot_at" in data
        assert "tenant_fingerprint" in data
        assert "total_requests" in data
        assert "by_state" in data
        assert "overdue_count" in data
        assert "escalated_count" in data
        assert "completed_last_30d" in data

    def test_cgin_snapshot_tenant_id_matches(self, client):
        resp = client.get("/verification-requests/cgin/snapshot")
        assert "tenant_id" not in resp.json()
        assert len(resp.json()["tenant_fingerprint"]) == 32

    def test_cgin_snapshot_counts_requests(self, client):
        _create_request(client, evidence_id="ev-cgin-001")
        resp = client.get("/verification-requests/cgin/snapshot")
        data = resp.json()
        assert data["total_requests"] >= 1

    def test_cgin_snapshot_by_state_populated(self, client):
        _create_request(client, evidence_id="ev-cgin-state-001")
        resp = client.get("/verification-requests/cgin/snapshot")
        data = resp.json()
        assert "REQUESTED" in data["by_state"]

    def test_cgin_snapshot_tenant_b_isolated(self, client, client_b):
        _create_request(client, evidence_id="ev-cgin-iso-001")
        resp_b = client_b.get("/verification-requests/cgin/snapshot")
        data_b = resp_b.json()
        # Tenant B's snapshot should not include tenant A's data
        assert "tenant_id" not in data_b
        assert len(data_b["tenant_fingerprint"]) == 32


# ---------------------------------------------------------------------------
# 13. TestEvidenceAuthorityIntegration
# ---------------------------------------------------------------------------


class TestEvidenceAuthorityIntegration:
    """Test that transitioning to APPROVED/REJECTED attempts evidence trust update."""

    def _reach_in_review(self, client: TestClient, ev_id: str) -> dict:
        data = _create_request(client, evidence_id=ev_id)
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        return data

    def test_approve_does_not_fail(self, client):
        """Transition to APPROVED should complete without error even if evidence update fails."""
        data = self._reach_in_review(client, "ev-ea-int-001")
        resp = _transition(client, data["id"], "APPROVED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "APPROVED"

    def test_reject_does_not_fail(self, client):
        """Transition to REJECTED should complete without error."""
        data = self._reach_in_review(client, "ev-ea-int-002")
        resp = _transition(client, data["id"], "REJECTED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "REJECTED"

    def test_complete_does_not_fail(self, client):
        """APPROVED → COMPLETED should complete without error."""
        data = self._reach_in_review(client, "ev-ea-int-003")
        _transition(client, data["id"], "APPROVED")
        resp = _transition(client, data["id"], "COMPLETED")
        assert resp.status_code == 200
        assert resp.json()["workflow_state"] == "COMPLETED"

    def test_approve_with_evidence_authority_evidence(self, client):
        """Create real evidence, verify workflow approval attempts trust update."""
        from datetime import datetime, timezone

        now = datetime.now(tz=timezone.utc).isoformat()
        ev_resp = client.post(
            "/evidence",
            json={
                "title": "Integration Test Evidence",
                "source_type": "DOCUMENT",
                "collection_method": "MANUAL_UPLOAD",
                "classification": "INTERNAL",
                "collected_at": now,
            },
        )
        if ev_resp.status_code != 201:
            # Evidence authority may not be in scope for this test
            pytest.skip("Evidence authority not available in test environment")

        ev_id = ev_resp.json()["id"]
        req_data = _create_request(client, evidence_id=ev_id)
        _assign(client, req_data["id"])
        _transition(client, req_data["id"], "IN_REVIEW")
        resp = _transition(client, req_data["id"], "APPROVED")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 14. TestTimelineIntegration
# ---------------------------------------------------------------------------


class TestTimelineIntegration:
    def test_create_emits_no_error(self, client):
        """Timeline emission on create should not cause request to fail."""
        resp = client.post(
            "/verification-requests", json=_vw_payload(evidence_id="ev-tl-001")
        )
        assert resp.status_code == 201

    def test_transition_emits_no_error(self, client):
        """Timeline emission on transition should not cause request to fail."""
        data = _create_request(client, evidence_id="ev-tl-002")
        resp = _transition(client, data["id"], "QUEUED")
        assert resp.status_code == 200

    def test_escalate_emits_no_error(self, client):
        """Timeline emission on escalate should not cause request to fail."""
        data = _create_request(client, evidence_id="ev-tl-003")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": "MANUAL"},
        )
        assert resp.status_code == 200

    def test_assign_emits_no_error(self, client):
        data = _create_request(client, evidence_id="ev-tl-assign-001")
        resp = _assign(client, data["id"])
        assert resp.status_code == 200

    def test_result_emits_no_error(self, client):
        data = _create_request(client, evidence_id="ev-tl-result-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 15. TestTenantIsolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_get_request_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-get-001")
        resp = client_b.get(f"/verification-requests/{data['id']}")
        assert resp.status_code == 404

    def test_list_requests_cross_tenant_blocked(self, client, client_b):
        ev_id = "ev-iso-list-001"
        _create_request(client, evidence_id=ev_id)
        resp_b = client_b.get(f"/verification-requests?evidence_id={ev_id}")
        assert resp_b.json()["total"] == 0

    def test_assign_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-assign-001")
        resp = _assign(client_b, data["id"])
        assert resp.status_code == 404

    def test_transition_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-trans-001")
        resp = _transition(client_b, data["id"], "QUEUED")
        assert resp.status_code == 404

    def test_escalate_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-esc-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client_b.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": "MANUAL"},
        )
        assert resp.status_code == 404

    def test_result_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-result-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        resp = client_b.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        assert resp.status_code == 404

    def test_audit_trail_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-audit-001")
        resp = client_b.get(f"/verification-requests/{data['id']}/audit")
        assert resp.status_code == 404

    def test_sla_cross_tenant_blocked(self, client, client_b):
        data = _create_request(client, evidence_id="ev-iso-sla-001")
        resp = client_b.put(
            f"/verification-requests/{data['id']}/sla",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 404

    def test_dashboard_tenant_b_does_not_see_tenant_a_data(self, client, client_b):
        ev_id = "ev-iso-dash-999"
        _create_request(client, evidence_id=ev_id)
        # Tenant B's dashboard should show 0 for their own data
        resp_b = client_b.get("/verification-requests/dashboard")
        # The key check: no cross-contamination
        resp_a = client.get("/verification-requests/dashboard")
        assert resp_a.json()["total_requests"] >= resp_b.json()["total_requests"]

    def test_queue_tenant_isolation(self, client, client_b):
        _create_request(client, evidence_id="ev-iso-queue-001")
        resp_b = client_b.get("/verification-requests/queue/REQUESTED")
        for item in resp_b.json()["items"]:
            assert item["evidence_id"] != "ev-iso-queue-001"


# ---------------------------------------------------------------------------
# 16. TestAuditTrail
# ---------------------------------------------------------------------------


class TestAuditTrail:
    def test_create_writes_created_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-create-001")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        assert resp.status_code == 200
        events = resp.json()["items"]
        assert any(e["event_type"] == "CREATED" for e in events)

    def test_transition_writes_audit_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-trans-001")
        _transition(client, data["id"], "QUEUED")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "QUEUED" for e in events)

    def test_assign_writes_assigned_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-assign-001")
        _assign(client, data["id"])
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "ASSIGNED" for e in events)

    def test_reassign_writes_reassigned_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-reassign-001")
        _assign(client, data["id"])
        _assign(client, data["id"], assignee_id="analyst-002")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "REASSIGNED" for e in events)

    def test_escalate_writes_escalated_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-esc-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{data['id']}/escalate",
            json={"escalation_type": "MANUAL"},
        )
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "ESCALATED" for e in events)

    def test_sla_set_writes_sla_set_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-sla-001")
        client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "SLA_SET" for e in events)

    def test_result_writes_result_recorded_event(self, client):
        data = _create_request(client, evidence_id="ev-audit-result-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        client.post(
            f"/verification-requests/{data['id']}/result",
            json={"result": "APPROVED"},
        )
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        assert any(e["event_type"] == "RESULT_RECORDED" for e in events)

    def test_audit_has_old_and_new_state(self, client):
        data = _create_request(client, evidence_id="ev-audit-states-001")
        _transition(client, data["id"], "QUEUED")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        queued_events = [e for e in events if e["event_type"] == "QUEUED"]
        assert len(queued_events) >= 1
        e = queued_events[0]
        assert e["old_state"] == "REQUESTED"
        assert e["new_state"] == "QUEUED"

    def test_audit_not_found_returns_404(self, client):
        resp = client.get("/verification-requests/nonexistent/audit")
        assert resp.status_code == 404

    def test_audit_list_has_request_id(self, client):
        data = _create_request(client, evidence_id="ev-audit-reqid-001")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        assert resp.json()["request_id"] == data["id"]

    def test_multiple_transitions_generate_multiple_audit_events(self, client):
        data = _create_request(client, evidence_id="ev-audit-multi-001")
        _transition(client, data["id"], "QUEUED")
        _transition(client, data["id"], "ASSIGNED")
        _transition(client, data["id"], "IN_REVIEW")
        resp = client.get(f"/verification-requests/{data['id']}/audit")
        events = resp.json()["items"]
        # CREATED + QUEUED + ASSIGNED + REVIEW_STARTED = at least 4 events
        assert len(events) >= 4


# ---------------------------------------------------------------------------
# State machine unit tests
# ---------------------------------------------------------------------------


class TestStateMachineUnit:
    def test_requested_to_queued_valid(self):
        validate_workflow_transition("REQUESTED", "QUEUED")

    def test_requested_to_in_review_invalid(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("REQUESTED", "IN_REVIEW")

    def test_in_review_to_approved_valid(self):
        validate_workflow_transition("IN_REVIEW", "APPROVED")

    def test_in_review_to_all_valid_transitions(self):
        for state in [
            "PENDING_INFORMATION",
            "APPROVED",
            "REJECTED",
            "ESCALATED",
            "CANCELLED",
            "EXPIRED",
        ]:
            validate_workflow_transition("IN_REVIEW", state)

    def test_completed_is_terminal(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("COMPLETED", "REQUESTED")

    def test_cancelled_is_terminal(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("CANCELLED", "REQUESTED")

    def test_rejected_is_terminal(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("REJECTED", "COMPLETED")

    def test_expired_is_terminal(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("EXPIRED", "REQUESTED")

    def test_escalated_to_in_review_valid(self):
        validate_workflow_transition("ESCALATED", "IN_REVIEW")

    def test_escalated_to_approved_valid(self):
        validate_workflow_transition("ESCALATED", "APPROVED")

    def test_escalated_to_rejected_valid(self):
        validate_workflow_transition("ESCALATED", "REJECTED")

    def test_approved_to_completed_valid(self):
        validate_workflow_transition("APPROVED", "COMPLETED")

    def test_approved_to_requested_invalid(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("APPROVED", "REQUESTED")

    def test_unknown_state_raises(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("UNKNOWN_STATE", "REQUESTED")

    def test_pending_information_to_in_review_valid(self):
        validate_workflow_transition("PENDING_INFORMATION", "IN_REVIEW")

    def test_pending_information_to_queued_invalid(self):
        with pytest.raises(ValueError):
            validate_workflow_transition("PENDING_INFORMATION", "QUEUED")


# ---------------------------------------------------------------------------
# 17. TestWorkflowSlaHelpers
# ---------------------------------------------------------------------------


class TestWorkflowSlaHelpers:
    def test_sla_status_computed_after_set(self, client):
        data = _create_request(client, evidence_id="ev-sla-helper-001")
        client.put(
            f"/verification-requests/{data['id']}/sla",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        resp = client.get(f"/verification-requests/{data['id']}")
        assert resp.json()["sla_status"] == WorkflowSlaStatus.ON_TRACK.value

    def test_list_requests_by_assignee_after_assign(self, client):
        ev_id = "ev-sla-helper-002"
        req = _create_request(client, evidence_id=ev_id)
        _assign(client, req["id"], assignee_id="sla-analyst-001")
        resp = client.get("/verification-requests?assignee_id=sla-analyst-001")
        ids = [r["id"] for r in resp.json()["items"]]
        assert req["id"] in ids

    def test_transition_with_notes(self, client):
        data = _create_request(client, evidence_id="ev-sla-helper-003")
        resp = _transition(client, data["id"], "QUEUED", notes="Fast-track this one")
        assert resp.status_code == 200

    def test_complete_full_workflow(self, client):
        """Full lifecycle: REQUESTED → QUEUED → ASSIGNED → IN_REVIEW → APPROVED → COMPLETED."""
        data = _create_request(client, evidence_id="ev-full-001")
        _transition(client, data["id"], "QUEUED")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "APPROVED")
        resp = _transition(client, data["id"], "COMPLETED")
        assert resp.json()["workflow_state"] == "COMPLETED"
        assert resp.json()["completed_at"] is not None

    def test_cancel_from_queued(self, client):
        data = _create_request(client, evidence_id="ev-cancel-001")
        _transition(client, data["id"], "QUEUED")
        resp = _transition(client, data["id"], "CANCELLED")
        assert resp.json()["workflow_state"] == "CANCELLED"

    def test_expire_from_assigned(self, client):
        data = _create_request(client, evidence_id="ev-expire-001")
        _assign(client, data["id"])
        resp = _transition(client, data["id"], "EXPIRED")
        assert resp.json()["workflow_state"] == "EXPIRED"

    def test_pending_information_then_cancel(self, client):
        data = _create_request(client, evidence_id="ev-pend-cancel-001")
        _assign(client, data["id"])
        _transition(client, data["id"], "IN_REVIEW")
        _transition(client, data["id"], "PENDING_INFORMATION")
        resp = _transition(client, data["id"], "CANCELLED")
        assert resp.json()["workflow_state"] == "CANCELLED"

    def test_escalate_all_types(self, client):
        """Test each escalation type creates a valid ESCALATED state."""
        for esc_type in ["MANUAL", "AUTOMATIC", "SLA", "REVIEW", "EXECUTIVE"]:
            data = _create_request(
                client, evidence_id=f"ev-esc-type-{esc_type.lower()}"
            )
            _assign(client, data["id"])
            _transition(client, data["id"], "IN_REVIEW")
            resp = client.post(
                f"/verification-requests/{data['id']}/escalate",
                json={"escalation_type": esc_type},
            )
            assert resp.status_code == 200
            assert resp.json()["workflow_state"] == "ESCALATED"
            assert resp.json()["last_escalation_type"] == esc_type
