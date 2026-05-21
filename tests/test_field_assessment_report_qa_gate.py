"""Tests for the report.qa.approved readiness gate.

Covers:
  - report.qa.approved gate is blocked when no reports exist
  - report.qa.approved gate is blocked when reports exist but none QA-approved
  - report.qa.approved gate passes when a finalized + QA-approved report exists
  - Gate blocks_status_transition includes "delivered"
  - Gate recommended_action_id points to action.approve_report_qa
  - action.approve_report_qa NextAction included when gate is blocked
"""

from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("FG_ENV", "test")


from services.field_assessment.playbooks import get_playbook
from services.field_assessment.readiness import build_execution_state


def _make_engagement(assessment_type: str = "ai_governance") -> object:
    return SimpleNamespace(
        id="eng-qa-gate",
        assessment_type=assessment_type,
        client_name="QA Corp",
        status="report_generation",
    )


def _make_report(
    report_id: str = "rpt-001",
    is_finalized: bool = True,
    qa_approved_by: str | None = None,
    qa_approved_at: str | None = None,
) -> object:
    return SimpleNamespace(
        id=report_id,
        is_finalized=is_finalized,
        qa_approved_by=qa_approved_by,
        qa_approved_at=qa_approved_at,
    )


def _get_gate(state: object, gate_id: str) -> object:
    for gate in state.gates:
        if gate.gate_id == gate_id:
            return gate
    raise AssertionError(f"gate {gate_id!r} not found")


def _get_action(state: object, action_id: str) -> object | None:
    for action in state.next_actions:
        if action.action_id == action_id:
            return action
    return None


class TestReportQaGateBlocked:
    def test_gate_blocked_when_no_reports(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.status == "blocked"
        assert "delivered" in gate.blocks_status_transition

    def test_gate_blocked_when_report_not_finalized(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        report = _make_report(is_finalized=False)
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[report],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.status == "blocked"

    def test_gate_blocked_when_finalized_but_not_approved(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        report = _make_report(is_finalized=True, qa_approved_by=None)
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[report],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.status == "blocked"

    def test_gate_blocked_recommended_action_set(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.recommended_action_id == "action.approve_report_qa"

    def test_approve_report_qa_action_included_when_blocked(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[],
        )
        action = _get_action(state, "action.approve_report_qa")
        assert action is not None
        assert "action.approve_report_qa" in [
            gate.recommended_action_id
            for gate in state.gates
            if gate.gate_id == "report.qa.approved"
        ]
        assert action.safe_for_junior_assessor is False

    def test_gate_blocked_missing_items_describes_what_is_needed(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert "qa_approved_report" in gate.missing_items


class TestReportQaGatePassed:
    def test_gate_passed_when_finalized_and_approved(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        report = _make_report(
            is_finalized=True,
            qa_approved_by="senior@example.com",
            qa_approved_at="2026-05-21T10:00:00Z",
        )
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[report],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.status == "passed"
        assert gate.blocks_status_transition == []

    def test_gate_passed_evidence_present_includes_report_id(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        report = _make_report(
            report_id="rpt-approved",
            is_finalized=True,
            qa_approved_by="lead@example.com",
            qa_approved_at="2026-05-21T10:00:00Z",
        )
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[report],
        )
        gate = _get_gate(state, "report.qa.approved")
        assert "rpt-approved" in gate.evidence_present

    def test_approve_action_not_in_next_actions_when_gate_passes(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        report = _make_report(
            is_finalized=True,
            qa_approved_by="lead@example.com",
            qa_approved_at="2026-05-21T10:00:00Z",
        )
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
            reports=[report],
        )
        action = _get_action(state, "action.approve_report_qa")
        assert action is None

    def test_gate_category_is_report(self) -> None:
        eng = _make_engagement()
        playbook = get_playbook("ai_governance")
        state = build_execution_state(
            engagement=eng,
            playbook=playbook,
            scan_results=[],
            document_analyses=[],
            observations=[],
            findings=[],
            evidence_links=[],
            generated_at="2026-05-21T00:00:00Z",
        )
        gate = _get_gate(state, "report.qa.approved")
        assert gate.readiness_category == "report"
        assert gate.severity == "critical"
