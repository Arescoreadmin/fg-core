"""Tests for the governance workflow engine."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401
import api.db_models_governance_workflows  # noqa: F401

from api.db_models_field_assessment import FaEngagementAuditEvent
from api.db_models_governance_workflows import GovernanceWorkflow
from services.governance_workflows import engine as wf_engine
from services.governance_workflows.evidence import attach_workflow_evidence

_TENANT = "tenant-engine-test"
_ENGAGEMENT = "eng-wf-001"


@pytest.fixture()
def engine():
    import api.signed_artifacts  # noqa: F401

    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


def _make_workflow(db: Session, **kwargs) -> GovernanceWorkflow:
    defaults = dict(
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        template_name="finding_remediation",
        context_ref_type="finding",
        context_ref_id="f-001",
        created_by="analyst@test.com",
        severity="high",
    )
    defaults.update(kwargs)
    return wf_engine.create_workflow(db, **defaults)


class TestCreateWorkflow:
    def test_creates_in_draft_state(self, db: Session) -> None:
        wf = _make_workflow(db)
        assert wf.state == "draft"
        assert wf.template_name == "finding_remediation"

    def test_auto_title_when_not_provided(self, db: Session) -> None:
        wf = _make_workflow(db)
        assert "finding_remediation" in wf.title

    def test_custom_title_respected(self, db: Session) -> None:
        wf = _make_workflow(db, title="Custom Title", context_ref_id="f-002")
        assert wf.title == "Custom Title"

    def test_unknown_template_raises(self, db: Session) -> None:
        with pytest.raises(wf_engine.UnknownTemplate):
            _make_workflow(db, template_name="does_not_exist", context_ref_id="f-003")

    def test_due_at_set_from_template(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="f-004")
        assert wf.due_at > wf.created_at

    def test_creates_audit_event(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="f-005")
        events = (
            db.query(FaEngagementAuditEvent)
            .filter(
                FaEngagementAuditEvent.event_type == "workflow.transition",
                FaEngagementAuditEvent.tenant_id == _TENANT,
            )
            .all()
        )
        wf_events = [e for e in events if e.payload.get("workflow_id") == wf.id]
        assert len(wf_events) == 1
        assert wf_events[0].payload["to_state"] == "draft"

    def test_critical_finding_routes_to_governance_admin(self, db: Session) -> None:
        wf = _make_workflow(db, severity="critical", context_ref_id="f-006")
        assert wf.assigned_to_role == "governance_admin"


class TestTransitionWorkflow:
    def test_draft_to_active(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-001")
        wf = wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="analyst@test.com",
            reason="starting",
        )
        assert wf.state == "active"

    def test_active_to_escalated(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-002")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="analyst@test.com",
            reason="start",
        )
        wf = wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="escalated",
            actor="system",
            reason="overdue",
        )
        assert wf.state == "escalated"

    def test_resolve_without_evidence_raises(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-003")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="analyst@test.com",
            reason="start",
        )
        with pytest.raises(wf_engine.WorkflowEvidenceError):
            wf_engine.transition_workflow(
                db,
                workflow_id=wf.id,
                tenant_id=_TENANT,
                to_state="resolved",
                actor="analyst@test.com",
                reason="done",
            )

    def test_resolve_with_evidence_succeeds(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-004")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="analyst@test.com",
            reason="start",
        )
        # finding_remediation requires ("link", "text")
        attach_workflow_evidence(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="link",
            reference="https://ticket.example.com",
            submitted_by="analyst@test.com",
        )
        attach_workflow_evidence(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="text",
            reference="Remediation confirmed.",
            submitted_by="analyst@test.com",
        )
        wf = wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="resolved",
            actor="analyst@test.com",
            reason="done",
        )
        assert wf.state == "resolved"
        assert wf.resolved_at is not None

    def test_invalid_transition_raises(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-005")
        with pytest.raises(wf_engine.WorkflowTransitionError):
            wf_engine.transition_workflow(
                db,
                workflow_id=wf.id,
                tenant_id=_TENANT,
                to_state="resolved",
                actor="actor",
                reason="skip",
            )

    def test_archived_is_terminal(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-006")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="archived",
            actor="actor",
            reason="closing",
        )
        with pytest.raises(wf_engine.WorkflowTransitionError):
            wf_engine.transition_workflow(
                db,
                workflow_id=wf.id,
                tenant_id=_TENANT,
                to_state="active",
                actor="actor",
                reason="reopen",
            )

    def test_not_found_raises(self, db: Session) -> None:
        with pytest.raises(wf_engine.WorkflowNotFound):
            wf_engine.transition_workflow(
                db,
                workflow_id="nonexistent",
                tenant_id=_TENANT,
                to_state="active",
                actor="actor",
                reason="r",
            )

    def test_transition_emits_audit_event(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-007")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="actor@test.com",
            reason="starting",
        )
        audit = wf_engine.get_workflow_audit(db, workflow_id=wf.id, tenant_id=_TENANT)
        states = [e.payload["to_state"] for e in audit]
        assert "draft" in states
        assert "active" in states

    def test_archived_stamps_archived_at(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="t-008")
        wf = wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="archived",
            actor="actor",
            reason="done",
        )
        assert wf.archived_at is not None


class TestListAndGet:
    def test_list_all(self, db: Session) -> None:
        _make_workflow(db, context_ref_id="l-001")
        _make_workflow(db, context_ref_id="l-002")
        workflows = wf_engine.list_workflows(db, tenant_id=_TENANT)
        assert len(workflows) >= 2

    def test_list_by_state(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="l-003")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="actor",
            reason="start",
        )
        active = wf_engine.list_workflows(db, tenant_id=_TENANT, state="active")
        assert all(w.state == "active" for w in active)

    def test_get_returns_workflow(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="l-004")
        fetched = wf_engine.get_workflow(db, workflow_id=wf.id, tenant_id=_TENANT)
        assert fetched is not None
        assert fetched.id == wf.id

    def test_get_unknown_returns_none(self, db: Session) -> None:
        result = wf_engine.get_workflow(db, workflow_id="ghost", tenant_id=_TENANT)
        assert result is None


class TestEscalateOverdue:
    def test_escalates_overdue_active_workflow(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="esc-001")
        wf_engine.transition_workflow(
            db,
            workflow_id=wf.id,
            tenant_id=_TENANT,
            to_state="active",
            actor="actor",
            reason="start",
        )
        # Force due_at into the past
        wf.due_at = "2020-01-01T00:00:00Z"
        db.flush()

        escalated = wf_engine.escalate_overdue(db, tenant_id=_TENANT)
        assert wf.id in escalated

        refreshed = wf_engine.get_workflow(db, workflow_id=wf.id, tenant_id=_TENANT)
        assert refreshed is not None
        assert refreshed.state == "escalated"

    def test_dry_run_does_not_change_state(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="esc-002")
        wf.due_at = "2020-01-01T00:00:00Z"
        db.flush()

        escalated = wf_engine.escalate_overdue(db, tenant_id=_TENANT, dry_run=True)
        assert wf.id in escalated
        assert wf.state == "draft"

    def test_skips_non_overdue(self, db: Session) -> None:
        wf = _make_workflow(db, context_ref_id="esc-003")
        future = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        wf.due_at = future
        db.flush()

        escalated = wf_engine.escalate_overdue(db, tenant_id=_TENANT)
        assert wf.id not in escalated
