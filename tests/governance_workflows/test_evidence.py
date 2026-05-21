"""Tests for workflow evidence attachment (via FaEvidenceLink)."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401
import api.db_models_governance_workflows  # noqa: F401

from services.governance_workflows.evidence import (
    InvalidEvidenceType,
    WorkflowEvidenceDuplicate,
    attach_workflow_evidence,
    get_evidence_for_workflow,
    workflow_evidence_complete,
)

_TENANT = "tenant-evidence-test"
_ENGAGEMENT = "eng-ev-001"
_WORKFLOW = "wf-ev-001"


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


class TestAttachWorkflowEvidence:
    def test_creates_link(self, db: Session) -> None:
        link = attach_workflow_evidence(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="link",
            reference="https://example.com/evidence",
            submitted_by="analyst@test.com",
        )
        assert link.source_entity_type == "workflow"
        assert link.source_entity_id == _WORKFLOW
        assert link.evidence_entity_type == "link"
        assert link.evidence_entity_id == "https://example.com/evidence"

    def test_invalid_evidence_type_raises(self, db: Session) -> None:
        with pytest.raises(InvalidEvidenceType):
            attach_workflow_evidence(
                db,
                workflow_id=_WORKFLOW,
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                evidence_type="invalid_type",
                reference="x",
                submitted_by="actor",
            )

    def test_duplicate_raises(self, db: Session) -> None:
        attach_workflow_evidence(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="text",
            reference="approved",
            submitted_by="actor",
        )
        with pytest.raises(WorkflowEvidenceDuplicate):
            attach_workflow_evidence(
                db,
                workflow_id=_WORKFLOW,
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                evidence_type="text",
                reference="approved",
                submitted_by="actor",
            )

    def test_different_types_both_succeed(self, db: Session) -> None:
        attach_workflow_evidence(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="link",
            reference="https://a.com",
            submitted_by="actor",
        )
        attach_workflow_evidence(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="text",
            reference="done",
            submitted_by="actor",
        )
        links = get_evidence_for_workflow(
            db, workflow_id=_WORKFLOW, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert len(links) == 2


class TestWorkflowEvidenceComplete:
    def test_empty_no_evidence_returns_false(self, db: Session) -> None:
        assert not workflow_evidence_complete(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            required_types=("link",),
        )

    def test_empty_required_types_returns_false(self, db: Session) -> None:
        assert not workflow_evidence_complete(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            required_types=(),
        )

    def test_partial_evidence_returns_false(self, db: Session) -> None:
        attach_workflow_evidence(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            evidence_type="link",
            reference="https://a.com",
            submitted_by="actor",
        )
        assert not workflow_evidence_complete(
            db,
            workflow_id=_WORKFLOW,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            required_types=("link", "text"),
        )

    def test_all_required_present_returns_true(self, db: Session) -> None:
        for ev_type, ref in [("link", "https://a.com"), ("text", "approved")]:
            attach_workflow_evidence(
                db,
                workflow_id="wf-complete",
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                evidence_type=ev_type,
                reference=ref,
                submitted_by="actor",
            )
        assert workflow_evidence_complete(
            db,
            workflow_id="wf-complete",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            required_types=("link", "text"),
        )

    def test_extra_evidence_does_not_block(self, db: Session) -> None:
        for ev_type, ref in [
            ("link", "https://a.com"),
            ("text", "approved"),
            ("finding_ref", "fid-001"),
        ]:
            attach_workflow_evidence(
                db,
                workflow_id="wf-extra",
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                evidence_type=ev_type,
                reference=ref,
                submitted_by="actor",
            )
        assert workflow_evidence_complete(
            db,
            workflow_id="wf-extra",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            required_types=("link", "text"),
        )
