"""Autonomous Governance Workflow Engine — core execution layer.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

State machine (inline, matches deployment/ops_governance pattern):
  draft → active → escalated → resolved → archived
  draft → archived   (direct close without activation)
  archived is terminal.

Evidence is fail-closed: transitioning to "resolved" requires all
required_evidence_types from the workflow's template to be attached via
FaEvidenceLink before the transition is accepted.

Audit trail: every transition is recorded as a FaEngagementAuditEvent with
event_type="workflow.transition". No separate transition table.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from api.db_models_field_assessment import FaEngagementAuditEvent

from api.db_models_governance_workflows import GovernanceWorkflow
from services.canonical import utc_iso8601_z_now
from services.field_assessment.audit import emit_engagement_audit_event
from services.governance_workflows import evidence as evidence_svc
from services.governance_workflows.routing import route_workflow
from services.governance_workflows.templates import get_template

log = logging.getLogger("frostgate.governance_workflows.engine")

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"active", "archived"}),
    "active": frozenset({"escalated", "resolved", "archived"}),
    "escalated": frozenset({"active", "resolved", "archived"}),
    "resolved": frozenset({"archived"}),
    "archived": frozenset(),
}

EVIDENCE_REQUIRED_STATES: frozenset[str] = frozenset({"resolved"})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class WorkflowNotFound(ValueError):
    pass


class WorkflowTransitionError(ValueError):
    pass


class WorkflowEvidenceError(ValueError):
    pass


class UnknownTemplate(ValueError):
    pass


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------


def _workflow_id(
    tenant_id: str,
    engagement_id: str,
    template_name: str,
    context_ref_id: str,
    now: str,
) -> str:
    raw = f"{tenant_id}:{engagement_id}:{template_name}:{context_ref_id}:{now}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _due_at(escalation_after_days: int) -> str:
    dt = datetime.now(UTC) + timedelta(days=escalation_after_days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_workflow(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    template_name: str,
    context_ref_type: str,
    context_ref_id: str,
    created_by: str,
    severity: str = "medium",
    title: str | None = None,
    description: str | None = None,
) -> GovernanceWorkflow:
    """Create a new workflow from a named template in draft state.

    Raises UnknownTemplate if template_name is not registered.
    """
    template = get_template(template_name)
    if template is None:
        raise UnknownTemplate(f"unknown workflow template: {template_name!r}")

    routing = route_workflow(
        template_name=template_name,
        severity=severity,
    )

    now = utc_iso8601_z_now()
    wf_id = _workflow_id(tenant_id, engagement_id, template_name, context_ref_id, now)

    auto_title = title or f"[{template_name}] {context_ref_type}:{context_ref_id}"
    auto_description = description or template.description

    wf = GovernanceWorkflow(
        id=wf_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        template_name=template_name,
        title=auto_title,
        description=auto_description,
        state="draft",
        priority=routing.priority,
        assigned_to_role=routing.assigned_to_role,
        context_ref_type=context_ref_type,
        context_ref_id=context_ref_id,
        due_at=_due_at(template.escalation_after_days),
        created_by=created_by,
        created_at=now,
        updated_at=now,
        resolved_at=None,
        archived_at=None,
        metadata_={},
        schema_version="1.0",
    )
    db.add(wf)
    db.flush()

    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="workflow.transition",
        actor=created_by,
        reason_code="WORKFLOW_CREATED",
        payload={
            "workflow_id": wf_id,
            "from_state": "",
            "to_state": "draft",
            "template_name": template_name,
        },
    )
    return wf


def transition_workflow(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
    to_state: str,
    actor: str,
    reason: str,
) -> GovernanceWorkflow:
    """Transition a workflow to a new state.

    Raises WorkflowNotFound if the workflow doesn't exist.
    Raises WorkflowTransitionError for invalid state machine paths.
    Raises WorkflowEvidenceError when transitioning to resolved without evidence.
    """
    wf = db.execute(
        select(GovernanceWorkflow).where(
            GovernanceWorkflow.id == workflow_id,
            GovernanceWorkflow.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    if wf is None:
        raise WorkflowNotFound(f"workflow {workflow_id!r} not found")

    allowed = VALID_TRANSITIONS.get(wf.state, frozenset())
    if to_state not in allowed:
        raise WorkflowTransitionError(
            f"cannot transition from {wf.state!r} to {to_state!r}; "
            f"allowed: {sorted(allowed)}"
        )

    if to_state in EVIDENCE_REQUIRED_STATES:
        template = get_template(wf.template_name)
        required = template.required_evidence_types if template else ()
        if not evidence_svc.workflow_evidence_complete(
            db,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            engagement_id=wf.engagement_id,
            required_types=required,
        ):
            raise WorkflowEvidenceError(
                f"workflow {workflow_id!r} cannot resolve: missing required evidence "
                f"types {list(required)}"
            )

    from_state = wf.state
    now = utc_iso8601_z_now()
    wf.state = to_state
    wf.updated_at = now
    if to_state == "resolved":
        wf.resolved_at = now
    if to_state == "archived":
        wf.archived_at = now
    db.flush()

    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=wf.engagement_id,
        event_type="workflow.transition",
        actor=actor,
        reason_code="WORKFLOW_TRANSITION",
        payload={
            "workflow_id": workflow_id,
            "from_state": from_state,
            "to_state": to_state,
            "reason": reason,
        },
    )
    return wf


def list_workflows(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str | None = None,
    state: str | None = None,
    limit: int = 100,
) -> list[GovernanceWorkflow]:
    stmt = select(GovernanceWorkflow).where(GovernanceWorkflow.tenant_id == tenant_id)
    if engagement_id is not None:
        stmt = stmt.where(GovernanceWorkflow.engagement_id == engagement_id)
    if state is not None:
        stmt = stmt.where(GovernanceWorkflow.state == state)
    stmt = stmt.order_by(GovernanceWorkflow.created_at.desc()).limit(min(limit, 200))
    return list(db.execute(stmt).scalars().all())


def get_workflow(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
) -> GovernanceWorkflow | None:
    return db.execute(
        select(GovernanceWorkflow).where(
            GovernanceWorkflow.id == workflow_id,
            GovernanceWorkflow.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()


def get_workflow_audit(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
    limit: int = 200,
) -> list[FaEngagementAuditEvent]:
    """Return transition events for a workflow from the engagement audit log."""
    rows: list[FaEngagementAuditEvent] = list(
        db.execute(
            select(FaEngagementAuditEvent)
            .where(
                FaEngagementAuditEvent.tenant_id == tenant_id,
                FaEngagementAuditEvent.event_type.in_(
                    ["workflow.transition", "workflow.evidence"]
                ),
                func.json_extract(FaEngagementAuditEvent.payload, "$.workflow_id")
                == workflow_id,
            )
            .order_by(FaEngagementAuditEvent.created_at.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return rows


def escalate_overdue(
    db: Session,
    *,
    tenant_id: str,
    dry_run: bool = False,
) -> list[str]:
    """Find active workflows past due_at and transition them to escalated.

    Returns list of workflow IDs that were (or would be, in dry_run) escalated.
    """
    now = utc_iso8601_z_now()
    overdue = (
        db.execute(
            select(GovernanceWorkflow).where(
                GovernanceWorkflow.tenant_id == tenant_id,
                GovernanceWorkflow.state == "active",
                GovernanceWorkflow.due_at < now,
            )
        )
        .scalars()
        .all()
    )

    escalated_ids: list[str] = []
    for wf in overdue:
        escalated_ids.append(wf.id)
        if not dry_run:
            try:
                transition_workflow(
                    db,
                    workflow_id=wf.id,
                    tenant_id=tenant_id,
                    to_state="escalated",
                    actor="system.escalation",
                    reason="Workflow overdue — auto-escalated.",
                )
            except (WorkflowTransitionError, WorkflowNotFound):
                log.warning("escalate_overdue: could not escalate %s", wf.id)

    return escalated_ids
