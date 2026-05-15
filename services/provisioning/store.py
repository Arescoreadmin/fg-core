"""Provisioning persistence layer (SQLAlchemy).

All queries are tenant-scoped: platform-level records (tenant_id=None) are
readable by any operator with sufficient scope; tenant-linked records are
only visible within the owning tenant's context.

No mutable module-level state. ProvisioningStore is stateless and receives
a Session at call time.
"""

from __future__ import annotations

import json as _json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models import (
    ProvisioningAuditEventRecord,
    ProvisioningOrganizationRecord,
    ProvisioningWorkflowRecord,
)
from services.provisioning.audit import (
    _get_previous_event_hash,
    compute_event_hash,
    emit_provisioning_event,
)
from services.provisioning.models import (
    ActivationBlocker,
    ComplianceClassification,
    DeploymentTier,
    FailureCategory,
    OnboardingState,
    OrgEventType,
    OrgLifecycleStatus,
    ProvisioningAuditEvent,
    ProvisioningOrganization,
    ProvisioningWorkflow,
    WorkflowState,
    check_activation_preconditions,
    validate_org_transition,
)

log = logging.getLogger("frostgate.provisioning.store")

_MAX_PAGE = 200
_DEFAULT_PAGE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ProvisioningStoreError(Exception):
    """Base error for provisioning store operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class OrgNotFound(ProvisioningStoreError):
    def __init__(self, org_id: str) -> None:
        super().__init__("PROV-001", f"Organization not found: {org_id}")


class WorkflowNotFound(ProvisioningStoreError):
    def __init__(self, provisioning_id: str) -> None:
        super().__init__("PROV-002", f"Workflow not found: {provisioning_id}")


class InvalidOrgTransition(ProvisioningStoreError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(
            "PROV-003",
            f"Invalid org lifecycle transition: {from_status!r} → {to_status!r}",
        )


class WorkflowTransitionError(ProvisioningStoreError):
    def __init__(self, provisioning_id: str, reason: str) -> None:
        super().__init__(
            "PROV-004",
            f"Workflow transition error for {provisioning_id}: {reason}",
        )


class ConcurrentModificationError(ProvisioningStoreError):
    def __init__(self, resource_id: str) -> None:
        super().__init__(
            "PROV-007",
            f"Resource {resource_id} was modified concurrently — retry the operation",
        )


class ActivationPreconditionFailed(ProvisioningStoreError):
    def __init__(self, org_id: str, blockers: list[ActivationBlocker]) -> None:
        reasons = "; ".join(b.reason for b in blockers)
        super().__init__(
            "PROV-008",
            f"Activation preconditions not met for {org_id}: {reasons}",
        )
        self.blockers = blockers


class DuplicateIdempotencyKey(ProvisioningStoreError):
    def __init__(self, key: str) -> None:
        super().__init__("PROV-009", f"Duplicate idempotency key: {key}")


class DuplicateSlug(ProvisioningStoreError):
    def __init__(self, slug: str) -> None:
        super().__init__("PROV-010", f"Slug already in use: {slug}")


# ---------------------------------------------------------------------------
# Internal conversion helpers
# ---------------------------------------------------------------------------


def _org_orm_to_domain(row: ProvisioningOrganizationRecord) -> ProvisioningOrganization:
    metadata: dict = {}
    if row.metadata_json:
        try:
            metadata = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            metadata = {}

    return ProvisioningOrganization(
        organization_id=row.organization_id,
        tenant_id=row.tenant_id,
        org_name=row.org_name,
        slug=row.slug,
        lifecycle_status=OrgLifecycleStatus(row.lifecycle_status),
        compliance_classification=ComplianceClassification(
            row.compliance_classification
        ),
        deployment_tier=DeploymentTier(row.deployment_tier),
        onboarding_state=OnboardingState(row.onboarding_state),
        env_assignment_id=row.env_assignment_id,
        region=row.region,
        idempotency_key=row.idempotency_key,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        activated_at=row.activated_at,
        suspended_at=row.suspended_at,
        archived_at=row.archived_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=metadata,
    )


def _wf_orm_to_domain(row: ProvisioningWorkflowRecord) -> ProvisioningWorkflow:
    validation_results: dict = {}
    if row.validation_results_json:
        try:
            validation_results = _json.loads(row.validation_results_json)
        except (ValueError, TypeError):
            validation_results = {}

    orch_meta: dict = {}
    if row.orchestration_metadata_json:
        try:
            orch_meta = _json.loads(row.orchestration_metadata_json)
        except (ValueError, TypeError):
            orch_meta = {}

    failure_cat = None
    if row.failure_category:
        try:
            failure_cat = FailureCategory(row.failure_category)
        except ValueError:
            failure_cat = None

    return ProvisioningWorkflow(
        provisioning_id=row.provisioning_id,
        organization_id=row.organization_id,
        tenant_id=row.tenant_id,
        workflow_state=WorkflowState(row.workflow_state),
        current_step=row.current_step,
        idempotency_key=row.idempotency_key,
        env_target=row.env_target,
        retry_count=row.retry_count,
        max_retries=row.max_retries,
        failure_reason=row.failure_reason,
        failure_category=failure_cat,
        initiated_by=row.initiated_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        last_updated_at=row.last_updated_at,
        state_version=getattr(row, "state_version", 0) or 0,
        validation_results=validation_results,
        orchestration_metadata=orch_meta,
    )


def _event_orm_to_domain(row: ProvisioningAuditEventRecord) -> ProvisioningAuditEvent:
    details: dict = {}
    if row.details_json:
        try:
            details = _json.loads(row.details_json)
        except (ValueError, TypeError):
            details = {}

    return ProvisioningAuditEvent(
        event_id=row.event_id,
        organization_id=row.organization_id,
        provisioning_id=row.provisioning_id,
        tenant_id=row.tenant_id,
        env_id=row.env_id,
        event_type=OrgEventType(row.event_type),
        actor=row.actor,
        outcome=row.outcome,
        timestamp=row.timestamp,
        workflow_state=row.workflow_state,
        failure_reason=row.failure_reason,
        details=details,
        event_hash=getattr(row, "event_hash", None),
        previous_event_hash=getattr(row, "previous_event_hash", None),
    )


# ---------------------------------------------------------------------------
# Store — stateless, session-injected
# ---------------------------------------------------------------------------


class ProvisioningStore:
    """Persistence operations for provisioning domains.

    Receives a SQLAlchemy Session at each call. No hidden state.
    All mutations emit a ProvisioningAuditEvent before returning.
    """

    def create_organization(
        self,
        db: Session,
        *,
        org_name: str,
        slug: str,
        compliance_classification: ComplianceClassification,
        deployment_tier: DeploymentTier,
        created_by: str,
        tenant_id: Optional[str] = None,
        region: Optional[str] = None,
        env_assignment_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ProvisioningOrganization:
        # Idempotency: return existing record deterministically.
        if idempotency_key is not None:
            existing = (
                db.query(ProvisioningOrganizationRecord)
                .filter(
                    ProvisioningOrganizationRecord.idempotency_key == idempotency_key
                )
                .first()
            )
            if existing is not None:
                return _org_orm_to_domain(existing)

        # Check slug uniqueness.
        slug_conflict = (
            db.query(ProvisioningOrganizationRecord)
            .filter(ProvisioningOrganizationRecord.slug == slug)
            .first()
        )
        if slug_conflict is not None:
            raise DuplicateSlug(slug)

        org_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        metadata_json = _json.dumps(metadata or {}, sort_keys=True)

        row = ProvisioningOrganizationRecord(
            organization_id=org_id,
            tenant_id=tenant_id,
            org_name=org_name,
            slug=slug,
            lifecycle_status=OrgLifecycleStatus.PENDING.value,
            compliance_classification=compliance_classification.value,
            deployment_tier=deployment_tier.value,
            onboarding_state=OnboardingState.NOT_STARTED.value,
            env_assignment_id=env_assignment_id,
            region=region,
            idempotency_key=idempotency_key,
            metadata_json=metadata_json,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.ORGANIZATION_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            now_iso=now_iso,
            details={
                "org_name": org_name,
                "slug": slug,
                "compliance_classification": compliance_classification.value,
                "deployment_tier": deployment_tier.value,
            },
        )

        return _org_orm_to_domain(row)

    def get_organization(
        self,
        db: Session,
        *,
        org_id: str,
        tenant_id: Optional[str] = None,
    ) -> ProvisioningOrganization:
        q = db.query(ProvisioningOrganizationRecord).filter(
            ProvisioningOrganizationRecord.organization_id == org_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ProvisioningOrganizationRecord.tenant_id == tenant_id)
                | (ProvisioningOrganizationRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise OrgNotFound(org_id)
        return _org_orm_to_domain(row)

    def list_organizations(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        lifecycle_status: Optional[OrgLifecycleStatus] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[ProvisioningOrganization]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(ProvisioningOrganizationRecord)
        if tenant_id is not None:
            q = q.filter(
                (ProvisioningOrganizationRecord.tenant_id == tenant_id)
                | (ProvisioningOrganizationRecord.tenant_id.is_(None))
            )
        if lifecycle_status is not None:
            q = q.filter(
                ProvisioningOrganizationRecord.lifecycle_status
                == lifecycle_status.value
            )
        rows = (
            q.order_by(ProvisioningOrganizationRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_org_orm_to_domain(r) for r in rows]

    def transition_org_status(
        self,
        db: Session,
        *,
        org_id: str,
        to_status: OrgLifecycleStatus,
        actor: str,
        tenant_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> ProvisioningOrganization:
        q = db.query(ProvisioningOrganizationRecord).filter(
            ProvisioningOrganizationRecord.organization_id == org_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ProvisioningOrganizationRecord.tenant_id == tenant_id)
                | (ProvisioningOrganizationRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise OrgNotFound(org_id)

        from_status = OrgLifecycleStatus(row.lifecycle_status)
        try:
            validate_org_transition(from_status, to_status)
        except ValueError as exc:
            raise InvalidOrgTransition(from_status.value, to_status.value) from exc

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = getattr(row, "state_version", 0) or 0
        new_version = current_version + 1

        updates: dict[str, Any] = {
            "lifecycle_status": to_status.value,
            "state_version": new_version,
            "updated_at": now,
        }
        if to_status == OrgLifecycleStatus.ACTIVE:
            updates["activated_at"] = now
        elif to_status == OrgLifecycleStatus.SUSPENDED:
            updates["suspended_at"] = now
        elif to_status == OrgLifecycleStatus.ARCHIVED:
            updates["archived_at"] = now

        rows_affected = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == org_id,
                ProvisioningOrganizationRecord.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(org_id)

        db.flush()
        db.refresh(row)

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.ORG_STATUS_CHANGED,
            actor=actor,
            outcome="success",
            tenant_id=row.tenant_id,
            now_iso=now_iso,
            details={
                "lifecycle_status": to_status.value,
                **(details or {}),
            },
        )

        return _org_orm_to_domain(row)

    def start_provisioning_workflow(
        self,
        db: Session,
        *,
        org_id: str,
        initiated_by: str,
        env_target: Optional[str] = None,
        tenant_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ProvisioningWorkflow:
        # Idempotency: return existing workflow deterministically.
        if idempotency_key is not None:
            existing = (
                db.query(ProvisioningWorkflowRecord)
                .filter(ProvisioningWorkflowRecord.idempotency_key == idempotency_key)
                .first()
            )
            if existing is not None:
                return _wf_orm_to_domain(existing)

        org = self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        if org.lifecycle_status not in (
            OrgLifecycleStatus.PENDING,
            OrgLifecycleStatus.FAILED,
        ):
            raise WorkflowTransitionError(
                org_id,
                f"Org must be in pending or failed state to start provisioning; "
                f"current status: {org.lifecycle_status.value!r}",
            )

        provisioning_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        orch_json = _json.dumps(metadata or {}, sort_keys=True)

        wf_row = ProvisioningWorkflowRecord(
            provisioning_id=provisioning_id,
            organization_id=org_id,
            tenant_id=org.tenant_id,
            workflow_state=WorkflowState.RUNNING.value,
            idempotency_key=idempotency_key,
            env_target=env_target,
            retry_count=0,
            max_retries=3,
            initiated_by=initiated_by,
            started_at=now,
            last_updated_at=now,
            orchestration_metadata_json=orch_json,
            state_version=0,
        )
        db.add(wf_row)
        db.flush()

        # Transition org to PROVISIONING.
        current_version = org.state_version
        rows_affected = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == org_id,
                ProvisioningOrganizationRecord.state_version == current_version,
            )
            .update(
                {
                    "lifecycle_status": OrgLifecycleStatus.PROVISIONING.value,
                    "onboarding_state": OnboardingState.IN_PROGRESS.value,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(org_id)
        db.flush()

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.PROVISIONING_STARTED,
            actor=initiated_by,
            outcome="success",
            provisioning_id=provisioning_id,
            tenant_id=org.tenant_id,
            now_iso=now_iso,
            workflow_state=WorkflowState.RUNNING.value,
            details={
                "env_target": env_target or "",
                "onboarding_state": OnboardingState.IN_PROGRESS.value,
            },
        )

        return _wf_orm_to_domain(wf_row)

    def complete_provisioning_workflow(
        self,
        db: Session,
        *,
        provisioning_id: str,
        actor: str,
        tenant_id: Optional[str] = None,
        validation_results: Optional[dict] = None,
    ) -> ProvisioningWorkflow:
        wf = self.get_workflow(db, provisioning_id=provisioning_id, tenant_id=tenant_id)

        if wf.workflow_state != WorkflowState.RUNNING:
            raise WorkflowTransitionError(
                provisioning_id,
                f"Workflow must be in running state to complete; "
                f"current state: {wf.workflow_state.value!r}",
            )

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = wf.state_version
        val_json = _json.dumps(validation_results or {}, sort_keys=True)

        rows_affected = (
            db.query(ProvisioningWorkflowRecord)
            .filter(
                ProvisioningWorkflowRecord.provisioning_id == provisioning_id,
                ProvisioningWorkflowRecord.state_version == current_version,
            )
            .update(
                {
                    "workflow_state": WorkflowState.COMPLETED.value,
                    "completed_at": now,
                    "last_updated_at": now,
                    "validation_results_json": val_json,
                    "state_version": current_version + 1,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(provisioning_id)
        db.flush()

        # Advance onboarding_state on the org.
        org_row = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == wf.organization_id
            )
            .first()
        )
        if org_row is not None:
            org_version = getattr(org_row, "state_version", 0) or 0
            db.query(ProvisioningOrganizationRecord).filter(
                ProvisioningOrganizationRecord.organization_id == wf.organization_id,
                ProvisioningOrganizationRecord.state_version == org_version,
            ).update(
                {
                    "onboarding_state": OnboardingState.PENDING_ACTIVATION.value,
                    "state_version": org_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
            db.flush()

        self._emit_event(
            db,
            org_id=wf.organization_id,
            event_type=OrgEventType.PROVISIONING_COMPLETED,
            actor=actor,
            outcome="success",
            provisioning_id=provisioning_id,
            tenant_id=wf.tenant_id,
            now_iso=now_iso,
            workflow_state=WorkflowState.COMPLETED.value,
            details={"onboarding_state": OnboardingState.PENDING_ACTIVATION.value},
        )

        wf_row = (
            db.query(ProvisioningWorkflowRecord)
            .filter(ProvisioningWorkflowRecord.provisioning_id == provisioning_id)
            .first()
        )
        return _wf_orm_to_domain(wf_row)

    def fail_provisioning_workflow(
        self,
        db: Session,
        *,
        provisioning_id: str,
        actor: str,
        failure_reason: str,
        failure_category: FailureCategory = FailureCategory.TERMINAL,
        tenant_id: Optional[str] = None,
    ) -> ProvisioningWorkflow:
        wf = self.get_workflow(db, provisioning_id=provisioning_id, tenant_id=tenant_id)

        if wf.workflow_state != WorkflowState.RUNNING:
            raise WorkflowTransitionError(
                provisioning_id,
                f"Workflow must be in running state to fail; "
                f"current state: {wf.workflow_state.value!r}",
            )

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = wf.state_version

        rows_affected = (
            db.query(ProvisioningWorkflowRecord)
            .filter(
                ProvisioningWorkflowRecord.provisioning_id == provisioning_id,
                ProvisioningWorkflowRecord.state_version == current_version,
            )
            .update(
                {
                    "workflow_state": WorkflowState.FAILED.value,
                    "failure_reason": failure_reason,
                    "failure_category": failure_category.value,
                    "last_updated_at": now,
                    "state_version": current_version + 1,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(provisioning_id)
        db.flush()

        # Transition org to FAILED.
        org_row = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == wf.organization_id
            )
            .first()
        )
        if org_row is not None:
            org_version = getattr(org_row, "state_version", 0) or 0
            db.query(ProvisioningOrganizationRecord).filter(
                ProvisioningOrganizationRecord.organization_id == wf.organization_id,
                ProvisioningOrganizationRecord.state_version == org_version,
            ).update(
                {
                    "lifecycle_status": OrgLifecycleStatus.FAILED.value,
                    "onboarding_state": OnboardingState.FAILED.value,
                    "state_version": org_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
            db.flush()

        self._emit_event(
            db,
            org_id=wf.organization_id,
            event_type=OrgEventType.PROVISIONING_FAILED,
            actor=actor,
            outcome="failure",
            provisioning_id=provisioning_id,
            tenant_id=wf.tenant_id,
            now_iso=now_iso,
            workflow_state=WorkflowState.FAILED.value,
            failure_reason=failure_reason,
            details={"failure_category": failure_category.value},
        )

        wf_row = (
            db.query(ProvisioningWorkflowRecord)
            .filter(ProvisioningWorkflowRecord.provisioning_id == provisioning_id)
            .first()
        )
        return _wf_orm_to_domain(wf_row)

    def retry_provisioning_workflow(
        self,
        db: Session,
        *,
        org_id: str,
        initiated_by: str,
        env_target: Optional[str] = None,
        tenant_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ProvisioningWorkflow:
        # Idempotency check.
        if idempotency_key is not None:
            existing = (
                db.query(ProvisioningWorkflowRecord)
                .filter(ProvisioningWorkflowRecord.idempotency_key == idempotency_key)
                .first()
            )
            if existing is not None:
                return _wf_orm_to_domain(existing)

        org = self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        if org.lifecycle_status != OrgLifecycleStatus.FAILED:
            raise WorkflowTransitionError(
                org_id,
                f"Org must be in failed state to retry provisioning; "
                f"current status: {org.lifecycle_status.value!r}",
            )

        # Find most recent failed workflow for retry_count.
        prev_wf_row = (
            db.query(ProvisioningWorkflowRecord)
            .filter(ProvisioningWorkflowRecord.organization_id == org_id)
            .order_by(ProvisioningWorkflowRecord.started_at.desc())
            .first()
        )
        prev_retry_count = 0
        if prev_wf_row is not None:
            if prev_wf_row.workflow_state == WorkflowState.RUNNING.value:
                raise WorkflowTransitionError(
                    org_id,
                    "Cannot retry: a workflow is already running",
                )
            prev_retry_count = (getattr(prev_wf_row, "retry_count", 0) or 0) + 1

        provisioning_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        wf_row = ProvisioningWorkflowRecord(
            provisioning_id=provisioning_id,
            organization_id=org_id,
            tenant_id=org.tenant_id,
            workflow_state=WorkflowState.RUNNING.value,
            idempotency_key=idempotency_key,
            env_target=env_target,
            retry_count=prev_retry_count,
            max_retries=3,
            initiated_by=initiated_by,
            started_at=now,
            last_updated_at=now,
            state_version=0,
        )
        db.add(wf_row)
        db.flush()

        # Transition org back to PROVISIONING.
        current_version = org.state_version
        rows_affected = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == org_id,
                ProvisioningOrganizationRecord.state_version == current_version,
            )
            .update(
                {
                    "lifecycle_status": OrgLifecycleStatus.PROVISIONING.value,
                    "onboarding_state": OnboardingState.IN_PROGRESS.value,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(org_id)
        db.flush()

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.PROVISIONING_STARTED,
            actor=initiated_by,
            outcome="success",
            provisioning_id=provisioning_id,
            tenant_id=org.tenant_id,
            now_iso=now_iso,
            workflow_state=WorkflowState.RUNNING.value,
            details={
                "retry_count": prev_retry_count,
                "env_target": env_target or "",
            },
        )

        return _wf_orm_to_domain(wf_row)

    def activate_organization(
        self,
        db: Session,
        *,
        org_id: str,
        actor: str,
        tenant_id: Optional[str] = None,
    ) -> ProvisioningOrganization:
        org = self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        # Fetch latest completed workflow if available.
        latest_wf_row = (
            db.query(ProvisioningWorkflowRecord)
            .filter(ProvisioningWorkflowRecord.organization_id == org_id)
            .order_by(ProvisioningWorkflowRecord.started_at.desc())
            .first()
        )
        latest_wf = _wf_orm_to_domain(latest_wf_row) if latest_wf_row else None

        blockers = check_activation_preconditions(org, workflow=latest_wf)
        if blockers:
            raise ActivationPreconditionFailed(org_id, blockers)

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = org.state_version

        rows_affected = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == org_id,
                ProvisioningOrganizationRecord.state_version == current_version,
            )
            .update(
                {
                    "lifecycle_status": OrgLifecycleStatus.ACTIVE.value,
                    "onboarding_state": OnboardingState.COMPLETED.value,
                    "activated_at": now,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(org_id)
        db.flush()

        row = (
            db.query(ProvisioningOrganizationRecord)
            .filter(ProvisioningOrganizationRecord.organization_id == org_id)
            .first()
        )

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.TENANT_ACTIVATED,
            actor=actor,
            outcome="success",
            tenant_id=row.tenant_id if row else None,
            now_iso=now_iso,
            details={
                "lifecycle_status": OrgLifecycleStatus.ACTIVE.value,
                "onboarding_state": OnboardingState.COMPLETED.value,
            },
        )

        return _org_orm_to_domain(row) if row else org

    def suspend_organization(
        self,
        db: Session,
        *,
        org_id: str,
        actor: str,
        tenant_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> ProvisioningOrganization:
        org = self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        if org.lifecycle_status != OrgLifecycleStatus.ACTIVE:
            raise InvalidOrgTransition(org.lifecycle_status.value, "suspended")

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = org.state_version

        rows_affected = (
            db.query(ProvisioningOrganizationRecord)
            .filter(
                ProvisioningOrganizationRecord.organization_id == org_id,
                ProvisioningOrganizationRecord.state_version == current_version,
            )
            .update(
                {
                    "lifecycle_status": OrgLifecycleStatus.SUSPENDED.value,
                    "suspended_at": now,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(org_id)
        db.flush()

        row = (
            db.query(ProvisioningOrganizationRecord)
            .filter(ProvisioningOrganizationRecord.organization_id == org_id)
            .first()
        )

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.TENANT_SUSPENDED,
            actor=actor,
            outcome="success",
            tenant_id=row.tenant_id if row else None,
            now_iso=now_iso,
            details={"lifecycle_status": OrgLifecycleStatus.SUSPENDED.value},
        )

        return _org_orm_to_domain(row) if row else org

    def assign_environment(
        self,
        db: Session,
        *,
        org_id: str,
        env_assignment_id: str,
        actor: str,
        tenant_id: Optional[str] = None,
    ) -> ProvisioningOrganization:
        org = self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        now = _utcnow()
        now_iso = now.isoformat()

        db.query(ProvisioningOrganizationRecord).filter(
            ProvisioningOrganizationRecord.organization_id == org_id
        ).update(
            {"env_assignment_id": env_assignment_id, "updated_at": now},
            synchronize_session="evaluate",
        )
        db.flush()

        row = (
            db.query(ProvisioningOrganizationRecord)
            .filter(ProvisioningOrganizationRecord.organization_id == org_id)
            .first()
        )

        self._emit_event(
            db,
            org_id=org_id,
            event_type=OrgEventType.ENVIRONMENT_ASSIGNED,
            actor=actor,
            outcome="success",
            tenant_id=org.tenant_id,
            env_id=env_assignment_id,
            now_iso=now_iso,
            details={"env_assignment_id": env_assignment_id},
        )

        return _org_orm_to_domain(row) if row else org

    def list_audit_events(
        self,
        db: Session,
        *,
        org_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[ProvisioningAuditEvent]:
        self.get_organization(db, org_id=org_id, tenant_id=tenant_id)

        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(ProvisioningAuditEventRecord)
            .filter(ProvisioningAuditEventRecord.organization_id == org_id)
            .order_by(ProvisioningAuditEventRecord.timestamp.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_event_orm_to_domain(r) for r in rows]

    def get_workflow(
        self,
        db: Session,
        *,
        provisioning_id: str,
        tenant_id: Optional[str] = None,
    ) -> ProvisioningWorkflow:
        q = db.query(ProvisioningWorkflowRecord).filter(
            ProvisioningWorkflowRecord.provisioning_id == provisioning_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ProvisioningWorkflowRecord.tenant_id == tenant_id)
                | (ProvisioningWorkflowRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise WorkflowNotFound(provisioning_id)
        return _wf_orm_to_domain(row)

    def list_workflows(
        self,
        db: Session,
        *,
        org_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[ProvisioningWorkflow]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(ProvisioningWorkflowRecord)
        if org_id is not None:
            q = q.filter(ProvisioningWorkflowRecord.organization_id == org_id)
        if tenant_id is not None:
            q = q.filter(
                (ProvisioningWorkflowRecord.tenant_id == tenant_id)
                | (ProvisioningWorkflowRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ProvisioningWorkflowRecord.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_wf_orm_to_domain(r) for r in rows]

    # --- Internal ---

    def _emit_event(
        self,
        db: Session,
        *,
        org_id: str,
        event_type: OrgEventType,
        actor: str,
        outcome: str,
        now_iso: str,
        provisioning_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        env_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
        workflow_state: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        event_id = str(uuid.uuid4())
        details_json = _json.dumps(details or {}, sort_keys=True)

        previous_hash = _get_previous_event_hash(db, org_id)
        event_hash = compute_event_hash(
            event_id=event_id,
            organization_id=org_id,
            event_type=event_type.value,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            previous_event_hash=previous_hash,
        )

        event_row = ProvisioningAuditEventRecord(
            event_id=event_id,
            organization_id=org_id,
            provisioning_id=provisioning_id,
            tenant_id=tenant_id,
            env_id=env_id,
            event_type=event_type.value,
            actor=actor,
            outcome=outcome,
            workflow_state=workflow_state,
            failure_reason=failure_reason,
            details_json=details_json,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
            timestamp=_utcnow(),
        )
        db.add(event_row)
        db.flush()

        emit_provisioning_event(
            event_id=event_id,
            organization_id=org_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            provisioning_id=provisioning_id,
            tenant_id=tenant_id,
            env_id=env_id,
            workflow_state=workflow_state,
            failure_reason=failure_reason,
            details=details,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
        )
