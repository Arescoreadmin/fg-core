"""Deployment persistence layer (SQLAlchemy).

All queries are tenant-scoped: platform-level records (tenant_id=None) are
readable by any operator with sufficient scope; tenant-dedicated records are
only visible within the owning tenant's context.

No mutable module-level state. DeploymentStore is stateless and receives
a Session at call time.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models import (
    DeploymentEnvironmentRecord,
    DeploymentEventRecord,
    DeploymentHealthRecord as DeploymentHealthORM,
    DeploymentRecordORM,
)
from services.deployment.models import (
    ComplianceClassification,
    DeploymentEnvironment,
    DeploymentEvent,
    DeploymentEventType,
    DeploymentHealthRecord,
    DeploymentRecord,
    DeploymentState,
    DeploymentStrategy,
    EnvironmentLifecycleState,
    EnvironmentType,
    HealthResult,
    validate_transition,
)
from services.deployment.audit import emit_deployment_event

log = logging.getLogger("frostgate.deployment.store")

_MAX_PAGE = 200
_DEFAULT_PAGE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


class DeploymentStoreError(Exception):
    """Base error for deployment store operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class DeploymentNotFound(DeploymentStoreError):
    def __init__(self, deployment_id: str) -> None:
        super().__init__("DEPLOY-001", f"Deployment not found: {deployment_id}")


class EnvironmentNotFound(DeploymentStoreError):
    def __init__(self, env_id: str) -> None:
        super().__init__("DEPLOY-002", f"Environment not found: {env_id}")


class InvalidStateTransition(DeploymentStoreError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(
            "DEPLOY-003",
            f"Invalid state transition: {from_state!r} → {to_state!r}",
        )


class ApprovalRequired(DeploymentStoreError):
    def __init__(self, deployment_id: str) -> None:
        super().__init__(
            "DEPLOY-004",
            f"Deployment {deployment_id} requires approval before transitioning to deploying",
        )


# ---------------------------------------------------------------------------
# Internal conversion helpers
# ---------------------------------------------------------------------------


def _env_orm_to_domain(row: DeploymentEnvironmentRecord) -> DeploymentEnvironment:
    import json as _json

    policy: dict = {}
    if row.deployment_policy_json:
        try:
            policy = _json.loads(row.deployment_policy_json)
        except (ValueError, TypeError):
            policy = {}

    return DeploymentEnvironment(
        env_id=row.env_id,
        env_type=EnvironmentType(row.env_type),
        region=row.region,
        lifecycle_state=EnvironmentLifecycleState(row.lifecycle_state),
        compliance_classification=ComplianceClassification(
            row.compliance_classification
        ),
        created_by=row.created_by,
        created_at=row.created_at,
        tenant_id=row.tenant_id,
        deployment_policy=policy,
    )


def _deployment_orm_to_domain(row: DeploymentRecordORM) -> DeploymentRecord:
    import json as _json

    metadata: dict = {}
    if row.deployment_metadata_json:
        try:
            metadata = _json.loads(row.deployment_metadata_json)
        except (ValueError, TypeError):
            metadata = {}

    return DeploymentRecord(
        deployment_id=row.deployment_id,
        env_id=row.env_id,
        version_ref=row.version_ref,
        strategy=DeploymentStrategy(row.strategy),
        state=DeploymentState(row.state),
        initiated_by=row.initiated_by,
        initiated_at=row.initiated_at,
        tenant_id=row.tenant_id,
        artifact_hash=row.artifact_hash,
        completed_at=row.completed_at,
        rollback_from_id=row.rollback_from_id,
        rollback_reason=row.rollback_reason,
        approval_required=bool(row.approval_required),
        approval_granted_by=row.approval_granted_by,
        deployment_metadata=metadata,
    )


def _event_orm_to_domain(row: DeploymentEventRecord) -> DeploymentEvent:
    import json as _json

    details: dict = {}
    if row.details_json:
        try:
            details = _json.loads(row.details_json)
        except (ValueError, TypeError):
            details = {}

    return DeploymentEvent(
        event_id=row.event_id,
        deployment_id=row.deployment_id,
        env_id=row.env_id,
        event_type=DeploymentEventType(row.event_type),
        actor=row.actor,
        timestamp=row.timestamp,
        tenant_id=row.tenant_id,
        from_state=DeploymentState(row.from_state) if row.from_state else None,
        to_state=DeploymentState(row.to_state) if row.to_state else None,
        details=details,
    )


def _health_orm_to_domain(row: DeploymentHealthORM) -> DeploymentHealthRecord:
    return DeploymentHealthRecord(
        record_id=row.record_id,
        deployment_id=row.deployment_id,
        env_id=row.env_id,
        readiness_result=HealthResult(row.readiness_result),
        liveness_result=HealthResult(row.liveness_result),
        smoke_test_result=HealthResult(row.smoke_test_result),
        validation_result=HealthResult(row.validation_result),
        checked_by=row.checked_by,
        checked_at=row.checked_at,
        tenant_id=row.tenant_id,
        rollback_trigger_reason=row.rollback_trigger_reason,
    )


# ---------------------------------------------------------------------------
# Store — stateless, session-injected
# ---------------------------------------------------------------------------


class DeploymentStore:
    """Persistence operations for deployment domains.

    Receives a SQLAlchemy Session at each call. No hidden state.
    All mutations emit a DeploymentEvent and an audit log entry.
    """

    # --- Environments ---

    def create_environment(
        self,
        db: Session,
        *,
        env_type: EnvironmentType,
        region: str,
        compliance_classification: ComplianceClassification,
        created_by: str,
        tenant_id: Optional[str] = None,
        deployment_policy: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentEnvironment:
        import json as _json

        env_id = str(uuid.uuid4())
        now = _utcnow()
        policy_json = _json.dumps(deployment_policy or {}, sort_keys=True)

        row = DeploymentEnvironmentRecord(
            env_id=env_id,
            env_type=env_type.value,
            region=region,
            lifecycle_state=EnvironmentLifecycleState.ACTIVE.value,
            compliance_classification=compliance_classification.value,
            created_by=created_by,
            created_at=now,
            tenant_id=tenant_id,
            deployment_policy_json=policy_json,
        )
        db.add(row)
        db.flush()

        domain = _env_orm_to_domain(row)
        log.info(
            "deployment_env_created env_id=%s env_type=%s region=%s actor=%s",
            env_id,
            env_type.value,
            region,
            created_by,
        )
        return domain

    def get_environment(
        self,
        db: Session,
        *,
        env_id: str,
        tenant_id: Optional[str] = None,
    ) -> DeploymentEnvironment:
        q = db.query(DeploymentEnvironmentRecord).filter(
            DeploymentEnvironmentRecord.env_id == env_id
        )
        if tenant_id is not None:
            q = q.filter(
                (DeploymentEnvironmentRecord.tenant_id == tenant_id)
                | (DeploymentEnvironmentRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise EnvironmentNotFound(env_id)
        return _env_orm_to_domain(row)

    def list_environments(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        env_type: Optional[EnvironmentType] = None,
        lifecycle_state: Optional[EnvironmentLifecycleState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[DeploymentEnvironment]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(DeploymentEnvironmentRecord)
        if tenant_id is not None:
            q = q.filter(
                (DeploymentEnvironmentRecord.tenant_id == tenant_id)
                | (DeploymentEnvironmentRecord.tenant_id.is_(None))
            )
        if env_type is not None:
            q = q.filter(DeploymentEnvironmentRecord.env_type == env_type.value)
        if lifecycle_state is not None:
            q = q.filter(
                DeploymentEnvironmentRecord.lifecycle_state == lifecycle_state.value
            )
        rows = (
            q.order_by(DeploymentEnvironmentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_env_orm_to_domain(r) for r in rows]

    # --- Deployment records ---

    def create_deployment(
        self,
        db: Session,
        *,
        env_id: str,
        version_ref: str,
        strategy: DeploymentStrategy,
        initiated_by: str,
        tenant_id: Optional[str] = None,
        artifact_hash: Optional[str] = None,
        rollback_from_id: Optional[str] = None,
        rollback_reason: Optional[str] = None,
        deployment_metadata: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentRecord:
        import json as _json

        # Verify env exists and is accessible.
        env = self.get_environment(db, env_id=env_id, tenant_id=tenant_id)

        deployment_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        approval_required = env.requires_approval()
        meta_json = _json.dumps(deployment_metadata or {}, sort_keys=True)

        row = DeploymentRecordORM(
            deployment_id=deployment_id,
            env_id=env_id,
            version_ref=version_ref,
            strategy=strategy.value,
            state=DeploymentState.PENDING.value,
            initiated_by=initiated_by,
            initiated_at=now,
            tenant_id=tenant_id,
            artifact_hash=artifact_hash,
            rollback_from_id=rollback_from_id,
            rollback_reason=rollback_reason,
            approval_required=1 if approval_required else 0,
            approval_granted_by=None,
            deployment_metadata_json=meta_json,
        )
        db.add(row)
        db.flush()

        # Emit creation event (always before returning).
        self._emit_event(
            db,
            deployment_id=deployment_id,
            env_id=env_id,
            tenant_id=tenant_id,
            event_type=DeploymentEventType.CREATED,
            actor=initiated_by,
            timestamp=now,
            now_iso=now_iso,
            to_state=DeploymentState.PENDING,
            details={
                "version_ref": version_ref,
                "strategy": strategy.value,
                "artifact_hash": artifact_hash or "",
                "rollback_from_id": rollback_from_id or "",
            },
            trace_id=trace_id,
        )

        return _deployment_orm_to_domain(row)

    def get_deployment(
        self,
        db: Session,
        *,
        deployment_id: str,
        tenant_id: Optional[str] = None,
    ) -> DeploymentRecord:
        q = db.query(DeploymentRecordORM).filter(
            DeploymentRecordORM.deployment_id == deployment_id
        )
        if tenant_id is not None:
            q = q.filter(
                (DeploymentRecordORM.tenant_id == tenant_id)
                | (DeploymentRecordORM.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise DeploymentNotFound(deployment_id)
        return _deployment_orm_to_domain(row)

    def list_deployments(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        env_id: Optional[str] = None,
        state: Optional[DeploymentState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[DeploymentRecord]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(DeploymentRecordORM)
        if tenant_id is not None:
            q = q.filter(
                (DeploymentRecordORM.tenant_id == tenant_id)
                | (DeploymentRecordORM.tenant_id.is_(None))
            )
        if env_id is not None:
            q = q.filter(DeploymentRecordORM.env_id == env_id)
        if state is not None:
            q = q.filter(DeploymentRecordORM.state == state.value)
        rows = (
            q.order_by(DeploymentRecordORM.initiated_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_deployment_orm_to_domain(r) for r in rows]

    def transition_state(
        self,
        db: Session,
        *,
        deployment_id: str,
        to_state: DeploymentState,
        actor: str,
        tenant_id: Optional[str] = None,
        details: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentRecord:
        q = db.query(DeploymentRecordORM).filter(
            DeploymentRecordORM.deployment_id == deployment_id
        )
        if tenant_id is not None:
            q = q.filter(
                (DeploymentRecordORM.tenant_id == tenant_id)
                | (DeploymentRecordORM.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise DeploymentNotFound(deployment_id)

        from_state = DeploymentState(row.state)
        try:
            validate_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(from_state.value, to_state.value) from exc

        # Production/regulated envs: moving to deploying requires approval.
        if to_state == DeploymentState.DEPLOYING and row.approval_required:
            if not row.approval_granted_by:
                raise ApprovalRequired(deployment_id)

        now = _utcnow()
        now_iso = now.isoformat()
        row.state = to_state.value
        if to_state in (
            DeploymentState.HEALTHY,
            DeploymentState.FAILED,
            DeploymentState.ROLLED_BACK,
        ):
            row.completed_at = now
        db.flush()

        self._emit_event(
            db,
            deployment_id=deployment_id,
            env_id=row.env_id,
            tenant_id=row.tenant_id,
            event_type=DeploymentEventType.STATE_TRANSITION,
            actor=actor,
            timestamp=now,
            now_iso=now_iso,
            from_state=from_state,
            to_state=to_state,
            details=details,
            trace_id=trace_id,
        )

        return _deployment_orm_to_domain(row)

    def record_approval(
        self,
        db: Session,
        *,
        deployment_id: str,
        approved: bool,
        actor: str,
        tenant_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentRecord:
        q = db.query(DeploymentRecordORM).filter(
            DeploymentRecordORM.deployment_id == deployment_id
        )
        if tenant_id is not None:
            q = q.filter(
                (DeploymentRecordORM.tenant_id == tenant_id)
                | (DeploymentRecordORM.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise DeploymentNotFound(deployment_id)

        now = _utcnow()
        now_iso = now.isoformat()

        if approved:
            row.approval_granted_by = actor
        db.flush()

        event_type = (
            DeploymentEventType.APPROVAL_GRANTED
            if approved
            else DeploymentEventType.APPROVAL_DENIED
        )
        self._emit_event(
            db,
            deployment_id=deployment_id,
            env_id=row.env_id,
            tenant_id=row.tenant_id,
            event_type=event_type,
            actor=actor,
            timestamp=now,
            now_iso=now_iso,
            details={"approval_granted_by": actor if approved else ""},
            trace_id=trace_id,
        )
        return _deployment_orm_to_domain(row)

    # --- Events ---

    def list_events(
        self,
        db: Session,
        *,
        deployment_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[DeploymentEvent]:
        # Verify access first.
        self.get_deployment(db, deployment_id=deployment_id, tenant_id=tenant_id)

        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(DeploymentEventRecord)
            .filter(DeploymentEventRecord.deployment_id == deployment_id)
            .order_by(DeploymentEventRecord.timestamp.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_event_orm_to_domain(r) for r in rows]

    # --- Health records ---

    def record_health(
        self,
        db: Session,
        *,
        deployment_id: str,
        readiness_result: HealthResult,
        liveness_result: HealthResult,
        smoke_test_result: HealthResult,
        validation_result: HealthResult,
        checked_by: str,
        tenant_id: Optional[str] = None,
        rollback_trigger_reason: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentHealthRecord:
        row_d = db.query(DeploymentRecordORM).filter(
            DeploymentRecordORM.deployment_id == deployment_id
        )
        if tenant_id is not None:
            row_d = row_d.filter(
                (DeploymentRecordORM.tenant_id == tenant_id)
                | (DeploymentRecordORM.tenant_id.is_(None))
            )
        dep_row = row_d.first()
        if dep_row is None:
            raise DeploymentNotFound(deployment_id)

        record_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        health_row = DeploymentHealthORM(
            record_id=record_id,
            deployment_id=deployment_id,
            env_id=dep_row.env_id,
            readiness_result=readiness_result.value,
            liveness_result=liveness_result.value,
            smoke_test_result=smoke_test_result.value,
            validation_result=validation_result.value,
            checked_by=checked_by,
            checked_at=now,
            tenant_id=dep_row.tenant_id,
            rollback_trigger_reason=rollback_trigger_reason,
        )
        db.add(health_row)
        db.flush()

        self._emit_event(
            db,
            deployment_id=deployment_id,
            env_id=dep_row.env_id,
            tenant_id=dep_row.tenant_id,
            event_type=DeploymentEventType.HEALTH_RECORDED,
            actor=checked_by,
            timestamp=now,
            now_iso=now_iso,
            details={
                "health_readiness": readiness_result.value,
                "health_liveness": liveness_result.value,
                "health_smoke_test": smoke_test_result.value,
                "health_validation": validation_result.value,
                "rollback_trigger_reason": rollback_trigger_reason or "",
            },
            trace_id=trace_id,
        )

        return _health_orm_to_domain(health_row)

    def list_health_records(
        self,
        db: Session,
        *,
        deployment_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[DeploymentHealthRecord]:
        self.get_deployment(db, deployment_id=deployment_id, tenant_id=tenant_id)

        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(DeploymentHealthORM)
            .filter(DeploymentHealthORM.deployment_id == deployment_id)
            .order_by(DeploymentHealthORM.checked_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_health_orm_to_domain(r) for r in rows]

    # --- Rollback lineage ---

    def get_rollback_lineage(
        self,
        db: Session,
        *,
        deployment_id: str,
        tenant_id: Optional[str] = None,
        max_depth: int = 20,
    ) -> list[DeploymentRecord]:
        """Return the rollback chain starting from deployment_id.

        Follows rollback_from_id links up to max_depth hops. Terminates when
        a record has no rollback_from_id or max_depth is reached (cycle guard).
        """
        chain: list[DeploymentRecord] = []
        seen: set[str] = set()
        current_id: Optional[str] = deployment_id

        while current_id and len(chain) < max_depth:
            if current_id in seen:
                log.warning(
                    "deployment_rollback_lineage_cycle detected deployment_id=%s",
                    current_id,
                )
                break
            seen.add(current_id)
            try:
                record = self.get_deployment(
                    db, deployment_id=current_id, tenant_id=tenant_id
                )
            except DeploymentNotFound:
                break
            chain.append(record)
            current_id = record.rollback_from_id

        return chain

    # --- Internal ---

    def _emit_event(
        self,
        db: Session,
        *,
        deployment_id: str,
        env_id: str,
        tenant_id: Optional[str],
        event_type: DeploymentEventType,
        actor: str,
        timestamp: datetime,
        now_iso: str,
        from_state: Optional[DeploymentState] = None,
        to_state: Optional[DeploymentState] = None,
        details: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        import json as _json

        event_id = str(uuid.uuid4())
        details_json = _json.dumps(details or {}, sort_keys=True)

        event_row = DeploymentEventRecord(
            event_id=event_id,
            deployment_id=deployment_id,
            env_id=env_id,
            tenant_id=tenant_id,
            event_type=event_type.value,
            actor=actor,
            timestamp=timestamp,
            from_state=from_state.value if from_state else None,
            to_state=to_state.value if to_state else None,
            details_json=details_json,
        )
        db.add(event_row)
        db.flush()

        emit_deployment_event(
            event_id=event_id,
            deployment_id=deployment_id,
            env_id=env_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            tenant_id=tenant_id,
            from_state=from_state,
            to_state=to_state,
            details=details,
            trace_id=trace_id,
        )
