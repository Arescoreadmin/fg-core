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
from services.deployment.audit import compute_event_hash, emit_deployment_event
from services.deployment.models import (
    ComplianceClassification,
    DeploymentEnvironment,
    DeploymentEvent,
    DeploymentEventType,
    DeploymentHealthRecord,
    DeploymentRecord,
    DeploymentSpec,
    DeploymentState,
    DeploymentStrategy,
    EnvironmentLifecycleState,
    EnvironmentType,
    HealthResult,
    TransitionDryRunResult,
    validate_classification_policy,
    validate_strategy_for_env,
    validate_transition,
)

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


class ConcurrentModificationError(DeploymentStoreError):
    def __init__(self, deployment_id: str) -> None:
        super().__init__(
            "DEPLOY-007",
            f"Deployment {deployment_id} was modified concurrently — retry the operation",
        )


class RollbackSafetyViolation(DeploymentStoreError):
    def __init__(self, reason: str) -> None:
        super().__init__("DEPLOY-008", f"Rollback safety violation: {reason}")


class StrategyGovernanceViolation(DeploymentStoreError):
    def __init__(self, reason: str) -> None:
        super().__init__("DEPLOY-009", f"Strategy governance violation: {reason}")


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

    spec = DeploymentSpec(
        image_digest=getattr(row, "spec_image_digest", None),
        commit_sha=getattr(row, "spec_commit_sha", None),
        contract_hash=getattr(row, "spec_contract_hash", None),
        topology_hash=getattr(row, "spec_topology_hash", None),
        policy_bundle_version=getattr(row, "spec_policy_bundle_version", None),
        migration_fingerprint=getattr(row, "spec_migration_fingerprint", None),
    )

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
        approval_granted_at=getattr(row, "approval_granted_at", None),
        approval_reason=getattr(row, "approval_reason", None),
        approval_policy_version=getattr(row, "approval_policy_version", None),
        spec=spec,
        state_version=getattr(row, "state_version", 0) or 0,
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
        event_hash=getattr(row, "event_hash", None),
        previous_event_hash=getattr(row, "previous_event_hash", None),
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
        expires_at=getattr(row, "expires_at", None),
    )


def _get_previous_event_hash(db: Session, deployment_id: str) -> Optional[str]:
    """Return the event_hash of the most recent event for this deployment."""
    row = (
        db.query(DeploymentEventRecord)
        .filter(DeploymentEventRecord.deployment_id == deployment_id)
        .order_by(DeploymentEventRecord.timestamp.desc())
        .first()
    )
    if row is None:
        return None
    return getattr(row, "event_hash", None)


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
        spec: Optional[DeploymentSpec] = None,
        deployment_metadata: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> DeploymentRecord:
        import json as _json

        # Verify env exists and is accessible.
        env = self.get_environment(db, env_id=env_id, tenant_id=tenant_id)

        # Strategy governance: validate strategy is permitted for this env.
        try:
            validate_strategy_for_env(
                strategy, env.env_type, env.compliance_classification
            )
            validate_classification_policy(strategy, env.compliance_classification)
        except ValueError as exc:
            raise StrategyGovernanceViolation(str(exc)) from exc

        deployment_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        approval_required = env.requires_approval()
        meta_json = _json.dumps(deployment_metadata or {}, sort_keys=True)
        resolved_spec = spec or DeploymentSpec()

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
            approval_granted_at=None,
            approval_reason=None,
            approval_policy_version=None,
            spec_image_digest=resolved_spec.image_digest,
            spec_commit_sha=resolved_spec.commit_sha,
            spec_contract_hash=resolved_spec.contract_hash,
            spec_topology_hash=resolved_spec.topology_hash,
            spec_policy_bundle_version=resolved_spec.policy_bundle_version,
            spec_migration_fingerprint=resolved_spec.migration_fingerprint,
            state_version=0,
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
                "spec_commit_sha": resolved_spec.commit_sha or "",
                "spec_contract_hash": resolved_spec.contract_hash or "",
                "spec_topology_hash": resolved_spec.topology_hash or "",
                "spec_policy_bundle_version": resolved_spec.policy_bundle_version or "",
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

        # Rollback safety checks.
        if to_state == DeploymentState.ROLLED_BACK:
            self._validate_rollback_safety(db, row, tenant_id=tenant_id)

        now = _utcnow()
        now_iso = now.isoformat()

        # Capture version before update for optimistic locking.
        current_version = getattr(row, "state_version", 0) or 0
        new_version = current_version + 1

        updates: dict = {
            "state": to_state.value,
            "state_version": new_version,
        }
        if to_state in (
            DeploymentState.HEALTHY,
            DeploymentState.FAILED,
            DeploymentState.ROLLED_BACK,
        ):
            updates["completed_at"] = now

        # Optimistic locking: only update if state_version hasn't changed.
        rows_affected = (
            db.query(DeploymentRecordORM)
            .filter(
                DeploymentRecordORM.deployment_id == deployment_id,
                DeploymentRecordORM.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(deployment_id)

        db.flush()
        db.refresh(row)

        # Emit transition event.
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

        # Emit SLO metrics.
        self._emit_transition_metrics(row, from_state, to_state)

        return _deployment_orm_to_domain(row)

    def validate_transition_dry_run(
        self,
        db: Session,
        *,
        deployment_id: str,
        to_state: DeploymentState,
        tenant_id: Optional[str] = None,
    ) -> TransitionDryRunResult:
        """Validate a state transition without executing it (no side effects)."""
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
        policy_violations: list[str] = []
        block_reasons: list[str] = []
        allowed = True

        try:
            validate_transition(from_state, to_state)
        except ValueError as exc:
            allowed = False
            block_reasons.append(str(exc))

        approval_required = bool(row.approval_required)
        missing_approval = (
            to_state == DeploymentState.DEPLOYING
            and approval_required
            and not row.approval_granted_by
        )
        if missing_approval:
            block_reasons.append(
                f"Approval required for deployment {deployment_id} before transitioning to deploying"
            )

        # Check rollback safety without executing.
        if to_state == DeploymentState.ROLLED_BACK and allowed:
            try:
                self._validate_rollback_safety(db, row, tenant_id=tenant_id)
            except RollbackSafetyViolation as exc:
                block_reasons.append(str(exc))

        blocked = not allowed or missing_approval or bool(block_reasons)

        return TransitionDryRunResult(
            allowed=allowed,
            from_state=from_state,
            to_state=to_state,
            approval_required=approval_required,
            missing_approval_granted_by=missing_approval,
            policy_violations=policy_violations,
            blocked=blocked,
            block_reasons=block_reasons,
        )

    def record_approval(
        self,
        db: Session,
        *,
        deployment_id: str,
        approved: bool,
        actor: str,
        approval_reason: Optional[str] = None,
        approval_policy_version: Optional[str] = None,
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
            row.approval_granted_at = now
            row.approval_reason = approval_reason
            row.approval_policy_version = approval_policy_version
            db.flush()

            self._emit_event(
                db,
                deployment_id=deployment_id,
                env_id=row.env_id,
                tenant_id=row.tenant_id,
                event_type=DeploymentEventType.APPROVAL_GRANTED,
                actor=actor,
                timestamp=now,
                now_iso=now_iso,
                details={
                    "approval_granted_by": actor,
                    "approval_reason": approval_reason or "",
                    "approval_policy_version": approval_policy_version or "",
                },
                trace_id=trace_id,
            )
        else:
            # Denied: record reason, do NOT set approval_granted_by, then
            # terminally block by transitioning to FAILED so no subsequent
            # transition to deploying can succeed.
            row.approval_reason = approval_reason
            row.approval_policy_version = approval_policy_version
            db.flush()

            # Emit denial event before state mutation so hash chain is ordered:
            # approval_denied → state_transition(→ failed).
            self._emit_event(
                db,
                deployment_id=deployment_id,
                env_id=row.env_id,
                tenant_id=row.tenant_id,
                event_type=DeploymentEventType.APPROVAL_DENIED,
                actor=actor,
                timestamp=now,
                now_iso=now_iso,
                details={
                    "approval_granted_by": "",
                    "approval_reason": approval_reason or "",
                    "approval_policy_version": approval_policy_version or "",
                },
                trace_id=trace_id,
            )

            # Terminally block if approval is required and not already terminal.
            from_state_val = DeploymentState(row.state)
            if row.approval_required and from_state_val not in (
                DeploymentState.FAILED,
                DeploymentState.ROLLED_BACK,
            ):
                current_version = getattr(row, "state_version", 0) or 0
                rows_affected = (
                    db.query(DeploymentRecordORM)
                    .filter(
                        DeploymentRecordORM.deployment_id == deployment_id,
                        DeploymentRecordORM.state_version == current_version,
                    )
                    .update(
                        {
                            "state": DeploymentState.FAILED.value,
                            "state_version": current_version + 1,
                            "completed_at": now,
                        },
                        synchronize_session="evaluate",
                    )
                )
                if rows_affected == 0:
                    raise ConcurrentModificationError(deployment_id)
                db.flush()
                db.refresh(row)

                self._emit_event(
                    db,
                    deployment_id=deployment_id,
                    env_id=row.env_id,
                    tenant_id=row.tenant_id,
                    event_type=DeploymentEventType.STATE_TRANSITION,
                    actor=actor,
                    timestamp=now,
                    now_iso=now_iso,
                    from_state=from_state_val,
                    to_state=DeploymentState.FAILED,
                    details={"reason": "approval_denied"},
                    trace_id=trace_id,
                )

        # Emit approval metrics.
        try:
            from services.deployment.metrics import APPROVAL_DECISIONS_TOTAL

            APPROVAL_DECISIONS_TOTAL.labels(
                decision="granted" if approved else "denied"
            ).inc()
            if approved and row.initiated_at:
                from services.deployment.metrics import APPROVAL_WAIT_DURATION_SECONDS

                wait_seconds = (
                    now - row.initiated_at.replace(tzinfo=timezone.utc)
                ).total_seconds()
                APPROVAL_WAIT_DURATION_SECONDS.labels(decision="granted").observe(
                    wait_seconds
                )
        except Exception:
            pass

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
        expires_at: Optional[datetime] = None,
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
            expires_at=expires_at,
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

        # Emit health probe metrics.
        try:
            from services.deployment.metrics import HEALTH_PROBE_RESULTS_TOTAL

            for probe, result in (
                ("readiness", readiness_result.value),
                ("liveness", liveness_result.value),
                ("smoke_test", smoke_test_result.value),
                ("validation", validation_result.value),
            ):
                HEALTH_PROBE_RESULTS_TOTAL.labels(probe=probe, result=result).inc()
        except Exception:
            pass

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

        The initial lookup for deployment_id always propagates DeploymentNotFound —
        a missing root deployment is always a caller error (→ 404 at the API layer).
        Missing ancestors encountered during traversal stop the chain cleanly.

        Follows rollback_from_id links up to max_depth hops. Terminates when
        a record has no rollback_from_id, max_depth is reached, or a cycle is detected.
        """
        # First lookup must propagate — missing initial deployment is always 404.
        first = self.get_deployment(
            db, deployment_id=deployment_id, tenant_id=tenant_id
        )

        chain: list[DeploymentRecord] = [first]
        seen: set[str] = {deployment_id}
        current_id: Optional[str] = first.rollback_from_id

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
                # Missing ancestor stops traversal; initial deployment was valid.
                break
            chain.append(record)
            current_id = record.rollback_from_id

        return chain

    # --- Internal ---

    def _validate_rollback_safety(
        self,
        db: Session,
        row: DeploymentRecordORM,
        *,
        tenant_id: Optional[str],
    ) -> None:
        """Raise RollbackSafetyViolation if rolling back is unsafe."""
        rollback_from_id = row.rollback_from_id
        if rollback_from_id is None:
            return

        # Fetch the target of the rollback without applying tenant filter —
        # we need to check the raw record to enforce boundary.
        target = (
            db.query(DeploymentRecordORM)
            .filter(DeploymentRecordORM.deployment_id == rollback_from_id)
            .first()
        )
        if target is None:
            raise RollbackSafetyViolation(
                f"rollback_from_id {rollback_from_id!r} does not exist"
            )

        # Cannot rollback to a failed deployment.
        if target.state == DeploymentState.FAILED.value:
            raise RollbackSafetyViolation(
                f"Cannot rollback to deployment {rollback_from_id!r} in failed state"
            )

        # Cannot rollback across tenant boundaries.
        source_tenant = row.tenant_id
        target_tenant = target.tenant_id
        if source_tenant != target_tenant:
            raise RollbackSafetyViolation("Cannot rollback across tenant boundaries")

    def _emit_transition_metrics(
        self,
        row: DeploymentRecordORM,
        from_state: DeploymentState,
        to_state: DeploymentState,
    ) -> None:
        try:
            from services.deployment.metrics import (
                DEPLOYMENT_DURATION_SECONDS,
                DEPLOYMENT_FAILURES_TOTAL,
                DEPLOYMENT_TRANSITIONS_TOTAL,
                ROLLBACK_TOTAL,
            )

            strategy = row.strategy or "unknown"

            DEPLOYMENT_TRANSITIONS_TOTAL.labels(
                strategy=strategy,
                env_type="unknown",
                from_state=from_state.value,
                to_state=to_state.value,
            ).inc()

            if to_state == DeploymentState.FAILED:
                DEPLOYMENT_FAILURES_TOTAL.labels(
                    strategy=strategy,
                    env_type="unknown",
                    compliance_classification="unknown",
                ).inc()

            if to_state == DeploymentState.ROLLED_BACK:
                ROLLBACK_TOTAL.labels(strategy=strategy, env_type="unknown").inc()

            # Emit duration for terminal + healthy states.
            if (
                to_state
                in (
                    DeploymentState.HEALTHY,
                    DeploymentState.FAILED,
                    DeploymentState.ROLLED_BACK,
                )
                and row.initiated_at
            ):
                duration = (
                    _utcnow() - row.initiated_at.replace(tzinfo=timezone.utc)
                ).total_seconds()
                DEPLOYMENT_DURATION_SECONDS.labels(
                    strategy=strategy,
                    env_type="unknown",
                    terminal_state=to_state.value,
                ).observe(duration)
        except Exception:
            pass

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

        # Build tamper-evident hash chain.
        previous_hash = _get_previous_event_hash(db, deployment_id)
        event_hash = compute_event_hash(
            event_id=event_id,
            deployment_id=deployment_id,
            event_type=event_type.value,
            actor=actor,
            timestamp_iso=now_iso,
            from_state=from_state.value if from_state else None,
            to_state=to_state.value if to_state else None,
            previous_event_hash=previous_hash,
        )

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
            event_hash=event_hash,
            previous_event_hash=previous_hash,
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
            event_hash=event_hash,
            previous_event_hash=previous_hash,
            trace_id=trace_id,
        )
