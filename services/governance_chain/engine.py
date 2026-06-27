"""services/governance_chain/engine.py — Canonical Governance Chain Authority Engine.

Deterministic orchestration of existing governance authorities. Does not create
competing scoring — it propagates governance events and records execution history
across authority boundaries.

All mutating operations:
  1. Validate inputs (fail-closed on the chain layer)
  2. Enforce tenant isolation
  3. Call target authority (wrapped in try/except — never blocks)
  4. Record chain execution (always — even on FAILURE or SKIPPED)
  5. Emit chain event (wrapped in try/except — never blocks)
  6. Commit execution record

The engine never exposes raw ORM rows — always returns schema objects.
Bridge calls that cannot safely complete record SKIPPED_UNAVAILABLE or NOOP_SAFE
with a human-readable reason — no fake success.

PR 17.6 — Canonical Governance Chain Authority
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from api.db_models_governance_chain import (
    FaGovernanceChainEvent,
    FaGovernanceChainExecution,
    FaGovernanceHealthSnapshot,
)
from services.governance_chain.models import (
    BRIDGE_AUTHORITIES,
    GOVERNANCE_CHAIN_VERSION,
    HEALTH_DEFAULT_NO_DATA,
    BridgeType,
    ChainEventType,
    ChainExecutionResult,
    classify_governance_health,
    compute_governance_confidence,
    compute_governance_health_score,
    compute_governance_momentum,
    compute_governance_stability,
)
from services.governance_chain.repository import GovernanceChainRepository
from services.governance_chain.schemas import (
    AuthorityAvailability,
    CGINChainAuthoritySnapshot,
    CGINChainSnapshotBundle,
    ChainBridgeNotFound,
    ChainDiagnosticsResponse,
    ChainEventListResponse,
    ChainEventResponse,
    ChainExecutionListResponse,
    ChainExecutionNotFound,
    ChainExecutionResponse,
    ChainFinding,
    ChainValidationResponse,
    EmitChainEventRequest,
    ExecuteBridgeRequest,
    GovernanceHealthNotFound,
    GovernanceHealthResponse,
    GovernanceHealthHistoryResponse,
    RecalculateHealthRequest,
)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _tenant_fingerprint(tenant_id: str) -> str:
    """One-way hash of tenant_id for CGIN anonymization."""
    return hashlib.sha256(f"cgin:v1:{tenant_id}".encode()).hexdigest()[:32]


class GovernanceChainEngine:
    """Business logic engine for Canonical Governance Chain Authority."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceChainRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _event_to_response(self, row: FaGovernanceChainEvent) -> ChainEventResponse:
        return ChainEventResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            event_type=row.event_type,
            authority=row.authority,
            object_type=row.object_type,
            object_id=row.object_id,
            correlation_id=row.correlation_id,
            actor_id=row.actor_id,
            actor_type=row.actor_type,
            reason=row.reason,
            payload_json=row.payload_json,
            created_at=row.created_at,
        )

    def _execution_to_response(
        self, row: FaGovernanceChainExecution
    ) -> ChainExecutionResponse:
        return ChainExecutionResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            chain_execution_id=row.chain_execution_id,
            source_authority=row.source_authority,
            target_authority=row.target_authority,
            bridge_type=row.bridge_type,
            trigger_reason=row.trigger_reason,
            trigger_object_id=row.trigger_object_id,
            trigger_object_type=row.trigger_object_type,
            execution_result=row.execution_result,
            success=bool(row.success),
            failure_reason=row.failure_reason,
            duration_ms=row.duration_ms,
            executed_at=row.executed_at,
        )

    def _health_to_response(
        self, row: FaGovernanceHealthSnapshot
    ) -> GovernanceHealthResponse:
        missing: list[str] = []
        if row.missing_inputs_json:
            try:
                missing = json.loads(row.missing_inputs_json)
            except Exception:
                pass
        return GovernanceHealthResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            verification_health=row.verification_health,
            freshness_health=row.freshness_health,
            effectiveness_health=row.effectiveness_health,
            remediation_health=row.remediation_health,
            forecast_health=row.forecast_health,
            governance_health_score=row.governance_health_score,
            governance_health_rating=row.governance_health_rating,
            missing_inputs=missing,
            snapshot_at=row.snapshot_at,
            calculation_version=row.calculation_version,
            governance_momentum=row.governance_momentum,
            governance_stability=row.governance_stability,
            governance_confidence=row.governance_confidence,
        )

    def _write_execution(
        self,
        *,
        bridge_type: str,
        trigger_object_id: str,
        trigger_object_type: str,
        trigger_reason: str,
        execution_result: ChainExecutionResult,
        success: bool,
        failure_reason: Optional[str],
        duration_ms: float,
        chain_execution_id: str,
    ) -> FaGovernanceChainExecution:
        source, target = BRIDGE_AUTHORITIES.get(bridge_type, ("unknown", "unknown"))
        row = FaGovernanceChainExecution(
            id=_new_id(),
            tenant_id=self._tenant_id,
            chain_execution_id=chain_execution_id,
            source_authority=source,
            target_authority=target,
            bridge_type=bridge_type,
            trigger_reason=trigger_reason,
            trigger_object_id=trigger_object_id,
            trigger_object_type=trigger_object_type,
            execution_result=execution_result.value,
            success=1 if success else 0,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            executed_at=_now(),
        )
        self._repo.create_execution(row)
        return row

    def _emit_event_internal(
        self,
        *,
        event_type: str,
        authority: str,
        object_type: str,
        object_id: str,
        reason: str,
        correlation_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_type: Optional[str] = None,
        payload_json: Optional[str] = None,
    ) -> None:
        row = FaGovernanceChainEvent(
            id=_new_id(),
            tenant_id=self._tenant_id,
            event_type=event_type,
            authority=authority,
            object_type=object_type,
            object_id=object_id,
            correlation_id=correlation_id,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=reason,
            payload_json=payload_json,
            created_at=_now(),
        )
        self._repo.create_event(row)

    # ------------------------------------------------------------------
    # Public: emit_chain_event
    # ------------------------------------------------------------------

    def emit_chain_event(
        self,
        request: EmitChainEventRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainEventResponse:
        if not request.event_type.strip():
            raise ValueError("event_type must be non-empty")
        if not request.object_id.strip():
            raise ValueError("object_id must be non-empty")

        now = _now()
        row = FaGovernanceChainEvent(
            id=_new_id(),
            tenant_id=self._tenant_id,
            event_type=request.event_type.upper(),
            authority=request.authority,
            object_type=request.object_type,
            object_id=request.object_id,
            correlation_id=request.correlation_id,
            actor_id=request.actor_id or actor_id,
            actor_type=request.actor_type or actor_type,
            reason=request.reason,
            payload_json=request.payload_json,
            created_at=now,
        )
        self._repo.create_event(row)
        self._db.commit()
        self._db.refresh(row)
        return self._event_to_response(row)

    # ------------------------------------------------------------------
    # Public: list_chain_events
    # ------------------------------------------------------------------

    def list_chain_events(
        self,
        event_type: Optional[str] = None,
        authority: Optional[str] = None,
        object_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ChainEventListResponse:
        rows, total = self._repo.list_events(
            event_type=event_type,
            authority=authority,
            object_type=object_type,
            limit=limit,
            offset=offset,
        )
        return ChainEventListResponse(
            events=[self._event_to_response(r) for r in rows],
            total=total,
        )

    def list_events_by_correlation(self, correlation_id: str) -> ChainEventListResponse:
        rows = self._repo.list_events_by_correlation(correlation_id)
        return ChainEventListResponse(
            events=[self._event_to_response(r) for r in rows],
            total=len(rows),
        )

    # ------------------------------------------------------------------
    # Public: list_executions / get_execution
    # ------------------------------------------------------------------

    def list_executions(
        self,
        bridge_type: Optional[str] = None,
        success: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ChainExecutionListResponse:
        rows, total = self._repo.list_executions(
            bridge_type=bridge_type,
            success=success,
            limit=limit,
            offset=offset,
        )
        return ChainExecutionListResponse(
            executions=[self._execution_to_response(r) for r in rows],
            total=total,
        )

    def get_execution(self, execution_id: str) -> ChainExecutionResponse:
        row = self._repo.get_execution(execution_id)
        if row is None:
            raise ChainExecutionNotFound(execution_id)
        return self._execution_to_response(row)

    # ------------------------------------------------------------------
    # Bridge: register_assessment_evidence (ASSESSMENT_TO_EVIDENCE)
    # ------------------------------------------------------------------

    def register_assessment_evidence(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 1: Register assessment evidence via EvidenceAuthorityEngine.

        Idempotent: if trigger_object_id already resolves to an evidence record,
        returns NOOP_SAFE. Otherwise creates the evidence and returns SUCCESS.
        """
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        try:
            from services.evidence_authority.engine import EvidenceAuthorityEngine
            from services.evidence_authority.models import (
                EvidenceCollectionMethod,
                EvidenceSourceType,
            )
            from services.evidence_authority.schemas import CreateEvidenceRequest

            ea_engine = EvidenceAuthorityEngine(self._db, self._tenant_id)

            # Idempotency: two paths.
            # (a) trigger_object_id is the primary key of an existing evidence row
            #     (pre-created externally and referenced by real ID).
            # (b) trigger_object_id was used as source_ref on a prior bridge-created
            #     evidence row. create_evidence() generates its own UUID so the ID
            #     never equals the trigger — source_ref is the dedup key for retries.
            from api.db_models_evidence_authority import FaEvidence

            trigger_id = request.trigger_object_id
            existing_ev = (
                self._db.query(FaEvidence)
                .filter(
                    FaEvidence.tenant_id == self._tenant_id,
                    (FaEvidence.id == trigger_id)
                    | (FaEvidence.source_ref == trigger_id),
                )
                .first()
            )
            if existing_ev is not None:
                result = ChainExecutionResult.NOOP_SAFE
                success = True
                failure_reason = None
            else:
                source_type_str = request.evidence_source_type or "ATTESTATION"
                collection_method_str = (
                    request.evidence_collection_method or "ATTESTATION_SUBMISSION"
                )
                try:
                    source_type = EvidenceSourceType(source_type_str)
                except ValueError:
                    source_type = EvidenceSourceType.ATTESTATION
                try:
                    collection_method = EvidenceCollectionMethod(collection_method_str)
                except ValueError:
                    collection_method = EvidenceCollectionMethod.ATTESTATION_SUBMISSION

                title = (
                    request.evidence_title
                    or f"Assessment Evidence {trigger_id[:8]}"
                )
                create_req = CreateEvidenceRequest(
                    title=title,
                    source_type=source_type,
                    collection_method=collection_method,
                    collected_at=_now(),
                    engagement_id=request.evidence_engagement_id,
                    description=request.trigger_reason,
                    source_ref=trigger_id,
                )
                ea_engine.create_evidence(
                    create_req, actor_id=actor_id, actor_type=actor_type
                )
                success = True
                result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        if success and result != ChainExecutionResult.NOOP_SAFE:
            try:
                self._emit_event_internal(
                    event_type=ChainEventType.EVIDENCE_REGISTERED.value,
                    authority="evidence_authority",
                    object_type=request.trigger_object_type,
                    object_id=request.trigger_object_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
            except Exception:
                pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: ensure_verification_requested (EVIDENCE_TO_VERIFICATION)
    # ------------------------------------------------------------------

    def ensure_verification_requested(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 2: Create a verification request for the given evidence.

        Guards:
        - Evidence must exist in evidence_authority (SKIPPED_UNAVAILABLE if not)
        - Active verification request already exists → NOOP_SAFE (duplicate prevention)
        """
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        evidence_id = request.trigger_object_id

        try:
            from api.db_models_verification_authority import FaVerificationRequest
            from services.evidence_authority.engine import EvidenceAuthorityEngine
            from services.verification_authority.engine import (
                VerificationAuthorityEngine,
            )
            from services.verification_authority.schemas import (
                CreateVerificationRequestRequest,
            )

            # First: verify evidence exists
            try:
                ea_engine = EvidenceAuthorityEngine(self._db, self._tenant_id)
                ea_engine.get_evidence(evidence_id)
            except Exception:
                duration_ms = round((time.monotonic() - start) * 1000, 2)
                exec_row = self._write_execution(
                    bridge_type=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                    trigger_object_id=request.trigger_object_id,
                    trigger_object_type=request.trigger_object_type,
                    trigger_reason=request.trigger_reason,
                    execution_result=ChainExecutionResult.SKIPPED_UNAVAILABLE,
                    success=False,
                    failure_reason=f"Evidence {evidence_id!r} not found in evidence_authority",
                    duration_ms=duration_ms,
                    chain_execution_id=chain_execution_id,
                )
                self._db.commit()
                return self._execution_to_response(exec_row)

            # Second: check for existing active verification request
            _TERMINAL_STATES = ("APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "COMPLETED")
            existing = (
                self._db.query(FaVerificationRequest)
                .filter(
                    FaVerificationRequest.tenant_id == self._tenant_id,
                    FaVerificationRequest.evidence_id == evidence_id,
                    ~FaVerificationRequest.workflow_state.in_(_TERMINAL_STATES),
                )
                .first()
            )
            if existing is not None:
                result = ChainExecutionResult.NOOP_SAFE
                success = True
                failure_reason = "verification_already_exists"
                duration_ms = round((time.monotonic() - start) * 1000, 2)
                exec_row = self._write_execution(
                    bridge_type=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                    trigger_object_id=request.trigger_object_id,
                    trigger_object_type=request.trigger_object_type,
                    trigger_reason=request.trigger_reason,
                    execution_result=result,
                    success=success,
                    failure_reason=failure_reason,
                    duration_ms=duration_ms,
                    chain_execution_id=chain_execution_id,
                )
                self._db.commit()
                return self._execution_to_response(exec_row)

            # No active request — create one
            va_engine = VerificationAuthorityEngine(self._db, self._tenant_id)
            va_engine.create_request(
                CreateVerificationRequestRequest(
                    evidence_id=evidence_id,
                    priority=50,
                    notes=request.trigger_reason,
                ),
                actor_id=actor_id or "governance_chain",
                actor_type=actor_type or "service",
            )
            success = True
            result = ChainExecutionResult.SUCCESS

        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.EVIDENCE_TO_VERIFICATION.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success and result == ChainExecutionResult.SUCCESS:
                self._emit_event_internal(
                    event_type=ChainEventType.VERIFICATION_CREATED.value,
                    authority="verification_authority",
                    object_type="verification_request",
                    object_id=evidence_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: propagate_verification_to_freshness (VERIFICATION_TO_FRESHNESS)
    # ------------------------------------------------------------------

    def propagate_verification_to_freshness(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 3: Propagate a completed verification into the freshness authority."""
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        evidence_id = request.trigger_object_id
        verified_at = request.verified_at or _now()

        try:
            from services.evidence_freshness_authority.engine import (
                EvidenceFreshnessEngine,
            )

            freshness_engine = EvidenceFreshnessEngine(self._db, self._tenant_id)
            freshness_engine.on_verification_approved(
                evidence_id=evidence_id,
                verified_at=verified_at,
                actor_id=actor_id or "governance_chain",
                actor_type=actor_type or "service",
            )
            success = True
            result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.VERIFICATION_TO_FRESHNESS.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.FRESHNESS_UPDATED.value,
                    authority="evidence_freshness_authority",
                    object_type="freshness_record",
                    object_id=evidence_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: queue_control_effectiveness_recalculation (FRESHNESS_TO_EFFECTIVENESS)
    # ------------------------------------------------------------------

    def queue_control_effectiveness_recalculation(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 4: Trigger effectiveness recalculation for a control."""
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        control_id = request.control_id
        if not control_id:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            exec_row = self._write_execution(
                bridge_type=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
                trigger_object_id=request.trigger_object_id,
                trigger_object_type=request.trigger_object_type,
                trigger_reason=request.trigger_reason,
                execution_result=ChainExecutionResult.SKIPPED_UNAVAILABLE,
                success=False,
                failure_reason="control_id is required for effectiveness recalculation",
                duration_ms=duration_ms,
                chain_execution_id=chain_execution_id,
            )
            self._db.commit()
            return self._execution_to_response(exec_row)

        try:
            from services.control_effectiveness.engine import ControlEffectivenessEngine

            ce_engine = ControlEffectivenessEngine(self._db, self._tenant_id)
            ce_engine.recalculate(control_id)
            success = True
            result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.EFFECTIVENESS_RECALCULATED.value,
                    authority="control_effectiveness",
                    object_type="control",
                    object_id=control_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: regenerate_explainability (EFFECTIVENESS_TO_EXPLAINABILITY)
    # ------------------------------------------------------------------

    def regenerate_explainability(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 5: Regenerate explainability for a control after effectiveness change."""
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        control_id = request.control_id
        if not control_id:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            exec_row = self._write_execution(
                bridge_type=BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value,
                trigger_object_id=request.trigger_object_id,
                trigger_object_type=request.trigger_object_type,
                trigger_reason=request.trigger_reason,
                execution_result=ChainExecutionResult.SKIPPED_UNAVAILABLE,
                success=False,
                failure_reason="control_id is required for explainability regeneration",
                duration_ms=duration_ms,
                chain_execution_id=chain_execution_id,
            )
            self._db.commit()
            return self._execution_to_response(exec_row)

        try:
            from services.control_effectiveness_explainability.engine import (
                ExplainabilityEngine,
            )

            cex_engine = ExplainabilityEngine(self._db, self._tenant_id)
            explanation = cex_engine.explain(control_id)
            if explanation is None:
                result = ChainExecutionResult.SKIPPED_UNAVAILABLE
                failure_reason = f"No effectiveness data found for control {control_id}"
                success = False
            else:
                success = True
                result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.EXPLANATION_REGENERATED.value,
                    authority="control_effectiveness_explainability",
                    object_type="control",
                    object_id=control_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: create_remediation_from_action (ACTION_TO_REMEDIATION)
    # ------------------------------------------------------------------

    def create_remediation_from_action(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 6: Create a remediation task from a governance action.

        Requires finding_id and assessment_id in request. Without them returns
        SKIPPED_UNAVAILABLE. Idempotent: if a remediation task already exists for
        the same finding+assessment, returns NOOP_SAFE.
        """
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()

        finding_id = request.finding_id
        assessment_id = request.assessment_id

        if not finding_id or not assessment_id:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            exec_row = self._write_execution(
                bridge_type=BridgeType.ACTION_TO_REMEDIATION.value,
                trigger_object_id=request.trigger_object_id,
                trigger_object_type=request.trigger_object_type,
                trigger_reason=request.trigger_reason,
                execution_result=ChainExecutionResult.SKIPPED_UNAVAILABLE,
                success=False,
                failure_reason=(
                    "finding_id and assessment_id required for remediation task creation"
                ),
                duration_ms=duration_ms,
                chain_execution_id=chain_execution_id,
            )
            self._db.commit()
            return self._execution_to_response(exec_row)

        # Check idempotency: if a remediation task already exists for this action
        try:
            from api.db_models_remediation import RemediationTask

            existing = (
                self._db.query(RemediationTask)
                .filter(
                    RemediationTask.tenant_id == self._tenant_id,
                    RemediationTask.finding_id == finding_id,
                    RemediationTask.assessment_id == assessment_id,
                )
                .first()
            )
            if existing is not None:
                duration_ms = round((time.monotonic() - start) * 1000, 2)
                exec_row = self._write_execution(
                    bridge_type=BridgeType.ACTION_TO_REMEDIATION.value,
                    trigger_object_id=request.trigger_object_id,
                    trigger_object_type=request.trigger_object_type,
                    trigger_reason=request.trigger_reason,
                    execution_result=ChainExecutionResult.NOOP_SAFE,
                    success=True,
                    failure_reason="remediation_already_exists",
                    duration_ms=duration_ms,
                    chain_execution_id=chain_execution_id,
                )
                self._db.commit()
                return self._execution_to_response(exec_row)
        except Exception:
            pass

        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        try:
            from services.remediation.engine import RemediationEngine
            from services.remediation.schemas import CreateTaskRequest, RemediationPriority

            title = (
                request.remediation_title
                or f"Governance Action {request.trigger_object_id[:8]}"
            )
            rem_engine = RemediationEngine(self._db, tenant_id=self._tenant_id)
            rem_engine.create_task(
                request=CreateTaskRequest(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    title=title,
                    description=request.trigger_reason,
                    priority=RemediationPriority.MEDIUM,
                ),
                actor=actor_id or "governance_chain",
            )
            success = True
            result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.ACTION_TO_REMEDIATION.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.REMEDIATION_CREATED.value,
                    authority="remediation",
                    object_type=request.trigger_object_type,
                    object_id=request.trigger_object_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: check_reporting_readiness (ALL_TO_REPORTING)
    # ------------------------------------------------------------------

    def check_reporting_readiness(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 8: Check that all authorities have data for reporting."""
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()

        authority_counts: dict[str, int] = {}
        missing: list[str] = []

        _AUTHORITY_MODELS = {
            "evidence_authority": (
                "api.db_models_evidence_authority",
                "FaEvidence",
                "tenant_id",
            ),
            "verification_authority": (
                "api.db_models_verification_authority",
                "FaVerificationRequest",
                "tenant_id",
            ),
            "evidence_freshness_authority": (
                "api.db_models_evidence_freshness_authority",
                "FaEvidenceFreshnessRecord",
                "tenant_id",
            ),
            "control_effectiveness": (
                "api.db_models_control_effectiveness",
                "FaControlEffectiveness",
                "tenant_id",
            ),
            "remediation_effectiveness": (
                "api.db_models_remediation_effectiveness",
                "FaRemediationOutcome",
                "tenant_id",
            ),
        }

        for auth_name, (module_name, class_name, tid_field) in _AUTHORITY_MODELS.items():
            try:
                import importlib

                mod = importlib.import_module(module_name)
                cls = getattr(mod, class_name)
                count = (
                    self._db.query(cls)
                    .filter(getattr(cls, tid_field) == self._tenant_id)
                    .count()
                )
                authority_counts[auth_name] = count
                if count == 0:
                    missing.append(auth_name)
            except Exception:
                authority_counts[auth_name] = 0
                missing.append(auth_name)

        success = len(missing) == 0
        result = (
            ChainExecutionResult.SUCCESS
            if success
            else ChainExecutionResult.SKIPPED_UNAVAILABLE
        )
        failure_reason: Optional[str] = (
            f"missing data in: {', '.join(missing)}" if missing else None
        )

        duration_ms = round((time.monotonic() - start) * 1000, 2)
        exec_row = self._write_execution(
            bridge_type=BridgeType.ALL_TO_REPORTING.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.REPORT_GENERATED.value,
                    authority="governance_chain",
                    object_type="reporting_readiness",
                    object_id=request.trigger_object_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Bridge: record_remediation_outcome (REMEDIATION_TO_OUTCOME)
    # ------------------------------------------------------------------

    def record_remediation_outcome(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        """Bridge 7: Record remediation outcome via RemediationEffectivenessEngine."""
        chain_execution_id = _new_id()
        correlation_id = request.correlation_id or _new_id()
        start = time.monotonic()
        success = False
        failure_reason: Optional[str] = None
        result = ChainExecutionResult.FAILURE

        control_id = request.control_id
        before = request.effectiveness_before
        after = request.effectiveness_after

        if not control_id or before is None or after is None:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            exec_row = self._write_execution(
                bridge_type=BridgeType.REMEDIATION_TO_OUTCOME.value,
                trigger_object_id=request.trigger_object_id,
                trigger_object_type=request.trigger_object_type,
                trigger_reason=request.trigger_reason,
                execution_result=ChainExecutionResult.SKIPPED_UNAVAILABLE,
                success=False,
                failure_reason=(
                    "control_id, effectiveness_before, and effectiveness_after "
                    "are required for outcome recording"
                ),
                duration_ms=duration_ms,
                chain_execution_id=chain_execution_id,
            )
            self._db.commit()
            return self._execution_to_response(exec_row)

        try:
            from services.remediation_effectiveness.engine import (
                RemediationEffectivenessEngine,
            )
            from services.remediation_effectiveness.schemas import RecordOutcomeRequest

            re_engine = RemediationEffectivenessEngine(self._db, self._tenant_id)
            re_engine.record_outcome(
                RecordOutcomeRequest(
                    remediation_task_id=request.trigger_object_id,
                    control_id=control_id,
                    before_score=before,
                    after_score=after,
                    before_effectiveness_level=(
                        request.before_effectiveness_level or "ADEQUATE"
                    ),
                    after_effectiveness_level=(
                        request.after_effectiveness_level or "ADEQUATE"
                    ),
                    remediation_category=request.remediation_category or "GENERAL",
                    verification_before=request.verification_before,
                    verification_after=request.verification_after,
                    freshness_before=request.freshness_before,
                    freshness_after=request.freshness_after,
                    forecast_before=request.forecast_before,
                    forecast_after=request.forecast_after,
                    governance_health_before=request.governance_health_before,
                    governance_health_after=request.governance_health_after,
                )
            )
            success = True
            result = ChainExecutionResult.SUCCESS
        except Exception as exc:
            failure_reason = str(exc)[:500]
            success = False
            result = ChainExecutionResult.FAILURE

        duration_ms = round((time.monotonic() - start) * 1000, 2)

        exec_row = self._write_execution(
            bridge_type=BridgeType.REMEDIATION_TO_OUTCOME.value,
            trigger_object_id=request.trigger_object_id,
            trigger_object_type=request.trigger_object_type,
            trigger_reason=request.trigger_reason,
            execution_result=result,
            success=success,
            failure_reason=failure_reason,
            duration_ms=duration_ms,
            chain_execution_id=chain_execution_id,
        )

        try:
            if success:
                self._emit_event_internal(
                    event_type=ChainEventType.OUTCOME_RECORDED.value,
                    authority="remediation_effectiveness",
                    object_type="remediation_task",
                    object_id=request.trigger_object_id,
                    reason=request.trigger_reason,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    actor_type=actor_type,
                )
        except Exception:
            pass

        self._db.commit()
        return self._execution_to_response(exec_row)

    # ------------------------------------------------------------------
    # Public: execute_bridge (dispatcher)
    # ------------------------------------------------------------------

    def execute_bridge(
        self,
        request: ExecuteBridgeRequest,
        actor_id: str,
        actor_type: str,
    ) -> ChainExecutionResponse:
        bridge = request.bridge.upper()
        dispatch = {
            BridgeType.ASSESSMENT_TO_EVIDENCE.value: self.register_assessment_evidence,
            BridgeType.EVIDENCE_TO_VERIFICATION.value: self.ensure_verification_requested,
            BridgeType.VERIFICATION_TO_FRESHNESS.value: self.propagate_verification_to_freshness,
            BridgeType.FRESHNESS_TO_EFFECTIVENESS.value: self.queue_control_effectiveness_recalculation,
            BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value: self.regenerate_explainability,
            BridgeType.ACTION_TO_REMEDIATION.value: self.create_remediation_from_action,
            BridgeType.REMEDIATION_TO_OUTCOME.value: self.record_remediation_outcome,
            BridgeType.ALL_TO_REPORTING.value: self.check_reporting_readiness,
        }
        fn = dispatch.get(bridge)
        if fn is None:
            raise ChainBridgeNotFound(f"Unknown bridge: {request.bridge!r}")
        return fn(request, actor_id, actor_type)

    # ------------------------------------------------------------------
    # Public: generate_governance_health_snapshot
    # ------------------------------------------------------------------

    def generate_governance_health_snapshot(
        self,
        request: Optional[RecalculateHealthRequest] = None,
    ) -> GovernanceHealthResponse:
        """Compute governance health from available authority data and persist a snapshot."""
        missing_inputs: list[str] = []

        verification_health = self._compute_verification_health(missing_inputs)
        freshness_health = self._compute_freshness_health(missing_inputs)
        effectiveness_health = self._compute_effectiveness_health(missing_inputs)
        remediation_health = self._compute_remediation_health(missing_inputs)
        forecast_health = self._compute_forecast_health(missing_inputs)

        score = compute_governance_health_score(
            verification_health=verification_health,
            freshness_health=freshness_health,
            effectiveness_health=effectiveness_health,
            remediation_health=remediation_health,
            forecast_health=forecast_health,
        )
        rating = classify_governance_health(score)

        # v2: momentum, stability, confidence
        recent_scores = self._repo.list_recent_health_scores(n=10)
        previous_score = recent_scores[0] if recent_scores else None
        momentum = compute_governance_momentum(score, previous_score)
        stability = compute_governance_stability(recent_scores[:5])
        total_exec, _success_count, failed_count, skipped_count = (
            self._repo.count_executions_success_failure()
        )
        confidence = compute_governance_confidence(
            missing_input_count=len(missing_inputs),
            total_executions=total_exec,
            failed_executions=failed_count,
            skipped_executions=skipped_count,
        )

        row = FaGovernanceHealthSnapshot(
            id=_new_id(),
            tenant_id=self._tenant_id,
            verification_health=verification_health,
            freshness_health=freshness_health,
            effectiveness_health=effectiveness_health,
            remediation_health=remediation_health,
            forecast_health=forecast_health,
            governance_health_score=score,
            governance_health_rating=rating.value,
            missing_inputs_json=json.dumps(missing_inputs) if missing_inputs else None,
            snapshot_at=_now(),
            calculation_version=GOVERNANCE_CHAIN_VERSION,
            governance_momentum=momentum,
            governance_stability=stability,
            governance_confidence=confidence,
        )
        self._repo.create_health_snapshot(row)
        self._db.commit()
        self._db.refresh(row)
        return self._health_to_response(row)

    def _compute_verification_health(self, missing: list[str]) -> float:
        try:
            from api.db_models_verification_authority import FaVerificationRequest

            total = (
                self._db.query(FaVerificationRequest)
                .filter(FaVerificationRequest.tenant_id == self._tenant_id)
                .count()
            )
            if total == 0:
                return HEALTH_DEFAULT_NO_DATA
            verified = (
                self._db.query(FaVerificationRequest)
                .filter(
                    FaVerificationRequest.tenant_id == self._tenant_id,
                    FaVerificationRequest.workflow_state == "APPROVED",
                )
                .count()
            )
            return round((verified / total) * 100.0, 2)
        except Exception:
            missing.append("verification_authority")
            return HEALTH_DEFAULT_NO_DATA

    def _compute_freshness_health(self, missing: list[str]) -> float:
        try:
            from api.db_models_evidence_freshness_authority import (
                FaEvidenceFreshnessRecord,
            )

            total = (
                self._db.query(FaEvidenceFreshnessRecord)
                .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
                .count()
            )
            if total == 0:
                return HEALTH_DEFAULT_NO_DATA
            current = (
                self._db.query(FaEvidenceFreshnessRecord)
                .filter(
                    FaEvidenceFreshnessRecord.tenant_id == self._tenant_id,
                    FaEvidenceFreshnessRecord.freshness_state == "CURRENT",
                )
                .count()
            )
            return round((current / total) * 100.0, 2)
        except Exception:
            missing.append("evidence_freshness_authority")
            return HEALTH_DEFAULT_NO_DATA

    def _compute_effectiveness_health(self, missing: list[str]) -> float:
        try:
            from api.db_models_control_effectiveness import FaControlEffectiveness

            result = (
                self._db.query(sqlfunc.avg(FaControlEffectiveness.effectiveness_score))
                .filter(FaControlEffectiveness.tenant_id == self._tenant_id)
                .scalar()
            )
            if result is None:
                return HEALTH_DEFAULT_NO_DATA
            return round(float(result), 2)
        except Exception:
            missing.append("control_effectiveness")
            return HEALTH_DEFAULT_NO_DATA

    def _compute_remediation_health(self, missing: list[str]) -> float:
        try:
            from api.db_models_remediation_effectiveness import FaRemediationOutcome

            result = (
                self._db.query(
                    sqlfunc.avg(FaRemediationOutcome.remediation_effectiveness_score)
                )
                .filter(FaRemediationOutcome.tenant_id == self._tenant_id)
                .scalar()
            )
            if result is None:
                return HEALTH_DEFAULT_NO_DATA
            return round(float(result), 2)
        except Exception:
            missing.append("remediation_effectiveness")
            return HEALTH_DEFAULT_NO_DATA

    def _compute_forecast_health(self, missing: list[str]) -> float:
        # No dedicated forecasting authority yet — derive from effectiveness as proxy
        try:
            from api.db_models_control_effectiveness import FaControlEffectiveness

            result = (
                self._db.query(sqlfunc.avg(FaControlEffectiveness.forecast_score))
                .filter(FaControlEffectiveness.tenant_id == self._tenant_id)
                .scalar()
            )
            if result is None:
                missing.append("forecast_authority")
                return HEALTH_DEFAULT_NO_DATA
            return round(float(result), 2)
        except Exception:
            missing.append("forecast_authority")
            return HEALTH_DEFAULT_NO_DATA

    # ------------------------------------------------------------------
    # Public: get_latest_health / list_health_history
    # ------------------------------------------------------------------

    def get_latest_health(self) -> GovernanceHealthResponse:
        row = self._repo.get_latest_health_snapshot()
        if row is None:
            raise GovernanceHealthNotFound("No health snapshots found for this tenant")
        return self._health_to_response(row)

    def list_health_history(
        self, limit: int = 50, offset: int = 0
    ) -> GovernanceHealthHistoryResponse:
        rows, total = self._repo.list_health_snapshots(limit=limit, offset=offset)
        return GovernanceHealthHistoryResponse(
            snapshots=[self._health_to_response(r) for r in rows],
            total=total,
        )

    # ------------------------------------------------------------------
    # Public: get_diagnostics
    # ------------------------------------------------------------------

    def get_diagnostics(self) -> ChainDiagnosticsResponse:
        event_dist = self._repo.count_events_by_type()
        total_events = sum(event_dist.values())

        bridge_dist = self._repo.count_executions_by_bridge()
        total_exec, success_count, failed_count, skipped_count = (
            self._repo.count_executions_success_failure()
        )

        success_rate = round(success_count / total_exec, 4) if total_exec > 0 else 1.0

        latest_health: Optional[GovernanceHealthResponse] = None
        missing: list[str] = []
        try:
            latest_health = self.get_latest_health()
            missing = latest_health.missing_inputs
        except GovernanceHealthNotFound:
            pass

        availability = self._probe_authority_availability()

        return ChainDiagnosticsResponse(
            tenant_id=self._tenant_id,
            total_chain_events=total_events,
            total_bridge_executions=total_exec,
            successful_executions=success_count,
            failed_executions=failed_count,
            skipped_executions=skipped_count,
            execution_success_rate=success_rate,
            event_type_distribution=event_dist,
            bridge_execution_distribution=bridge_dist,
            authority_availability=availability,
            latest_governance_health=latest_health,
            missing_inputs=missing,
            generated_at=_now(),
        )

    def _probe_authority_availability(self) -> list[AuthorityAvailability]:
        authorities = [
            "evidence_authority",
            "verification_authority",
            "evidence_freshness_authority",
            "control_effectiveness",
            "control_effectiveness_explainability",
            "remediation",
            "remediation_effectiveness",
        ]
        probes: list[AuthorityAvailability] = []
        for auth in authorities:
            available, reason = self._is_authority_available(auth)
            probes.append(
                AuthorityAvailability(
                    authority=auth, available=available, reason=reason
                )
            )
        return probes

    def _is_authority_available(self, authority: str) -> tuple[bool, Optional[str]]:
        module_map = {
            "evidence_authority": "services.evidence_authority.engine",
            "verification_authority": "services.verification_authority.engine",
            "evidence_freshness_authority": "services.evidence_freshness_authority.engine",
            "control_effectiveness": "services.control_effectiveness.engine",
            "control_effectiveness_explainability": "services.control_effectiveness_explainability.engine",
            "remediation": "services.remediation.engine",
            "remediation_effectiveness": "services.remediation_effectiveness.engine",
        }
        module = module_map.get(authority)
        if not module:
            return False, "unknown authority"
        try:
            import importlib

            importlib.import_module(module)
            return True, None
        except Exception as exc:
            return False, str(exc)[:200]

    # ------------------------------------------------------------------
    # Public: validate_chain
    # ------------------------------------------------------------------

    def validate_chain(self) -> ChainValidationResponse:
        """Validate governance chain integrity and return a list of findings."""
        findings: list[ChainFinding] = []

        # Check 1: Failed bridge executions
        _, _, failed_count, _ = self._repo.count_executions_success_failure()
        if failed_count > 0:
            findings.append(
                ChainFinding(
                    finding_type="FAILED_BRIDGE_EXECUTIONS",
                    severity="ERROR",
                    description=f"{failed_count} bridge execution(s) recorded as FAILURE",
                    context={"failed_count": failed_count},
                )
            )

        # Check 2: No governance health snapshot
        latest_health = self._repo.get_latest_health_snapshot()
        if latest_health is None:
            findings.append(
                ChainFinding(
                    finding_type="NO_HEALTH_SNAPSHOT",
                    severity="WARNING",
                    description="No governance health snapshot exists for this tenant",
                )
            )

        evidence_count = 0

        # Check 3: Missing verification coverage
        try:
            from api.db_models_evidence_authority import FaEvidence
            from api.db_models_verification_authority import FaVerificationRequest

            evidence_count = (
                self._db.query(FaEvidence)
                .filter(FaEvidence.tenant_id == self._tenant_id)
                .count()
            )
            if evidence_count > 0:
                verified_evidence = (
                    self._db.query(FaVerificationRequest)
                    .filter(
                        FaVerificationRequest.tenant_id == self._tenant_id,
                        FaVerificationRequest.workflow_state == "APPROVED",
                    )
                    .count()
                )
                if verified_evidence == 0:
                    findings.append(
                        ChainFinding(
                            finding_type="NO_VERIFIED_EVIDENCE",
                            severity="WARNING",
                            description=(
                                f"{evidence_count} evidence record(s) exist but "
                                "none have been verified"
                            ),
                            context={"evidence_count": evidence_count},
                        )
                    )
        except Exception:
            pass

        # Check 4: Missing freshness after verified evidence
        try:
            from api.db_models_evidence_freshness_authority import (
                FaEvidenceFreshnessRecord,
            )

            freshness_count = (
                self._db.query(FaEvidenceFreshnessRecord)
                .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
                .count()
            )
            if freshness_count == 0 and evidence_count > 0:
                findings.append(
                    ChainFinding(
                        finding_type="NO_FRESHNESS_RECORDS",
                        severity="WARNING",
                        description=(
                            "Evidence exists but no freshness records have been created"
                        ),
                    )
                )
        except Exception:
            pass

        # Check 5: Count executions for orphan check
        event_dist = self._repo.count_events_by_type()
        total_events = sum(event_dist.values())
        total_exec_count = 0
        try:
            total_exec_count = (
                self._db.query(FaGovernanceChainExecution)
                .filter(FaGovernanceChainExecution.tenant_id == self._tenant_id)
                .count()
            )
        except Exception:
            pass

        # Check 6: No data at all
        if total_events == 0 and total_exec_count == 0 and latest_health is None:
            findings.append(
                ChainFinding(
                    finding_type="NO_CHAIN_DATA",
                    severity="WARNING",
                    description=(
                        "No governance chain data found — chain has not been initialized"
                    ),
                )
            )

        # Determine status
        has_errors = any(f.severity == "ERROR" for f in findings)
        has_warnings = any(f.severity == "WARNING" for f in findings)

        if has_errors:
            status = "FAIL"
        elif has_warnings:
            status = "WARNING"
        else:
            status = "PASS"

        return ChainValidationResponse(
            status=status,
            findings=findings,
            checked_at=_now(),
            tenant_id=self._tenant_id,
        )

    # ------------------------------------------------------------------
    # Public: get_cgin_snapshot
    # ------------------------------------------------------------------

    def get_cgin_snapshot(self) -> CGINChainSnapshotBundle:
        fingerprint = _tenant_fingerprint(self._tenant_id)
        _SKIPPED = (
            ChainExecutionResult.SKIPPED_UNAVAILABLE.value,
            ChainExecutionResult.NOOP_SAFE.value,
        )

        # Build per-authority aggregates from execution records.
        # Duration is accumulated here (keyed by target_authority) rather than
        # using average_duration_by_bridge() which is keyed by bridge_type.
        authority_map: dict[str, dict] = {}
        rows, _ = self._repo.list_executions(limit=10000)
        for row in rows:
            auth = row.target_authority
            if auth not in authority_map:
                authority_map[auth] = {
                    "execution_count": 0,
                    "success_count": 0,
                    "failure_count": 0,
                    "skipped_count": 0,
                    "total_duration_ms": 0.0,
                    "duration_count": 0,
                }
            authority_map[auth]["execution_count"] += 1
            if row.duration_ms is not None:
                authority_map[auth]["total_duration_ms"] += row.duration_ms
                authority_map[auth]["duration_count"] += 1
            if row.success:
                authority_map[auth]["success_count"] += 1
            elif row.execution_result in _SKIPPED:
                authority_map[auth]["skipped_count"] += 1
            else:
                authority_map[auth]["failure_count"] += 1

        snapshots: list[CGINChainAuthoritySnapshot] = []
        for auth, counts in authority_map.items():
            exec_count = counts["execution_count"]
            success = counts["success_count"]
            success_rate = round(success / exec_count, 4) if exec_count > 0 else 0.0
            dc = counts["duration_count"]
            avg_ms = round(counts["total_duration_ms"] / dc, 2) if dc > 0 else None
            snapshots.append(
                CGINChainAuthoritySnapshot(
                    authority=auth,
                    execution_count=exec_count,
                    success_count=success,
                    failure_count=counts["failure_count"],
                    skipped_count=counts["skipped_count"],
                    success_rate=success_rate,
                    average_duration_ms=avg_ms,
                )
            )

        # Governance health (latest)
        health_score: Optional[float] = None
        health_rating: Optional[str] = None
        try:
            h = self.get_latest_health()
            health_score = h.governance_health_score
            health_rating = h.governance_health_rating
        except GovernanceHealthNotFound:
            pass

        total_events, _ = self._repo.list_events(limit=1)
        event_count = (
            self._db.query(FaGovernanceChainEvent)
            .filter(FaGovernanceChainEvent.tenant_id == self._tenant_id)
            .count()
        )

        return CGINChainSnapshotBundle(
            bundle_id=_new_id(),
            bundle_version=GOVERNANCE_CHAIN_VERSION,
            tenant_fingerprint=fingerprint,
            authority_snapshots=snapshots,
            total_chain_events=event_count,
            governance_health_score=health_score,
            governance_health_rating=health_rating,
            generated_at=_now(),
        )
