"""Tenant-scoped data access for the Governance Intelligence Authority.

Every query includes a tenant_id predicate. Caller (engine / API) owns
``db.commit()``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models_governance_intelligence import (
    GovIntelBenchmark,
    GovIntelConfidenceHistory,
    GovIntelExplainability,
    GovIntelExternalEvent,
    GovIntelFederation,
    GovIntelPolicy,
    GovIntelPolicyVersion,
    GovIntelSimulation,
    GovIntelSimulationHistory,
    GovIntelTimeline,
)
from services.canonical import utc_iso8601_z_now


def _now() -> str:
    return utc_iso8601_z_now()


def _new_id() -> str:
    return str(uuid.uuid4())


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


class GovernanceIntelligenceRepository:
    """Tenant-scoped data access for the fa_gov_intel_* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def create_simulation(self, **fields: Any) -> GovIntelSimulation:
        now = _now()
        row = GovIntelSimulation(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            description=fields.get("description"),
            scenario_type=fields["scenario_type"],
            parameters=_dumps(fields.get("parameters") or {}),
            state=fields.get("state", "DRAFT"),
            result=_dumps(fields["result"])
            if fields.get("result") is not None
            else None,
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_simulation(self, simulation_id: str) -> Optional[GovIntelSimulation]:
        return (
            self._db.query(GovIntelSimulation)
            .filter(
                GovIntelSimulation.id == simulation_id,
                GovIntelSimulation.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_simulations(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelSimulation], int]:
        q = self._db.query(GovIntelSimulation).filter(
            GovIntelSimulation.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelSimulation.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_simulation(self, row: GovIntelSimulation) -> GovIntelSimulation:
        row.updated_at = _now()
        self._db.flush()
        return row

    def delete_simulation(self, row: GovIntelSimulation) -> None:
        self._db.delete(row)
        self._db.flush()

    # ------------------------------------------------------------------
    # Simulation history (append-only)
    # ------------------------------------------------------------------

    def append_simulation_history(
        self,
        *,
        simulation_id: str,
        state: str,
        actor_id: str,
        data: Optional[dict[str, Any]] = None,
    ) -> GovIntelSimulationHistory:
        row = GovIntelSimulationHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            simulation_id=simulation_id,
            state=state,
            actor_id=actor_id,
            data=_dumps(data or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_simulation_history(
        self, simulation_id: str
    ) -> list[GovIntelSimulationHistory]:
        return (
            self._db.query(GovIntelSimulationHistory)
            .filter(
                GovIntelSimulationHistory.tenant_id == self._tenant_id,
                GovIntelSimulationHistory.simulation_id == simulation_id,
            )
            .order_by(GovIntelSimulationHistory.created_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Intelligence policies
    # ------------------------------------------------------------------

    def create_policy(self, **fields: Any) -> GovIntelPolicy:
        now = _now()
        row = GovIntelPolicy(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            description=fields.get("description"),
            policy_type=fields["policy_type"],
            policy_data=_dumps(fields.get("policy_data") or {}),
            framework=fields.get("framework"),
            lifecycle_state=fields.get("lifecycle_state", "DRAFT"),
            version=fields.get("version", "1.0"),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_policy(self, policy_id: str) -> Optional[GovIntelPolicy]:
        return (
            self._db.query(GovIntelPolicy)
            .filter(
                GovIntelPolicy.id == policy_id,
                GovIntelPolicy.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_policies(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelPolicy], int]:
        q = self._db.query(GovIntelPolicy).filter(
            GovIntelPolicy.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelPolicy.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_policy(self, row: GovIntelPolicy) -> GovIntelPolicy:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Policy versions (append-only)
    # ------------------------------------------------------------------

    def append_policy_version(
        self,
        *,
        policy_id: str,
        version: str,
        policy_data: dict[str, Any],
        changed_by: Optional[str],
    ) -> GovIntelPolicyVersion:
        row = GovIntelPolicyVersion(
            id=_new_id(),
            policy_id=policy_id,
            tenant_id=self._tenant_id,
            version=version,
            policy_data=_dumps(policy_data),
            changed_by=changed_by,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_policy_versions(self, policy_id: str) -> list[GovIntelPolicyVersion]:
        return (
            self._db.query(GovIntelPolicyVersion)
            .filter(
                GovIntelPolicyVersion.tenant_id == self._tenant_id,
                GovIntelPolicyVersion.policy_id == policy_id,
            )
            .order_by(GovIntelPolicyVersion.created_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def create_benchmark(self, **fields: Any) -> GovIntelBenchmark:
        row = GovIntelBenchmark(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            framework=fields["framework"],
            category=fields["category"],
            metric_key=fields["metric_key"],
            value=float(fields["value"]),
            percentile=fields.get("percentile"),
            tier=fields.get("tier"),
            extra_metadata=_dumps(fields.get("metadata") or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_benchmark(self, benchmark_id: str) -> Optional[GovIntelBenchmark]:
        return (
            self._db.query(GovIntelBenchmark)
            .filter(
                GovIntelBenchmark.id == benchmark_id,
                GovIntelBenchmark.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_benchmarks(
        self,
        *,
        framework: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovIntelBenchmark], int]:
        q = self._db.query(GovIntelBenchmark).filter(
            GovIntelBenchmark.tenant_id == self._tenant_id
        )
        if framework is not None:
            q = q.filter(GovIntelBenchmark.framework == framework)
        total = q.count()
        items = (
            q.order_by(GovIntelBenchmark.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def delete_benchmark(self, row: GovIntelBenchmark) -> None:
        self._db.delete(row)
        self._db.flush()

    # ------------------------------------------------------------------
    # External events (append-only)
    # ------------------------------------------------------------------

    def append_external_event(self, **fields: Any) -> GovIntelExternalEvent:
        row = GovIntelExternalEvent(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            event_type=fields["event_type"],
            source=fields["source"],
            payload=_dumps(fields.get("payload") or {}),
            occurred_at=fields.get("occurred_at") or _now(),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_external_event(self, event_id: str) -> Optional[GovIntelExternalEvent]:
        return (
            self._db.query(GovIntelExternalEvent)
            .filter(
                GovIntelExternalEvent.id == event_id,
                GovIntelExternalEvent.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_external_events(
        self,
        *,
        event_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovIntelExternalEvent], int]:
        q = self._db.query(GovIntelExternalEvent).filter(
            GovIntelExternalEvent.tenant_id == self._tenant_id
        )
        if event_type is not None:
            q = q.filter(GovIntelExternalEvent.event_type == event_type)
        total = q.count()
        items = (
            q.order_by(GovIntelExternalEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Federation
    # ------------------------------------------------------------------

    def create_federation(self, **fields: Any) -> GovIntelFederation:
        row = GovIntelFederation(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            instance_id=fields["instance_id"],
            role=fields["role"],
            extra_metadata=_dumps(fields.get("metadata") or {}),
            last_sync_at=fields.get("last_sync_at"),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_federation(self, federation_id: str) -> Optional[GovIntelFederation]:
        return (
            self._db.query(GovIntelFederation)
            .filter(
                GovIntelFederation.id == federation_id,
                GovIntelFederation.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_federation(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelFederation], int]:
        q = self._db.query(GovIntelFederation).filter(
            GovIntelFederation.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelFederation.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def delete_federation(self, row: GovIntelFederation) -> None:
        self._db.delete(row)
        self._db.flush()

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def create_explainability(self, **fields: Any) -> GovIntelExplainability:
        row = GovIntelExplainability(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            decision_id=fields["decision_id"],
            trigger=fields["trigger"],
            policy_version=fields["policy_version"],
            evaluation=_dumps(fields.get("evaluation") or {}),
            decision=fields["decision"],
            authorities_invoked=_dumps(fields.get("authorities_invoked") or []),
            expected_impact=_dumps(fields.get("expected_impact") or {}),
            observed_impact=_dumps(fields["observed_impact"])
            if fields.get("observed_impact") is not None
            else None,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_explainability_by_decision(
        self, decision_id: str
    ) -> Optional[GovIntelExplainability]:
        return (
            self._db.query(GovIntelExplainability)
            .filter(
                GovIntelExplainability.decision_id == decision_id,
                GovIntelExplainability.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_explainability(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelExplainability], int]:
        q = self._db.query(GovIntelExplainability).filter(
            GovIntelExplainability.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelExplainability.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Confidence history (append-only)
    # ------------------------------------------------------------------

    def append_confidence_history(
        self,
        *,
        dimension: str,
        score: float,
        level: str,
        factors: dict[str, Any],
        computed_at: str,
    ) -> GovIntelConfidenceHistory:
        row = GovIntelConfidenceHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            dimension=dimension,
            score=score,
            level=level,
            factors=_dumps(factors),
            computed_at=computed_at,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_confidence_history(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelConfidenceHistory], int]:
        q = self._db.query(GovIntelConfidenceHistory).filter(
            GovIntelConfidenceHistory.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelConfidenceHistory.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def get_latest_confidence(
        self, dimension: str
    ) -> Optional[GovIntelConfidenceHistory]:
        return (
            self._db.query(GovIntelConfidenceHistory)
            .filter(
                GovIntelConfidenceHistory.tenant_id == self._tenant_id,
                GovIntelConfidenceHistory.dimension == dimension,
            )
            .order_by(GovIntelConfidenceHistory.created_at.desc())
            .first()
        )

    # ------------------------------------------------------------------
    # Timeline (append-only)
    # ------------------------------------------------------------------

    def append_timeline(
        self,
        *,
        event_type: str,
        entity_id: str,
        entity_type: str,
        actor_id: str,
        data: Optional[dict[str, Any]] = None,
    ) -> GovIntelTimeline:
        row = GovIntelTimeline(
            id=_new_id(),
            tenant_id=self._tenant_id,
            event_type=event_type,
            entity_id=entity_id,
            entity_type=entity_type,
            actor_id=actor_id,
            data=_dumps(data or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_timeline(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovIntelTimeline], int]:
        q = self._db.query(GovIntelTimeline).filter(
            GovIntelTimeline.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovIntelTimeline.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Count helpers
    # ------------------------------------------------------------------

    def count_simulations(self) -> int:
        return (
            self._db.query(GovIntelSimulation)
            .filter(GovIntelSimulation.tenant_id == self._tenant_id)
            .count()
        )

    def count_simulations_by_state(self, state: str) -> int:
        return (
            self._db.query(GovIntelSimulation)
            .filter(
                GovIntelSimulation.tenant_id == self._tenant_id,
                GovIntelSimulation.state == state,
            )
            .count()
        )

    def count_policies(self) -> int:
        return (
            self._db.query(GovIntelPolicy)
            .filter(GovIntelPolicy.tenant_id == self._tenant_id)
            .count()
        )

    def count_benchmarks(self) -> int:
        return (
            self._db.query(GovIntelBenchmark)
            .filter(GovIntelBenchmark.tenant_id == self._tenant_id)
            .count()
        )

    def count_external_events(self) -> int:
        return (
            self._db.query(GovIntelExternalEvent)
            .filter(GovIntelExternalEvent.tenant_id == self._tenant_id)
            .count()
        )
