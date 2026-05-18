# api/db_models_alerting.py
"""SQLAlchemy ORM models for immutable alerting records.

Infrastructure note (PR 94):
  This file extends Base.metadata with 5 new tables:
    - readiness_alert_runs
    - readiness_alert_instances
    - readiness_alert_transitions
    - readiness_alert_suppressions
    - readiness_alert_escalations
  Imported by api.db._ensure_models_imported() so init_db() creates the tables.
  Alert runs and instances are write-once — no UPDATE paths in AlertingStore.
  Transitions, suppressions, and escalations are append-only history tables.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


class AlertRunModel(Base):
    """Immutable alert run record — write-once, never updated.

    run_id is a deterministic SHA-256 digest derived from the source
    monitoring run_id; identical monitoring run → identical alert run_id
    (idempotent alerting).

    alert_run_output_json stores the export-safe serialized AlertEngineOutput.
    It is NEVER exposed in API responses — deserialized dict is returned instead.
    """

    __tablename__ = "readiness_alert_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_monitoring_run_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    assessment_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    alert_generation_version: Mapped[str] = mapped_column(String(32), nullable=False)
    escalation_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    total_alerts_generated: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_alerts_deduplicated: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_alerts_suppressed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    generation_timestamp_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_run_output_json: Mapped[str] = mapped_column(Text, nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_alert_runs_tenant_created", "tenant_id", "created_at"),
        Index(
            "ix_alert_runs_tenant_monitoring_run",
            "tenant_id",
            "source_monitoring_run_id",
        ),
    )


class AlertInstanceModel(Base):
    """Immutable alert instance record — write-once, lifecycle_state mutable.

    alert_instance_id is a deterministic SHA-256 digest derived from
    (rule_id, source_run_id, source_event_fingerprint, tenant_id).

    lifecycle_state is the only mutable field; all other fields are write-once.
    """

    __tablename__ = "readiness_alert_instances"

    alert_instance_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    alert_run_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    alert_rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    alert_rule_class: Mapped[str] = mapped_column(String(64), nullable=False)
    source_monitoring_run_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    source_drift_event_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    source_drift_snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    assessment_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    certainty: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    affected_scope: Mapped[str] = mapped_column(String(512), nullable=False)
    affected_control_ids_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )
    affected_evidence_ids_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )
    affected_framework_ids_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )
    alert_detail: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_window_start_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_window_end_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_generation_version: Mapped[str] = mapped_column(String(32), nullable=False)
    escalation_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    replay_contract_metadata_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_alert_instances_tenant_created", "tenant_id", "created_at"),
        Index("ix_alert_instances_tenant_severity", "tenant_id", "severity"),
        Index("ix_alert_instances_tenant_state", "tenant_id", "lifecycle_state"),
        Index("ix_alert_instances_tenant_assessment", "tenant_id", "assessment_id"),
    )


class AlertLifecycleTransitionModel(Base):
    """Immutable lifecycle transition record — append-only history."""

    __tablename__ = "readiness_alert_transitions"

    transition_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_instance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    transitioned_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_safe_metadata_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_alert_transitions_tenant_created", "tenant_id", "created_at"),
        Index("ix_alert_transitions_alert_id", "alert_instance_id"),
    )


class AlertSuppressionModel(Base):
    """Immutable suppression record — append-only history."""

    __tablename__ = "readiness_alert_suppressions"

    suppression_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_instance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    suppression_reason: Mapped[str] = mapped_column(Text, nullable=False)
    suppression_actor: Mapped[str] = mapped_column(String(255), nullable=False)
    suppression_source: Mapped[str] = mapped_column(String(64), nullable=False)
    suppressed_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at_iso: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suppression_lineage_metadata_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_alert_suppressions_tenant_created", "tenant_id", "created_at"),
        Index("ix_alert_suppressions_alert_id", "alert_instance_id"),
    )


class AlertEscalationModel(Base):
    """Immutable escalation record — append-only history."""

    __tablename__ = "readiness_alert_escalations"

    escalation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_instance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    escalation_target_class: Mapped[str] = mapped_column(String(64), nullable=False)
    escalation_routing_rule: Mapped[str] = mapped_column(String(255), nullable=False)
    severity_at_escalation: Mapped[str] = mapped_column(String(32), nullable=False)
    escalated_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    escalation_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    escalation_lineage_metadata_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_alert_escalations_tenant_created", "tenant_id", "created_at"),
        Index("ix_alert_escalations_alert_id", "alert_instance_id"),
    )
