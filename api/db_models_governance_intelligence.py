"""SQLAlchemy ORM models for PR 18.5 — Governance Intelligence Authority.

Tables:
  fa_gov_intel_simulation          - intelligence simulations
  fa_gov_intel_simulation_history  - simulation state history (append-only)
  fa_gov_intel_policy              - intelligence policy lifecycle
  fa_gov_intel_policy_version      - policy version history (append-only)
  fa_gov_intel_benchmark           - governance benchmarks
  fa_gov_intel_external_event      - external events (append-only)
  fa_gov_intel_federation          - federated governance registrations
  fa_gov_intel_explainability      - decision explainability records
  fa_gov_intel_confidence_history  - confidence score history (append-only)
  fa_gov_intel_timeline            - append-only intelligence timeline

Design:
  - Every table carries tenant_id NOT NULL.
  - Append-only tables (simulation_history, policy_version, external_event,
    confidence_history, timeline) install ORM before_update/before_delete
    guards and SQL PG rules that block UPDATE / DELETE.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Float, Index, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_gov_intel_simulation
# ---------------------------------------------------------------------------


class GovIntelSimulation(Base):
    """Intelligence simulation record."""

    __tablename__ = "fa_gov_intel_simulation"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scenario_type: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_simulation_tenant_state", "tenant_id", "state"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_simulation_history (append-only)
# ---------------------------------------------------------------------------


class GovIntelSimulationHistory(Base):
    """Append-only history of simulation state transitions."""

    __tablename__ = "fa_gov_intel_simulation_history"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    simulation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_sim_history_tenant_sim",
            "tenant_id",
            "simulation_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelSimulationHistory, "before_update")
def _block_sim_history_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_simulation_history is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelSimulationHistory, "before_delete")
def _block_sim_history_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_simulation_history is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_policy
# ---------------------------------------------------------------------------


class GovIntelPolicy(Base):
    """Intelligence policy lifecycle record."""

    __tablename__ = "fa_gov_intel_policy"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_type: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="DRAFT"
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_policy_tenant_state",
            "tenant_id",
            "lifecycle_state",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_policy_version (append-only)
# ---------------------------------------------------------------------------


class GovIntelPolicyVersion(Base):
    """Append-only history of intelligence policy versions."""

    __tablename__ = "fa_gov_intel_policy_version"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_policy_version_tenant_policy",
            "tenant_id",
            "policy_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelPolicyVersion, "before_update")
def _block_policy_version_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_policy_version is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelPolicyVersion, "before_delete")
def _block_policy_version_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_policy_version is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_benchmark
# ---------------------------------------------------------------------------


class GovIntelBenchmark(Base):
    """Governance benchmark record."""

    __tablename__ = "fa_gov_intel_benchmark"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    metric_key: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    tier: Mapped[str | None] = mapped_column(String(32), nullable=True)
    extra_metadata: Mapped[str | None] = mapped_column("metadata", Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_benchmark_tenant_metric",
            "tenant_id",
            "metric_key",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_external_event (append-only)
# ---------------------------------------------------------------------------


class GovIntelExternalEvent(Base):
    """Append-only external governance event record."""

    __tablename__ = "fa_gov_intel_external_event"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_ext_event_tenant_type",
            "tenant_id",
            "event_type",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelExternalEvent, "before_update")
def _block_external_event_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_external_event is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelExternalEvent, "before_delete")
def _block_external_event_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_external_event is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_federation
# ---------------------------------------------------------------------------


class GovIntelFederation(Base):
    """Federated governance instance registration."""

    __tablename__ = "fa_gov_intel_federation"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    extra_metadata: Mapped[str | None] = mapped_column("metadata", Text, nullable=True)
    last_sync_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_federation_tenant", "tenant_id"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_explainability
# ---------------------------------------------------------------------------


class GovIntelExplainability(Base):
    """Decision explainability record."""

    __tablename__ = "fa_gov_intel_explainability"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    decision_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evaluation: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(String(255), nullable=False)
    authorities_invoked: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_explainability_tenant_decision",
            "tenant_id",
            "decision_id",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_confidence_history (append-only)
# ---------------------------------------------------------------------------


class GovIntelConfidenceHistory(Base):
    """Append-only confidence score history."""

    __tablename__ = "fa_gov_intel_confidence_history"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    dimension: Mapped[str] = mapped_column(String(255), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    factors: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_confidence_history_tenant_dim",
            "tenant_id",
            "dimension",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelConfidenceHistory, "before_update")
def _block_confidence_history_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_confidence_history is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelConfidenceHistory, "before_delete")
def _block_confidence_history_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_confidence_history is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_timeline (append-only)
# ---------------------------------------------------------------------------


class GovIntelTimeline(Base):
    """Append-only intelligence timeline events."""

    __tablename__ = "fa_gov_intel_timeline"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_timeline_tenant_entity",
            "tenant_id",
            "entity_type",
            "entity_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelTimeline, "before_update")
def _block_timeline_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_gov_intel_timeline is append-only - updates are forbidden")


@sa_event.listens_for(GovIntelTimeline, "before_delete")
def _block_timeline_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_gov_intel_timeline is append-only - deletes are forbidden")


# ===========================================================================
# PR 18.5A — Evidence Graph & Decision Provenance additions
# ===========================================================================


# ---------------------------------------------------------------------------
# fa_gov_intel_provenance_node
# ---------------------------------------------------------------------------


class GovIntelProvenanceNode(Base):
    """Provenance graph node — deterministic, content-addressed."""

    __tablename__ = "fa_gov_intel_provenance_node"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    authority: Mapped[str] = mapped_column(String(255), nullable=False)
    authority_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0"
    )
    source_object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    child_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    trust_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    transparency_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    simulation_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    replay_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_provenance_node_tenant", "tenant_id"),
        Index(
            "ix_fa_gov_intel_provenance_node_tenant_type",
            "tenant_id",
            "node_type",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_provenance_edge (append-only)
# ---------------------------------------------------------------------------


class GovIntelProvenanceEdge(Base):
    """Append-only provenance graph edge."""

    __tablename__ = "fa_gov_intel_provenance_edge"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    parent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    child_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    edge_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="DERIVED_FROM"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_provenance_edge_tenant_parent",
            "tenant_id",
            "parent_id",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelProvenanceEdge, "before_update")
def _block_provenance_edge_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_provenance_edge is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelProvenanceEdge, "before_delete")
def _block_provenance_edge_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_provenance_edge is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_replay_snapshot
# ---------------------------------------------------------------------------


class GovIntelReplaySnapshot(Base):
    """Historical governance replay snapshot and result."""

    __tablename__ = "fa_gov_intel_replay_snapshot"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    time_window: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    replay_label: Mapped[str] = mapped_column(
        String(32), nullable=False, default="REPLAY"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_replay_snapshot_tenant", "tenant_id"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_evidence_matrix
# ---------------------------------------------------------------------------


class GovIntelEvidenceMatrix(Base):
    """Recommendation evidence matrix record."""

    __tablename__ = "fa_gov_intel_evidence_matrix"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    recommendation_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    matrix_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    coverage: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_evidence_matrix_tenant_rec",
            "tenant_id",
            "recommendation_id",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_quality_score (append-only)
# ---------------------------------------------------------------------------


class GovIntelQualityScore(Base):
    """Append-only intelligence quality score record."""

    __tablename__ = "fa_gov_intel_quality_score"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(32), nullable=False)
    inputs: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_quality_score_tenant_entity",
            "tenant_id",
            "entity_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelQualityScore, "before_update")
def _block_quality_score_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_quality_score is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelQualityScore, "before_delete")
def _block_quality_score_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_quality_score is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_simulation_comparison
# ---------------------------------------------------------------------------


class GovIntelSimulationComparison(Base):
    """Side-by-side simulation comparison record."""

    __tablename__ = "fa_gov_intel_simulation_comparison"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    baseline_id: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_id: Mapped[str] = mapped_column(String(255), nullable=False)
    comparison_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_sim_comparison_tenant", "tenant_id"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_timeline_diff
# ---------------------------------------------------------------------------


class GovIntelTimelineDiff(Base):
    """Governance timeline diff record."""

    __tablename__ = "fa_gov_intel_timeline_diff"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    window: Mapped[str] = mapped_column(String(64), nullable=False)
    diff_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_timeline_diff_tenant_window",
            "tenant_id",
            "window",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_counterfactual
# ---------------------------------------------------------------------------


class GovIntelCounterfactual(Base):
    """Counterfactual scenario run record."""

    __tablename__ = "fa_gov_intel_counterfactual"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scenario: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameters: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_intel_counterfactual_tenant_scenario",
            "tenant_id",
            "scenario",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_intel_export_history (append-only)
# ---------------------------------------------------------------------------


class GovIntelExportHistory(Base):
    """Append-only export history record."""

    __tablename__ = "fa_gov_intel_export_history"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    package_id: Mapped[str] = mapped_column(String(255), nullable=False)
    export_format: Mapped[str] = mapped_column(String(32), nullable=False)
    contents_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_intel_export_history_tenant", "tenant_id"),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovIntelExportHistory, "before_update")
def _block_export_history_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_export_history is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovIntelExportHistory, "before_delete")
def _block_export_history_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_intel_export_history is append-only - deletes are forbidden"
    )
