# api/db_models_governance_assets.py
"""SQLAlchemy ORM models for the Governance Asset Registry.

Infrastructure note (PR 3.5):
  Extends Base.metadata with eight governance asset tables.
  Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.

Append-only contract:
  governance_asset_audit_events is append-only. No UPDATE or DELETE.
  governance_asset_versions is append-only. Versions are immutable snapshots.

Cryptographic integrity:
  governance_asset_versions — each version carries a canonical_hash + Ed25519
    chain_signature over that hash; parent_hash chains versions like ConfigVersion.
  governance_asset_attestations — each attestation is signed.
  governance_asset_audit_events — tamper-evident chain via chain_hash(prev, entry).

Trust-but-Verify posture:
  risk scores are computed and stored per-trigger-event; the full factor
  breakdown is preserved so any score can be independently reproduced.
  Shadow assets (discovered but undeclared) carry a discovery_penalty in scoring.

Tables:
  governance_assets                 — canonical asset registry
  governance_asset_versions         — immutable signed version snapshots
  governance_asset_owners           — ownership assignments + attestation TTL
  governance_asset_attestations     — periodic signed attestation records
  governance_asset_relationships    — relationship graph / data flow edges
  governance_asset_risk_scores      — deterministic risk score history
  governance_asset_policy_bindings  — policy-to-asset bindings
  governance_asset_audit_events     — tamper-evident chained audit trail
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GaAsset(Base):
    """Canonical governance asset registry entry.

    asset_id is the stable UUID identity referenced by all downstream tables.
    current_version_hash points to the latest GaAssetVersion.version_hash and
    is updated atomically with every PATCH.

    discovery_source distinguishes assets that an owner declared ('declared')
    from those found by scan cross-reference ('discovered') or inferred from
    governance report analysis ('inferred').  Shadow assets begin as 'discovered'
    and transition to 'declared' when claimed.
    """

    __tablename__ = "governance_assets"

    asset_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="active")
    risk_tier: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unclassified"
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    discovery_source: Mapped[str] = mapped_column(
        String(32), nullable=False, default="declared"
    )
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    current_version_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_email: Mapped[str] = mapped_column(String(512), nullable=False)
    source_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_ga_assets_tenant_type", "tenant_id", "asset_type"),
        Index("ix_ga_assets_tenant_status", "tenant_id", "status"),
        Index("ix_ga_assets_tenant_risk_tier", "tenant_id", "risk_tier"),
        Index("ix_ga_assets_tenant_discovery", "tenant_id", "discovery_source"),
        Index("ix_ga_assets_external_id", "tenant_id", "external_id"),
    )


class GaAssetVersion(Base):
    """Immutable signed version snapshot — append-only, never updated.

    parent_hash chains to the previous version_hash (None for the genesis version),
    mirroring the ConfigVersion pattern.  chain_signature is an Ed25519 signature
    over version_hash produced by signed_artifacts.sign_hash().

    version_payload_json is the full canonical asset state at this point in time,
    enabling point-in-time ('time-travel') queries without joins.
    """

    __tablename__ = "governance_asset_versions"

    version_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_payload_json: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_email: Mapped[str] = mapped_column(String(512), nullable=False)
    chain_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "version_hash", name="uq_ga_asset_version_hash"),
        Index("ix_ga_asset_versions_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_asset_versions_asset_seq", "asset_id", "version_seq"),
    )


class GaAssetOwner(Base):
    """Business owner assignment with attestation TTL tracking.

    attestation_interval_days defaults to 90 but is overridden per risk_tier:
      critical → 30, high → 60, medium/low → 90.
    next_attestation_due_at is recomputed whenever last_attested_at changes or
    when the asset's risk_tier changes.
    """

    __tablename__ = "governance_asset_owners"

    ownership_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    owner_email: Mapped[str] = mapped_column(String(512), nullable=False)
    owner_role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="primary"
    )
    attestation_interval_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90
    )
    last_attested_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    next_attestation_due_at: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    assigned_at: Mapped[str] = mapped_column(String(64), nullable=False)
    assigned_by_email: Mapped[str] = mapped_column(String(512), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "tenant_id", "owner_email", name="uq_ga_asset_owner_email"
        ),
        Index("ix_ga_owners_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_owners_tenant_due", "tenant_id", "next_attestation_due_at"),
    )


class GaAssetAttestation(Base):
    """Periodic signed attestation record — append-only.

    attestation_hash = canonical_hash({asset_id, owner_email, attestation_type,
                                       attested_version_hash, statement, due_at}).
    chain_signature = Ed25519 signature over attestation_hash.

    status transitions: pending → completed | overdue | waived.
    Completed attestations update GaAssetOwner.last_attested_at.
    """

    __tablename__ = "governance_asset_attestations"

    attestation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    owner_email: Mapped[str] = mapped_column(String(512), nullable=False)
    attestation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    attested_version_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    attestation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    due_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_ga_attestations_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_attestations_tenant_status", "tenant_id", "status"),
        Index("ix_ga_attestations_tenant_due", "tenant_id", "due_at"),
    )


class GaAssetRelationship(Base):
    """Relationship graph edge between two governance assets.

    Covers data flows, dependency chains, delegation, and training lineage.
    is_declared=False marks system-detected relationships (from scan cross-reference).
    data_classification and transfer_volume_tier feed into upstream risk scoring.
    """

    __tablename__ = "governance_asset_relationships"

    relationship_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    data_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    transfer_volume_tier: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unknown"
    )
    is_declared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_email: Mapped[str] = mapped_column(String(512), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_ga_relationship",
        ),
        Index("ix_ga_relationships_source_tenant", "source_asset_id", "tenant_id"),
        Index("ix_ga_relationships_target_tenant", "target_asset_id", "tenant_id"),
        Index("ix_ga_relationships_tenant_type", "tenant_id", "relationship_type"),
    )


class GaAssetRiskScore(Base):
    """Deterministic risk score snapshot stored per-trigger-event.

    is_current=True marks the single live score per asset (updated atomically).
    factors_json preserves the full factor breakdown so any score can be
    independently reproduced from first principles.

    trigger_event documents what caused the recomputation:
      asset.created | asset.updated | owner.assigned | attestation.overdue |
      finding.added | vendor.risk_propagated | relationship.created
    """

    __tablename__ = "governance_asset_risk_scores"

    score_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    tier: Mapped[str] = mapped_column(String(32), nullable=False)
    factors_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    trigger_event: Mapped[str] = mapped_column(String(128), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    computed_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_ga_risk_scores_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_risk_scores_tenant_current", "tenant_id", "is_current"),
        Index("ix_ga_risk_scores_tenant_tier", "tenant_id", "tier"),
    )


class GaAssetPolicyBinding(Base):
    """Binding between a governance asset and a governance policy.

    policy_version_hash is an immutable reference — if the policy is updated
    the binding status transitions to 'superseded' and a new binding is created.
    effective_until=None means the binding has no expiry.
    """

    __tablename__ = "governance_asset_policy_bindings"

    binding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_type: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    policy_version_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    bound_at: Mapped[str] = mapped_column(String(64), nullable=False)
    bound_by_email: Mapped[str] = mapped_column(String(512), nullable=False)
    effective_from: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effective_until: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_ga_policy_bindings_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_policy_bindings_tenant_status", "tenant_id", "status"),
    )


class GaAssetAuditEvent(Base):
    """Tamper-evident chained audit trail — append-only.

    Uses the same chain_hash(prev_chain_hash, entry_hash) construction as
    SecurityAuditLog and the approval chain in attestation.py.

    chain_id is per-tenant (one chain per tenant across all assets).
    seq is monotonically increasing per chain_id.
    entry_hash = canonical_hash(event_payload_json).
    chain_hash_val = chain_hash(prev_hash, entry_hash).
    chain_signature = Ed25519 signature over chain_hash_val.

    Replay verification: iterate rows ordered by seq, recompute chain_hash at
    each step, verify signature — any tampering invalidates the suffix.
    """

    __tablename__ = "governance_asset_audit_events"

    audit_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    chain_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(512), nullable=False)
    event_payload_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash_val: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("chain_id", "seq", name="uq_ga_audit_chain_seq"),
        Index("ix_ga_audit_events_asset_tenant", "asset_id", "tenant_id"),
        Index("ix_ga_audit_events_tenant_type", "tenant_id", "event_type"),
        Index("ix_ga_audit_events_chain_seq", "chain_id", "seq"),
    )
