# api/db_models_evidence_authority.py
"""SQLAlchemy ORM models for PR 14.6.1 — Canonical Evidence Authority.

Tables:
  fa_evidence                 — canonical evidence entity (the authority)
  fa_evidence_ownership       — append-only ownership history
  fa_evidence_relationships   — M2M links: evidence ↔ governed resources
  fa_evidence_trust_events    — append-only trust state transitions (hash-chained)
  fa_evidence_audit_events    — append-only lifecycle audit trail

Design principles:
  - Every table carries tenant_id NOT NULL — never query without it.
  - Append-only tables (trust_events, audit_events, relationships) have ORM-level
    guards below. PostgreSQL-level guards are in migration 0123.
  - fa_evidence is the single source of truth for all evidence in FrostGate.
    No other model creates competing evidence ownership.

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — the store layer always provides an explicit value.

Lifecycle states (fa_evidence.lifecycle_state):
  DRAFT | COLLECTED | SUBMITTED | UNDER_REVIEW | VERIFIED |
  REJECTED | SUPERSEDED | EXPIRED | REVOKED | ARCHIVED

Trust states (fa_evidence.trust_state):
  UNVERIFIED | PARTIALLY_VERIFIED | VERIFIED | HIGH_CONFIDENCE |
  DISPUTED | INVALIDATED
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base
from sqlalchemy import Index, UniqueConstraint


# ---------------------------------------------------------------------------
# fa_evidence — canonical evidence entity
# ---------------------------------------------------------------------------


class FaEvidence(Base):
    """Canonical evidence entity — the single source of truth for all evidence.

    Every other subsystem (findings, controls, risk, governance, reports) that
    needs to reference evidence should link to fa_evidence.id. No subsystem
    creates its own evidence ownership model.

    Forward-compatibility fields for FA-17.5 (Evidence Authority arc):
      content_hash / content_hash_algorithm — raw artifact integrity (PR 18.1)
      integrity_hash / integrity_hash_algorithm — canonical identity hash (PR 1.1)
      provenance_chain_head — pointer to latest trust event (PR 18.2)
    """

    __tablename__ = "fa_evidence"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_ref: Mapped[str] = mapped_column(String(512), nullable=False)

    # Lifecycle
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="COLLECTED"
    )

    # Classification
    classification: Mapped[str] = mapped_column(
        String(64), nullable=False, default="INTERNAL"
    )
    classification_labels: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )

    # Source
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    collection_method: Mapped[str] = mapped_column(String(64), nullable=False)

    # Description
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Integrity / provenance (FA-17.5 forward-compatibility)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_hash_algorithm: Mapped[str | None] = mapped_column(
        String(32), nullable=True, default="sha256"
    )
    integrity_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    integrity_hash_algorithm: Mapped[str | None] = mapped_column(
        String(32), nullable=True, default="sha256"
    )
    provenance_chain_head: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Trust
    trust_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNVERIFIED"
    )
    verification_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_verification_source: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    last_verifier_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Ownership
    owner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_type: Mapped[str | None] = mapped_column(
        String(32), nullable=True, default="human"
    )
    creator_id: Mapped[str] = mapped_column(String(255), nullable=False)
    creator_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )

    # Context
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Temporal
    collected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    submitted_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    archived_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Versioning
    evidence_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1"
    )
    superseded_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "evidence_ref", name="uq_fa_evidence_tenant_ref"),
        Index("ix_fa_evidence_tenant_state", "tenant_id", "lifecycle_state"),
        Index("ix_fa_evidence_tenant_trust", "tenant_id", "trust_state"),
        Index("ix_fa_evidence_tenant_classification", "tenant_id", "classification"),
        Index("ix_fa_evidence_tenant_source_type", "tenant_id", "source_type"),
        Index("ix_fa_evidence_engagement", "tenant_id", "engagement_id"),
        Index("ix_fa_evidence_tenant_created", "tenant_id", "created_at"),
        Index("ix_fa_evidence_expires", "tenant_id", "expires_at"),
    )


# ---------------------------------------------------------------------------
# fa_evidence_ownership — append-only ownership history
# ---------------------------------------------------------------------------


class FaEvidenceOwnership(Base):
    """Evidence ownership record — append-only.

    Revocation is recorded via revoked_at / is_active=0 rather than DELETE.
    The ORM guard below prevents DELETE; the PostgreSQL trigger in migration 0123
    provides the same protection in Postgres.
    """

    __tablename__ = "fa_evidence_ownership"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    role: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="human")

    assigned_at: Mapped[str] = mapped_column(String(64), nullable=False)
    assigned_by: Mapped[str] = mapped_column(String(255), nullable=False)
    assigned_by_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )

    revoked_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_evidence_ownership_evidence", "tenant_id", "evidence_id"),
        Index(
            "ix_fa_evidence_ownership_active",
            "tenant_id",
            "evidence_id",
            "is_active",
        ),
        Index("ix_fa_evidence_ownership_actor", "tenant_id", "actor_id"),
    )


@sa_event.listens_for(FaEvidenceOwnership, "before_delete")
def _block_ownership_delete(mapper, connection, target):
    raise ValueError(
        "fa_evidence_ownership rows are immutable — revoke via is_active=0"
    )


# ---------------------------------------------------------------------------
# fa_evidence_relationships — append-only M2M links
# ---------------------------------------------------------------------------


class FaEvidenceRelationship(Base):
    """Append-only relationship between evidence and governed resources.

    Both UPDATE and DELETE are blocked at the ORM layer. If a relationship was
    created incorrectly, create a REVOKED audit event and suppress it at read
    time — do not delete.
    """

    __tablename__ = "fa_evidence_relationships"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    related_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    related_entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)

    link_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    linked_at: Mapped[str] = mapped_column(String(64), nullable=False)
    linked_by: Mapped[str] = mapped_column(String(255), nullable=False)
    linked_by_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "evidence_id",
            "related_entity_type",
            "related_entity_id",
            "relationship_type",
            name="uq_fa_evidence_relationship",
        ),
        Index("ix_fa_evidence_rel_evidence", "tenant_id", "evidence_id"),
        Index(
            "ix_fa_evidence_rel_entity",
            "tenant_id",
            "related_entity_type",
            "related_entity_id",
        ),
    )


@sa_event.listens_for(FaEvidenceRelationship, "before_update")
def _block_relationship_update(mapper, connection, target):
    raise ValueError("fa_evidence_relationships rows are immutable")


@sa_event.listens_for(FaEvidenceRelationship, "before_delete")
def _block_relationship_delete(mapper, connection, target):
    raise ValueError("fa_evidence_relationships rows are immutable")


# ---------------------------------------------------------------------------
# fa_evidence_trust_events — append-only, hash-chained trust transitions
# ---------------------------------------------------------------------------


class FaEvidenceTrustEvent(Base):
    """Append-only, hash-chained trust state transition record.

    event_hash is a SHA-256 of (event_id, evidence_id, tenant_id, from_state,
    to_state, verifier_id, created_at, prev_event_hash) — enabling independent
    chain verification without database access (FA-17.5 forward-compatibility).
    """

    __tablename__ = "fa_evidence_trust_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    from_trust_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_trust_state: Mapped[str] = mapped_column(String(32), nullable=False)

    verification_source: Mapped[str] = mapped_column(String(32), nullable=False)
    verifier_id: Mapped[str] = mapped_column(String(255), nullable=False)
    verifier_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="human"
    )
    verification_method: Mapped[str | None] = mapped_column(String(128), nullable=True)
    confidence_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prev_event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_evidence_trust_events_evidence", "tenant_id", "evidence_id"),
        Index("ix_fa_evidence_trust_events_created", "tenant_id", "created_at"),
    )


@sa_event.listens_for(FaEvidenceTrustEvent, "before_update")
def _block_trust_event_update(mapper, connection, target):
    raise ValueError("fa_evidence_trust_events rows are immutable")


@sa_event.listens_for(FaEvidenceTrustEvent, "before_delete")
def _block_trust_event_delete(mapper, connection, target):
    raise ValueError("fa_evidence_trust_events rows are immutable")


# ---------------------------------------------------------------------------
# fa_evidence_audit_events — append-only lifecycle audit trail
# ---------------------------------------------------------------------------


class FaEvidenceAuditEvent(Base):
    """Append-only audit trail for all evidence lifecycle mutations.

    Schema v1.0: standard fields.
    transaction_id / correlation_id: H13-style correlation (nullable, populated
    when caller provides a transaction context).
    """

    __tablename__ = "fa_evidence_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(64), nullable=True)

    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="human")

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    transaction_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_evidence_audit_evidence", "tenant_id", "evidence_id"),
        Index("ix_fa_evidence_audit_created", "tenant_id", "created_at"),
        Index("ix_fa_evidence_audit_event_type", "tenant_id", "event_type"),
    )


@sa_event.listens_for(FaEvidenceAuditEvent, "before_update")
def _block_audit_event_update(mapper, connection, target):
    raise ValueError("fa_evidence_audit_events rows are immutable")


@sa_event.listens_for(FaEvidenceAuditEvent, "before_delete")
def _block_audit_event_delete(mapper, connection, target):
    raise ValueError("fa_evidence_audit_events rows are immutable")
