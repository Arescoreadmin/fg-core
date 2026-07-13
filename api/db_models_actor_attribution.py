# api/db_models_actor_attribution.py
"""SQLAlchemy ORM models for PR 535 — Enterprise Actor Attribution & Non-Repudiation.

Tables:
  actor_identities            — canonical actor record; mutable for status/last_seen updates
  actor_identity_snapshots    — append-only snapshots captured at action time
  actor_attribution_records   — append-only per-governance-event attribution records
  actor_audit_events          — append-only audit trail for actor identity changes

Design principles:
  - Every table carries tenant_id NOT NULL — never query without it.
  - Append-only tables (actor_identity_snapshots, actor_attribution_records,
    actor_audit_events) have ORM-level guards below. PostgreSQL-level guards are
    in migration 0152.
  - actor_identities is the canonical actor registry. Snapshots are captured at
    action time and are immutable forever — they represent who acted, as they were
    at the moment of action.
  - actor_attribution_records provide cryptographic non-repudiation via chained
    SHA-256 fingerprints (actor_fingerprint, identity_fingerprint,
    request_fingerprint, attribution_hash, event_hash).

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — the store layer always provides an explicit value.

Actor types (actor_identities.actor_type / snapshots / attribution):
  human_user | system_process | automation | connector | api_client |
  service_account | scheduled_job | ai_agent | governance_workflow |
  autonomous_system

Authentication methods:
  oidc_auth0 | oidc_entra | api_key | system | dev_bypass

Trust levels:
  verified | high | medium | low | unverified
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base
from sqlalchemy import Index, UniqueConstraint


# ---------------------------------------------------------------------------
# actor_identities — canonical actor record
# ---------------------------------------------------------------------------


class ActorIdentity(Base):
    """Canonical actor record — one per (tenant_id, actor_subject).

    Mutable for status and last_seen_at updates. All other changes should be
    recorded via ActorAuditEvent. Snapshots are taken at action time via
    ActorIdentitySnapshot to provide immutable point-in-time records.

    actor_subject is the globally unique identity anchor (e.g. auth0|sub,
    api_key_prefix) and must be unique within a tenant.

    is_service_account and is_robot use Integer (0/1) for SQLite compatibility.
    """

    __tablename__ = "actor_identities"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    organization_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Actor classification
    actor_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # human_user|system_process|automation|connector|api_client|service_account|scheduled_job|ai_agent|governance_workflow|autonomous_system
    actor_subject: Mapped[str] = mapped_column(
        String(512), nullable=False
    )  # globally unique identity anchor: auth0|sub, api_key_prefix, etc.
    actor_display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    email_hash: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # SHA-256 of email, privacy-safe

    # Authentication
    authentication_method: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # oidc_auth0|oidc_entra|api_key|system|dev_bypass
    identity_provider: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # auth0|entra|api_key|system|unknown

    # Governance
    governance_role: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # most-privileged role

    # Service / robot flags (Integer for SQLite compat)
    is_service_account: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_robot: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    service_account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    robot_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Delegation
    delegated_by: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # actor_id of delegator

    # Trust & status
    trust_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unverified"
    )  # verified|high|medium|low|unverified
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active"
    )  # active|inactive|revoked|suspended

    # Temporal
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Versioning
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "actor_subject", name="uq_actor_identities_tenant_subject"
        ),
        Index("ix_actor_identities_tenant_type", "tenant_id", "actor_type"),
        Index("ix_actor_identities_tenant_status", "tenant_id", "status"),
    )


# ---------------------------------------------------------------------------
# actor_identity_snapshots — append-only immutable snapshots
# ---------------------------------------------------------------------------


class ActorIdentitySnapshot(Base):
    """Append-only immutable snapshot of an actor's identity at action time.

    Captured when a governance action is taken, ensuring that the state of the
    actor at the moment of action is preserved forever, independent of any
    subsequent changes to actor_identities.

    Both UPDATE and DELETE are blocked at the ORM layer. PostgreSQL-level guards
    are in migration 0152.
    """

    __tablename__ = "actor_identity_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # FK to actor_identities.id

    snapshot_reason: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # action_time|audit_event|periodic

    # Actor state at snapshot time
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(512), nullable=False)
    actor_display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    email_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    authentication_method: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_provider: Mapped[str] = mapped_column(String(128), nullable=False)
    governance_role: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Permission / group snapshots (JSON lists)
    permission_snapshot: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )  # JSON list of permission strings
    groups_snapshot: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )  # JSON list

    # Org context
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    organization_snapshot: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # Trust & flags
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)
    is_service_account: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_robot: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delegated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Temporal
    captured_at: Mapped[str] = mapped_column(String(64), nullable=False)

    # Versioning
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_actor_identity_snapshots_tenant_actor", "tenant_id", "actor_id"),
    )


@sa_event.listens_for(ActorIdentitySnapshot, "before_update")
def _block_snapshot_update(mapper, connection, target):
    raise ValueError("actor_identity_snapshots rows are immutable")


@sa_event.listens_for(ActorIdentitySnapshot, "before_delete")
def _block_snapshot_delete(mapper, connection, target):
    raise ValueError("actor_identity_snapshots rows are immutable")


# ---------------------------------------------------------------------------
# actor_attribution_records — append-only per-governance-event attribution
# ---------------------------------------------------------------------------


class ActorAttributionRecord(Base):
    """Append-only, cryptographically-linked attribution record per governance event.

    Provides non-repudiation by recording exactly who performed an action, with
    three-layer fingerprinting:
      actor_fingerprint     — derived from actor identity fields
      identity_fingerprint  — derived from the linked snapshot
      request_fingerprint   — derived from session/request context
      attribution_hash      — SHA-256 of the three fingerprints
      event_hash            — SHA-256 of attribution_hash + event context

    previous_hash enables optional chain support for sequential event streams.

    Autonomous actor fields (autonomous_*) are populated only when actor_type
    indicates an autonomous system (ai_agent, autonomous_system, governance_workflow).

    Both UPDATE and DELETE are blocked at the ORM layer. PostgreSQL-level guards
    are in migration 0152.
    """

    __tablename__ = "actor_attribution_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    organization_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Event classification
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # scan_ingestion|document_analysis|observation|artifact_upload|report_generation|report_approval|report_supersede|report_delivery|manifest_generation|evidence_provenance|governance_decision|custom
    event_ref: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # external entity ID
    event_ref_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Actor context (denormalised from snapshot for query performance)
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    authentication_method: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_provider: Mapped[str] = mapped_column(String(128), nullable=False)

    # Request context
    session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_ip_hash: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # privacy-safe hash
    user_agent_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Governance context
    governance_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)

    # Cryptographic fingerprints
    actor_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    identity_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    attribution_hash: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # SHA-256 of the three fingerprints
    event_hash: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # SHA-256 of attribution_hash + event context
    previous_hash: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # for optional chain support

    # Temporal / versioning
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Autonomous actor fields (populated when actor_type is autonomous)
    autonomous_decision_confidence: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON float
    autonomous_policy_version: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    autonomous_authority_chain: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON
    autonomous_execution_context: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON
    autonomous_reasoning_reference: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    autonomous_governance_scope: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    __table_args__ = (
        Index("ix_actor_attribution_records_tenant_actor", "tenant_id", "actor_id"),
        Index(
            "ix_actor_attribution_records_tenant_event_type", "tenant_id", "event_type"
        ),
        Index(
            "ix_actor_attribution_records_tenant_event_ref", "tenant_id", "event_ref"
        ),
        Index(
            "ix_actor_attribution_records_tenant_attribution_hash",
            "tenant_id",
            "attribution_hash",
        ),  # for replay verification
    )


@sa_event.listens_for(ActorAttributionRecord, "before_update")
def _block_attribution_record_update(mapper, connection, target):
    raise ValueError("actor_attribution_records rows are immutable")


@sa_event.listens_for(ActorAttributionRecord, "before_delete")
def _block_attribution_record_delete(mapper, connection, target):
    raise ValueError("actor_attribution_records rows are immutable")


# ---------------------------------------------------------------------------
# actor_audit_events — append-only audit trail for actor identity changes
# ---------------------------------------------------------------------------


class ActorAuditEvent(Base):
    """Append-only audit trail for all actor identity mutations.

    Records who changed what on an actor_identities row, what the before/after
    values were (as JSON), and why. changed_by_actor_id is nullable to support
    system-initiated changes (e.g. automated trust-level recalculation).

    Both UPDATE and DELETE are blocked at the ORM layer. PostgreSQL-level guards
    are in migration 0152.
    """

    __tablename__ = "actor_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # actor_created|actor_updated|actor_suspended|actor_revoked|trust_level_changed|status_changed
    actor_type_snapshot: Mapped[str] = mapped_column(String(64), nullable=False)
    changed_by_actor_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # who made the change; null for system

    # Change payload (JSON)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Temporal / versioning
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_actor_audit_events_tenant_actor", "tenant_id", "actor_id"),
        Index("ix_actor_audit_events_tenant_event_type", "tenant_id", "event_type"),
    )


@sa_event.listens_for(ActorAuditEvent, "before_update")
def _block_audit_event_update(mapper, connection, target):
    raise ValueError("actor_audit_events rows are immutable")


@sa_event.listens_for(ActorAuditEvent, "before_delete")
def _block_audit_event_delete(mapper, connection, target):
    raise ValueError("actor_audit_events rows are immutable")
