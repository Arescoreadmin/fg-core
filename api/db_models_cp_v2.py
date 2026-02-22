"""
api/db_models_cp_v2.py — SQLAlchemy ORM models for Control Plane v2.

Four truth-plane tables:
  1. ControlPlaneEventLedger   — tamper-evident hash-chained audit spine
  2. ControlPlaneCommand       — operator command records (append-only)
  3. ControlPlaneCommandReceipt — executor evidence (append-only)
  4. ControlPlaneHeartbeat     — entity liveness (upsert-mutable)

Security invariants:
  - Append-only tables: UPDATE/DELETE blocked by DB triggers.
  - tenant_id NEVER sourced from request headers.
  - chain_hash maintained by application layer (cp_ledger service).
  - No arbitrary payload — command enum validated at service layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import declarative_base

# Use the shared Base from db_models so init_db picks up these tables.
# Importing declarative_base here as fallback for direct unit-test usage.
try:
    from api.db_models import Base
except ImportError:
    Base = declarative_base()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class ControlPlaneEventLedger(Base):
    """
    Tamper-evident, hash-chained, append-only audit spine.

    Hash chain:
      content_hash = SHA256(canonical_json(payload + headers))
      chain_hash   = SHA256(prev_hash || content_hash || canonical_metadata)

    The 'signature' column is reserved for future Ed25519 signing.
    """

    __tablename__ = "control_plane_event_ledger"

    id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    # Monotonic autoincrement for stable chain ordering (cross-platform)
    seq = Column(Integer, autoincrement=True, nullable=True, index=True)
    ts = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    # NULL for global/cross-tenant events (MSP chain anchor)
    tenant_id = Column(String(128), nullable=True, index=True)
    actor_id = Column(String(128), nullable=False)
    actor_role = Column(String(64), nullable=False, default="unknown")
    event_type = Column(String(64), nullable=False, index=True)
    payload_json = Column(JSON, nullable=False, default=dict)
    content_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    chain_hash = Column(String(64), nullable=False)
    trace_id = Column(String(64), nullable=False, default="", index=True)
    severity = Column(String(16), nullable=False, default="info")
    # Source: "api" | "agent" | "system"
    source = Column(String(16), nullable=False, default="api")
    # Reserved for future Ed25519 signature
    signature = Column(Text, nullable=True)


class ControlPlaneCommand(Base):
    """
    Operator command record — append-only after initial insert.

    Status transitions:
      queued → executing → completed | failed
      queued → cancelled (operator-initiated)
      executing → conflict (cancel rejected)

    The idempotency_key_hash is SHA-256 of the raw idempotency key,
    never the raw key itself.
    """

    __tablename__ = "control_plane_commands"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "actor_id",
            "idempotency_key_hash",
            "command",
            "target_id",
            name="uq_cp_commands_idempotency",
        ),
    )

    command_id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    ts = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    tenant_id = Column(String(128), nullable=False, index=True)
    actor_id = Column(String(128), nullable=False)
    actor_role = Column(String(64), nullable=False, default="operator")
    # Target classification: locker | module | connector | playbook
    target_type = Column(String(32), nullable=False)
    target_id = Column(String(256), nullable=False)
    # Enum enforced at service layer
    command = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    # SHA-256(raw idempotency key) — raw key never stored
    idempotency_key_hash = Column(String(64), nullable=False)
    # queued | executing | completed | failed | cancelled
    status = Column(String(32), nullable=False, default="queued", index=True)
    trace_id = Column(String(64), nullable=False, default="", index=True)
    # SHA-256(client_ip) — raw IP never stored
    requested_from_ip_hash = Column(String(64), nullable=True)


class ControlPlaneCommandReceipt(Base):
    """
    Executor evidence record — fully append-only.

    Executors POST receipts after executing commands.
    The receipt endpoint rejects submissions from non-executors.
    evidence_hash = SHA-256 of execution evidence bundle.
    """

    __tablename__ = "control_plane_command_receipts"

    receipt_id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    command_id = Column(
        String(36),
        ForeignKey("control_plane_commands.command_id"),
        nullable=False,
        index=True,
    )
    ts = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    executor_id = Column(String(128), nullable=False)
    # agent | system | operator
    executor_type = Column(String(32), nullable=False, default="agent")
    ok = Column(Boolean, nullable=False)
    error_code = Column(String(64), nullable=True)
    evidence_hash = Column(String(64), nullable=False, default="")
    duration_ms = Column(Integer, nullable=True)
    # Redacted execution details — no raw secrets
    details_json = Column(JSON, nullable=False, default=dict)


class ControlPlaneHeartbeat(Base):
    """
    Entity liveness state — mutable (upsert), NOT append-only.

    One row per (entity_type, entity_id, tenant_id).
    Staleness detection: application layer compares last_seen_ts to threshold.

    breaker_state: closed | open | half_open
    """

    __tablename__ = "control_plane_heartbeats"
    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "entity_id",
            "tenant_id",
            name="pk_cp_heartbeats",
        ),
    )

    # Composite PK: no surrogate key needed
    entity_type = Column(String(64), primary_key=True)
    entity_id = Column(String(256), primary_key=True)
    tenant_id = Column(String(128), primary_key=True)
    node_id = Column(String(128), nullable=False, default="")
    version = Column(String(64), nullable=False, default="")
    last_seen_ts = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    # unknown | active | paused | degraded | stopped
    last_state = Column(String(32), nullable=False, default="unknown")
    # closed | open | half_open
    breaker_state = Column(String(16), nullable=False, default="closed")
    queue_depth = Column(Integer, nullable=False, default=0)
    last_error_code = Column(String(64), nullable=True)
