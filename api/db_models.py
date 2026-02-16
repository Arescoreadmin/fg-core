# api/db_models.py
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Index, String, text
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint
from sqlalchemy import JSON, Text
from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    Integer,
    event,
    func,
)
from sqlalchemy.orm import declarative_base

from api.signed_artifacts import canonical_hash

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


def hash_api_key(api_key: str) -> str:
    # Stable hashing for lookup. (If you later want pepper/salt, do it carefully.)
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class ApiKey(Base):
    """
    API Key model with rotation support.

    SaaS-ready features:
    - Key versioning for rotation tracking
    - Expiration timestamps for TTL enforcement
    - Previous key hash for rotation chain
    - Last used tracking for security monitoring
    - Tenant isolation support
    """

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False, default="default")
    prefix = Column(String(64), nullable=False, index=True)
    key_hash = Column(Text, nullable=False, unique=True, index=True)
    key_lookup = Column(String(64), nullable=True, index=True)
    hash_alg = Column(String(32), nullable=True)
    hash_params = Column(JSON, nullable=True)
    scopes_csv = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)

    # Must be NOT NULL and must default for SQLite + ORM
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    # Key rotation and lifecycle support (SaaS-ready)
    version = Column(Integer, nullable=False, default=1, server_default=text("1"))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    rotated_from = Column(
        String(64), nullable=True
    )  # Previous key_hash for rotation chain
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    use_count = Column(Integer, nullable=False, default=0, server_default=text("0"))

    # Tenant isolation (multi-tenant SaaS)
    tenant_id = Column(
        String(128),
        nullable=True,
        index=True,
        default="unknown",
        server_default=text("'unknown'"),
    )

    # Security metadata
    created_by = Column(String(128), nullable=True)  # Who created the key
    description = Column(Text, nullable=True)  # Purpose/description


class SecurityAuditLog(Base):
    """
    Security audit log for compliance and forensics.

    Records all security-relevant events:
    - Authentication attempts (success/failure)
    - Key operations (create, revoke, rotate)
    - Rate limit events
    - Suspicious activity
    """

    __tablename__ = "security_audit_log"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "entry_hash", name="uq_security_audit_chain_entry"
        ),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    # Event classification
    event_type = Column(String(64), nullable=False, index=True)
    event_category = Column(String(32), nullable=False, default="security")
    severity = Column(
        String(16), nullable=False, default="info"
    )  # info, warning, error, critical

    # Actor information
    tenant_id = Column(String(128), nullable=True, index=True)
    key_prefix = Column(String(64), nullable=True)
    client_ip = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(512), nullable=True)

    # Request context
    request_id = Column(String(64), nullable=True, index=True)
    request_path = Column(String(256), nullable=True)
    request_method = Column(String(16), nullable=True)

    # Event details
    success = Column(Boolean, nullable=False, default=True)
    reason = Column(String(256), nullable=True)
    details_json = Column(JSON, nullable=True)

    chain_id = Column(
        String(128),
        nullable=False,
        default="global",
        server_default=text("'global'"),
        index=True,
    )
    prev_hash = Column(
        String(64), nullable=False, default="GENESIS", server_default=text("'GENESIS'")
    )
    entry_hash = Column(String(64), nullable=False, unique=True, index=True)


class ConfigVersion(Base):
    __tablename__ = "config_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "config_hash", name="uq_config_versions_tenant_hash"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    config_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    created_by = Column(String(128), nullable=True)
    config_json = Column(JSON, nullable=False, server_default=text("'{}'"))
    config_json_canonical = Column(Text, nullable=False)
    parent_hash = Column(String(64), nullable=True)


class TenantActiveConfig(Base):
    __tablename__ = "tenant_config_active"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "active_config_hash"],
            ["config_versions.tenant_id", "config_versions.config_hash"],
            name="fk_tenant_active_config",
        ),
    )

    tenant_id = Column(String(128), primary_key=True)
    active_config_hash = Column(String(64), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantAIConfig(Base):
    __tablename__ = "tenant_ai_config"

    tenant_id = Column(String(128), primary_key=True)
    ai_enabled = Column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    rpm_limit = Column(Integer, nullable=False, default=30, server_default=text("30"))
    daily_token_budget = Column(
        Integer, nullable=False, default=20000, server_default=text("20000")
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantAIUsage(Base):
    __tablename__ = "tenant_ai_usage"

    tenant_id = Column(String(128), primary_key=True)
    usage_day = Column(String(10), primary_key=True)
    minute_bucket = Column(String(16), nullable=False, default="")
    minute_requests = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    daily_tokens = Column(Integer, nullable=False, default=0, server_default=text("0"))
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class DecisionRecord(Base):
    __tablename__ = "decisions"
    __table_args__ = (
        Index(
            "ix_decisions_tenant_config_created",
            "tenant_id",
            "config_hash",
            "created_at",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "config_hash"],
            ["config_versions.tenant_id", "config_versions.config_hash"],
            name="fk_decisions_config_version",
        ),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    tenant_id = Column(String, nullable=True, index=True)
    source = Column(String, nullable=True)
    event_id = Column(String, nullable=True)
    event_type = Column(String, nullable=True)
    policy_hash = Column(String(64), nullable=True)
    config_hash = Column(
        String(64),
        nullable=False,
        index=True,
        default="legacy_config_hash",
        server_default=text("'legacy_config_hash'"),
    )

    threat_level = Column(String, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    ai_adversarial_score = Column(Float, nullable=True)
    pq_fallback = Column(Boolean, nullable=True)

    # DB-side defaults are REQUIRED because tests insert via raw sqlite and omit some columns.
    rules_triggered_json = Column(
        JSON,
        nullable=False,
        default=list,
        server_default=text("'[]'"),
    )
    decision_diff_json = Column(JSON, nullable=True)

    request_json = Column(
        JSON,
        nullable=False,
        server_default=text("'{}'"),
    )
    response_json = Column(
        JSON,
        nullable=False,
        server_default=text("'{}'"),
    )

    prev_hash = Column(String(64), nullable=True)
    chain_hash = Column(String(64), nullable=True)
    chain_alg = Column(String(64), nullable=True)
    chain_ts = Column(DateTime(timezone=True), nullable=True)


class BillingDevice(Base):
    __tablename__ = "billing_devices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_key", name="uq_billing_devices_tenant_key"
        ),
        Index("ix_billing_devices_tenant_status", "tenant_id", "status"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, default=lambda: str(uuid.uuid4()))
    device_key = Column(String(256), nullable=False)
    device_type = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="active")
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    labels = Column(JSON, nullable=False, default=dict, server_default=text("'{}'"))
    identity_confidence = Column(Integer, nullable=False, default=0)
    collision_signal = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    billable_state = Column(
        String(32),
        nullable=False,
        default="billable",
        server_default=text("'billable'"),
    )


class PricingVersion(Base):
    __tablename__ = "pricing_versions"

    pricing_version_id = Column(String(64), primary_key=True)
    effective_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    rates_json = Column(JSON, nullable=False, default=dict, server_default=text("'{}'"))
    sha256_hash = Column(String(64), nullable=False, unique=True)


class TenantContract(Base):
    __tablename__ = "tenant_contracts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "contract_id", name="uq_tenant_contracts_tenant_contract"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    contract_id = Column(String(128), nullable=False)
    pricing_version_id = Column(
        String(64), ForeignKey("pricing_versions.pricing_version_id"), nullable=False
    )
    discount_rules_json = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    commitment_minimum = Column(Float, nullable=False, default=0.0)
    start_at = Column(DateTime(timezone=True), nullable=False)
    end_at = Column(DateTime(timezone=True), nullable=True)
    contract_hash = Column(
        String(64), nullable=False, default="", server_default=text("''")
    )


class DeviceCoverageLedger(Base):
    __tablename__ = "device_coverage_ledger"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "event_id", name="uq_device_coverage_tenant_event"
        ),
        Index(
            "ix_device_coverage_tenant_device_from",
            "tenant_id",
            "device_id",
            "effective_from",
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    event_id = Column(String(128), nullable=False)
    device_id = Column(String(36), nullable=False, index=True)
    plan_id = Column(String(128), nullable=True, index=True)
    action = Column(String(16), nullable=False)
    effective_from = Column(DateTime(timezone=True), nullable=False)
    effective_to = Column(DateTime(timezone=True), nullable=True)
    pricing_version_id = Column(String(64), nullable=True)
    config_hash = Column(String(64), nullable=False)
    policy_hash = Column(String(64), nullable=False)
    source = Column(String(64), nullable=False, default="api")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    self_hash = Column(String(64), nullable=False, unique=True)
    signature = Column(String(256), nullable=True)


class BillingIdentityClaim(Base):
    __tablename__ = "billing_identity_claims"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "claimed_id_type",
            "claimed_id_value",
            name="uq_billing_identity_claims_tenant_claim",
        ),
        Index("ix_billing_identity_claims_tenant_device", "tenant_id", "device_id"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    claimed_id_type = Column(String(32), nullable=False)
    claimed_id_value = Column(String(512), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    source_agent_id = Column(String(256), nullable=True)
    source_ip = Column(String(64), nullable=True)
    attestation_level = Column(String(32), nullable=False, default="none")
    conflict_state = Column(
        String(32),
        nullable=False,
        default="clean",
        server_default=text("'clean'"),
    )


class BillingCoverageDailyState(Base):
    __tablename__ = "billing_coverage_daily_state"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "device_id",
            "coverage_day",
            name="uq_billing_coverage_daily_state_tenant_device_day",
        ),
        Index(
            "ix_billing_coverage_daily_state_tenant_day", "tenant_id", "coverage_day"
        ),
        Index(
            "ix_billing_coverage_daily_state_tenant_device_day",
            "tenant_id",
            "device_id",
            "coverage_day",
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    coverage_day = Column(Date, nullable=False, index=True)
    coverage_state = Column(String(16), nullable=False)
    plan_id = Column(String(128), nullable=True)
    source_event_id = Column(String(128), nullable=False)
    source_event_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingCountSyncCheckpoint(Base):
    __tablename__ = "billing_count_sync_checkpoints"

    tenant_id = Column(String(128), primary_key=True)
    last_ledger_id = Column(Integer, nullable=False, default=0)
    processed_digest = Column(String(64), nullable=False, default="GENESIS")
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    self_hash = Column(String(64), nullable=False, default="GENESIS")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingCountSyncCheckpointEvent(Base):
    __tablename__ = "billing_count_sync_checkpoint_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "sequence", name="uq_billing_sync_checkpoint_events_seq"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    from_ledger_id = Column(Integer, nullable=False)
    to_ledger_id = Column(Integer, nullable=False)
    processed_digest = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    self_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingIdentityClaimEvent(Base):
    __tablename__ = "billing_identity_claim_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "claim_id",
            "sequence",
            name="uq_billing_identity_claim_events_seq",
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    claim_id = Column(Integer, nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    transition = Column(String(64), nullable=False)
    from_state = Column(String(32), nullable=True)
    to_state = Column(String(32), nullable=False)
    actor = Column(String(128), nullable=True)
    reason = Column(Text, nullable=True)
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    self_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingRun(Base):
    __tablename__ = "billing_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "run_id", name="uq_billing_runs_tenant_run"),
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_billing_runs_tenant_idempotency"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    run_id = Column(String(128), nullable=False)
    replay_id = Column(String(128), nullable=False)
    idempotency_key = Column(String(128), nullable=False, index=True)
    pricing_version_id = Column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    contract_hash = Column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(32), nullable=False, default="scheduled")
    invoice_id = Column(String(128), nullable=True)
    export_path = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingInvoiceStateEvent(Base):
    __tablename__ = "billing_invoice_state_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "invoice_id",
            "sequence",
            name="uq_billing_invoice_state_events_seq",
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    invoice_id = Column(String(128), nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    transition = Column(String(64), nullable=False)
    from_state = Column(String(32), nullable=True)
    to_state = Column(String(32), nullable=False)
    actor = Column(String(128), nullable=False)
    authority_ticket_id = Column(String(128), nullable=False)
    reason = Column(Text, nullable=False)
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    self_hash = Column(String(64), nullable=False, unique=True)
    signature = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingCreditNote(Base):
    __tablename__ = "billing_credit_notes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "credit_note_id", name="uq_billing_credit_notes_tenant_credit"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    credit_note_id = Column(String(128), nullable=False)
    invoice_id = Column(String(128), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(8), nullable=False, default="USD")
    reason = Column(Text, nullable=False)
    ticket_id = Column(String(128), nullable=False)
    created_by = Column(String(128), nullable=False)
    credit_json = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    credit_sha256 = Column(String(64), nullable=False)
    evidence_path = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingDeviceEnrollment(Base):
    __tablename__ = "billing_device_enrollments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_id", name="uq_billing_device_enrollments_device"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    attestation_type = Column(String(64), nullable=False)
    attestation_payload_hash = Column(String(64), nullable=False)
    enrolled_by = Column(String(128), nullable=False)
    enrolled_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingDeviceActivityProof(Base):
    __tablename__ = "billing_device_activity_proofs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "device_id",
            "activity_day",
            "proof_hash",
            name="uq_billing_activity_proof",
        ),
        Index("ix_billing_activity_tenant_day", "tenant_id", "activity_day"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    activity_day = Column(Date, nullable=False, index=True)
    proof_type = Column(String(64), nullable=False)
    proof_hash = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingDailyCount(Base):
    __tablename__ = "billing_daily_counts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "day",
            "plan_id",
            name="uq_billing_daily_counts_tenant_day_plan",
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    day = Column(Date, nullable=False, index=True)
    plan_id = Column(String(128), nullable=False)
    covered_count = Column(Integer, nullable=False, default=0)
    computed_from_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class BillingInvoice(Base):
    __tablename__ = "billing_invoices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "invoice_id", name="uq_billing_invoices_tenant_invoice"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    invoice_id = Column(String(128), nullable=False)
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    pricing_version_id = Column(String(64), nullable=False)
    pricing_hash = Column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    contract_hash = Column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    config_hash = Column(String(64), nullable=False)
    policy_hash = Column(String(64), nullable=False)
    invoice_json = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    invoice_sha256 = Column(String(64), nullable=False)
    evidence_path = Column(String(512), nullable=True)
    invoice_state = Column(
        String(32), nullable=False, default="draft", server_default=text("'draft'")
    )
    finalized_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


@event.listens_for(TenantContract, "before_insert")
def _tenant_contract_hash_defaults(mapper, connection, target) -> None:
    payload = {
        "tenant_id": target.tenant_id,
        "contract_id": target.contract_id,
        "pricing_version_id": target.pricing_version_id,
        "discount_rules_json": target.discount_rules_json or {},
        "commitment_minimum": float(target.commitment_minimum or 0.0),
        "start_at": target.start_at.isoformat() if target.start_at else None,
        "end_at": target.end_at.isoformat() if target.end_at else None,
    }
    target.contract_hash = canonical_hash(payload)


@event.listens_for(BillingIdentityClaimEvent, "before_insert")
def _identity_claim_event_hash_defaults(mapper, connection, target) -> None:
    payload = {
        "tenant_id": target.tenant_id,
        "claim_id": target.claim_id,
        "sequence": target.sequence,
        "transition": target.transition,
        "from_state": target.from_state,
        "to_state": target.to_state,
        "actor": target.actor,
        "reason": target.reason,
        "prev_hash": target.prev_hash,
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }
    target.self_hash = canonical_hash(payload)


@event.listens_for(BillingCountSyncCheckpointEvent, "before_insert")
def _checkpoint_event_hash_defaults(mapper, connection, target) -> None:
    payload = {
        "tenant_id": target.tenant_id,
        "sequence": target.sequence,
        "from_ledger_id": target.from_ledger_id,
        "to_ledger_id": target.to_ledger_id,
        "processed_digest": target.processed_digest,
        "prev_hash": target.prev_hash,
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }
    target.self_hash = canonical_hash(payload)


@event.listens_for(BillingInvoiceStateEvent, "before_insert")
def _invoice_state_event_hash_defaults(mapper, connection, target) -> None:
    payload = {
        "tenant_id": target.tenant_id,
        "invoice_id": target.invoice_id,
        "sequence": target.sequence,
        "transition": target.transition,
        "from_state": target.from_state,
        "to_state": target.to_state,
        "actor": target.actor,
        "authority_ticket_id": target.authority_ticket_id,
        "reason": target.reason,
        "prev_hash": target.prev_hash,
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }
    target.self_hash = canonical_hash(payload)


@event.listens_for(DeviceCoverageLedger, "before_insert")
def _coverage_ledger_defaults(mapper, connection, target) -> None:
    payload = {
        "tenant_id": target.tenant_id,
        "event_id": target.event_id,
        "device_id": target.device_id,
        "plan_id": target.plan_id,
        "action": target.action,
        "effective_from": target.effective_from.isoformat()
        if target.effective_from
        else None,
        "effective_to": target.effective_to.isoformat()
        if target.effective_to
        else None,
        "pricing_version_id": target.pricing_version_id,
        "config_hash": target.config_hash,
        "policy_hash": target.policy_hash,
        "source": target.source,
        "created_at": target.created_at.isoformat() if target.created_at else None,
        "prev_hash": target.prev_hash,
    }
    target.self_hash = canonical_hash(payload)


class DecisionEvidenceArtifact(Base):
    __tablename__ = "decision_evidence_artifacts"

    id = Column(Integer, primary_key=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    tenant_id = Column(String, nullable=True, index=True)
    decision_id = Column(Integer, nullable=False, index=True)
    evidence_sha256 = Column(String(64), nullable=False)
    storage_path = Column(Text, nullable=False)
    payload_json = Column(JSON, nullable=False)


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    subject_type = Column(String(64), nullable=False, index=True)
    subject_id = Column(String(128), nullable=False, index=True)
    bundle_json = Column(JSON, nullable=False)
    bundle_hash = Column(String(64), nullable=False, index=True)
    signature = Column(Text, nullable=False)
    key_id = Column(String(128), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class ApprovalLog(Base):
    __tablename__ = "approval_logs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "subject_type", "subject_id", "seq", name="uq_approval_seq"
        ),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    subject_type = Column(String(64), nullable=False, index=True)
    subject_id = Column(String(128), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    entry_json = Column(JSON, nullable=False)
    entry_hash = Column(String(64), nullable=False)
    prev_chain_hash = Column(String(64), nullable=False)
    chain_hash = Column(String(64), nullable=False, index=True)
    signature = Column(Text, nullable=False)
    key_id = Column(String(128), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class ModuleRegistry(Base):
    __tablename__ = "module_registry"

    module_id = Column(String(128), primary_key=True)
    version = Column(String(64), primary_key=True)
    record_json = Column(JSON, nullable=False)
    registration_hash = Column(String(64), nullable=False, index=True)
    signature = Column(Text, nullable=False)
    key_id = Column(String(128), nullable=False)
    registered_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
        index=True,
    )


def _raise_immutable(mapper, connection, target) -> None:
    raise ValueError(f"{target.__class__.__name__} rows are append-only")


event.listen(DecisionRecord, "before_update", _raise_immutable)
event.listen(DecisionRecord, "before_delete", _raise_immutable)
event.listen(DecisionEvidenceArtifact, "before_update", _raise_immutable)
event.listen(DecisionEvidenceArtifact, "before_delete", _raise_immutable)
event.listen(EvidenceBundle, "before_update", _raise_immutable)
event.listen(EvidenceBundle, "before_delete", _raise_immutable)
event.listen(ApprovalLog, "before_update", _raise_immutable)
event.listen(ApprovalLog, "before_delete", _raise_immutable)
event.listen(ModuleRegistry, "before_update", _raise_immutable)
event.listen(ModuleRegistry, "before_delete", _raise_immutable)


class PolicyChangeRequest(Base):
    """
    Persistent storage for governance policy change requests.

    Security requirements (P0):
    - Survives restart (database-backed)
    - Auditable (all changes logged with timestamps)
    - Fail-closed on DB error
    """

    __tablename__ = "policy_change_requests"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    change_id = Column(String(64), unique=True, nullable=False, index=True)
    change_type = Column(String(64), nullable=False)
    proposed_by = Column(String(128), nullable=False)
    proposed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    justification = Column(Text, nullable=False)

    # Policy content (nullable for different change types)
    rule_definition_json = Column(JSON, nullable=True)
    roe_update_json = Column(JSON, nullable=True)

    # Simulation and confidence
    simulation_results_json = Column(JSON, nullable=False, default=dict)
    estimated_false_positives = Column(Integer, nullable=False, default=0)
    estimated_true_positives = Column(Integer, nullable=False, default=0)
    confidence = Column(String(16), nullable=False, default="medium")

    # Approval workflow
    requires_approval_from_json = Column(JSON, nullable=False, default=list)
    approvals_json = Column(JSON, nullable=False, default=list)
    status = Column(String(32), nullable=False, default="pending", index=True)
    deployed_at = Column(DateTime(timezone=True), nullable=True)


@event.listens_for(SecurityAuditLog, "before_insert")
def _security_audit_defaults(mapper, connection, target) -> None:
    if not getattr(target, "chain_id", None):
        target.chain_id = target.tenant_id or "global"
    if not getattr(target, "prev_hash", None):
        target.prev_hash = "GENESIS"
    if not getattr(target, "entry_hash", None):
        payload = {
            "tenant_id": target.tenant_id,
            "event_type": target.event_type,
            "severity": target.severity,
            "success": bool(target.success),
            "reason": target.reason,
            "created_at": target.created_at.isoformat() if target.created_at else None,
            "nonce": str(uuid.uuid4()),
        }
        target.entry_hash = hashlib.sha256(
            f"{target.prev_hash}|{json.dumps(payload, sort_keys=True)}".encode("utf-8")
        ).hexdigest()
