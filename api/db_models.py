# api/db_models.py
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from api.signed_artifacts import canonical_hash


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    name: Mapped[Any] = mapped_column(String(128), nullable=False, default="default")
    prefix: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    key_hash: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    key_lookup: Mapped[Any] = mapped_column(String(64), nullable=True, index=True)
    hash_alg: Mapped[Any] = mapped_column(String(32), nullable=True)
    hash_params: Mapped[Any] = mapped_column(JSON, nullable=True)
    scopes_csv: Mapped[Any] = mapped_column(Text, nullable=True)
    enabled: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)

    # Must be NOT NULL and must default for SQLite + ORM
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    # Key rotation and lifecycle support (SaaS-ready)
    version: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_from: Mapped[Any] = mapped_column(
        String(64), nullable=True
    )  # previous key_hash
    last_used_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    use_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    # Tenant isolation (multi-tenant SaaS)
    tenant_id: Mapped[Any] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        default="unknown",
        server_default=text("'unknown'"),
    )

    # Security metadata
    created_by: Mapped[Any] = mapped_column(String(128), nullable=True)
    description: Mapped[Any] = mapped_column(Text, nullable=True)


class SecurityAuditLog(Base):
    """
    Security audit log for compliance and forensics.
    """

    __tablename__ = "security_audit_log"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "entry_hash", name="uq_security_audit_chain_entry"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    event_type: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    event_category: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="security"
    )
    severity: Mapped[Any] = mapped_column(String(16), nullable=False, default="info")

    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    key_prefix: Mapped[Any] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[Any] = mapped_column(String(45), nullable=True)  # IPv6 max length
    user_agent: Mapped[Any] = mapped_column(String(512), nullable=True)

    request_id: Mapped[Any] = mapped_column(String(64), nullable=True, index=True)
    request_path: Mapped[Any] = mapped_column(String(256), nullable=True)
    request_method: Mapped[Any] = mapped_column(String(16), nullable=True)

    success: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    reason: Mapped[Any] = mapped_column(String(256), nullable=True)
    details_json: Mapped[Any] = mapped_column(JSON, nullable=True)

    chain_id: Mapped[Any] = mapped_column(
        String(128),
        nullable=False,
        default="global",
        server_default=text("'global'"),
        index=True,
    )
    prev_hash: Mapped[Any] = mapped_column(
        String(64),
        nullable=False,
        default="GENESIS",
        server_default=text("'GENESIS'"),
    )
    entry_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    created_by: Mapped[Any] = mapped_column(
        String(128), nullable=False, default="unknown"
    )
    reason: Mapped[Any] = mapped_column(
        String(256), nullable=False, default="unspecified"
    )
    ticket: Mapped[Any] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    max_uses: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    used_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentDeviceRegistry(Base):
    __tablename__ = "agent_device_registry"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    fingerprint_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    status: Mapped[Any] = mapped_column(
        String(16), nullable=False, default="active", index=True
    )
    suspicious: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    last_seen_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[Any] = mapped_column(String(64), nullable=True)
    last_version: Mapped[Any] = mapped_column(String(64), nullable=True)
    ring: Mapped[Any] = mapped_column(
        String(16), nullable=False, default="broad", server_default=text("'broad'")
    )


class AgentDeviceKey(Base):
    __tablename__ = "agent_device_keys"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Any] = mapped_column(
        String(64),
        ForeignKey("agent_device_registry.device_id"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    key_prefix: Mapped[Any] = mapped_column(
        String(32), nullable=False, unique=True, index=True
    )
    key_hash: Mapped[Any] = mapped_column(Text, nullable=False)
    key_lookup: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    hash_alg: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="argon2id"
    )
    hmac_secret_enc: Mapped[Any] = mapped_column(Text, nullable=False)
    enabled: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("1")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentDeviceNonce(Base):
    __tablename__ = "agent_device_nonces"
    __table_args__ = (
        Index("ix_agent_device_nonces_device_created", "device_id", "created_at"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    nonce_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentDeviceIdentity(Base):
    __tablename__ = "agent_device_identities"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    cert_fingerprint: Mapped[Any] = mapped_column(
        String(64), nullable=False, index=True
    )
    cert_pem: Mapped[Any] = mapped_column(Text, nullable=False)
    cert_chain_pem: Mapped[Any] = mapped_column(Text, nullable=True)
    cert_not_after: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[Any] = mapped_column(
        String(16), nullable=False, default="active", index=True
    )
    last_seen_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentTenantConfig(Base):
    """Per-tenant agent lifecycle configuration (version floor, etc.)."""

    __tablename__ = "agent_tenant_configs"

    tenant_id: Mapped[Any] = mapped_column(String(128), primary_key=True)
    version_floor: Mapped[Any] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[Any] = mapped_column(String(128), nullable=True)


class AgentCollectorStatus(Base):
    """Last-known collector run outcome per device, reported via heartbeat."""

    __tablename__ = "agent_collector_statuses"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "collector_name",
            name="uq_agent_collector_statuses_device_name",
        ),
        Index("ix_agent_collector_statuses_device", "device_id"),
        Index("ix_agent_collector_statuses_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Any] = mapped_column(
        String(64),
        ForeignKey("agent_device_registry.device_id"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    collector_name: Mapped[Any] = mapped_column(String(128), nullable=False)
    last_outcome: Mapped[Any] = mapped_column(
        String(16), nullable=False
    )  # "ran" | "failed" | "skipped"
    last_run_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_error: Mapped[Any] = mapped_column(Text, nullable=True)


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    command_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    command_type: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[Any] = mapped_column(
        JSON, nullable=False, server_default=text("'{}'")
    )
    issued_by: Mapped[Any] = mapped_column(String(128), nullable=False)
    issued_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    nonce: Mapped[Any] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    lease_owner: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    lease_expires_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    status: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="issued", index=True
    )
    terminal_state: Mapped[Any] = mapped_column(String(32), nullable=True, index=True)
    acked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentUpdateRollout(Base):
    __tablename__ = "agent_update_rollouts"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    canary_percent_per_hour: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=10
    )
    pilot_percent_per_hour: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=30
    )
    broad_percent_per_hour: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=100
    )
    canary_error_budget: Mapped[Any] = mapped_column(Integer, nullable=False, default=5)
    canary_error_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    paused: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    kill_switch: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentRateBudgetCounter(Base):
    __tablename__ = "agent_rate_budget_counters"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(64), nullable=True, index=True)
    metric: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    window_start: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentPolicyBundle(Base):
    __tablename__ = "agent_policy_bundles"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[Any] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    policy_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, server_default=text("'{}'")
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    revoked: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentLogAnchor(Base):
    __tablename__ = "agent_log_anchors"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    anchored_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AgentQuarantineEvent(Base):
    __tablename__ = "agent_quarantine_events"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[Any] = mapped_column(String(32), nullable=False)
    reason: Mapped[Any] = mapped_column(String(512), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class ConfigVersion(Base):
    __tablename__ = "config_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "config_hash", name="uq_config_versions_tenant_hash"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    config_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    created_by: Mapped[Any] = mapped_column(String(128), nullable=True)
    config_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, server_default=text("'{}'")
    )
    config_json_canonical: Mapped[Any] = mapped_column(Text, nullable=False)
    parent_hash: Mapped[Any] = mapped_column(String(64), nullable=True)


class TenantActiveConfig(Base):
    __tablename__ = "tenant_config_active"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "active_config_hash"],
            ["config_versions.tenant_id", "config_versions.config_hash"],
            name="fk_tenant_active_config",
        ),
    )

    tenant_id: Mapped[Any] = mapped_column(String(128), primary_key=True)
    active_config_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[Any] = mapped_column(
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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    tenant_id: Mapped[Any] = mapped_column(String, nullable=True, index=True)
    source: Mapped[Any] = mapped_column(String, nullable=True)
    event_id: Mapped[Any] = mapped_column(String, nullable=True)
    event_type: Mapped[Any] = mapped_column(String, nullable=True)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=True)
    config_hash: Mapped[Any] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default="legacy_config_hash",
        server_default=text("'legacy_config_hash'"),
    )

    threat_level: Mapped[Any] = mapped_column(String, nullable=True)
    anomaly_score: Mapped[Any] = mapped_column(Float, nullable=True)
    ai_adversarial_score: Mapped[Any] = mapped_column(Float, nullable=True)
    pq_fallback: Mapped[Any] = mapped_column(Boolean, nullable=True)

    rules_triggered_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    decision_diff_json: Mapped[Any] = mapped_column(JSON, nullable=True)

    request_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, server_default=text("'{}'")
    )
    response_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, server_default=text("'{}'")
    )

    prev_hash: Mapped[Any] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[Any] = mapped_column(String(64), nullable=True)
    chain_alg: Mapped[Any] = mapped_column(String(64), nullable=True)
    chain_ts: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


class BillingDevice(Base):
    __tablename__ = "billing_devices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_key", name="uq_billing_devices_tenant_key"
        ),
        Index("ix_billing_devices_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(
        String(36), nullable=False, default=lambda: str(uuid.uuid4())
    )
    device_key: Mapped[Any] = mapped_column(String(256), nullable=False)
    device_type: Mapped[Any] = mapped_column(String(64), nullable=False)
    status: Mapped[Any] = mapped_column(String(32), nullable=False, default="active")
    first_seen_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    labels: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    identity_confidence: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    collision_signal: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    billable_state: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="billable",
        server_default=text("'billable'"),
    )


class AIDeviceRegistry(Base):
    __tablename__ = "ai_device_registry"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_id", name="uq_ai_device_registry_tenant_device"
        ),
        Index("ix_ai_device_registry_tenant_enabled", "tenant_id", "enabled"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    enabled: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    registered_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    telemetry_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )


class AITokenUsage(Base):
    __tablename__ = "ai_token_usage"
    __table_args__ = (
        Index("ix_ai_token_usage_tenant_day", "tenant_id", "usage_day"),
        Index(
            "ix_ai_token_usage_tenant_device_day", "tenant_id", "device_id", "usage_day"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    usage_record_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    persona: Mapped[Any] = mapped_column(String(64), nullable=False, default="default")
    provider: Mapped[Any] = mapped_column(String(64), nullable=False)
    model: Mapped[Any] = mapped_column(String(128), nullable=False)
    prompt_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    total_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    usage_day: Mapped[Any] = mapped_column(String(10), nullable=False, index=True)
    metering_mode: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    estimation_mode: Mapped[Any] = mapped_column(
        String(16), nullable=False, default="estimated"
    )
    request_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    experience_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AIQuotaDaily(Base):
    __tablename__ = "ai_quota_daily"
    __table_args__ = (
        UniqueConstraint(
            "quota_scope", "usage_day", name="uq_ai_quota_daily_scope_day"
        ),
        Index("ix_ai_quota_daily_tenant_day", "tenant_id", "usage_day"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    quota_scope: Mapped[Any] = mapped_column(String(256), nullable=False, index=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    usage_day: Mapped[Any] = mapped_column(String(10), nullable=False, index=True)
    token_limit: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    used_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class PricingVersion(Base):
    __tablename__ = "pricing_versions"

    pricing_version_id: Mapped[Any] = mapped_column(String(64), primary_key=True)
    effective_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    rates_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    sha256_hash: Mapped[Any] = mapped_column(String(64), nullable=False, unique=True)


class TenantContract(Base):
    __tablename__ = "tenant_contracts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "contract_id", name="uq_tenant_contracts_tenant_contract"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    contract_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    pricing_version_id: Mapped[Any] = mapped_column(
        String(64), ForeignKey("pricing_versions.pricing_version_id"), nullable=False
    )
    discount_rules_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    commitment_minimum: Mapped[Any] = mapped_column(Float, nullable=False, default=0.0)
    start_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    contract_hash: Mapped[Any] = mapped_column(
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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    event_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    device_id: Mapped[Any] = mapped_column(String(36), nullable=False, index=True)
    plan_id: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    action: Mapped[Any] = mapped_column(String(16), nullable=False)
    effective_from: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_to: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    pricing_version_id: Mapped[Any] = mapped_column(String(64), nullable=True)
    config_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    source: Mapped[Any] = mapped_column(String(64), nullable=False, default="api")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    prev_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    self_hash: Mapped[Any] = mapped_column(String(64), nullable=False, unique=True)
    signature: Mapped[Any] = mapped_column(String(256), nullable=True)


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(36), nullable=False, index=True)
    claimed_id_type: Mapped[Any] = mapped_column(String(32), nullable=False)
    claimed_id_value: Mapped[Any] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    source_agent_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    source_ip: Mapped[Any] = mapped_column(String(64), nullable=True)
    attestation_level: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="none"
    )
    conflict_state: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="clean", server_default=text("'clean'")
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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(36), nullable=False, index=True)
    coverage_day: Mapped[Any] = mapped_column(Date, nullable=False, index=True)
    coverage_state: Mapped[Any] = mapped_column(String(16), nullable=False)
    plan_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    source_event_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    source_event_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingCountSyncCheckpoint(Base):
    __tablename__ = "billing_count_sync_checkpoints"

    tenant_id: Mapped[Any] = mapped_column(String(128), primary_key=True)
    last_ledger_id: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    processed_digest: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    prev_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    self_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingCountSyncCheckpointEvent(Base):
    __tablename__ = "billing_count_sync_checkpoint_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "sequence", name="uq_billing_sync_checkpoint_events_seq"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    sequence: Mapped[Any] = mapped_column(Integer, nullable=False)
    from_ledger_id: Mapped[Any] = mapped_column(Integer, nullable=False)
    to_ledger_id: Mapped[Any] = mapped_column(Integer, nullable=False)
    processed_digest: Mapped[Any] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    self_hash: Mapped[Any] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    claim_id: Mapped[Any] = mapped_column(Integer, nullable=False, index=True)
    sequence: Mapped[Any] = mapped_column(Integer, nullable=False)
    transition: Mapped[Any] = mapped_column(String(64), nullable=False)
    from_state: Mapped[Any] = mapped_column(String(32), nullable=True)
    to_state: Mapped[Any] = mapped_column(String(32), nullable=False)
    actor: Mapped[Any] = mapped_column(String(128), nullable=True)
    reason: Mapped[Any] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    self_hash: Mapped[Any] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingRun(Base):
    __tablename__ = "billing_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "run_id", name="uq_billing_runs_tenant_run"),
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_billing_runs_tenant_idempotency"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    run_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    replay_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[Any] = mapped_column(
        String(128), nullable=False, index=True
    )
    pricing_version_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    contract_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    period_start: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[Any] = mapped_column(String(32), nullable=False, default="scheduled")
    invoice_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    export_path: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    invoice_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    sequence: Mapped[Any] = mapped_column(Integer, nullable=False)
    transition: Mapped[Any] = mapped_column(String(64), nullable=False)
    from_state: Mapped[Any] = mapped_column(String(32), nullable=True)
    to_state: Mapped[Any] = mapped_column(String(32), nullable=False)
    actor: Mapped[Any] = mapped_column(String(128), nullable=False)
    authority_ticket_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    reason: Mapped[Any] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    self_hash: Mapped[Any] = mapped_column(String(64), nullable=False, unique=True)
    signature: Mapped[Any] = mapped_column(String(256), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingCreditNote(Base):
    __tablename__ = "billing_credit_notes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "credit_note_id", name="uq_billing_credit_notes_tenant_credit"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    credit_note_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    invoice_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    amount: Mapped[Any] = mapped_column(Float, nullable=False)
    currency: Mapped[Any] = mapped_column(String(8), nullable=False, default="USD")
    reason: Mapped[Any] = mapped_column(Text, nullable=False)
    ticket_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    created_by: Mapped[Any] = mapped_column(String(128), nullable=False)
    credit_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    credit_sha256: Mapped[Any] = mapped_column(String(64), nullable=False)
    evidence_path: Mapped[Any] = mapped_column(String(512), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingDeviceEnrollment(Base):
    __tablename__ = "billing_device_enrollments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "device_id", name="uq_billing_device_enrollments_device"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(36), nullable=False, index=True)
    attestation_type: Mapped[Any] = mapped_column(String(64), nullable=False)
    attestation_payload_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    enrolled_by: Mapped[Any] = mapped_column(String(128), nullable=False)
    enrolled_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[Any] = mapped_column(String(36), nullable=False, index=True)
    activity_day: Mapped[Any] = mapped_column(Date, nullable=False, index=True)
    proof_type: Mapped[Any] = mapped_column(String(64), nullable=False)
    proof_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    day: Mapped[Any] = mapped_column(Date, nullable=False, index=True)
    plan_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    covered_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    computed_from_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingInvoice(Base):
    __tablename__ = "billing_invoices"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "invoice_id", name="uq_billing_invoices_tenant_invoice"
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    invoice_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    period_start: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    pricing_version_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    pricing_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    contract_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="", server_default=text("''")
    )
    config_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    invoice_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    invoice_sha256: Mapped[Any] = mapped_column(String(64), nullable=False)
    evidence_path: Mapped[Any] = mapped_column(String(512), nullable=True)
    invoice_state: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="draft", server_default=text("'draft'")
    )
    finalized_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    tenant_id: Mapped[Any] = mapped_column(String, nullable=True, index=True)
    decision_id: Mapped[Any] = mapped_column(Integer, nullable=False, index=True)
    evidence_sha256: Mapped[Any] = mapped_column(String(64), nullable=False)
    storage_path: Mapped[Any] = mapped_column(Text, nullable=False)
    payload_json: Mapped[Any] = mapped_column(JSON, nullable=False)


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id: Mapped[Any] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    subject_type: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    subject_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    bundle_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    bundle_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    created_at: Mapped[Any] = mapped_column(
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

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    subject_type: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    subject_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    seq: Mapped[Any] = mapped_column(Integer, nullable=False)
    entry_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    entry_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    prev_chain_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class ModuleRegistry(Base):
    __tablename__ = "module_registry"

    module_id: Mapped[Any] = mapped_column(String(128), primary_key=True)
    version: Mapped[Any] = mapped_column(String(64), primary_key=True)
    record_json: Mapped[Any] = mapped_column(JSON, nullable=False)
    registration_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, index=True
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    registered_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
        index=True,
    )


class ComplianceRequirementRecord(Base):
    __tablename__ = "compliance_requirements"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    req_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    source: Mapped[Any] = mapped_column(String(32), nullable=False)
    source_ref: Mapped[Any] = mapped_column(String(256), nullable=False)
    title: Mapped[Any] = mapped_column(String(256), nullable=False)
    description: Mapped[Any] = mapped_column(Text, nullable=False)
    severity: Mapped[Any] = mapped_column(String(16), nullable=False)
    effective_date_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    version: Mapped[Any] = mapped_column(String(64), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    evidence_type: Mapped[Any] = mapped_column(String(16), nullable=False)
    owner: Mapped[Any] = mapped_column(String(128), nullable=False)
    source_name: Mapped[Any] = mapped_column(String(128), nullable=True)
    source_version: Mapped[Any] = mapped_column(String(64), nullable=True)
    published_at_utc: Mapped[Any] = mapped_column(String(64), nullable=True)
    retrieved_at_utc: Mapped[Any] = mapped_column(String(64), nullable=True)
    bundle_sha256: Mapped[Any] = mapped_column(String(64), nullable=True)
    tags_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    created_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    previous_record_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "req_id": self.req_id,
            "source": self.source,
            "source_ref": self.source_ref,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "effective_date_utc": self.effective_date_utc,
            "version": self.version,
            "status": self.status,
            "evidence_type": self.evidence_type,
            "owner": self.owner,
            "source_name": self.source_name,
            "source_version": self.source_version,
            "published_at_utc": self.published_at_utc,
            "retrieved_at_utc": self.retrieved_at_utc,
            "bundle_sha256": self.bundle_sha256,
            "tags": self.tags_json,
            "created_at_utc": self.created_at_utc,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


class ComplianceFindingRecord(Base):
    __tablename__ = "compliance_findings"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    finding_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    req_ids_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    title: Mapped[Any] = mapped_column(String(256), nullable=False)
    details: Mapped[Any] = mapped_column(Text, nullable=False)
    severity: Mapped[Any] = mapped_column(String(16), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False, index=True)
    waiver_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    detected_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    evidence_refs_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    created_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    previous_record_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "req_ids": self.req_ids_json,
            "title": self.title,
            "details": self.details,
            "severity": self.severity,
            "status": self.status,
            "waiver": self.waiver_json,
            "detected_at_utc": self.detected_at_utc,
            "evidence_refs": self.evidence_refs_json,
            "created_at_utc": self.created_at_utc,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


class ComplianceSnapshotRecord(Base):
    __tablename__ = "compliance_snapshots"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    snapshot_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    summary_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    created_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    previous_record_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class AuditExamSession(Base):
    __tablename__ = "audit_exam_sessions"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    exam_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[Any] = mapped_column(String(128), nullable=False)
    window_start_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    window_end_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    export_path: Mapped[Any] = mapped_column(String(512), nullable=True)
    reproduce_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    previous_record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="GENESIS"
    )
    record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True, default=""
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    key_id: Mapped[Any] = mapped_column(String(64), nullable=False, default="")


class ComplianceRequirementUpdateRecord(Base):
    __tablename__ = "compliance_requirement_updates"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    update_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    source_name: Mapped[Any] = mapped_column(String(128), nullable=False)
    source_version: Mapped[Any] = mapped_column(String(64), nullable=False)
    published_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    retrieved_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)
    bundle_sha256: Mapped[Any] = mapped_column(String(64), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False, index=True)
    diff_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    previous_record_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    key_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    created_at_utc: Mapped[Any] = mapped_column(String(64), nullable=False)


class AuditLedgerRecord(Base):
    __tablename__ = "audit_ledger"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    cycle_kind: Mapped[Any] = mapped_column(String(16), nullable=False, default="light")
    timestamp_utc: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    invariant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    decision: Mapped[Any] = mapped_column(String(8), nullable=False)
    config_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    git_commit: Mapped[Any] = mapped_column(String(64), nullable=False)
    runtime_version: Mapped[Any] = mapped_column(String(64), nullable=False)
    host_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[Any] = mapped_column(
        String(128), nullable=False, index=True, default="unknown"
    )
    sha256_engine_code_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, default=""
    )
    sha256_self_hash: Mapped[Any] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    previous_record_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    signature: Mapped[Any] = mapped_column(Text, nullable=False)
    details_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "cycle_kind": self.cycle_kind,
            "timestamp_utc": self.timestamp_utc,
            "invariant_id": self.invariant_id,
            "decision": self.decision,
            "config_hash": self.config_hash,
            "policy_hash": self.policy_hash,
            "git_commit": self.git_commit,
            "runtime_version": self.runtime_version,
            "host_id": self.host_id,
            "tenant_id": self.tenant_id,
            "sha256_engine_code_hash": self.sha256_engine_code_hash,
            "sha256_self_hash": self.sha256_self_hash,
            "previous_record_hash": self.previous_record_hash,
            "signature": self.signature,
            "details_json": self.details_json,
        }


def _raise_immutable(mapper, connection, target) -> None:
    raise ValueError(f"{target.__class__.__name__} rows are append-only")


# append-only enforcement (ORM-level)
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
event.listen(AuditLedgerRecord, "before_update", _raise_immutable)
event.listen(AuditLedgerRecord, "before_delete", _raise_immutable)
event.listen(ComplianceRequirementRecord, "before_update", _raise_immutable)
event.listen(ComplianceRequirementRecord, "before_delete", _raise_immutable)
event.listen(ComplianceFindingRecord, "before_update", _raise_immutable)
event.listen(ComplianceFindingRecord, "before_delete", _raise_immutable)
event.listen(ComplianceSnapshotRecord, "before_update", _raise_immutable)
event.listen(ComplianceSnapshotRecord, "before_delete", _raise_immutable)
event.listen(AuditExamSession, "before_update", _raise_immutable)
event.listen(AuditExamSession, "before_delete", _raise_immutable)
event.listen(ComplianceRequirementUpdateRecord, "before_update", _raise_immutable)
event.listen(ComplianceRequirementUpdateRecord, "before_delete", _raise_immutable)


class PolicyChangeRequest(Base):
    """
    Persistent storage for governance policy change requests.
    """

    __tablename__ = "policy_change_requests"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    change_id: Mapped[Any] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    change_type: Mapped[Any] = mapped_column(String(64), nullable=False)
    proposed_by: Mapped[Any] = mapped_column(String(128), nullable=False)
    proposed_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    justification: Mapped[Any] = mapped_column(Text, nullable=False)

    rule_definition_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    roe_update_json: Mapped[Any] = mapped_column(JSON, nullable=True)

    simulation_results_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    estimated_false_positives: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0
    )
    estimated_true_positives: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0
    )
    confidence: Mapped[Any] = mapped_column(
        String(16), nullable=False, default="medium"
    )

    requires_approval_from_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list
    )
    approvals_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="pending", index=True
    )
    deployed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


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


# ---------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------


class ConnectorTenantState(Base):
    __tablename__ = "connectors_tenant_state"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "connector_id", name="uq_connectors_tenant_state"
        ),
        Index("ix_connectors_tenant_state_tenant_enabled", "tenant_id", "enabled"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    connector_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    enabled: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    config_hash: Mapped[Any] = mapped_column(String(128), nullable=False)
    last_success_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[Any] = mapped_column(String(64), nullable=True)
    failure_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    updated_by: Mapped[Any] = mapped_column(
        String(128), nullable=False, default="unknown"
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
        onupdate=utcnow,
    )


class ConnectorCredential(Base):
    __tablename__ = "connectors_credentials"
    __table_args__ = (
        Index(
            "ix_connectors_credentials_tenant_connector", "tenant_id", "connector_id"
        ),
        Index("ix_connectors_credentials_tenant_active", "tenant_id", "revoked_at"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    connector_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    credential_id: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="primary"
    )
    principal_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    auth_mode: Mapped[Any] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[Any] = mapped_column(Text, nullable=False)
    kek_version: Mapped[Any] = mapped_column(String(32), nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


class ConnectorAuditLedger(Base):
    __tablename__ = "connectors_audit_ledger"
    __table_args__ = (
        Index(
            "ix_connectors_audit_tenant_connector",
            "tenant_id",
            "connector_id",
            "created_at",
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    connector_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[Any] = mapped_column(String(64), nullable=False)
    params_hash: Mapped[Any] = mapped_column(String(64), nullable=False)
    actor: Mapped[Any] = mapped_column(String(128), nullable=False)
    request_id: Mapped[Any] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class ConnectorIdempotency(Base):
    __tablename__ = "connectors_idempotency"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "connector_id",
            "action",
            "idempotency_key",
            name="uq_connectors_idempotency_key",
        ),
        Index("ix_connectors_idempotency_expiry", "expires_at"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    connector_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[Any] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[Any] = mapped_column(String(128), nullable=False)
    response_hash: Mapped[Any] = mapped_column(String(64), nullable=True)

    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)


class ProviderBaaRecord(Base):
    """
    Tenant-scoped provider BAA (Business Associate Agreement) record.

    One authoritative row per (tenant_id, provider_id). The BAA enforcement
    boundary (services/provider_baa/policy.py) is the only authorized reader.
    Callers must never bypass the enforcement boundary to read this table.
    """

    __tablename__ = "provider_baa_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider_id",
            name="uq_provider_baa_records_tenant_provider",
        ),
        Index("ix_provider_baa_records_tenant_provider", "tenant_id", "provider_id"),
        Index("ix_provider_baa_records_tenant_status", "tenant_id", "baa_status"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    provider_id: Mapped[Any] = mapped_column(Text, nullable=False)
    baa_status: Mapped[Any] = mapped_column(
        Text, nullable=False
    )  # active | expired | missing | revoked | pending
    expiry_date: Mapped[Any] = mapped_column(Date, nullable=True)
    signed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    document_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# =============================================================================
# Assessment & Report models (migration 0032)
# These power the customer-facing onboarding → assessment → report flow.
# =============================================================================


class OrgProfile(Base):
    """One row per customer org created through the onboarding wizard."""

    __tablename__ = "org_profiles"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    org_name: Mapped[Any] = mapped_column(Text, nullable=False)
    industry: Mapped[Any] = mapped_column(Text, nullable=False, default="other")
    employee_count: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    revenue: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    profile_type: Mapped[Any] = mapped_column(Text, nullable=False, default="smb_basic")
    handles_phi: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    handles_cui: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    is_dod_contractor: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    fedramp_required: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    email: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AssessmentSchema(Base):
    """Versioned question banks. Seeded by migration 0033."""

    __tablename__ = "assessment_schemas"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schema_version: Mapped[Any] = mapped_column(Text, nullable=False, unique=True)
    profile_type: Mapped[Any] = mapped_column(Text, nullable=False)
    questions: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    is_current: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AssessmentRecord(Base):
    """One row per assessment session."""

    __tablename__ = "assessments"

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    org_profile_id: Mapped[Any] = mapped_column(
        Integer, ForeignKey("org_profiles.id", ondelete="SET NULL"), nullable=True
    )
    org_id: Mapped[Any] = mapped_column(Text, nullable=False, default="", index=True)
    schema_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="v2025.1-base"
    )
    profile_type: Mapped[Any] = mapped_column(Text, nullable=False, default="smb_basic")
    status: Mapped[Any] = mapped_column(Text, nullable=False, default="draft")
    responses: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    scores: Mapped[Any] = mapped_column(JSON, nullable=True)
    overall_score: Mapped[Any] = mapped_column(Float, nullable=True)
    risk_band: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    submitted_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    scored_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    email: Mapped[Any] = mapped_column(Text, nullable=True)
    stripe_session_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    payment_status: Mapped[Any] = mapped_column(Text, nullable=False, default="unpaid")
    tier: Mapped[Any] = mapped_column(Text, nullable=True)


class PromptVersion(Base):
    """AI prompt templates for report generation. Seeded by migration 0033."""

    __tablename__ = "prompt_versions"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prompt_key: Mapped[Any] = mapped_column(Text, nullable=False)
    version: Mapped[Any] = mapped_column(Text, nullable=False)
    system_prompt: Mapped[Any] = mapped_column(Text, nullable=False)
    user_prompt_template: Mapped[Any] = mapped_column(Text, nullable=False)
    is_active: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReportRecord(Base):
    """One row per generated advisory report."""

    __tablename__ = "reports"

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    assessment_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )
    org_id: Mapped[Any] = mapped_column(Text, nullable=False, default="", index=True)
    org_profile_id: Mapped[Any] = mapped_column(
        Integer, ForeignKey("org_profiles.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    prompt_type: Mapped[Any] = mapped_column(Text, nullable=False, default="executive")
    content: Mapped[Any] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Any] = mapped_column(Text, nullable=True)
    pdf_storage_key: Mapped[Any] = mapped_column(Text, nullable=True)
    manifest_hash: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    manifest_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="governance-export-manifest-v1"
    )
    export_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="governance-export-v1"
    )
    report_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    reviewer_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    approval_status: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unapproved"
    )
    finalized_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    finalized_manifest_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    previous_report_id: Mapped[Any] = mapped_column(Text, nullable=True)
    superseded_by_report_id: Mapped[Any] = mapped_column(Text, nullable=True)
    evidence_snapshot_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="evidence-snapshot-v1"
    )
    scoring_contract_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="assessment-scoring-v1"
    )
    framework_mapping_version: Mapped[Any] = mapped_column(
        Text, nullable=False, default="framework-mapping-v1"
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


class TenantRetrievalPolicy(Base):
    """DB-backed tenant-scoped retrieval policy. One row per tenant, upserted on PUT."""

    __tablename__ = "tenant_retrieval_policies"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[Any] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    rag_enabled: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    allowed_corpus_ids: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    denied_corpus_ids: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    max_top_k: Mapped[Any] = mapped_column(Integer, nullable=False, default=4)
    allowed_retrieval_strategies: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=lambda: ["lexical"]
    )
    require_grounded_response: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=True
    )
    no_answer_on_ungrounded: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=True
    )
    require_grounded_context: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    allow_lexical_fallback: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    allow_semantic: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    allow_no_context_answer: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=True
    )
    reranking_enabled: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    policy_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    updated_by: Mapped[Any] = mapped_column(Text, nullable=True)
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class KnowledgeFact(Base):
    """Source-bound, tenant-scoped verified fact substrate."""

    __tablename__ = "knowledge_facts"
    __table_args__ = (
        CheckConstraint("trim(subject) <> ''", name="ck_knowledge_facts_subject"),
        CheckConstraint("trim(predicate) <> ''", name="ck_knowledge_facts_predicate"),
        CheckConstraint("trim(object) <> ''", name="ck_knowledge_facts_object"),
        CheckConstraint(
            "trim(source_hash) <> ''", name="ck_knowledge_facts_source_hash"
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_knowledge_facts_confidence",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from",
            name="ck_knowledge_facts_valid_window",
        ),
        CheckConstraint(
            "review_status IN ('active','contradicted','needs_review','superseded','expired')",
            name="ck_knowledge_facts_review_status",
        ),
        UniqueConstraint(
            "tenant_id",
            "source_doc_id",
            "source_chunk_id",
            "source_hash",
            "normalized_subject",
            "normalized_predicate",
            "normalized_object",
            name="uq_knowledge_facts_source_fact",
        ),
        Index(
            "ix_knowledge_facts_tenant_current",
            "tenant_id",
            "review_status",
            "valid_to",
        ),
        Index(
            "ix_knowledge_facts_tenant_sp",
            "tenant_id",
            "normalized_subject",
            "normalized_predicate",
        ),
        Index(
            "ix_knowledge_facts_tenant_source",
            "tenant_id",
            "source_doc_id",
            "source_chunk_id",
        ),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    subject: Mapped[Any] = mapped_column(Text, nullable=False)
    predicate: Mapped[Any] = mapped_column(Text, nullable=False)
    object: Mapped[Any] = mapped_column(Text, nullable=False)
    normalized_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    normalized_predicate: Mapped[Any] = mapped_column(Text, nullable=False)
    normalized_object: Mapped[Any] = mapped_column(Text, nullable=False)
    confidence: Mapped[Any] = mapped_column(Float, nullable=False)
    source_doc_id: Mapped[Any] = mapped_column(Text, nullable=False)
    source_chunk_id: Mapped[Any] = mapped_column(Text, nullable=False)
    source_hash: Mapped[Any] = mapped_column(Text, nullable=False)
    valid_from: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    review_status: Mapped[Any] = mapped_column(
        Text, nullable=False, default="active", server_default="active"
    )
    contradiction_of_fact_id: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class KnowledgeEntity(Base):
    """Tenant-scoped entity identity derived only from source-bound evidence."""

    __tablename__ = "knowledge_entities"
    __table_args__ = (
        CheckConstraint("trim(label) <> ''", name="ck_knowledge_entities_label"),
        CheckConstraint(
            "trim(normalized_label) <> ''",
            name="ck_knowledge_entities_normalized_label",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_knowledge_entities_confidence",
        ),
        UniqueConstraint(
            "tenant_id",
            "normalized_label",
            "entity_type",
            name="uq_knowledge_entities_identity",
        ),
        Index("ix_knowledge_entities_tenant_label", "tenant_id", "normalized_label"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    label: Mapped[Any] = mapped_column(Text, nullable=False)
    normalized_label: Mapped[Any] = mapped_column(Text, nullable=False)
    entity_type: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[Any] = mapped_column(Float, nullable=True)
    source_doc_id: Mapped[Any] = mapped_column(Text, nullable=True)
    source_chunk_id: Mapped[Any] = mapped_column(Text, nullable=True)
    source_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class KnowledgeRelationship(Base):
    """Tenant-scoped source-bound relationship between entities or literals."""

    __tablename__ = "knowledge_relationships"
    __table_args__ = (
        CheckConstraint(
            "trim(predicate) <> ''", name="ck_knowledge_relationships_predicate"
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_knowledge_relationships_confidence",
        ),
        CheckConstraint(
            "object_entity_id IS NOT NULL OR trim(coalesce(object_literal, '')) <> ''",
            name="ck_knowledge_relationships_object",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from",
            name="ck_knowledge_relationships_valid_window",
        ),
        CheckConstraint(
            "review_status IN ('active','contradicted','needs_review','superseded','expired')",
            name="ck_knowledge_relationships_review_status",
        ),
        CheckConstraint(
            "trim(source_hash) <> ''", name="ck_knowledge_relationships_source_hash"
        ),
        UniqueConstraint(
            "tenant_id",
            "subject_entity_id",
            "predicate",
            "object_entity_id",
            "object_literal",
            "source_hash",
            name="uq_knowledge_relationships_source_relation",
        ),
        Index(
            "ix_knowledge_relationships_tenant_subject",
            "tenant_id",
            "subject_entity_id",
        ),
        Index(
            "ix_knowledge_relationships_tenant_source",
            "tenant_id",
            "source_doc_id",
            "source_chunk_id",
        ),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    subject_entity_id: Mapped[Any] = mapped_column(Text, nullable=False)
    predicate: Mapped[Any] = mapped_column(Text, nullable=False)
    object_entity_id: Mapped[Any] = mapped_column(Text, nullable=True)
    object_literal: Mapped[Any] = mapped_column(Text, nullable=True)
    confidence: Mapped[Any] = mapped_column(Float, nullable=False)
    source_doc_id: Mapped[Any] = mapped_column(Text, nullable=False)
    source_chunk_id: Mapped[Any] = mapped_column(Text, nullable=False)
    source_hash: Mapped[Any] = mapped_column(Text, nullable=False)
    valid_from: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    review_status: Mapped[Any] = mapped_column(
        Text, nullable=False, default="active", server_default="active"
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class StripeEvent(Base):
    """Raw Stripe webhook events — used for idempotency and audit."""

    __tablename__ = "stripe_events"

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stripe_event_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    payload: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# =============================================================================
# Provider Governance models (PR 53)
# =============================================================================


class ProviderGovernanceRecord(Base):
    """
    Tenant-scoped provider governance state.

    One row per (tenant_id, provider_id). Tracks operational state, governance
    posture, BAA-derived trust, routing/failover eligibility, and policy
    restrictions for a provider as seen by a specific tenant.

    This table is append-safe: mutations go through the governance control-plane
    only; direct SQL writes are not permitted by application code.
    """

    __tablename__ = "provider_governance_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider_id",
            name="uq_provider_governance_tenant_provider",
        ),
        Index("ix_provider_governance_tenant_provider", "tenant_id", "provider_id"),
        Index(
            "ix_provider_governance_tenant_opstate",
            "tenant_id",
            "operational_state",
        ),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    provider_id: Mapped[Any] = mapped_column(Text, nullable=False)
    # healthy | degraded | unavailable | blocked | restricted | maintenance
    operational_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="healthy"
    )
    # approved | restricted | blocked | pending_review
    governance_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="approved"
    )
    # trusted | regulated | untrusted | unknown
    trust_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    routing_eligible: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    failover_eligible: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False
    )
    restrictions_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    blocked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    block_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    policy_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# =============================================================================
# Retrieval Evaluation models (PR 53 — Phase 5 foundation)
# =============================================================================


class RetrievalEvaluationRun(Base):
    """
    Tenant-scoped retrieval evaluation run record.

    Captures evaluation metadata for a retrieval quality run. Does NOT store
    raw prompts, completions, or PII. Scores are structural indicators only —
    no fabricated metrics. Evaluation algorithms are external; this model is
    the persistence substrate.
    """

    __tablename__ = "retrieval_evaluation_runs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "run_ref",
            name="uq_retrieval_eval_tenant_run_ref",
        ),
        Index("ix_retrieval_eval_tenant_run", "tenant_id", "run_ref"),
        Index("ix_retrieval_eval_tenant_status", "tenant_id", "status"),
        Index("ix_retrieval_eval_tenant_corpus", "tenant_id", "corpus_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    run_ref: Mapped[Any] = mapped_column(
        Text, nullable=False, default=lambda: str(uuid.uuid4())
    )
    corpus_id: Mapped[Any] = mapped_column(Text, nullable=True)
    # pending | running | completed | failed
    status: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    started_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    query_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    relevance_indicators_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    coverage_indicators_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    correctness_indicators_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    evaluator_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    evaluation_metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# =============================================================================
# Evaluation Lab models (PR 54 — Evaluation Lab UI)
# =============================================================================


class EvaluationQuerySet(Base):
    """
    Tenant-scoped evaluation query set.

    Stores operator-defined query set metadata for retrieval evaluation.
    Does NOT store raw query text or PII — query identity is by item_ref UUID.
    Expected source/chunk references enable retrieval precision measurement.
    """

    __tablename__ = "evaluation_query_sets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "set_ref",
            name="uq_eval_query_set_tenant_ref",
        ),
        Index("ix_eval_query_set_tenant_ref", "tenant_id", "set_ref"),
        Index("ix_eval_query_set_tenant_corpus", "tenant_id", "corpus_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    set_ref: Mapped[Any] = mapped_column(
        Text, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[Any] = mapped_column(Text, nullable=False)
    corpus_id: Mapped[Any] = mapped_column(Text, nullable=True)
    description: Mapped[Any] = mapped_column(Text, nullable=True)
    operator_notes_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    export_safe_metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class EvaluationQueryItem(Base):
    """
    Tenant-scoped evaluation query item within a query set.

    Stores expected source/chunk/provenance references per query.
    Raw query text is NOT stored — item identity is by item_ref UUID.
    Expected source hashes enable retrieval grounding validation.
    """

    __tablename__ = "evaluation_query_items"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "set_ref",
            "item_ref",
            name="uq_eval_query_item_tenant_set_ref",
        ),
        Index("ix_eval_query_item_tenant_set", "tenant_id", "set_ref"),
        Index("ix_eval_query_item_tenant_ref", "tenant_id", "item_ref"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    set_ref: Mapped[Any] = mapped_column(Text, nullable=False)
    item_ref: Mapped[Any] = mapped_column(
        Text, nullable=False, default=lambda: str(uuid.uuid4())
    )
    query_category: Mapped[Any] = mapped_column(Text, nullable=True)
    expected_source_ids_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list
    )
    expected_chunk_ids_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list
    )
    expected_source_hashes_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list
    )
    expected_provenance_ids_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list
    )
    retrieval_expectations_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict
    )
    operator_notes: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# ---------------------------------------------------------------------------
# PR 80 — Deployment Manager Foundation
# Touching schema — flagged explicitly per CLAUDE.md.
# ---------------------------------------------------------------------------


class DeploymentEnvironmentRecord(Base):
    """Immutable deployment environment descriptor.

    tenant_id=None denotes a platform-level environment accessible to all
    operators with sufficient scope. tenant_id set denotes a tenant-dedicated
    environment visible only within that tenant's context.
    """

    __tablename__ = "deployment_environments"
    __table_args__ = (
        Index("ix_deployment_env_tenant_type", "tenant_id", "env_type"),
        Index("ix_deployment_env_lifecycle", "lifecycle_state"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    env_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    env_type: Mapped[Any] = mapped_column(Text, nullable=False)
    region: Mapped[Any] = mapped_column(Text, nullable=False)
    lifecycle_state: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    compliance_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    deployment_policy_json: Mapped[Any] = mapped_column(Text, nullable=True)


class DeploymentRecordORM(Base):
    """Mutable deployment lifecycle record.

    state field is the canonical lifecycle state and transitions must be
    validated against VALID_TRANSITIONS before writing. Every mutation
    must produce a corresponding DeploymentEventRecord.

    artifact_hash is the SHA-256 of the deployment artifact bundle.
    It is nullable until the artifact is resolved during validation.
    """

    __tablename__ = "deployment_records"
    __table_args__ = (
        Index("ix_deploy_record_env_state", "env_id", "state"),
        Index("ix_deploy_record_tenant_state", "tenant_id", "state"),
        Index("ix_deploy_record_initiated_at", "initiated_at"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    deployment_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    env_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    version_ref: Mapped[Any] = mapped_column(Text, nullable=False)
    strategy: Mapped[Any] = mapped_column(Text, nullable=False)
    state: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=False)
    initiated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    artifact_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    rollback_from_id: Mapped[Any] = mapped_column(Text, nullable=True)
    rollback_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    approval_required: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    approval_granted_by: Mapped[Any] = mapped_column(Text, nullable=True)
    approval_granted_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approval_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    approval_policy_version: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_image_digest: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_commit_sha: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_contract_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_topology_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_policy_bundle_version: Mapped[Any] = mapped_column(Text, nullable=True)
    spec_migration_fingerprint: Mapped[Any] = mapped_column(Text, nullable=True)
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    deployment_metadata_json: Mapped[Any] = mapped_column(Text, nullable=True)


class DeploymentEventRecord(Base):
    """Append-only audit event for deployment lifecycle changes.

    Rows are never updated or deleted (enforced at DB level via rules in
    the Postgres migration). Every deployment mutation must write an event
    before returning to the caller.
    """

    __tablename__ = "deployment_events"
    __table_args__ = (
        Index("ix_deploy_event_deployment_ts", "deployment_id", "timestamp"),
        Index("ix_deploy_event_env_ts", "env_id", "timestamp"),
        Index("ix_deploy_event_tenant_ts", "tenant_id", "timestamp"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    deployment_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    env_id: Mapped[Any] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    actor: Mapped[Any] = mapped_column(Text, nullable=False)
    timestamp: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    from_state: Mapped[Any] = mapped_column(Text, nullable=True)
    to_state: Mapped[Any] = mapped_column(Text, nullable=True)
    details_json: Mapped[Any] = mapped_column(Text, nullable=True)
    event_hash: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    previous_event_hash: Mapped[Any] = mapped_column(Text, nullable=True)


class DeploymentHealthRecord(Base):
    """Point-in-time health assessment record for a deployment.

    rollback_trigger_reason is set only when this health check caused or
    recommended a rollback. Must never contain secrets or raw error messages.
    """

    __tablename__ = "deployment_health_records"
    __table_args__ = (
        Index("ix_deploy_health_deployment_ts", "deployment_id", "checked_at"),
        Index("ix_deploy_health_tenant_ts", "tenant_id", "checked_at"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    deployment_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    env_id: Mapped[Any] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    readiness_result: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    liveness_result: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    smoke_test_result: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    validation_result: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    checked_by: Mapped[Any] = mapped_column(Text, nullable=False)
    checked_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    rollback_trigger_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Provisioning subsystem ORM models (PR 81)
# ---------------------------------------------------------------------------


class ProvisioningOrganizationRecord(Base):
    """Mutable organization lifecycle record.

    lifecycle_status is the canonical state; transitions are validated against
    VALID_ORG_TRANSITIONS before writing. Every mutation must produce a
    corresponding ProvisioningAuditEventRecord.
    """

    __tablename__ = "provisioning_organizations"
    __table_args__ = (
        Index("ix_prov_orm_org_tenant", "tenant_id"),
        Index("ix_prov_orm_org_lifecycle", "lifecycle_status"),
        Index("ix_prov_orm_org_state_version", "state_version"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    org_name: Mapped[Any] = mapped_column(Text, nullable=False)
    slug: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    lifecycle_status: Mapped[Any] = mapped_column(
        Text, nullable=False, default="pending"
    )
    compliance_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    deployment_tier: Mapped[Any] = mapped_column(Text, nullable=False, default="shared")
    onboarding_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="not_started"
    )
    env_assignment_id: Mapped[Any] = mapped_column(Text, nullable=True)
    region: Mapped[Any] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    activated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class ProvisioningWorkflowRecord(Base):
    """Provisioning workflow run for an organization.

    Each provisioning attempt creates a new workflow record. Retries
    create fresh records with an incremented retry_count.
    """

    __tablename__ = "provisioning_workflows"
    __table_args__ = (
        Index("ix_prov_orm_wf_org", "organization_id"),
        Index("ix_prov_orm_wf_tenant", "tenant_id"),
        Index("ix_prov_orm_wf_state", "workflow_state"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provisioning_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    organization_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    workflow_state: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    current_step: Mapped[Any] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    parent_provisioning_id: Mapped[Any] = mapped_column(Text, nullable=True)
    env_target: Mapped[Any] = mapped_column(Text, nullable=True)
    retry_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[Any] = mapped_column(Integer, nullable=False, default=3)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    failure_category: Mapped[Any] = mapped_column(Text, nullable=True)
    validation_results_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    orchestration_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=False)
    started_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    last_updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class ProvisioningAuditEventRecord(Base):
    """Append-only audit event for provisioning lifecycle changes.

    Rows are never updated or deleted (enforced at DB level via rules in
    the Postgres migration). Every provisioning mutation must write an event
    before returning to the caller.
    """

    __tablename__ = "provisioning_audit_events"
    __table_args__ = (
        Index("ix_prov_audit_orm_org_ts", "organization_id", "timestamp"),
        Index("ix_prov_audit_orm_prov_ts", "provisioning_id", "timestamp"),
        Index("ix_prov_audit_orm_tenant_ts", "tenant_id", "timestamp"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    organization_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    provisioning_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    env_id: Mapped[Any] = mapped_column(Text, nullable=True)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    actor: Mapped[Any] = mapped_column(Text, nullable=False)
    outcome: Mapped[Any] = mapped_column(Text, nullable=False, default="success")
    workflow_state: Mapped[Any] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    details_json: Mapped[Any] = mapped_column(Text, nullable=True)
    event_hash: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    previous_event_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    timestamp: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# ---------------------------------------------------------------------------
# Operational Governance ORM models
# ---------------------------------------------------------------------------


class OpsEnvironmentRecord(Base):
    """Governance metadata for a managed deployment environment.

    SECURITY: No infrastructure topology, credentials, or secrets stored here.
    """

    __tablename__ = "ops_environments"
    __table_args__ = (
        Index("ix_ops_env_tenant", "tenant_id"),
        Index("ix_ops_env_slug", "slug"),
        Index("ix_ops_env_state", "lifecycle_state"),
    )

    environment_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    env_name: Mapped[Any] = mapped_column(Text, nullable=False)
    slug: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    lifecycle_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="provisioning"
    )
    env_type: Mapped[Any] = mapped_column(Text, nullable=False, default="shared")
    compliance_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    isolation_level: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    residency_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unrestricted"
    )
    recovery_readiness: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    region: Mapped[Any] = mapped_column(Text, nullable=True)
    validation_token: Mapped[Any] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    archived_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsSecretGovernanceRecord(Base):
    """Governance metadata for a managed secret.

    SECURITY: No raw secret values, credentials, or key material ever stored.
    Only metadata about the secret's lifecycle and classification.
    """

    __tablename__ = "ops_secret_governance"
    __table_args__ = (
        Index("ix_ops_secret_tenant", "tenant_id"),
        Index("ix_ops_secret_env", "environment_id"),
        Index("ix_ops_secret_state", "lifecycle_state"),
        Index("ix_ops_secret_rotation", "rotation_state"),
    )

    secret_governance_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    secret_name: Mapped[Any] = mapped_column(Text, nullable=False)
    secret_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    secret_type: Mapped[Any] = mapped_column(Text, nullable=False, default="api_key")
    lifecycle_state: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    external_provider: Mapped[Any] = mapped_column(Text, nullable=True)
    external_reference_id: Mapped[Any] = mapped_column(Text, nullable=True)
    owner_scope: Mapped[Any] = mapped_column(Text, nullable=True)
    rotation_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="not_scheduled"
    )
    rotation_policy_days: Mapped[Any] = mapped_column(Integer, nullable=True)
    last_rotated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    next_rotation_due_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    governance_policy_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsKeyRotationScheduleRecord(Base):
    """Key rotation schedule for a managed secret."""

    __tablename__ = "ops_key_rotation_schedules"
    __table_args__ = (
        Index("ix_ops_rotation_secret", "secret_governance_id"),
        Index("ix_ops_rotation_tenant", "tenant_id"),
        Index("ix_ops_rotation_state", "rotation_state"),
        Index("ix_ops_rotation_scheduled_at", "scheduled_at"),
    )

    rotation_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    secret_governance_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    rotation_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="scheduled"
    )
    scheduled_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    initiated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    compliance_override: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    override_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    override_approved_by: Mapped[Any] = mapped_column(Text, nullable=True)
    emergency_rotation: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    waiver_reference: Mapped[Any] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=True)
    outcome: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsRetentionPolicyRecord(Base):
    """Data retention policy for a managed environment or tenant."""

    __tablename__ = "ops_retention_policies"
    __table_args__ = (
        Index("ix_ops_retention_tenant", "tenant_id"),
        Index("ix_ops_retention_env", "environment_id"),
        Index("ix_ops_retention_state", "retention_state"),
        Index("ix_ops_retention_legal_hold", "legal_hold"),
    )

    retention_policy_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    policy_name: Mapped[Any] = mapped_column(Text, nullable=False)
    retention_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    retention_state: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    retention_days: Mapped[Any] = mapped_column(Integer, nullable=False)
    archive_after_days: Mapped[Any] = mapped_column(Integer, nullable=True)
    deletion_scheduled_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    archived_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    legal_hold: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    legal_hold_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    legal_hold_set_by: Mapped[Any] = mapped_column(Text, nullable=True)
    legal_hold_set_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    export_restricted: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    compliance_policy_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    override_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsExportRequestRecord(Base):
    """Export request for tenant or environment data."""

    __tablename__ = "ops_export_requests"
    __table_args__ = (
        Index("ix_ops_export_tenant", "tenant_id"),
        Index("ix_ops_export_env", "environment_id"),
        Index("ix_ops_export_state", "export_state"),
        Index("ix_ops_export_requested_by", "requested_by"),
    )

    export_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    export_state: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    export_scope: Mapped[Any] = mapped_column(Text, nullable=False, default="tenant")
    export_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    export_purpose: Mapped[Any] = mapped_column(Text, nullable=True)
    requested_by: Mapped[Any] = mapped_column(Text, nullable=False)
    approved_by: Mapped[Any] = mapped_column(Text, nullable=True)
    rejected_by: Mapped[Any] = mapped_column(Text, nullable=True)
    approval_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    rejection_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    legal_hold_validated: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0
    )
    residency_validated: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    retention_validated: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    export_restriction_flags: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsBackupRecord(Base):
    """Backup record — governance metadata only, no backup data or paths."""

    __tablename__ = "ops_backup_records"
    __table_args__ = (
        Index("ix_ops_backup_tenant", "tenant_id"),
        Index("ix_ops_backup_env", "environment_id"),
        Index("ix_ops_backup_state", "backup_state"),
    )

    backup_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    backup_scope: Mapped[Any] = mapped_column(Text, nullable=False, default="full")
    backup_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="standard"
    )
    backup_state: Mapped[Any] = mapped_column(Text, nullable=False, default="initiated")
    backup_reference: Mapped[Any] = mapped_column(Text, nullable=True)
    retention_policy_id: Mapped[Any] = mapped_column(Text, nullable=True)
    backup_size_bytes: Mapped[Any] = mapped_column(Integer, nullable=True)
    checksum_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=False)
    started_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsRestoreRecord(Base):
    """Restore operation record — governance metadata only."""

    __tablename__ = "ops_restore_records"
    __table_args__ = (
        Index("ix_ops_restore_tenant", "tenant_id"),
        Index("ix_ops_restore_backup", "source_backup_id"),
        Index("ix_ops_restore_state", "restore_state"),
    )

    restore_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    source_backup_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    target_environment_id: Mapped[Any] = mapped_column(Text, nullable=True)
    restore_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="initiated"
    )
    restore_scope: Mapped[Any] = mapped_column(Text, nullable=False, default="full")
    point_in_time_ref: Mapped[Any] = mapped_column(Text, nullable=True)
    validation_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="pending"
    )
    validation_token: Mapped[Any] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=False)
    started_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    recovery_lineage_id: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsRecoveryRecord(Base):
    """Recovery operation record — governance metadata and drill tracking."""

    __tablename__ = "ops_recovery_records"
    __table_args__ = (
        Index("ix_ops_recovery_tenant", "tenant_id"),
        Index("ix_ops_recovery_env", "environment_id"),
        Index("ix_ops_recovery_state", "recovery_state"),
        Index("ix_ops_recovery_drill", "drill_mode"),
    )

    recovery_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    recovery_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="initiated"
    )
    recovery_type: Mapped[Any] = mapped_column(Text, nullable=False)
    recovery_trigger: Mapped[Any] = mapped_column(Text, nullable=True)
    validation_state: Mapped[Any] = mapped_column(
        Text, nullable=False, default="pending"
    )
    readiness_classification: Mapped[Any] = mapped_column(
        Text, nullable=False, default="unknown"
    )
    initiated_by: Mapped[Any] = mapped_column(Text, nullable=False)
    started_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    validated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    failure_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    drill_mode: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class OpsGovernanceAuditEventRecord(Base):
    """Append-only audit event for ops governance lifecycle changes.

    Rows are never updated or deleted (enforced at DB level in the migration).
    Hash-chained per resource_id for tamper evidence.
    """

    __tablename__ = "ops_governance_audit_events"
    __table_args__ = (
        Index("ix_ops_audit_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_ops_audit_resource", "resource_type", "resource_id"),
        Index("ix_ops_audit_env_ts", "environment_id", "timestamp"),
    )

    event_id: Mapped[Any] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    environment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    resource_type: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    resource_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    actor: Mapped[Any] = mapped_column(Text, nullable=False)
    outcome: Mapped[Any] = mapped_column(Text, nullable=False, default="success")
    policy_state: Mapped[Any] = mapped_column(Text, nullable=True)
    operational_context: Mapped[Any] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[Any] = mapped_column(Text, nullable=True)
    details_json: Mapped[Any] = mapped_column(Text, nullable=True)
    event_hash: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    previous_event_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    timestamp: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# ---------------------------------------------------------------------------
# Readiness ORM models
# ---------------------------------------------------------------------------


class ReadinessFrameworkRecord(Base):
    """Immutable-once-activated readiness framework definition.

    framework_status gates mutations: domains/controls/tiers can only be
    added while status=draft. Once activated the structural definition is
    frozen and historical assessments remain reconstructable.
    """

    __tablename__ = "readiness_frameworks"
    __table_args__ = (
        Index("ix_ready_fw_slug", "framework_slug"),
        Index("ix_ready_fw_status", "framework_status"),
        Index("ix_ready_fw_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_name: Mapped[Any] = mapped_column(Text, nullable=False)
    framework_slug: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_version: Mapped[Any] = mapped_column(Text, nullable=False)
    framework_status: Mapped[Any] = mapped_column(Text, nullable=False, default="draft")
    framework_description: Mapped[Any] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    framework_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    compatibility_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    deprecation_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    activated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class ReadinessFrameworkVersionRecord(Base):
    """Framework version snapshot metadata.

    Enables parallel versions and frozen historical assessment reconstruction.
    """

    __tablename__ = "readiness_framework_versions"
    __table_args__ = (
        Index("ix_ready_fwv_framework", "framework_id"),
        Index("ix_ready_fwv_tag", "framework_id", "version_tag"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    version_tag: Mapped[Any] = mapped_column(Text, nullable=False)
    version_status: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    schema_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    compatibility_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    deprecation_note: Mapped[Any] = mapped_column(Text, nullable=True)


class ReadinessDomainRecord(Base):
    """Readiness domain within a framework.

    domain_order controls display ordering. domain_parent_id is a forward-
    compatible hook for future hierarchical domain support.
    """

    __tablename__ = "readiness_domains"
    __table_args__ = (
        Index("ix_ready_dom_framework", "framework_id"),
        Index("ix_ready_dom_tenant", "tenant_id"),
        Index("ix_ready_dom_order", "framework_id", "domain_order"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    domain_name: Mapped[Any] = mapped_column(Text, nullable=False)
    domain_slug: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    domain_description: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    domain_order: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    domain_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    maturity_applicability_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    domain_parent_id: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReadinessControlRecord(Base):
    """Readiness control within a domain.

    Controls are framework-version aware and immutable once the parent framework
    is activated. Evidence requirements and maturity/scoring metadata are
    declarative contracts — no logic lives here.
    """

    __tablename__ = "readiness_controls"
    __table_args__ = (
        Index("ix_ready_ctrl_framework", "framework_id"),
        Index("ix_ready_ctrl_domain", "domain_id"),
        Index("ix_ready_ctrl_tenant", "tenant_id"),
        Index("ix_ready_ctrl_identifier", "framework_id", "control_identifier"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    control_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    domain_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    control_identifier: Mapped[Any] = mapped_column(Text, nullable=False)
    control_name: Mapped[Any] = mapped_column(Text, nullable=False)
    control_description: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    control_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    applicability_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    evidence_requirements_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    maturity_mapping_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    scoring_compatibility_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReadinessControlReferenceRecord(Base):
    """Cross-framework control mapping (future cross-framework translation)."""

    __tablename__ = "readiness_control_references"
    __table_args__ = (
        Index("ix_ready_cref_source", "source_control_id"),
        Index("ix_ready_cref_target", "target_control_id"),
        Index("ix_ready_cref_frameworks", "source_framework_id", "target_framework_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reference_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    source_control_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    source_framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    target_control_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    target_framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    mapping_type: Mapped[Any] = mapped_column(Text, nullable=False)
    mapping_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReadinessMaturityTierRecord(Base):
    """Maturity tier definition within a framework.

    tier_order ascending = lower maturity. Immutable once framework activates.
    """

    __tablename__ = "readiness_maturity_tiers"
    __table_args__ = (
        Index("ix_ready_tier_framework", "framework_id"),
        Index("ix_ready_tier_order", "framework_id", "tier_order"),
        Index("ix_ready_tier_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tier_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    tier_identifier: Mapped[Any] = mapped_column(Text, nullable=False)
    tier_name: Mapped[Any] = mapped_column(Text, nullable=False)
    tier_order: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    tier_criteria: Mapped[Any] = mapped_column(Text, nullable=False, default="")
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    tier_metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    readiness_classification: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReadinessAssessmentRecord(Base):
    """Tenant-scoped readiness assessment record.

    Once finalized, assessment is immutable — results and evidence references
    are frozen. snapshot_version pins the framework state for deterministic
    historical reconstruction. state_version is the optimistic-lock counter.
    """

    __tablename__ = "readiness_assessments"
    __table_args__ = (
        Index("ix_ready_assess_tenant", "tenant_id"),
        Index("ix_ready_assess_framework", "framework_id"),
        Index("ix_ready_assess_status", "assessment_status"),
        Index("ix_ready_assess_tenant_fw", "tenant_id", "framework_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    framework_version_tag: Mapped[Any] = mapped_column(Text, nullable=False)
    assessment_status: Mapped[Any] = mapped_column(
        Text, nullable=False, default="draft"
    )
    snapshot_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    assessment_name: Mapped[Any] = mapped_column(Text, nullable=True)
    assessment_description: Mapped[Any] = mapped_column(Text, nullable=True)
    assessment_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    actor_metadata_json: Mapped[Any] = mapped_column(Text, nullable=False, default="{}")
    scoring_contract_id: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    activated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    finalized_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    state_version: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)


class ReadinessAssessmentResultRecord(Base):
    """Per-control result within an assessment.

    Append-only within a non-finalized assessment. Frozen after finalization.
    No scoring logic — scoring_metadata is a declarative contract field.
    """

    __tablename__ = "readiness_assessment_results"
    __table_args__ = (
        Index("ix_ready_result_assessment", "assessment_id"),
        Index("ix_ready_result_control", "control_id"),
        Index("ix_ready_result_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    result_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    assessment_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    control_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    maturity_tier_id: Mapped[Any] = mapped_column(Text, nullable=True)
    outcome: Mapped[Any] = mapped_column(Text, nullable=False, default="not_evaluated")
    actor: Mapped[Any] = mapped_column(Text, nullable=False)
    timestamp: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    evaluation_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    scoring_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    evidence_reference_ids_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="[]"
    )
    notes: Mapped[Any] = mapped_column(Text, nullable=True)


class ReadinessEvidenceReferenceRecord(Base):
    """Evidence reference contract record.

    Schema only — no evidence ingestion, extraction, or automation.
    evidence_integrity_metadata_json holds hash/checksum contract fields
    for future tamper-evidence verification.
    """

    __tablename__ = "readiness_evidence_references"
    __table_args__ = (
        Index("ix_ready_evref_assessment", "assessment_id"),
        Index("ix_ready_evref_tenant", "tenant_id"),
        Index("ix_ready_evref_type", "evidence_type"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    assessment_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    evidence_type: Mapped[Any] = mapped_column(Text, nullable=False)
    evidence_title: Mapped[Any] = mapped_column(Text, nullable=False)
    submitted_by: Mapped[Any] = mapped_column(Text, nullable=False)
    submitted_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    evidence_source_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    evidence_ownership_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    evidence_integrity_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    evidence_classification: Mapped[Any] = mapped_column(Text, nullable=True)
    effective_date: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    control_ids_json: Mapped[Any] = mapped_column(Text, nullable=False, default="[]")
    notes: Mapped[Any] = mapped_column(Text, nullable=True)


class ReadinessScoringContractRecord(Base):
    """Scoring schema contract for a framework.

    Declares scoring architecture without implementing calculation logic.
    Scoring engines (future) must validate against this contract.
    """

    __tablename__ = "readiness_scoring_contracts"
    __table_args__ = (
        Index("ix_ready_sc_framework", "framework_id"),
        Index("ix_ready_sc_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[Any] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    framework_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    scoring_schema_version: Mapped[Any] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    normalization_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    weighting_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    compatibility_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    scoring_metadata_json: Mapped[Any] = mapped_column(
        Text, nullable=False, default="{}"
    )
    is_active: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ReadinessAuditEventRecord(Base):
    """Append-only audit event for readiness lifecycle changes.

    Rows are never updated or deleted. Every readiness mutation must write
    an event before returning. Hash-chained per (resource_type, resource_id)
    for tamper-evidence.
    """

    __tablename__ = "readiness_audit_events"
    __table_args__ = (
        Index("ix_ready_audit_resource", "resource_type", "resource_id"),
        Index("ix_ready_audit_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_ready_audit_assessment", "assessment_id"),
        Index("ix_ready_audit_framework", "framework_id"),
    )

    id: Mapped[Any] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[Any] = mapped_column(Text, nullable=False, unique=True, index=True)
    resource_type: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    resource_id: Mapped[Any] = mapped_column(Text, nullable=False, index=True)
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    framework_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    assessment_id: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    actor: Mapped[Any] = mapped_column(Text, nullable=False)
    outcome: Mapped[Any] = mapped_column(Text, nullable=False, default="success")
    details_json: Mapped[Any] = mapped_column(Text, nullable=True)
    event_hash: Mapped[Any] = mapped_column(Text, nullable=True, index=True)
    previous_event_hash: Mapped[Any] = mapped_column(Text, nullable=True)
    timestamp: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


# ─── Workforce Intelligence (PR 36) ──────────────────────────────────────────


class TenantUser(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_tenant_users_tenant_email"),
        Index("ix_tenant_users_tenant_id", "tenant_id"),
        Index("ix_tenant_users_invite_token", "invite_token"),
    )

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    email: Mapped[Any] = mapped_column(String(256), nullable=False)
    display_name: Mapped[Any] = mapped_column(String(256), nullable=False)
    role: Mapped[Any] = mapped_column(String(32), nullable=False, default="user")
    invite_token: Mapped[Any] = mapped_column(String(128), nullable=True, unique=True)
    invite_expires_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    active: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    last_active_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AIQueryLog(Base):
    __tablename__ = "ai_query_log"
    __table_args__ = (
        Index("ix_ai_query_log_tenant_id", "tenant_id"),
        Index("ix_ai_query_log_user_id", "user_id"),
        Index("ix_ai_query_log_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    user_email: Mapped[Any] = mapped_column(String(256), nullable=True)
    session_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    query_text: Mapped[Any] = mapped_column(Text, nullable=False)
    response_text: Mapped[Any] = mapped_column(Text, nullable=True)
    provider: Mapped[Any] = mapped_column(String(64), nullable=True)
    model: Mapped[Any] = mapped_column(String(128), nullable=True)
    prompt_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    policy_decision: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="allow"
    )
    subject_category: Mapped[Any] = mapped_column(String(64), nullable=True)
    work_relevance: Mapped[Any] = mapped_column(String(32), nullable=True)
    sensitivity_flags: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    risk_signals: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    classified_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class RiskScoreSnapshot(Base):
    __tablename__ = "risk_score_snapshots"
    __table_args__ = (
        Index("idx_risk_snapshot_user_date", "tenant_id", "user_id", "captured_at"),
        # Expression-based unique index (per-user per-day) is created by migration 0070.
        # Not representable as a SQLAlchemy UniqueConstraint.
    )

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    user_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    risk_score: Mapped[Any] = mapped_column(Numeric(5, 1), nullable=False, default=0)
    risk_band: Mapped[Any] = mapped_column(String(32), nullable=False, default="low")
    total_queries: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    policy_violations: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    personal_ratio: Mapped[Any] = mapped_column(
        Numeric(5, 3), nullable=False, default=0
    )
    sensitive_topic_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0
    )
    pii_query_count: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    competitor_query_count: Mapped[Any] = mapped_column(
        Integer, nullable=False, default=0
    )
    active_days: Mapped[Any] = mapped_column(Integer, nullable=False, default=0)
    period_days: Mapped[Any] = mapped_column(Integer, nullable=False, default=30)
    captured_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class TenantKeyword(Base):
    __tablename__ = "tenant_keywords"
    __table_args__ = (Index("idx_tenant_keyword_tenant", "tenant_id", "active"),)

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    keyword: Mapped[Any] = mapped_column(Text, nullable=False)
    match_type: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="contains"
    )
    case_sensitive: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    flag_value: Mapped[Any] = mapped_column(Text, nullable=False)
    flag_type: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="sensitivity"
    )
    action: Mapped[Any] = mapped_column(String(32), nullable=False, default="flag")
    description: Mapped[Any] = mapped_column(Text, nullable=True)
    created_by: Mapped[Any] = mapped_column(String(256), nullable=True)
    active: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class RiskAlertRule(Base):
    __tablename__ = "risk_alert_rules"
    __table_args__ = (Index("idx_alert_rules_tenant", "tenant_id", "active"),)

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    name: Mapped[Any] = mapped_column(Text, nullable=False)
    threshold_score: Mapped[Any] = mapped_column(Numeric(5, 1), nullable=True)
    threshold_band: Mapped[Any] = mapped_column(Text, nullable=True)
    cooldown_hours: Mapped[Any] = mapped_column(Integer, nullable=False, default=24)
    active: Mapped[Any] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class RiskAlertFired(Base):
    __tablename__ = "risk_alerts_fired"
    __table_args__ = (
        Index("idx_alerts_fired_tenant", "tenant_id", "fired_at"),
        Index("idx_alerts_fired_rule_user", "rule_id", "user_id", "fired_at"),
    )

    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[Any] = mapped_column(
        String(128),
        ForeignKey("risk_alert_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    user_email: Mapped[Any] = mapped_column(String(256), nullable=True)
    risk_score: Mapped[Any] = mapped_column(Numeric(5, 1), nullable=False)
    risk_band: Mapped[Any] = mapped_column(String(32), nullable=False)
    dismissed: Mapped[Any] = mapped_column(Boolean, nullable=False, default=False)
    dismissed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    fired_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

# PR3 External AI Risk Register ORM registration for Base.metadata.create_all().
import api.db_models_external_ai_risk  # noqa: F401
