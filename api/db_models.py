# api/db_models.py
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, Index, String, text
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint
from sqlalchemy import JSON, Text
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    event,
    func,
)
from sqlalchemy.orm import declarative_base

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
