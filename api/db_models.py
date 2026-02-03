# api/db_models.py
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from sqlalchemy import Column, String
from sqlalchemy import JSON, Text

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    func,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()

prev_hash = Column(String(64), nullable=True)
chain_hash = Column(String(64), nullable=True)


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
    version = Column(Integer, nullable=False, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    rotated_from = Column(
        String(64), nullable=True
    )  # Previous key_hash for rotation chain
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    use_count = Column(Integer, nullable=False, default=0)

    # Tenant isolation (multi-tenant SaaS)
    tenant_id = Column(String(128), nullable=True, index=True)

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


class DecisionRecord(Base):
    __tablename__ = "decisions"

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

    threat_level = Column(String, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    ai_adversarial_score = Column(Float, nullable=True)
    pq_fallback = Column(Boolean, nullable=True)

    rules_triggered_json = Column(JSON, nullable=False, default=list)
    decision_diff_json = Column(JSON, nullable=True)
    request_json = Column(JSON, nullable=False)
    response_json = Column(JSON, nullable=False)
    prev_hash = Column(String(64), nullable=True)
    chain_hash = Column(String(64), nullable=True)
    chain_alg = Column(String(64), nullable=True)
    chain_ts = Column(DateTime(timezone=True), nullable=True)


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
