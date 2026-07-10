"""api/identity_governance/models.py — Shared enums and dataclasses.

All governance data models are immutable (``frozen=True``) to guarantee
deterministic behavior and prevent accidental mutation of shared state.
Every record is tenant-scoped: the ``tenant_id`` field is REQUIRED on all
mutable / persisted records so cross-tenant contamination is impossible
by construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IdentityLifecycleState(str, Enum):
    """Governed lifecycle states for a subject."""

    CREATED = "CREATED"
    INVITED = "INVITED"
    ACCEPTED = "ACCEPTED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"
    # Extended states added by PR-02 (Customer Identity Lifecycle)
    INVITATION_SENT = "INVITATION_SENT"
    INVITATION_OPENED = "INVITATION_OPENED"
    PROVISIONED = "PROVISIONED"
    PASSWORD_RESET_PENDING = "PASSWORD_RESET_PENDING"
    MFA_ENROLLMENT_REQUIRED = "MFA_ENROLLMENT_REQUIRED"
    VERIFIED = "VERIFIED"
    LOCKED = "LOCKED"


class DeviceTrustState(str, Enum):
    """Device trust states used by the continuous evaluation pipeline."""

    UNKNOWN = "UNKNOWN"
    KNOWN = "KNOWN"
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    REVOKED = "REVOKED"


class SessionEvaluationDecision(str, Enum):
    """Outcomes of the continuous session evaluation pipeline."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    REVOKE_SESSION = "REVOKE_SESSION"


class PolicyDecision(str, Enum):
    """Decisions returned by the conditional access policy engine."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    JUSTIFICATION_REQUIRED = "JUSTIFICATION_REQUIRED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class RiskBand(str, Enum):
    """Risk classification bands emitted by the risk engine."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IdentityTimelineEventType(str, Enum):
    """Event categories recorded on the identity event timeline."""

    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    MFA_VERIFIED = "MFA_VERIFIED"
    MFA_MISSING = "MFA_MISSING"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_REFRESHED = "SESSION_REFRESHED"
    SESSION_REVOKED = "SESSION_REVOKED"
    POLICY_DECISION = "POLICY_DECISION"
    PERMISSION_ELEVATED = "PERMISSION_ELEVATED"
    ROLE_CHANGED = "ROLE_CHANGED"
    DEVICE_REGISTERED = "DEVICE_REGISTERED"
    DEVICE_TRUST_CHANGED = "DEVICE_TRUST_CHANGED"
    BREAK_GLASS_REQUESTED = "BREAK_GLASS_REQUESTED"
    BREAK_GLASS_APPROVED = "BREAK_GLASS_APPROVED"
    BREAK_GLASS_EXPIRED = "BREAK_GLASS_EXPIRED"
    ADMIN_ACTION = "ADMIN_ACTION"
    LOGOUT = "LOGOUT"


class BreakGlassStatus(str, Enum):
    """Lifecycle status of an emergency access (break-glass) request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class DelegatedAdminLevel(str, Enum):
    """Hierarchical administration levels for delegated authority.

    Ordered from most powerful (platform) to most narrow (engagement).
    Use ``ADMIN_LEVEL_ORDER`` in ``delegated_admin.py`` to compare rank.
    """

    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    REGIONAL_ADMIN = "REGIONAL_ADMIN"
    BUSINESS_UNIT_ADMIN = "BUSINESS_UNIT_ADMIN"
    DEPARTMENT_ADMIN = "DEPARTMENT_ADMIN"
    PROJECT_ADMIN = "PROJECT_ADMIN"
    ENGAGEMENT_ADMIN = "ENGAGEMENT_ADMIN"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityLifecycleRecord:
    """Immutable record of a governed lifecycle transition."""

    record_id: str
    subject: str
    tenant_id: str
    from_state: IdentityLifecycleState
    to_state: IdentityLifecycleState
    reason: str
    actor: str
    occurred_at: datetime


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceRecord:
    """Immutable device trust record.

    The ``fingerprint_hash`` is caller-provided — the registry never sees raw
    fingerprints. The ``user_agent_hash`` is caller-provided for the same
    reason.
    """

    device_id: str
    tenant_id: str
    subject: str
    fingerprint_hash: str
    user_agent_hash: str
    ip_metadata: str
    trust_state: DeviceTrustState
    risk_score: float
    registered_at: datetime
    updated_at: datetime
    last_reason: str


# ---------------------------------------------------------------------------
# Session evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionEvaluationContext:
    """Input context for the continuous session evaluation pipeline."""

    subject: str
    tenant_id: str
    session_id: str
    identity_state: IdentityLifecycleState
    session_expires_at: datetime
    session_revoked: bool
    device: Optional[DeviceRecord]
    mfa_verified: bool
    tenant_requires_mfa: bool
    risk_score: "RiskScore"
    evaluated_at: datetime


@dataclass(frozen=True)
class SessionEvaluationResult:
    """Deterministic outcome of the session evaluation pipeline."""

    decision: SessionEvaluationDecision
    reason: str
    checks_run: tuple[str, ...]
    stopped_at_check: str
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyCondition:
    """Deterministic policy condition. ``kind`` selects the evaluator branch."""

    kind: str
    params: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PolicyRecord:
    """A conditional-access policy.

    ``priority`` — lower value wins. Deny overrides allow at the same priority.
    ``conditions`` — all must match for the policy to apply.
    ``on_match`` — the decision to emit when all conditions match.
    """

    policy_id: str
    tenant_id: str
    name: str
    priority: int
    conditions: tuple[PolicyCondition, ...]
    on_match: PolicyDecision
    enabled: bool = True


@dataclass(frozen=True)
class PolicyEvaluationContext:
    """Input context for policy evaluation."""

    subject: str
    tenant_id: str
    roles: frozenset[str]
    capabilities: frozenset[str]
    mfa_verified: bool
    identity_state: IdentityLifecycleState
    ip: str
    now_hour_utc: int
    justification: Optional[str] = None
    break_glass_reason: Optional[str] = None


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Deterministic policy evaluation result."""

    decision: PolicyDecision
    matched_policy_id: Optional[str]
    reason: str
    evaluated_policies: tuple[str, ...]


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityTimelineEvent:
    """Immutable, hash-chained timeline event.

    ``previous_hash`` is the ``event_hash`` of the prior event in the same
    chain, or ``"genesis"`` for the first event.
    """

    event_id: str
    event_type: IdentityTimelineEventType
    subject: str
    tenant_id: str
    actor: str
    occurred_at: datetime
    details: tuple[tuple[str, str], ...]
    correlation_id: Optional[str]
    previous_hash: str
    event_hash: str


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    """A node in the identity graph."""

    node_id: str
    node_type: str  # "identity" | "role" | "permission" | "device" | "tenant"
    label: str
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class GraphEdge:
    """A directed edge in the identity graph."""

    edge_id: str
    source: str
    target: str
    edge_type: str
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class IdentityGraphSnapshot:
    """Deterministic snapshot of the identity graph for a subject/tenant."""

    subject: str
    tenant_id: str
    generated_at: datetime
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    fingerprint: str


# ---------------------------------------------------------------------------
# Delegated admin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegatedAdminScope:
    """Scope description for a delegated admin grant."""

    tenant_id: str
    organization_id: Optional[str] = None
    business_unit_id: Optional[str] = None
    department_id: Optional[str] = None
    project_id: Optional[str] = None
    engagement_id: Optional[str] = None


@dataclass(frozen=True)
class DelegatedAdminRecord:
    """Delegated admin grant record."""

    record_id: str
    tenant_id: str
    subject: str
    level: DelegatedAdminLevel
    scope: DelegatedAdminScope
    granted_by: str
    granted_at: datetime


# ---------------------------------------------------------------------------
# Break glass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BreakGlassRequest:
    """Break-glass emergency access request."""

    request_id: str
    tenant_id: str
    subject: str
    requested_capability: str
    reason: str
    requested_by: str
    requested_at: datetime
    duration_seconds: int
    status: BreakGlassStatus
    approver: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskContext:
    """Input to the deterministic risk engine."""

    subject: str
    tenant_id: str
    lifecycle_state: IdentityLifecycleState
    device_state: Optional[DeviceTrustState]
    mfa_verified: bool
    tenant_requires_mfa: bool
    active_break_glass: int
    evaluated_at: datetime


@dataclass(frozen=True)
class RiskScore:
    """Deterministic risk score record."""

    subject: str
    tenant_id: str
    score: float
    band: RiskBand
    factors: tuple[tuple[str, float], ...]
    evaluator_version: str
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# Digital twin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DigitalTwinSnapshot:
    """Deterministic identity digital twin snapshot."""

    subject: str
    tenant_id: str
    generated_at: datetime
    identity_summary: tuple[tuple[str, str], ...]
    lifecycle_state: IdentityLifecycleState
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    device_records: tuple[tuple[tuple[str, str], ...], ...] = field(default=())
    active_sessions_count: int = 0
    risk_score: Optional[RiskScore] = None
    active_break_glass_count: int = 0
    recent_timeline_events: tuple[IdentityTimelineEvent, ...] = ()
    assessments_count: int = 0
    evidence_count: int = 0
    fingerprint: str = ""
