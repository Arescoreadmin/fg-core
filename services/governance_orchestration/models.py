"""Enums and constants for the Governance Orchestration Authority (PR 18.4).

Pure Python. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from enum import Enum


GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION: str = "1.0"


class GovernanceOrchestrationState(str, Enum):
    """Lifecycle state of the orchestrator itself."""

    IDLE = "IDLE"
    EVALUATING = "EVALUATING"
    TRIGGERING = "TRIGGERING"
    EXECUTING = "EXECUTING"
    SUSPENDED = "SUSPENDED"
    FAILED = "FAILED"


class TriggerType(str, Enum):
    """Categorised reason a governance workflow is initiated."""

    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    EVIDENCE_REVOKED = "EVIDENCE_REVOKED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CONTROL_DEGRADED = "CONTROL_DEGRADED"
    RISK_THRESHOLD_EXCEEDED = "RISK_THRESHOLD_EXCEEDED"
    REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    TRUST_ROTATION = "TRUST_ROTATION"
    TRANSPARENCY_INCONSISTENCY = "TRANSPARENCY_INCONSISTENCY"
    MANUAL_REQUEST = "MANUAL_REQUEST"
    SCHEDULED = "SCHEDULED"
    FRAMEWORK_REVISION = "FRAMEWORK_REVISION"
    TENANT_POLICY = "TENANT_POLICY"


class PolicyRiskLevel(str, Enum):
    """Risk classification for a policy evaluation result."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class WorkflowState(str, Enum):
    """Lifecycle of a governance workflow execution."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELLED = "CANCELLED"


class ReassessmentState(str, Enum):
    """Lifecycle of a reassessment."""

    REQUESTED = "REQUESTED"
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ApprovalState(str, Enum):
    """Lifecycle of a governance approval record."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    DELEGATED = "DELEGATED"


class MaintenanceWindowState(str, Enum):
    """Lifecycle of a maintenance/blackout window."""

    SCHEDULED = "SCHEDULED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class SimulationState(str, Enum):
    """Lifecycle of a governance impact simulation."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PlaybookType(str, Enum):
    """Built-in playbook templates."""

    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    NIST_CSF = "NIST_CSF"
    ISO_27001 = "ISO_27001"
    SOC2 = "SOC2"
    MICROSOFT_SECURE_SCORE = "MICROSOFT_SECURE_SCORE"
    CIS_CONTROLS = "CIS_CONTROLS"


class ImpactLevel(str, Enum):
    """Level of governance impact for a change or event."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class ChangeType(str, Enum):
    """Classification of a detected change event."""

    EVIDENCE_CHANGE = "EVIDENCE_CHANGE"
    CONTROL_CHANGE = "CONTROL_CHANGE"
    RISK_CHANGE = "RISK_CHANGE"
    POLICY_CHANGE = "POLICY_CHANGE"
    FRAMEWORK_CHANGE = "FRAMEWORK_CHANGE"
    TRUST_CHANGE = "TRUST_CHANGE"


# Terminal / frozen sets used across the engine
TERMINAL_WORKFLOW_STATES = frozenset(
    {
        WorkflowState.COMPLETED,
        WorkflowState.FAILED,
        WorkflowState.ROLLED_BACK,
        WorkflowState.CANCELLED,
    }
)

TERMINAL_REASSESSMENT_STATES = frozenset(
    {
        ReassessmentState.COMPLETED,
        ReassessmentState.FAILED,
        ReassessmentState.CANCELLED,
    }
)

ACTIVE_APPROVAL_STATES = frozenset(
    {
        ApprovalState.PENDING,
        ApprovalState.DELEGATED,
    }
)


# ---------------------------------------------------------------------------
# Domain error base classes
# ---------------------------------------------------------------------------


class GovernanceOrchestrationDomainError(Exception):
    """Base class for domain-level (non-schema) errors."""


class GovernanceOrchestrationNotFoundDomainError(GovernanceOrchestrationDomainError):
    """Requested orchestration entity not found for tenant."""


class GovernanceOrchestrationTenantViolationDomainError(
    GovernanceOrchestrationDomainError
):
    """Cross-tenant access attempt detected."""
