"""Field assessment domain models — pure Python, no I/O, no SQLAlchemy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EngagementStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    DELIVERED = "delivered"
    REMEDIATION = "remediation"
    MONITORING = "monitoring"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class AssessmentType(str, Enum):
    AI_GOVERNANCE = "ai_governance"
    CMMC = "cmmc"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    COMPREHENSIVE = "comprehensive"


class ScanSourceType(str, Enum):
    MICROSOFT_GRAPH = "microsoft_graph"
    GOOGLE_WORKSPACE = "google_workspace"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    NETWORK_SCAN = "network_scan"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    OAUTH_INVENTORY = "oauth_inventory"
    DNS_EMAIL = "dns_email"
    WEB_HEADERS = "web_headers"
    ENTRA_GOVERNANCE = "entra_governance"
    SHAREPOINT_ONEDRIVE = "sharepoint_onedrive"
    OAUTH_RISK = "oauth_risk"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


class DocumentClassification(str, Enum):
    AI_POLICY = "ai_policy"
    DATA_GOVERNANCE = "data_governance"
    INCIDENT_RESPONSE = "incident_response"
    VENDOR_RISK = "vendor_risk"
    ACCESS_CONTROL = "access_control"
    TRAINING_RECORDS = "training_records"
    AUDIT_REPORTS = "audit_reports"
    OTHER = "other"


class ObservationDomain(str, Enum):
    AI_GOVERNANCE = "ai_governance"
    DATA_SECURITY = "data_security"
    ACCESS_MANAGEMENT = "access_management"
    OPERATIONAL_SECURITY = "operational_security"
    COMPLIANCE = "compliance"
    VENDOR_MANAGEMENT = "vendor_management"
    INCIDENT_RESPONSE = "incident_response"
    TRAINING = "training"


class ObservationType(str, Enum):
    GAP = "gap"
    STRENGTH = "strength"
    CONCERN = "concern"
    FINDING = "finding"
    NOTE = "note"
    INTERVIEW = "interview"


class ObservationSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceLinkType(str, Enum):
    SCAN_RESULT = "scan_result"
    DOCUMENT_ANALYSIS = "document_analysis"
    FIELD_OBSERVATION = "field_observation"
    ATTESTATION = "attestation"


class FrameworkId(str, Enum):
    NIST_AI_RMF = "nist_ai_rmf"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    CMMC = "cmmc"
    ISO27001 = "iso27001"


# Valid engagement state transitions
VALID_ENGAGEMENT_TRANSITIONS: dict[str, set[str]] = {
    "in_progress": {"cancelled"},
    "delivered": {"remediation", "monitoring", "closed"},
    "remediation": {"monitoring", "closed"},
    "monitoring": {"remediation", "closed"},
    "closed": set(),
    "cancelled": set(),
}


@dataclass(frozen=True)
class FrameworkMapping:
    framework_id: str
    control_id: str
    description: str


@dataclass(frozen=True)
class NistAiRmfMapping:
    function: str  # GOVERN | MAP | MEASURE | MANAGE
    category: str  # e.g. "GOVERN-1.1"
    description: str


# Domain exceptions
class FieldAssessmentError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class EngagementNotFound(FieldAssessmentError): ...


class InvalidEngagementTransition(FieldAssessmentError): ...


class EngagementImmutableError(FieldAssessmentError): ...


class FindingNotFound(FieldAssessmentError): ...


class EvidenceLinkNotFound(FieldAssessmentError): ...


class TenantIsolationViolation(FieldAssessmentError): ...


class SchemaVersionMismatch(FieldAssessmentError): ...


class EvidenceLinkDuplicate(FieldAssessmentError): ...


class ScanResultNotFound(FieldAssessmentError): ...


class ScanValidationError(FieldAssessmentError): ...


class ScanQuarantinedError(FieldAssessmentError): ...


class EngagementGateBlocked(FieldAssessmentError):
    def __init__(
        self,
        message: str,
        gate_ids: list[str],
        not_ready_reasons: list[dict],
    ) -> None:
        self.gate_ids = gate_ids
        self.not_ready_reasons = not_ready_reasons
        super().__init__(message)


class PromotionNotFound(FieldAssessmentError): ...


class PromotionAlreadyExists(FieldAssessmentError): ...
