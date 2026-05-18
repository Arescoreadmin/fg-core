"""Deterministic Governance Report — package exports."""

from .confidence import calculate_confidence
from .engine import GovernanceReportEngine, GovernanceReportError
from .framework_mappings import (
    FRAMEWORK_CONTROL_MAP,
    get_framework_mappings,
    get_supported_frameworks,
)
from .identity import (
    derive_canonical_inputs_hash,
    derive_evidence_id,
    derive_finding_id,
    derive_findings_hash,
    derive_manifest_hash,
    derive_remediation_id,
    derive_report_id,
)
from .models import (
    ConfidenceScore,
    EvidenceRef,
    FrameworkMapping,
    GovernanceFinding,
    GovernanceReport,
    RemediationEntry,
    ReplayContract,
    ValidationState,
)
from .serialization import (
    ExportUnavailableError,
    deserialize_report,
    export_html,
    export_pdf_bytes,
    serialize_for_manifest,
    serialize_report,
)

__all__ = [
    # Engine
    "GovernanceReportEngine",
    "GovernanceReportError",
    # Models
    "ConfidenceScore",
    "EvidenceRef",
    "FrameworkMapping",
    "GovernanceFinding",
    "GovernanceReport",
    "RemediationEntry",
    "ReplayContract",
    "ValidationState",
    # Identity
    "derive_canonical_inputs_hash",
    "derive_evidence_id",
    "derive_finding_id",
    "derive_findings_hash",
    "derive_manifest_hash",
    "derive_remediation_id",
    "derive_report_id",
    # Confidence
    "calculate_confidence",
    # Framework mappings
    "FRAMEWORK_CONTROL_MAP",
    "get_framework_mappings",
    "get_supported_frameworks",
    # Serialization
    "ExportUnavailableError",
    "deserialize_report",
    "export_html",
    "export_pdf_bytes",
    "serialize_for_manifest",
    "serialize_report",
]
