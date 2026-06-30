"""services/report_authority/schemas.py — Pydantic schemas for Report Authority API.

All request schemas use ConfigDict(extra="forbid") to prevent field injection.
All response schemas use ConfigDict(extra="forbid") for contract stability.
All dates are ISO 8601 strings.

Exception hierarchy:
  ReportAuthorityError
    ├── ReportNotFound
    ├── ReportTenantViolation
    ├── ReportConflict
    ├── ReportInvalidTransition
    ├── ReportImmutableState
    ├── ReportGenerationError
    ├── ReportSigningError
    ├── ReportExportError
    └── ReportRenderingError
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from services.report_authority.models import ReportType


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class ReportAuthorityError(Exception):
    """Base exception for all Report Authority errors."""


class ReportNotFound(ReportAuthorityError):
    """Report does not exist or is not visible to the tenant."""


class ReportTenantViolation(ReportAuthorityError):
    """Cross-tenant access attempt detected."""


class ReportConflict(ReportAuthorityError):
    """Conflict with existing report (e.g., duplicate ref)."""


class ReportInvalidTransition(ReportAuthorityError):
    """Requested lifecycle transition is not permitted."""


class ReportImmutableState(ReportAuthorityError):
    """Report is in an immutable state; mutation is not allowed."""


class ReportGenerationError(ReportAuthorityError):
    """Report generation pipeline encountered an unrecoverable error."""


class ReportSigningError(ReportAuthorityError):
    """Report signing pipeline encountered an error."""


class ReportExportError(ReportAuthorityError):
    """Report export bundle creation failed."""


class ReportRenderingError(ReportAuthorityError):
    """Report rendering to a specific format failed."""


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class GenerateReportRequest(BaseModel):
    """Request to generate a new report for an assessment."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(..., min_length=1, max_length=64)
    report_type: ReportType
    title: str = Field(..., min_length=1, max_length=512)
    scope: str = Field(..., min_length=1, max_length=4096)
    objectives: str = Field(..., min_length=1, max_length=4096)
    assessor_id: str = Field(..., min_length=1, max_length=255)
    reviewer_id: str = Field(..., min_length=1, max_length=255)
    branding_config: dict[str, Any] | None = Field(default=None)
    regulatory_profile: str | None = Field(default=None, max_length=128)


class PublishReportRequest(BaseModel):
    """Request to publish a signed or generated report."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=1024)


class VerifyReportRequest(BaseModel):
    """Request to verify a report's integrity by a named verifier."""

    model_config = ConfigDict(extra="forbid")

    verifier_id: str = Field(..., min_length=1, max_length=255)
    verifier_notes: str | None = Field(default=None, max_length=2048)


class CompareReportsRequest(BaseModel):
    """Request to compare two report versions for diff analysis."""

    model_config = ConfigDict(extra="forbid")

    baseline_report_id: str = Field(..., min_length=1, max_length=64)
    comparison_report_id: str = Field(..., min_length=1, max_length=64)


# ---------------------------------------------------------------------------
# Response schemas — core
# ---------------------------------------------------------------------------


class ReportResponse(BaseModel):
    """Full representation of a report record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    report_ref: str
    assessment_id: str
    report_type: str
    lifecycle_state: str
    title: str
    scope: str
    objectives: str
    assessor_id: str
    reviewer_id: str
    quality_score: float | None
    quality_grade: str | None
    evidence_coverage_score: float | None
    verification_coverage_score: float | None
    freshness_score: float | None
    confidence_score: float | None
    report_hash_sha256: str | None
    report_hash_sha512: str | None
    manifest_hash: str | None
    transparency_root: str | None
    schema_version: str
    manifest_schema_version: str
    generator_version: str
    created_at: str
    updated_at: str
    published_at: str | None
    superseded_at: str | None
    archived_at: str | None


class ReportListResponse(BaseModel):
    """Paginated list of reports."""

    model_config = ConfigDict(extra="forbid")

    items: list[ReportResponse]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------------------
# Response schemas — manifest and quality
# ---------------------------------------------------------------------------


class ReportManifestResponse(BaseModel):
    """Manifest metadata for a report — cryptographic proof of content."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    report_version: str
    schema_version: str
    manifest_schema_version: str
    authority_versions: dict[str, str]
    report_hash_sha256: str | None
    report_hash_sha512: str | None
    manifest_hash: str | None
    transparency_root: str | None
    merkle_root: str | None
    generation_timestamp: str
    generator_version: str
    provider_version: str
    export_version: str
    is_immutable: bool


class ReportQualityResponse(BaseModel):
    """Detailed quality breakdown for a single report."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    quality_score: float | None
    quality_grade: str | None
    evidence_coverage_score: float | None
    verification_coverage_score: float | None
    freshness_score: float | None
    confidence_score: float | None
    completeness_score: float | None
    computed_at: str


class ReportStatisticsResponse(BaseModel):
    """Tenant-level report statistics."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_reports: int
    by_type: dict[str, int]
    by_lifecycle_state: dict[str, int]
    by_quality_grade: dict[str, int]
    published_count: int
    failed_count: int
    generated_this_month: int


# ---------------------------------------------------------------------------
# Section-level item schemas
# ---------------------------------------------------------------------------


class FindingSchema(BaseModel):
    """A single finding as represented in a report section."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    severity: str
    category: str
    control_mapping: list[str]
    framework_mapping: list[str]
    evidence_references: list[str]
    confidence: float
    verification_status: str
    source_authority: str
    owner_id: str | None
    created_at: str
    updated_at: str


class EvidenceItemSchema(BaseModel):
    """A single evidence item as represented in a report appendix."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    hash_value: str | None
    collection_method: str
    freshness_status: str
    classification: str
    verification_status: str
    trust_digest: str | None
    transparency_entry: str | None
    chain_reference: str | None
    source: str
    timestamp: str


class ControlItemSchema(BaseModel):
    """A single control item as represented in a report appendix."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    framework: str
    status: str
    evidence_references: list[str]
    coverage: float
    effectiveness_score: float
    recommendations: list[str]
    mapped_findings: list[str]
    mapped_risks: list[str]


class RemediationItemSchema(BaseModel):
    """A single remediation task as represented in a report appendix."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    owner_id: str | None
    priority: str
    target_date: str | None
    verification_requirement: str | None
    closure_evidence_id: str | None
    current_status: str
    history: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------


class VersionComparisonResponse(BaseModel):
    """Diff between two report versions."""

    model_config = ConfigDict(extra="forbid")

    baseline_report_id: str
    comparison_report_id: str
    baseline_version: str
    comparison_version: str
    added_findings: list[str]
    removed_findings: list[str]
    changed_findings: list[str]
    added_controls: list[str]
    removed_controls: list[str]
    quality_delta: float
    generated_at: str


# ---------------------------------------------------------------------------
# Export bundle
# ---------------------------------------------------------------------------


class BundleResponse(BaseModel):
    """Export bundle metadata for a report."""

    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    report_id: str
    bundle_state: str
    bundle_hash_sha256: str | None
    bundle_hash_sha512: str | None
    bundle_signature: str | None
    contains_pdf: bool
    contains_html: bool
    contains_json: bool
    contains_manifest: bool
    contains_trust_manifest: bool
    contains_transparency_proof: bool
    contains_evidence_index: bool
    contains_verification_instructions: bool
    created_at: str
    expires_at: str | None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Health check response for the Report Authority service."""

    model_config = ConfigDict(extra="forbid")

    status: str
    authority: str
    version: str
    schema_version: str
    checks: dict[str, str]
