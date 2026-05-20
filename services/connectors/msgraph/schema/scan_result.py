"""ScanResult, Finding, EvidenceRef, and AcknowledgmentReceipt Pydantic models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AcknowledgmentReceipt(BaseModel):
    """Cryptographic operator acknowledgment — chain of custody artifact."""

    model_config = {"frozen": True}

    operator_name: str
    operator_org: str
    client_org_name: str
    scopes_acknowledged: list[str]
    scan_authorized_at: str  # ISO 8601
    engagement_id: str  # UUID hex
    receipt_hmac: str  # HMAC-SHA256 hex


class EvidenceRef(BaseModel):
    """Pointer to collected evidence — counts and config state only, no content."""

    model_config = {"frozen": True}

    ref_id: str
    endpoint: str
    record_count: int
    config_state: dict[str, Any] = Field(default_factory=dict)
    collected_at: str  # ISO 8601
    data_hash: str  # sha256(record_count + sorted config keys)
    truncated: bool = False


class Finding(BaseModel):
    """Security finding — no raw user content, no UPNs, no display names."""

    model_config = {"frozen": True}

    finding_id: str  # sha256-derived, deterministic
    control_id: str  # e.g. "NIST-AI-RMF-GOVERN-1.2"
    framework_refs: list[str] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    title: str
    evidence_summary: str  # counts and config state only
    affected_count: int
    affected_entities: list[str] = Field(default_factory=list)  # entity types only
    recommendation: str
    remediation_effort: Literal["low", "medium", "high"]
    remediation_owner: Literal["IT", "Legal", "HR", "Exec", "Vendor"]
    first_seen_scan_id: str | None = None
    delta_status: Literal["new", "persisted", "resolved", "regressed"] | None = None
    evidence_refs: list[str] = Field(default_factory=list)  # ref_id references


class ScanResult(BaseModel):
    """Top-level scan output — schema-versioned, integrity-signed."""

    schema_version: Literal["1.0"] = "1.0"
    scan_id: str  # UUID hex
    scan_type: Literal["msgraph_v1"] = "msgraph_v1"
    tenant_id_hash: str  # sha256(tenant_id) — never plaintext
    engagement_id: str  # UUID hex
    operator_acknowledgment_receipt: AcknowledgmentReceipt
    scan_initiated_at: str  # ISO 8601
    scan_completed_at: str  # ISO 8601
    scan_duration_seconds: int
    scan_status: Literal["completed", "timeout", "error"] = "completed"
    scopes_authorized: list[str]
    scopes_in_token: list[str]
    pages_fetched: dict[str, int] = Field(default_factory=dict)
    endpoints_called: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_references: list[EvidenceRef] = Field(default_factory=list)
    analyzer_outputs: dict[str, Any] = Field(default_factory=dict)
    integrity_manifest: dict[str, Any] = Field(default_factory=dict)
    baseline_scan_id: str | None = None
