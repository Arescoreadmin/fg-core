from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ComplianceCPEvidenceIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    req_ids: list[str] = Field(default_factory=list)
    title: str
    details: str
    severity: str = "med"
    detected_at_utc: str
    control_refs: list[str] | None = None


class ComplianceCPError(BaseModel):
    error_code: str
    detail: str
