from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ComplianceMode = Literal[
    "strict_grounded",
    "retrieval_preferred",
    "phi_restricted",
    "legal_grade",
    "finance_grade",
    "internal_ops",
]


class AIInferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=10000)
    provider: str | None = Field(default=None, min_length=1, max_length=128)
    compliance_mode: ComplianceMode | None = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    doc_id: str
    chunk_id: str
    source_hash: str | None = None
    corpus_id: str | None = None
    citation_label: str | None = None
    source_title: str | None = None
    support_summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    retrieval_rank: int | None = Field(default=None, ge=1)
    rerank_score: float | None = Field(default=None, ge=0.0, le=1.0)
    provenance_status: str | None = None


class InferenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str
    based_on_evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_type: str | None = None
    limitation: str | None = None


class UncertaintyItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue: str
    reason_code: str
    affected_claim_or_area: str
    severity: Literal["low", "medium", "high"]
    evidence_refs: list[str] = Field(default_factory=list)


class EvidenceAwareResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    inference: list[InferenceItem] = Field(default_factory=list)
    uncertainty: list[UncertaintyItem] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0)
    requires_human_review: bool
    review_reasons: list[str] = Field(default_factory=list)
    compliance_mode: ComplianceMode
    retrieval_mode: str | None = None
    policy_version: int | None = None
    provenance_status: str | None = None
    retrieval_policy_applied: bool
    confidence: float = Field(ge=0.0, le=1.0)
    answer_reason: str | None = None
    no_answer_reason: str | None = None
    risk_factors: list[str] = Field(default_factory=list)


class AIInferResponse(BaseModel):
    ok: bool
    model: str
    response: str
    simulated: bool


class AIChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=10000)
    provider: str | None = Field(default=None, min_length=1, max_length=128)


class AIChatSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str


class AIChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str
    sources: list[AIChatSource] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class AIPolicyUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_prompt_chars: int = 2000
    denylist: list[str] = Field(default_factory=list)
