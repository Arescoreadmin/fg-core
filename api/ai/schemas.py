from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class AIQueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=32000)


class Citation(BaseModel):
    source_id: str = Field(..., min_length=1, max_length=256)
    chunk_id: str = Field(..., min_length=1, max_length=256)
    score: float = Field(..., ge=0.0, le=1.0)


class AIQueryResponse(BaseModel):
    answer: str = Field(..., min_length=1, max_length=12000)
    citations: list[Citation] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)
    trace_id: str = Field(..., min_length=8, max_length=128)

    @field_validator("warnings")
    @classmethod
    def _warnings_limit(cls, v: list[str]) -> list[str]:
        return [w[:256] for w in v[:16]]

    @field_validator("citations")
    @classmethod
    def _citations_limit(cls, v: list[Citation]) -> list[Citation]:
        if len(v) > 20:
            raise ValueError("too many citations")
        return v
