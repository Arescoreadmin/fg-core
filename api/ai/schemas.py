from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AIQueryRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


class AICitation(BaseModel):
    source_id: str = Field(min_length=1, max_length=256)
    chunk_id: str = Field(min_length=1, max_length=256)
    score: float = Field(ge=0.0, le=1.0)


class AIQueryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str = Field(min_length=0, max_length=8000)
    citations: list[AICitation] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)
    trace_id: str = Field(min_length=1, max_length=128)
