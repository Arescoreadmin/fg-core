from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AIInferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=10000)
    provider: str | None = Field(default=None, min_length=1, max_length=128)


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
