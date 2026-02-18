from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AIInferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str


class AIInferResponse(BaseModel):
    ok: bool
    model: str
    response: str
    simulated: bool


class AIPolicyUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_prompt_chars: int = 2000
    denylist: list[str] = Field(default_factory=list)
