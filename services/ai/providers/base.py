from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Stable error codes — never change meaning once published
AI_PROVIDER_CONFIG_MISSING = "AI_PROVIDER_CONFIG_MISSING"
AI_PROVIDER_CALL_FAILED = "AI_PROVIDER_CALL_FAILED"
AI_PROVIDER_TIMEOUT = "AI_PROVIDER_TIMEOUT"
AI_PROVIDER_RESPONSE_INVALID = "AI_PROVIDER_RESPONSE_INVALID"
AI_PROVIDER_NOT_ALLOWED = "AI_PROVIDER_NOT_ALLOWED"
AI_SIMULATED_PROVIDER_DISABLED = "AI_SIMULATED_PROVIDER_DISABLED"


class ProviderCallError(Exception):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class ProviderRequest:
    tenant_id: str
    provider_id: str
    prompt: str
    max_tokens: int
    request_id: str
    system_prompt: str | None = None


@dataclass(frozen=True)
class ProviderResponse:
    provider_id: str
    text: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reason: str | None = None


@runtime_checkable
class LlmProvider(Protocol):
    def call(self, req: ProviderRequest) -> ProviderResponse: ...
