from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, request

from api.ai.policy import ai_max_tokens, ai_model_name, ai_temperature, error_response
from api.ai.schemas import AIQueryResponse
from api.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerError,
    circuit_breaker,
)


@dataclass(frozen=True)
class LLMRequest:
    prompt: str
    trace_id: str


class RetryableProviderError(RuntimeError):
    pass


class RetryableNoTripProviderError(RuntimeError):
    pass


class TerminalProviderError(RuntimeError):
    pass


class LLMClient:
    provider_name = "openai_chat_completions"

    def __init__(self) -> None:
        self._timeout_s = max(
            1.0, float(os.getenv("FG_AI_TIMEOUT_SECONDS", "15") or 15)
        )
        self._max_retries = max(0, int(os.getenv("FG_AI_MAX_RETRIES", "2") or 2))
        self._retry_backoff_s = max(
            0.05, float(os.getenv("FG_AI_RETRY_BACKOFF_SECONDS", "0.25") or 0.25)
        )
        self._total_budget_s = max(
            1.0, float(os.getenv("FG_AI_TOTAL_BUDGET_SECONDS", "20") or 20)
        )
        self._breaker = circuit_breaker(
            "ai_llm_provider",
            CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=20,
                half_open_max_calls=2,
                success_threshold=1,
                timeout=self._timeout_s,
                excluded_exceptions=(
                    TerminalProviderError,
                    RetryableNoTripProviderError,
                ),
            ),
        )

    def query(self, req: LLMRequest) -> AIQueryResponse:
        raw_output = self._complete_with_retries(req.prompt)
        try:
            payload: Any = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise error_response(
                502, "AI_SCHEMA_INVALID", "Model output was invalid"
            ) from exc

        try:
            parsed = AIQueryResponse.model_validate(payload)
        except Exception as exc:
            raise error_response(
                502, "AI_SCHEMA_INVALID", "Model output was invalid"
            ) from exc

        if parsed.trace_id != req.trace_id:
            parsed = parsed.model_copy(update={"trace_id": req.trace_id})
        return parsed

    def _complete_with_retries(self, prompt: str) -> str:
        deadline = time.monotonic() + self._total_budget_s
        attempts = self._max_retries + 1

        for attempt in range(attempts):
            if time.monotonic() >= deadline:
                break
            try:
                return self._breaker.protect(self._complete_once)(prompt)
            except TerminalProviderError as exc:
                raise error_response(502, "AI_PROVIDER_INVALID", str(exc)) from exc
            except CircuitBreakerError as exc:
                raise error_response(
                    503, "AI_PROVIDER_UNAVAILABLE", "AI provider circuit open"
                ) from exc
            except (RetryableProviderError, RetryableNoTripProviderError):
                if attempt >= attempts - 1:
                    break
                remaining = max(0.0, deadline - time.monotonic())
                sleep_for = min(self._retry_backoff_s * (2**attempt), remaining)
                if sleep_for > 0:
                    time.sleep(sleep_for)

        raise error_response(
            503, "AI_PROVIDER_UNAVAILABLE", "AI provider request failed"
        )

    def _complete_once(self, prompt: str) -> str:
        mock = os.getenv("FG_AI_MOCK_RESPONSE")
        if mock:
            return mock

        api_key = (os.getenv("FG_OPENAI_API_KEY") or "").strip()
        if not api_key:
            raise TerminalProviderError("AI provider is not configured")

        body = {
            "model": ai_model_name(),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": ai_temperature(),
            "max_tokens": ai_max_tokens(),
        }
        data = json.dumps(body).encode("utf-8")
        req = request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self._timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as exc:
            status = int(getattr(exc, "code", 0))
            if status == 429:
                raise RetryableNoTripProviderError("provider_http_429") from exc
            if status in {408, 409, 425} or 500 <= status <= 599:
                raise RetryableProviderError(f"provider_http_{status}") from exc
            raise TerminalProviderError(f"provider_http_{status}") from exc
        except error.URLError as exc:
            raise RetryableProviderError("provider_network_error") from exc

        try:
            return str(payload["choices"][0]["message"]["content"])
        except Exception as exc:
            raise TerminalProviderError("AI provider returned invalid content") from exc
