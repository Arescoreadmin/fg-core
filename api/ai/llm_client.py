from __future__ import annotations

import json
import os
import time
import logging
from dataclasses import dataclass
from typing import Protocol


class LLMError(RuntimeError):
    code: str

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class LLMClient(Protocol):
    def generate(
        self, *, model: str, prompt: str, max_tokens: int, temperature: float
    ) -> str: ...


@dataclass
class OpenAILLMClient:
    """Strict no-tools client. Does not browse or invoke external tools."""

    _log = logging.getLogger("frostgate.security")

    _window_started_at: float = 0.0
    _window_errors: int = 0
    _degraded_until: float = 0.0
    _breaker_open_count: int = 0
    _breaker_half_open_trials: int = 0
    _breaker_close_count: int = 0
    _last_open_log_at: float = 0.0

    RETRYABLE_HTTP_STATUS: frozenset[int] = frozenset({408, 409, 425, 429})
    BREAKER_TRIP_HTTP_STATUS: frozenset[int] = frozenset({408, 425})
    _COUNTER_MAX: int = 1_000_000_000

    @classmethod
    def _circuit_window_s(cls) -> int:
        return max(10, min(int(os.getenv("FG_AI_CB_WINDOW_S", "60")), 600))

    @classmethod
    def _circuit_threshold(cls) -> int:
        return max(1, min(int(os.getenv("FG_AI_CB_ERROR_THRESHOLD", "5")), 100))

    @classmethod
    def _circuit_degraded_s(cls) -> int:
        return max(5, min(int(os.getenv("FG_AI_CB_DEGRADED_S", "120")), 1800))

    @classmethod
    def _open_log_cooldown_s(cls) -> int:
        return max(1, min(int(os.getenv("FG_AI_CB_OPEN_LOG_COOLDOWN_S", "30")), 600))

    @classmethod
    def is_retryable_http_status(cls, status_code: int) -> bool:
        return int(status_code) in cls.RETRYABLE_HTTP_STATUS

    @classmethod
    def is_breaker_trip_http_status(cls, status_code: int) -> bool:
        return int(status_code) in cls.BREAKER_TRIP_HTTP_STATUS

    @classmethod
    def _bounded_counter(cls, value: int) -> int:
        return max(0, min(int(value), cls._COUNTER_MAX))

    @classmethod
    def breaker_snapshot(cls) -> dict[str, int | str]:
        return {
            "state": cls.breaker_state(),
            "open_count": cls._bounded_counter(cls._breaker_open_count),
            "half_open_trials": cls._bounded_counter(cls._breaker_half_open_trials),
            "close_count": cls._bounded_counter(cls._breaker_close_count),
            "log_cooldown_seconds": int(cls._open_log_cooldown_s()),
        }

    @classmethod
    def _record_error(cls) -> None:
        now = time.monotonic()
        window_s = cls._circuit_window_s()
        if now - cls._window_started_at > window_s:
            cls._window_started_at = now
            cls._window_errors = 0
        cls._window_errors += 1
        if cls._window_errors >= cls._circuit_threshold():
            was_open = cls._is_degraded()
            cls._degraded_until = now + cls._circuit_degraded_s()
            if not was_open:
                cls._breaker_open_count += 1
                if now - cls._last_open_log_at >= cls._open_log_cooldown_s():
                    cls._last_open_log_at = now
                    cls._log.warning(
                        "ai_circuit_breaker_open",
                        extra={
                            "event": "ai_circuit_breaker_open",
                            "open_count": cls._breaker_open_count,
                            "half_open_trials": cls._breaker_half_open_trials,
                            "close_count": cls._breaker_close_count,
                            "log_cooldown_s": cls._open_log_cooldown_s(),
                        },
                    )

    @classmethod
    def _is_degraded(cls) -> bool:
        return time.monotonic() < cls._degraded_until

    @classmethod
    def breaker_state(cls) -> str:
        now = time.monotonic()
        if now < cls._degraded_until:
            return "open"
        if cls._degraded_until > 0 and now >= cls._degraded_until:
            return "half_open"
        return "closed"

    @staticmethod
    def _should_trip_breaker(exc: Exception) -> bool:
        status_code = getattr(exc, "status_code", None)
        if isinstance(status_code, int):
            if 500 <= status_code <= 599:
                return True
            if 400 <= status_code <= 499:
                return OpenAILLMClient.is_breaker_trip_http_status(status_code)
            return OpenAILLMClient.is_breaker_trip_http_status(status_code)

        text = str(type(exc)).lower() + " " + str(exc).lower()
        if "timeout" in text:
            return True
        if isinstance(exc, TimeoutError):
            return True
        return True

    def generate(
        self, *, model: str, prompt: str, max_tokens: int, temperature: float
    ) -> str:
        now = time.monotonic()
        if self._is_degraded():
            raise LLMError("AI_DEGRADED", "llm provider circuit breaker open")
        if self._degraded_until and now >= self._degraded_until:
            self._breaker_half_open_trials += 1
            self._log.info(
                "ai_circuit_breaker_half_open_trial",
                extra={
                    "event": "ai_circuit_breaker_half_open_trial",
                    "open_count": self._breaker_open_count,
                    "half_open_trials": self._breaker_half_open_trials,
                    "close_count": self._breaker_close_count,
                },
            )
        api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
        if not api_key:
            raise LLMError("AI_LLM_UNAVAILABLE", "OPENAI_API_KEY is not configured")
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover
            raise LLMError("AI_LLM_UNAVAILABLE", "openai sdk unavailable") from exc

        client = OpenAI(api_key=api_key)
        try:
            response = client.responses.create(
                model=model,
                input=prompt,
                max_output_tokens=max_tokens,
                temperature=temperature,
                tools=[],
            )
        except Exception as exc:
            if self._should_trip_breaker(exc):
                self._record_error()
            raise LLMError("AI_LLM_CALL_FAILED", "upstream llm call failed") from exc

        output_text = getattr(response, "output_text", "")
        if not output_text:
            raise LLMError("AI_LLM_EMPTY", "llm output empty")

        if self._degraded_until:
            self._degraded_until = 0.0
            self._window_errors = 0
            self._breaker_close_count += 1
            self._log.info(
                "ai_circuit_breaker_closed",
                extra={
                    "event": "ai_circuit_breaker_closed",
                    "open_count": self._breaker_open_count,
                    "half_open_trials": self._breaker_half_open_trials,
                    "close_count": self._breaker_close_count,
                },
            )
        return output_text


def parse_and_validate_json(raw_output: str) -> dict:
    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise LLMError("AI_SCHEMA_INVALID", "llm output is not valid json") from exc
    if not isinstance(parsed, dict):
        raise LLMError("AI_SCHEMA_INVALID", "llm output must be a json object")
    return parsed


def get_llm_client() -> LLMClient:
    return OpenAILLMClient()


def get_breaker_state() -> str:
    return OpenAILLMClient.breaker_state()


def get_breaker_snapshot() -> dict[str, int | str]:
    return OpenAILLMClient.breaker_snapshot()
