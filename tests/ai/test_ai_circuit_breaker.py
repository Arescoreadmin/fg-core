from __future__ import annotations

import types

import pytest

from api.ai.llm_client import LLMError, OpenAILLMClient


class _FailingResponses:
    def create(self, **kwargs):
        _ = kwargs
        raise RuntimeError("upstream failure")


class _FailingOpenAI:
    def __init__(self, **kwargs):
        _ = kwargs
        self.responses = _FailingResponses()


class _HTTPErr(Exception):
    def __init__(self, status_code: int):
        super().__init__(f"status={status_code}")
        self.status_code = status_code


class _ClientErrorResponses:
    def create(self, **kwargs):
        _ = kwargs
        raise _HTTPErr(400)


class _ServerErrorResponses:
    def create(self, **kwargs):
        _ = kwargs
        raise _HTTPErr(503)


class _ClientErrorOpenAI:
    def __init__(self, **kwargs):
        _ = kwargs
        self.responses = _ClientErrorResponses()


class _ServerErrorOpenAI:
    def __init__(self, **kwargs):
        _ = kwargs
        self.responses = _ServerErrorResponses()


class _RateLimitedResponses:
    def create(self, **kwargs):
        _ = kwargs
        raise _HTTPErr(429)


class _RateLimitedOpenAI:
    def __init__(self, **kwargs):
        _ = kwargs
        self.responses = _RateLimitedResponses()


def test_retryable_status_table_centralized():
    assert OpenAILLMClient.is_retryable_http_status(429) is True
    assert OpenAILLMClient.is_retryable_http_status(408) is True
    assert OpenAILLMClient.is_retryable_http_status(400) is False
    assert OpenAILLMClient.is_breaker_trip_http_status(408) is True
    assert OpenAILLMClient.is_breaker_trip_http_status(429) is False


def test_llm_circuit_breaker_opens(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("FG_AI_CB_ERROR_THRESHOLD", "1")
    monkeypatch.setenv("FG_AI_CB_WINDOW_S", "60")
    monkeypatch.setenv("FG_AI_CB_DEGRADED_S", "120")

    fake_openai_module = types.SimpleNamespace(OpenAI=_FailingOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_openai_module)

    OpenAILLMClient._window_started_at = 0.0
    OpenAILLMClient._window_errors = 0
    OpenAILLMClient._degraded_until = 0.0

    client = OpenAILLMClient()
    with pytest.raises(LLMError) as first:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert first.value.code == "AI_LLM_CALL_FAILED"

    with pytest.raises(LLMError) as second:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert second.value.code == "AI_DEGRADED"


class _SuccessResponses:
    def create(self, **kwargs):
        _ = kwargs

        class _Resp:
            output_text = '{"answer":"ok"}'

        return _Resp()


class _SuccessOpenAI:
    def __init__(self, **kwargs):
        _ = kwargs
        self.responses = _SuccessResponses()


def test_llm_circuit_breaker_half_open_and_close_counters(
    monkeypatch: pytest.MonkeyPatch, caplog
):
    caplog.set_level("INFO", logger="frostgate.security")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    fake_openai_module = types.SimpleNamespace(OpenAI=_SuccessOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_openai_module)

    monkeypatch.setattr("api.ai.llm_client.time.monotonic", lambda: 10.0)

    monkeypatch.setattr(OpenAILLMClient, "_is_degraded", classmethod(lambda cls: False))

    client = OpenAILLMClient()
    client._window_started_at = 0.0
    client._window_errors = 0
    client._degraded_until = 1.0
    client._breaker_open_count = 1
    client._breaker_half_open_trials = 0
    client._breaker_close_count = 0

    client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)

    assert client._breaker_half_open_trials >= 1
    assert client._breaker_close_count >= 1


def test_breaker_does_not_trip_on_deterministic_4xx(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("FG_AI_CB_ERROR_THRESHOLD", "1")

    fake_openai_module = types.SimpleNamespace(OpenAI=_ClientErrorOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_openai_module)

    OpenAILLMClient._window_started_at = 0.0
    OpenAILLMClient._window_errors = 0
    OpenAILLMClient._degraded_until = 0.0

    client = OpenAILLMClient()
    with pytest.raises(LLMError) as first:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert first.value.code == "AI_LLM_CALL_FAILED"

    with pytest.raises(LLMError) as second:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert second.value.code == "AI_LLM_CALL_FAILED"


def test_breaker_trips_on_5xx(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("FG_AI_CB_ERROR_THRESHOLD", "1")

    fake_openai_module = types.SimpleNamespace(OpenAI=_ServerErrorOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_openai_module)

    OpenAILLMClient._window_started_at = 0.0
    OpenAILLMClient._window_errors = 0
    OpenAILLMClient._degraded_until = 0.0

    client = OpenAILLMClient()
    with pytest.raises(LLMError):
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)

    with pytest.raises(LLMError) as second:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert second.value.code == "AI_DEGRADED"


def test_retryable_429_does_not_trip_breaker(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("FG_AI_CB_ERROR_THRESHOLD", "1")

    fake_openai_module = types.SimpleNamespace(OpenAI=_RateLimitedOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_openai_module)

    OpenAILLMClient._window_started_at = 0.0
    OpenAILLMClient._window_errors = 0
    OpenAILLMClient._degraded_until = 0.0

    client = OpenAILLMClient()
    with pytest.raises(LLMError) as first:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert first.value.code == "AI_LLM_CALL_FAILED"

    with pytest.raises(LLMError) as second:
        client.generate(model="gpt-4o-mini", prompt="x", max_tokens=64, temperature=0.2)
    assert second.value.code == "AI_LLM_CALL_FAILED"


def test_health_exposes_breaker_state(build_app):
    app = build_app()
    from fastapi.testclient import TestClient

    c = TestClient(app)
    h = c.get("/health")
    r = c.get("/health/ready")
    assert h.status_code == 200
    assert r.status_code in {200, 503}
    assert h.json().get("ai_breaker_state") in {"closed", "open", "half_open"}
    assert isinstance(h.json().get("ai_breaker_log_cooldown_seconds"), int)
    metrics = h.json().get("ai_breaker_metrics", {})
    assert isinstance(metrics.get("open_count"), int)
    assert isinstance(metrics.get("half_open_trials"), int)
    assert isinstance(metrics.get("close_count"), int)
    assert 0 <= metrics.get("open_count") <= 1_000_000_000
    assert 0 <= metrics.get("half_open_trials") <= 1_000_000_000
    assert 0 <= metrics.get("close_count") <= 1_000_000_000
    if r.status_code == 200:
        assert r.json().get("ai_breaker_state") in {"closed", "open", "half_open"}
        assert isinstance(r.json().get("ai_breaker_log_cooldown_seconds"), int)
