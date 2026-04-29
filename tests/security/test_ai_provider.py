"""
AI provider MVP tests.

Covers:
  Provider boundary:
    - ProviderCallError carries stable error_code
    - call_provider dispatches to AnthropicProvider / SimulatedProvider
    - call_provider rejects unknown provider_id
    - call_provider does not fallback on failure

  AnthropicProvider:
    - builds correct request (model, max_tokens, messages) — mocked transport
    - parses successful response (text, model, usage tokens, finish_reason)
    - handles non-200 → AI_PROVIDER_CALL_FAILED
    - handles timeout → AI_PROVIDER_TIMEOUT
    - handles transport error → AI_PROVIDER_CALL_FAILED
    - handles malformed response (missing content) → AI_PROVIDER_RESPONSE_INVALID
    - missing API key → AI_PROVIDER_CONFIG_MISSING
    - API key never appears in ProviderCallError message

  SimulatedProvider:
    - returns deterministic SIMULATED_RESPONSE text
    - blocked when FG_AI_ENABLE_SIMULATED=0 in prod-like env

  Provider selection (ui_ai_console):
    - FG_AI_DEFAULT_PROVIDER=anthropic → anthropic used as default
    - explicit payload.provider overrides env default
    - unknown provider → 400 AI_PROVIDER_UNKNOWN
    - anthropic missing API key → 400 AI_PROVIDER_DENIED_BY_ENV
    - simulated blocked in prod-like env → 400 AI_PROVIDER_DENIED_BY_ENV

  Route integration (mocked provider):
    - anthropic mocked → 200, response not SIMULATED_RESPONSE
    - BAA gate denial → 403, provider not called
    - provider config error → 503
    - simulated provider → response is SIMULATED_RESPONSE:*

  Regression:
    - removing provider boundary raises in tests
    - no fallback to simulated after anthropic failure
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from services.ai.dispatch import call_provider
from services.ai.providers.base import (
    AI_PROVIDER_CALL_FAILED,
    AI_PROVIDER_CONFIG_MISSING,
    AI_PROVIDER_NOT_ALLOWED,
    AI_PROVIDER_RESPONSE_INVALID,
    AI_PROVIDER_TIMEOUT,
    AI_SIMULATED_PROVIDER_DISABLED,
    ProviderCallError,
    ProviderRequest,
    ProviderResponse,
)

_CLEAN_TEXT = "Please summarize the quarterly report."
_MRN_TEXT = "MRN: 4872910 — schedule appointment next week."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_req(
    provider_id: str = "anthropic",
    prompt: str = _CLEAN_TEXT,
    max_tokens: int = 512,
    tenant_id: str = "tenant-test",
    request_id: str = "req-001",
) -> ProviderRequest:
    return ProviderRequest(
        tenant_id=tenant_id,
        provider_id=provider_id,
        prompt=prompt,
        max_tokens=max_tokens,
        request_id=request_id,
    )


def _anthropic_ok_body(
    text: str = "Hello from Anthropic",
    model: str = "claude-haiku-4-5-20251001",
    input_tokens: int = 10,
    output_tokens: int = 5,
    stop_reason: str = "end_turn",
) -> dict[str, Any]:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": model,
        "stop_reason": stop_reason,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }


def _db(tmp_path: Path):
    db_path = str(tmp_path / "test.db")
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker()()


def _insert_baa(db, *, tenant_id: str, provider_id: str, baa_status: str) -> None:
    db.execute(
        text(
            "INSERT INTO provider_baa_records "
            "(tenant_id, provider_id, baa_status, effective_date, expiry_date) "
            "VALUES (:tenant_id, :provider_id, :baa_status, '2025-01-01', '2030-01-01')"
        ),
        {"tenant_id": tenant_id, "provider_id": provider_id, "baa_status": baa_status},
    )
    db.commit()


# ---------------------------------------------------------------------------
# Section 1: ProviderCallError
# ---------------------------------------------------------------------------


def test_provider_call_error_carries_code() -> None:
    err = ProviderCallError(AI_PROVIDER_CONFIG_MISSING, "key not set")
    assert err.error_code == AI_PROVIDER_CONFIG_MISSING
    assert "key not set" in str(err)


@pytest.mark.parametrize(
    "code",
    [
        AI_PROVIDER_CONFIG_MISSING,
        AI_PROVIDER_CALL_FAILED,
        AI_PROVIDER_TIMEOUT,
        AI_PROVIDER_RESPONSE_INVALID,
        AI_PROVIDER_NOT_ALLOWED,
        AI_SIMULATED_PROVIDER_DISABLED,
    ],
)
def test_provider_error_codes_are_strings(code: str) -> None:
    assert isinstance(code, str)
    assert code.isupper()


# ---------------------------------------------------------------------------
# Section 2: call_provider dispatch
# ---------------------------------------------------------------------------


def test_call_provider_unknown_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ProviderCallError) as exc_info:
        call_provider(
            provider_id="nonexistent",
            prompt="hello",
            max_tokens=100,
            request_id="r-1",
            tenant_id="t-1",
        )
    assert exc_info.value.error_code == AI_PROVIDER_NOT_ALLOWED


def test_call_provider_dispatches_to_simulated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    resp = call_provider(
        provider_id="simulated",
        prompt="hello",
        max_tokens=100,
        request_id="r-1",
        tenant_id="t-1",
    )
    assert resp.provider_id == "simulated"
    assert resp.text.startswith("SIMULATED_RESPONSE:")


def test_call_provider_no_fallback_on_anthropic_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ProviderCallError) as exc_info:
        call_provider(
            provider_id="anthropic",
            prompt="hello",
            max_tokens=100,
            request_id="r-1",
            tenant_id="t-1",
        )
    # Must fail with config error, NOT fall back to simulated
    assert exc_info.value.error_code == AI_PROVIDER_CONFIG_MISSING


# ---------------------------------------------------------------------------
# Section 3: AnthropicProvider unit tests (mocked transport)
# ---------------------------------------------------------------------------


def test_anthropic_provider_builds_correct_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key-abc")
    monkeypatch.setenv("FG_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    captured: dict[str, Any] = {}

    def _mock_post(url, *, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = json
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _anthropic_ok_body()
        return mock_resp

    with patch("httpx.post", side_effect=_mock_post):
        provider = AnthropicProvider()
        provider.call(_make_req(provider_id="anthropic", max_tokens=256))

    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "test-key-abc"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    body = captured["body"]
    assert body["model"] == "claude-haiku-4-5-20251001"
    assert body["max_tokens"] == 256
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"] == _CLEAN_TEXT


def test_anthropic_provider_parses_response(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _anthropic_ok_body(
        text="Summary here",
        model="claude-haiku-4-5-20251001",
        input_tokens=20,
        output_tokens=8,
        stop_reason="end_turn",
    )

    with patch("httpx.post", return_value=mock_resp):
        provider = AnthropicProvider()
        resp = provider.call(_make_req())

    assert resp.text == "Summary here"
    assert resp.model == "claude-haiku-4-5-20251001"
    assert resp.input_tokens == 20
    assert resp.output_tokens == 8
    assert resp.finish_reason == "end_turn"
    assert resp.provider_id == "anthropic"


def test_anthropic_provider_non_200_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("httpx.post", return_value=mock_resp):
        provider = AnthropicProvider()
        with pytest.raises(ProviderCallError) as exc_info:
            provider.call(_make_req())

    assert exc_info.value.error_code == AI_PROVIDER_CALL_FAILED


def test_anthropic_provider_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    with patch("httpx.post", side_effect=httpx.TimeoutException("timeout")):
        provider = AnthropicProvider()
        with pytest.raises(ProviderCallError) as exc_info:
            provider.call(_make_req())

    assert exc_info.value.error_code == AI_PROVIDER_TIMEOUT


def test_anthropic_provider_transport_error_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    with patch(
        "httpx.post",
        side_effect=httpx.ConnectError("connection refused"),
    ):
        provider = AnthropicProvider()
        with pytest.raises(ProviderCallError) as exc_info:
            provider.call(_make_req())

    assert exc_info.value.error_code == AI_PROVIDER_CALL_FAILED


def test_anthropic_provider_malformed_response_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"unexpected": "format"}

    with patch("httpx.post", return_value=mock_resp):
        provider = AnthropicProvider()
        with pytest.raises(ProviderCallError) as exc_info:
            provider.call(_make_req())

    assert exc_info.value.error_code == AI_PROVIDER_RESPONSE_INVALID


def test_anthropic_provider_missing_api_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)

    provider = AnthropicProvider()
    with pytest.raises(ProviderCallError) as exc_info:
        provider.call(_make_req())

    assert exc_info.value.error_code == AI_PROVIDER_CONFIG_MISSING


def test_anthropic_provider_error_does_not_expose_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    secret_key = "sk-ant-secret-key-must-not-appear"
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", secret_key)

    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("httpx.post", return_value=mock_resp):
        provider = AnthropicProvider()
        with pytest.raises(ProviderCallError) as exc_info:
            provider.call(_make_req())

    error_msg = str(exc_info.value)
    assert secret_key not in error_msg


def test_anthropic_provider_system_prompt_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.anthropic_provider import AnthropicProvider

    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    captured: dict[str, Any] = {}

    def _mock_post(url, *, headers, json, timeout):
        captured["body"] = json
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _anthropic_ok_body()
        return mock_resp

    req = ProviderRequest(
        tenant_id="t-1",
        provider_id="anthropic",
        prompt="hello",
        max_tokens=100,
        request_id="r-1",
        system_prompt="You are a helpful assistant.",
    )

    with patch("httpx.post", side_effect=_mock_post):
        AnthropicProvider().call(req)

    assert captured["body"].get("system") == "You are a helpful assistant."


# ---------------------------------------------------------------------------
# Section 4: SimulatedProvider
# ---------------------------------------------------------------------------


def test_simulated_provider_returns_deterministic_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.simulated_provider import SimulatedProvider

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    p = SimulatedProvider()
    r1 = p.call(_make_req(provider_id="simulated", prompt="same prompt"))
    r2 = p.call(_make_req(provider_id="simulated", prompt="same prompt"))
    assert r1.text == r2.text
    assert r1.text.startswith("SIMULATED_RESPONSE:")


def test_simulated_provider_blocked_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.ai.providers.simulated_provider import SimulatedProvider

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "0")

    p = SimulatedProvider()
    with pytest.raises(ProviderCallError) as exc_info:
        p.call(_make_req(provider_id="simulated"))

    assert exc_info.value.error_code == AI_SIMULATED_PROVIDER_DISABLED


def test_simulated_provider_explicitly_enabled_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai.providers.simulated_provider import SimulatedProvider

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    p = SimulatedProvider()
    resp = p.call(_make_req(provider_id="simulated"))
    assert resp.text.startswith("SIMULATED_RESPONSE:")


# ---------------------------------------------------------------------------
# Section 5: Provider selection in ui_ai_console
# ---------------------------------------------------------------------------


def test_fg_ai_default_provider_overrides_policy(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FG_AI_DEFAULT_PROVIDER=anthropic → anthropic selected as default."""
    from services.ai.providers.base import ProviderResponse

    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    _fake = ProviderResponse(
        provider_id="anthropic",
        text="real response",
        model="claude-haiku-4-5-20251001",
        input_tokens=5,
        output_tokens=3,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **kw: _fake)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-1"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "anthropic"
    assert body["response"] == "real response"
    assert "SIMULATED_RESPONSE" not in body["response"]


def test_explicit_payload_provider_overrides_env_default(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """payload.provider=simulated overrides FG_AI_DEFAULT_PROVIDER=anthropic."""
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "anthropic")
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-2"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 200
    assert resp.json()["provider"] == "simulated"
    assert resp.json()["response"].startswith("SIMULATED_RESPONSE:")


def test_unknown_provider_rejected(build_app, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,bogus_provider")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-3"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={
            "message": _CLEAN_TEXT,
            "device_id": device_id,
            "provider": "bogus_provider",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_PROVIDER_UNKNOWN"


def test_anthropic_missing_api_key_denied_by_env(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-4"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_PROVIDER_DENIED_BY_ENV"


def test_simulated_blocked_in_prod_like_env(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "0")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-5"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_PROVIDER_DENIED_BY_ENV"


# ---------------------------------------------------------------------------
# Section 6: Route integration with mocked provider
# ---------------------------------------------------------------------------


def test_chat_anthropic_mocked_returns_real_text(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Anthropic mocked → 200, response is real text, not SIMULATED_RESPONSE."""
    from services.ai.providers.base import ProviderResponse

    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    _fake = ProviderResponse(
        provider_id="anthropic",
        text="Here is the quarterly summary.",
        model="claude-haiku-4-5-20251001",
        input_tokens=12,
        output_tokens=7,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **kw: _fake)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-6"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["response"] == "Here is the quarterly summary."
    assert "SIMULATED_RESPONSE" not in body["response"]
    assert body["provider"] == "anthropic"
    assert body["usage"]["metering_mode"] == "provider"
    assert body["usage"]["prompt_tokens"] == 12
    assert body["usage"]["completion_tokens"] == 7


def test_chat_provider_config_error_returns_503(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai.providers.base import ProviderCallError

    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    def _fail(**kw):
        raise ProviderCallError(AI_PROVIDER_CONFIG_MISSING, "key missing")

    monkeypatch.setattr(ai_console, "_call_provider", _fail)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-7"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == AI_PROVIDER_CONFIG_MISSING


def test_simulated_response_is_deterministic_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same prompt → same SIMULATED_RESPONSE text (unit, no HTTP)."""
    from services.ai.providers.simulated_provider import SimulatedProvider

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    p = SimulatedProvider()
    r1 = p.call(_make_req(provider_id="simulated", prompt=_CLEAN_TEXT))
    r2 = p.call(_make_req(provider_id="simulated", prompt=_CLEAN_TEXT))
    assert r1.text == r2.text
    assert r1.text.startswith("SIMULATED_RESPONSE:")


def test_chat_simulated_response_via_route(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulated provider via chat route returns SIMULATED_RESPONSE: prefix."""
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-8"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 200
    assert resp.json()["response"].startswith("SIMULATED_RESPONSE:")


# ---------------------------------------------------------------------------
# Section 7: Regression
# ---------------------------------------------------------------------------


def test_provider_call_not_made_when_baa_denied(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BAA gate denial → provider must not be called."""
    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    call_count = {"n": 0}

    def _count_calls(**kw):
        call_count["n"] += 1
        return ProviderResponse(provider_id="anthropic", text="x", model="m")

    monkeypatch.setattr(ai_console, "_call_provider", _count_calls)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-9"},
    )

    # PHI + anthropic + no BAA → 403 before provider call
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 403
    assert call_count["n"] == 0, "provider must not be called when BAA gate denies"


def test_no_fallback_from_anthropic_to_simulated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider failure must not silently fall back to simulated."""
    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ProviderCallError) as exc_info:
        call_provider(
            provider_id="anthropic",
            prompt="hello",
            max_tokens=100,
            request_id="r-fallback",
            tenant_id="t-1",
        )
    # Must be a config error, not a simulated response
    assert exc_info.value.error_code == AI_PROVIDER_CONFIG_MISSING


def test_production_path_does_not_return_simulated_response(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In prod-like env with simulated disabled, simulated responses must not appear."""
    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "0")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-10"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id},
    )
    # Must fail — simulated disabled, no real provider configured
    assert resp.status_code in {400, 503}


# ---------------------------------------------------------------------------
# Section 8: Prod-gate tightening — independent checks, no silent downgrade
# ---------------------------------------------------------------------------


def test_global_allowed_providers_excludes_simulated_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In prod without FG_AI_ALLOWED_PROVIDERS, simulated must not be in the
    server-allowed set — even before the env check runs."""
    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_AI_ENABLE_SIMULATED", raising=False)
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)

    allowed = ai_console._global_allowed_providers()
    assert "simulated" not in allowed, (
        "_global_allowed_providers must not include simulated in prod "
        "— two independent checks required"
    )


def test_global_allowed_providers_excludes_simulated_in_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_ENV", "staging")
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_AI_ENABLE_SIMULATED", raising=False)

    allowed = ai_console._global_allowed_providers()
    assert "simulated" not in allowed


def test_no_provider_configured_rejected_at_server_check(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When simulated is disabled and no other provider is configured, the
    fallback must be caught at the server-allowed check (AI_PROVIDER_DENIED_BY_SERVER),
    not at the env check — proving the two gates are independent.

    FG_AI_ENABLE_SIMULATED=0 mirrors prod-default behaviour without triggering
    the auth_gate's FG_DB_URL requirement (set by build_app's conftest)."""
    client = TestClient(build_app(auth_enabled=True))
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "0")
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "AI-11"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id},
    )
    assert resp.status_code == 400
    # Must be caught at server check, not env check
    assert resp.json()["detail"]["error_code"] == "AI_PROVIDER_DENIED_BY_SERVER"


def test_resolve_effective_provider_raises_in_prod_without_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In prod with no FG_AI_DEFAULT_PROVIDER, selection must fail immediately —
    not silently return 'simulated' and let it fail downstream."""
    from services.ai_plane_extension.service import _resolve_effective_provider

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)

    with pytest.raises(ValueError, match="AI_PROVIDER_NOT_CONFIGURED"):
        _resolve_effective_provider()


def test_resolve_effective_provider_raises_in_staging_without_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai_plane_extension.service import _resolve_effective_provider

    monkeypatch.setenv("FG_ENV", "staging")
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)

    with pytest.raises(ValueError, match="AI_PROVIDER_NOT_CONFIGURED"):
        _resolve_effective_provider()


def test_resolve_effective_provider_returns_simulated_in_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from services.ai_plane_extension.service import _resolve_effective_provider

    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)

    assert _resolve_effective_provider() == "simulated"
