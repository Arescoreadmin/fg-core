from __future__ import annotations

import pytest

from api.tripwires import WebhookDeliveryService, sanitize_url_for_log


class FakeResponse:
    def __init__(self, status_code: int, location: str | None = None):
        self.status_code = status_code
        self.status = status_code
        self.headers = {}
        if location is not None:
            self.headers["Location"] = location


class FakeHttpClient:
    def __init__(self, responses: list[FakeResponse]):
        self._responses = responses
        self.calls: list[str] = []

    async def post(self, url: str, **kwargs):
        self.calls.append(url)
        idx = min(len(self.calls) - 1, len(self._responses) - 1)
        return self._responses[idx]

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_tripwire_redirect_to_private_is_blocked(monkeypatch) -> None:
    service = WebhookDeliveryService(max_attempts=1)
    service._http_client = FakeHttpClient(
        [FakeResponse(302, "http://127.0.0.1/internal")]
    )

    def fake_validate(url: str, context: str):
        if "127.0.0.1" in url:
            return False, "forbidden_private_ip"
        return True, "allowed"

    monkeypatch.setattr("api.tripwires.validate_outbound_url", fake_validate)

    result = await service.deliver("https://example.com/hook", {"a": 1})
    assert result.success is False
    assert "forbidden_private_ip" in (result.error or "")


@pytest.mark.asyncio
async def test_tripwire_redirect_hop_limit_enforced(monkeypatch) -> None:
    service = WebhookDeliveryService(max_attempts=1)
    service._http_client = FakeHttpClient(
        [
            FakeResponse(302, "/one"),
            FakeResponse(302, "/two"),
            FakeResponse(302, "/three"),
            FakeResponse(302, "/four"),
        ]
    )
    monkeypatch.setattr(
        "api.tripwires.validate_outbound_url", lambda url, context: (True, "allowed")
    )

    result = await service.deliver("https://example.com/hook", {"a": 1})
    assert result.success is False
    assert result.error == "tripwire_webhook: redirect_hop_limit"


@pytest.mark.asyncio
async def test_tripwire_relative_redirect_location_resolved(monkeypatch) -> None:
    service = WebhookDeliveryService(max_attempts=1)
    fake_client = FakeHttpClient([FakeResponse(302, "/next"), FakeResponse(200)])
    service._http_client = fake_client
    monkeypatch.setattr(
        "api.tripwires.validate_outbound_url", lambda url, context: (True, "allowed")
    )

    result = await service.deliver("https://example.com/base", {"a": 1})
    assert result.success is True
    assert fake_client.calls == ["https://example.com/base", "https://example.com/next"]


def test_sanitize_url_for_log_strips_query_and_userinfo() -> None:
    sanitized_query = sanitize_url_for_log("https://ex.com/hook?token=secret")
    assert sanitized_query == "https://ex.com/hook"
    assert "token" not in sanitized_query
    assert "secret" not in sanitized_query

    sanitized_userinfo = sanitize_url_for_log("https://user:pass@ex.com/hook")
    assert sanitized_userinfo == "https://ex.com/hook"
    assert "user:pass" not in sanitized_userinfo
