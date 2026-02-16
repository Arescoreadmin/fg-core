import pytest

from api import security_alerts
from api.security_alerts import (
    SSRFBlocked,
    sanitize_header_value,
    sanitize_url_for_log,
    validate_target,
)
from api.tripwires import WebhookDeliveryService


class _MockResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.status = status_code
        self.headers = headers or {}


class _MockHttpClient:
    def __init__(self, responses):
        self.responses = responses
        self.call_count = 0

    async def post(self, url: str, **kwargs):
        response = self.responses[self.call_count]
        self.call_count += 1
        return response


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch):
    def _resolve(host: str):
        if host in {"example.com", "public.example"}:
            return ["93.184.216.34"]
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        if host == "169.254.169.254":
            return ["169.254.169.254"]
        if host == "::1":
            return ["::1"]
        if host == "::ffff:127.0.0.1":
            return ["::ffff:127.0.0.1"]
        return ["93.184.216.34"]

    monkeypatch.setattr(security_alerts, "resolve_host", _resolve)


def test_validate_target_blocks_loopback_127_0_0_1():
    with pytest.raises(SSRFBlocked, match="resolved_ip_blocked"):
        validate_target("http://127.0.0.1/hook")


def test_validate_target_blocks_metadata_ip_169_254_169_254():
    with pytest.raises(SSRFBlocked, match="resolved_ip_blocked"):
        validate_target("http://169.254.169.254/latest/meta-data")


def test_validate_target_blocks_ipv6_loopback():
    with pytest.raises(SSRFBlocked, match="resolved_ip_blocked"):
        validate_target("http://[::1]/")


def test_validate_target_blocks_ipv4_mapped_ipv6_loopback():
    with pytest.raises(SSRFBlocked, match="resolved_ip_blocked"):
        validate_target("http://[::ffff:127.0.0.1]/")


def test_validate_target_rejects_url_userinfo():
    with pytest.raises(SSRFBlocked, match="userinfo_not_allowed"):
        validate_target("http://user:pass@example.com/path")


@pytest.mark.asyncio
async def test_tripwire_blocks_redirect_to_private_ip_before_second_fetch():
    service = WebhookDeliveryService(max_attempts=1)
    service._http_client = _MockHttpClient(
        [
            _MockResponse(
                302,
                headers={"Location": "http://127.0.0.1/private"},
            ),
            _MockResponse(200),
        ]
    )

    result = await service.deliver(
        url="http://public.example/hook",
        payload={"event": "test"},
    )

    assert result.success is False
    assert "resolved_ip_blocked" in (result.error or "")
    assert service._http_client.call_count == 1


@pytest.mark.asyncio
async def test_tripwire_blocks_scheme_relative_redirect_to_private_ip():
    service = WebhookDeliveryService(max_attempts=1)
    service._http_client = _MockHttpClient(
        [
            _MockResponse(
                302,
                headers={"Location": "//127.0.0.1/private"},
            ),
            _MockResponse(200),
        ]
    )

    result = await service.deliver(
        url="http://public.example/hook",
        payload={"event": "test"},
    )

    assert result.success is False
    assert "resolved_ip_blocked" in (result.error or "")
    assert service._http_client.call_count == 1


@pytest.mark.asyncio
async def test_tripwire_rejects_redirect_without_location_header():
    service = WebhookDeliveryService(max_attempts=1)
    service._http_client = _MockHttpClient([_MockResponse(302, headers={})])

    result = await service.deliver(
        url="http://public.example/hook",
        payload={"event": "test"},
    )

    assert result.success is False
    assert "redirect_location_missing" in (result.error or "")
    assert service._http_client.call_count == 1


def test_sanitize_url_for_log_strips_userinfo():
    sanitized = sanitize_url_for_log("http://user:pass@example.com/path?token=abc")
    assert "user" not in sanitized
    assert "pass" not in sanitized
    assert "@example.com" not in sanitized
    assert sanitized == "http://example.com/path"


def test_sanitize_url_for_log_strips_control_characters():
    dirty = "http://example.com/path\r\n\t\x00?q=abc"
    sanitized = sanitize_url_for_log(dirty)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\t" not in sanitized
    assert "\x00" not in sanitized
    assert sanitized == "http://example.com/path"


def test_sanitize_header_value_strips_control_chars_and_injection_suffix():
    sanitized = sanitize_header_value("ok\r\nInjected: yes")
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "Injected" not in sanitized
    assert sanitized == "ok"


def test_sanitize_header_value_caps_length_at_256():
    sanitized = sanitize_header_value("A" * 10000)
    assert len(sanitized) <= 256
    assert sanitized == "A" * 256
