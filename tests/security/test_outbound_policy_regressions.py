from __future__ import annotations

import pytest

from api.security.outbound_policy import OutboundPolicyError, sanitize_outbound_headers
from api.security_alerts import WebhookAlertChannel
from api.tripwires import WebhookDeliveryService


def test_webhook_alert_channel_rejects_invalid_header_name() -> None:
    with pytest.raises(OutboundPolicyError):
        WebhookAlertChannel("https://example.com/hook", headers={"Bad\nHeader": "x"})


def test_sanitize_outbound_headers_strips_control_values() -> None:
    cleaned = sanitize_outbound_headers({"X-Test": "abc\r\nInjected: bad"})
    assert cleaned["X-Test"] == "abc"


@pytest.mark.anyio
async def test_tripwire_close_uses_async_close_for_aiohttp_style_client() -> None:
    closed = {"value": False}

    class FakeAiohttpClient:
        async def close(self) -> None:
            closed["value"] = True

    svc = WebhookDeliveryService()
    svc._http_client = FakeAiohttpClient()
    await svc.close()
    assert closed["value"] is True
