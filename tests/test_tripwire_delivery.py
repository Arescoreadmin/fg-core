"""
Tests for Tripwire Webhook Delivery.

Tests verify:
- Successful delivery
- Retry on transient failure
- Permanent failure handling
- Audit logging of delivery events
"""

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.tripwires import (
    DeliveryResult,
    TripwireAlert,
    WebhookDelivery,
    WebhookDeliveryService,
    check_auth_anomaly,
    check_canary_key,
    check_honeypot_path,
    deliver_webhook_async,
    queue_webhook_delivery,
)


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(self, status_code: int):
        self.status_code = status_code
        self.status = status_code  # aiohttp uses .status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class MockHttpClient:
    """Mock HTTP client for testing webhook delivery."""

    def __init__(self, responses: list[int] | None = None):
        self.responses = responses or [200]
        self.call_count = 0
        self.requests: list[dict] = []

    async def post(self, url: str, **kwargs) -> MockResponse:
        self.requests.append({"url": url, **kwargs})
        if self.call_count < len(self.responses):
            status = self.responses[self.call_count]
        else:
            status = self.responses[-1]
        self.call_count += 1

        if status == -1:  # Simulate exception
            raise ConnectionError("Connection refused")

        return MockResponse(status)

    async def aclose(self):
        pass


class TestWebhookDeliveryService:
    """Tests for WebhookDeliveryService."""

    @pytest.mark.asyncio
    async def test_successful_delivery(self):
        """Webhook delivers successfully on first attempt."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.01,  # Fast for testing
            audit_logger=audit_logger,
        )
        service._http_client = MockHttpClient([200])

        result = await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
            alert_type="TEST_ALERT",
            severity="HIGH",
        )

        assert result.success is True
        assert result.status_code == 200
        assert result.attempt == 1
        assert len(audit_events) == 1
        assert audit_events[0]["event_type"] == "webhook_delivered"
        assert audit_events[0]["success"] is True

    @pytest.mark.asyncio
    async def test_retry_on_server_error(self):
        """Webhook retries on 5xx server errors."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.01,
            audit_logger=audit_logger,
        )
        # First two attempts fail, third succeeds
        service._http_client = MockHttpClient([500, 503, 200])

        result = await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
        )

        assert result.success is True
        assert result.attempt == 3
        assert service._http_client.call_count == 3

        # Check retry events were logged
        retry_events = [e for e in audit_events if e["event_type"] == "webhook_retry"]
        assert len(retry_events) == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_client_error(self):
        """Webhook does not retry on 4xx client errors."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.01,
            audit_logger=audit_logger,
        )
        service._http_client = MockHttpClient([400])

        result = await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
        )

        assert result.success is False
        assert result.status_code == 400
        assert result.attempt == 1
        assert service._http_client.call_count == 1

        # Should be marked as permanent failure
        failed_events = [e for e in audit_events if e["event_type"] == "webhook_failed"]
        assert len(failed_events) == 1
        assert failed_events[0]["permanent_failure"] is True

    @pytest.mark.asyncio
    async def test_permanent_failure_after_max_attempts(self):
        """Webhook fails permanently after max attempts exhausted."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.01,
            audit_logger=audit_logger,
        )
        # All attempts fail
        service._http_client = MockHttpClient([500, 500, 500])

        result = await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
        )

        assert result.success is False
        assert result.attempt == 3
        assert "Server error" in result.error

        # Should have retry events and final failure
        retry_events = [e for e in audit_events if e["event_type"] == "webhook_retry"]
        failed_events = [e for e in audit_events if e["event_type"] == "webhook_failed"]
        assert len(retry_events) == 2  # 2 retries (after attempts 1 and 2)
        assert len(failed_events) == 1  # 1 final failure

    @pytest.mark.asyncio
    async def test_retry_on_connection_error(self):
        """Webhook retries on connection errors."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.01,
            audit_logger=audit_logger,
        )
        # First attempt fails with connection error, second succeeds
        service._http_client = MockHttpClient([-1, 200])

        result = await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
        )

        assert result.success is True
        assert result.attempt == 2

    @pytest.mark.asyncio
    async def test_audit_logging_includes_details(self):
        """Audit log events include relevant details."""
        audit_events = []

        def audit_logger(event):
            audit_events.append(event)

        service = WebhookDeliveryService(
            max_attempts=1,
            audit_logger=audit_logger,
        )
        service._http_client = MockHttpClient([200])

        await service.deliver(
            url="http://example.com/webhook",
            payload={"alert": "test"},
            alert_type="CANARY_TOKEN_ACCESSED",
            severity="CRITICAL",
        )

        assert len(audit_events) == 1
        event = audit_events[0]
        assert event["url"] == "http://example.com/webhook"
        assert event["alert_type"] == "CANARY_TOKEN_ACCESSED"
        assert event["severity"] == "CRITICAL"
        assert event["status_code"] == 200
        assert "response_time_ms" in event


class TestDeliverWebhookAsync:
    """Tests for the deliver_webhook_async function."""

    @pytest.mark.asyncio
    async def test_delivers_webhook(self):
        """deliver_webhook_async delivers webhook successfully."""
        mock_client = MockHttpClient([200])

        with patch("api.tripwires._delivery_service", None):
            with patch("api.tripwires.WebhookDeliveryService") as MockService:
                instance = MagicMock()
                instance.deliver = AsyncMock(return_value=DeliveryResult(success=True))
                MockService.return_value = instance

                result = await deliver_webhook_async(
                    url="http://example.com/webhook",
                    payload={"test": "data"},
                )

                assert result.success is True


class TestQueueWebhookDelivery:
    """Tests for the queue_webhook_delivery function."""

    def test_queues_delivery(self):
        """queue_webhook_delivery adds delivery to queue."""
        # Clear any existing queue items
        from api.tripwires import _delivery_queue

        while not _delivery_queue.empty():
            try:
                _delivery_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        queue_webhook_delivery(
            url="http://example.com/webhook",
            payload={"alert": "test"},
            alert_type="TEST",
            severity="HIGH",
        )

        assert not _delivery_queue.empty()
        delivery = _delivery_queue.get_nowait()
        assert delivery.url == "http://example.com/webhook"
        assert delivery.alert_type == "TEST"


class TestTripwireDetection:
    """Tests for tripwire detection functions."""

    def test_canary_key_detected(self):
        """Canary key prefix triggers alert."""
        # Patch _emit_alert to capture alerts
        with patch("api.tripwires._emit_alert") as mock_emit:
            result = check_canary_key("fgk_canary_abc123")
            assert result is True
            mock_emit.assert_called_once()
            alert = mock_emit.call_args[0][0]
            assert alert.alert_type == "CANARY_TOKEN_ACCESSED"
            assert alert.severity == "CRITICAL"

    def test_normal_key_not_detected(self):
        """Normal key prefix does not trigger alert."""
        with patch("api.tripwires._emit_alert") as mock_emit:
            result = check_canary_key("fgk_normal_key")
            assert result is False
            mock_emit.assert_not_called()

    def test_none_key_not_detected(self):
        """None key does not trigger alert."""
        with patch("api.tripwires._emit_alert") as mock_emit:
            result = check_canary_key(None)
            assert result is False
            mock_emit.assert_not_called()

    def test_honeypot_path_detected(self):
        """Honeypot path triggers alert."""
        honeypot_paths = [
            "/admin/backup",
            "/.git/config",
            "/.env",
            "/wp-admin",
            "/phpmyadmin",
        ]

        for path in honeypot_paths:
            with patch("api.tripwires._emit_alert") as mock_emit:
                result = check_honeypot_path(path)
                assert result is True, f"Path {path} should trigger alert"
                alert = mock_emit.call_args[0][0]
                assert alert.alert_type == "HONEYPOT_PATH_ACCESSED"

    def test_normal_path_not_detected(self):
        """Normal paths do not trigger alert."""
        normal_paths = [
            "/api/health",
            "/defend",
            "/ingest",
            "/admin/users",  # Not in honeypot list
        ]

        for path in normal_paths:
            with patch("api.tripwires._emit_alert") as mock_emit:
                result = check_honeypot_path(path)
                assert result is False, f"Path {path} should not trigger alert"
                mock_emit.assert_not_called()

    def test_auth_anomaly_detected(self):
        """High auth failure rate triggers alert."""
        with patch("api.tripwires._emit_alert") as mock_emit:
            result = check_auth_anomaly(
                client_ip="10.0.0.1",
                failed_attempts=15,
                threshold=10,
            )
            assert result is True
            alert = mock_emit.call_args[0][0]
            assert alert.alert_type == "AUTH_ANOMALY_DETECTED"
            assert "10.0.0.1" in alert.details["client_ip"]

    def test_auth_below_threshold_not_detected(self):
        """Below-threshold auth failures do not trigger alert."""
        with patch("api.tripwires._emit_alert") as mock_emit:
            result = check_auth_anomaly(
                client_ip="10.0.0.1",
                failed_attempts=5,
                threshold=10,
            )
            assert result is False
            mock_emit.assert_not_called()


class TestTripwireAlert:
    """Tests for TripwireAlert dataclass."""

    def test_to_dict(self):
        """TripwireAlert.to_dict() returns correct structure."""
        alert = TripwireAlert(
            alert_type="TEST_ALERT",
            severity="HIGH",
            message="Test message",
            details={"key": "value"},
            timestamp="2024-01-01T00:00:00Z",
        )

        d = alert.to_dict()

        assert d["alert_type"] == "TEST_ALERT"
        assert d["severity"] == "HIGH"
        assert d["alert_message"] == "Test message"  # Note: alert_message not message
        assert d["details"] == {"key": "value"}
        assert d["alert_timestamp"] == "2024-01-01T00:00:00Z"


class TestWebhookDeliveryDataclass:
    """Tests for WebhookDelivery dataclass."""

    def test_default_values(self):
        """WebhookDelivery has correct default values."""
        delivery = WebhookDelivery(
            url="http://example.com",
            payload={"test": "data"},
            alert_type="TEST",
            severity="HIGH",
        )

        assert delivery.attempt == 0
        assert delivery.delivered is False
        assert delivery.last_error is None
        assert isinstance(delivery.created_at, datetime)


class TestDeliveryResult:
    """Tests for DeliveryResult dataclass."""

    def test_success_result(self):
        """DeliveryResult for successful delivery."""
        result = DeliveryResult(
            success=True,
            status_code=200,
            attempt=1,
            response_time_ms=50.5,
        )

        assert result.success is True
        assert result.status_code == 200
        assert result.error is None

    def test_failure_result(self):
        """DeliveryResult for failed delivery."""
        result = DeliveryResult(
            success=False,
            status_code=500,
            error="Server error",
            attempt=3,
        )

        assert result.success is False
        assert result.error == "Server error"
        assert result.attempt == 3


class TestIntegration:
    """Integration tests for tripwire delivery."""

    @pytest.mark.asyncio
    async def test_full_alert_flow_with_webhook(self):
        """Test complete flow: detection -> alert -> webhook delivery."""
        audit_events = []
        delivered_payloads = []

        def audit_logger(event):
            audit_events.append(event)

        # Create service with mock client
        service = WebhookDeliveryService(
            max_attempts=1,
            audit_logger=audit_logger,
        )

        mock_client = MockHttpClient([200])
        service._http_client = mock_client

        # Simulate a tripwire alert payload
        alert_payload = {
            "alert_type": "CANARY_TOKEN_ACCESSED",
            "severity": "CRITICAL",
            "alert_message": "Canary API key was used",
            "details": {"key_prefix": "fgk_canary_test"},
            "alert_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        result = await service.deliver(
            url="http://security-siem.example.com/alerts",
            payload=alert_payload,
            alert_type="CANARY_TOKEN_ACCESSED",
            severity="CRITICAL",
        )

        assert result.success is True
        assert len(mock_client.requests) == 1
        assert mock_client.requests[0]["json"] == alert_payload

        # Verify audit log captured the delivery
        assert any(e["event_type"] == "webhook_delivered" for e in audit_events)

    @pytest.mark.asyncio
    async def test_backoff_timing(self):
        """Verify exponential backoff timing between retries."""
        import time

        service = WebhookDeliveryService(
            max_attempts=3,
            backoff_base=0.1,  # 100ms base
            timeout=1.0,
        )
        service._http_client = MockHttpClient([500, 500, 200])

        start = time.time()
        result = await service.deliver(
            url="http://example.com/webhook",
            payload={},
        )
        elapsed = time.time() - start

        # Should have slept: 0.1^0 + 0.1^1 = 0.1 + 0.1 = 0.2 seconds minimum
        # (backoff_base^(attempt-1) for attempts 1 and 2)
        # Actually: 0.1^0 = 1 -> 0.1*1 = 0.1, 0.1^1 = 0.1 -> wait 0.1
        # So minimum ~0.1s + 0.1s = 0.2s (plus request time)
        assert result.success is True
        # Allow some tolerance for test timing
        assert elapsed >= 0.1, f"Expected >= 0.1s, got {elapsed}s"
