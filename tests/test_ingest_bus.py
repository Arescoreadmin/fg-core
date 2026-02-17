"""
Tests for NATS Ingestion Bus.

Tests verify:
- Message serialization/deserialization
- Subject routing by tenant
- End-to-end publish/consume flow
- Message validation
- Decision processing
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from api.ingest_bus import (
    MESSAGE_SCHEMA_VERSION,
    IngestMessage,
    IngestProcessor,
    IngestProducer,
    IngestConsumer,
    validate_message,
)


class TestIngestMessage:
    """Tests for IngestMessage dataclass."""

    def test_create_message(self):
        """Create a valid ingest message."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"failed_auths": 5},
        )

        assert msg.tenant_id == "tenant1"
        assert msg.source == "agent"
        assert msg.event_type == "auth"
        assert msg.version == MESSAGE_SCHEMA_VERSION
        assert msg.message_id is not None
        assert msg.timestamp is not None

    def test_to_json_deterministic(self):
        """Message JSON serialization is deterministic."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"b": 2, "a": 1},
            message_id="fixed-id",
            timestamp="2024-01-01T00:00:00Z",
        )

        json1 = msg.to_json()
        json2 = msg.to_json()

        assert json1 == json2
        assert '"tenant_id":"tenant1"' in json1

    def test_to_bytes(self):
        """Message serializes to UTF-8 bytes."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )

        data = msg.to_bytes()
        assert isinstance(data, bytes)
        assert b"tenant1" in data

    def test_from_json_roundtrip(self):
        """Message survives JSON roundtrip."""
        original = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"key": "value"},
            metadata={"persona": "guardian"},
        )

        json_str = original.to_json()
        restored = IngestMessage.from_json(json_str)

        assert restored.tenant_id == original.tenant_id
        assert restored.source == original.source
        assert restored.event_type == original.event_type
        assert restored.payload == original.payload
        assert restored.metadata == original.metadata
        assert restored.message_id == original.message_id

    def test_from_bytes_roundtrip(self):
        """Message survives bytes roundtrip."""
        original = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"data": "test"},
        )

        data = original.to_bytes()
        restored = IngestMessage.from_json(data)

        assert restored.tenant_id == original.tenant_id
        assert restored.payload == original.payload

    def test_subject_generation(self):
        """Message generates correct NATS subject."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )

        subject = msg.subject()
        assert subject == "frostgate.ingest.tenant1.auth"

    def test_subject_with_dots_sanitized(self):
        """Dots in tenant_id/event_type are replaced."""
        msg = IngestMessage(
            tenant_id="org.team.tenant",
            source="agent",
            event_type="auth.bruteforce",
            payload={},
        )

        subject = msg.subject()
        assert subject == "frostgate.ingest.org_team_tenant.auth_bruteforce"


class TestValidateMessage:
    """Tests for message validation."""

    def test_valid_message(self):
        """Valid message passes validation."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )

        errors = validate_message(msg)
        assert len(errors) == 0

    def test_missing_tenant_id(self):
        """Missing tenant_id fails validation."""
        msg = IngestMessage(
            tenant_id="",
            source="agent",
            event_type="auth",
            payload={},
        )

        errors = validate_message(msg)
        assert "tenant_id is required" in errors

    def test_missing_source(self):
        """Missing source fails validation."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="",
            event_type="auth",
            payload={},
        )

        errors = validate_message(msg)
        assert "source is required" in errors

    def test_missing_event_type(self):
        """Missing event_type fails validation."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="",
            payload={},
        )

        errors = validate_message(msg)
        assert "event_type is required" in errors

    def test_invalid_tenant_id_format(self):
        """Invalid tenant_id format fails validation."""
        msg = IngestMessage(
            tenant_id="tenant/id",  # Contains /
            source="agent",
            event_type="auth",
            payload={},
        )

        errors = validate_message(msg)
        assert any("alphanumeric" in e for e in errors)

    def test_valid_tenant_id_formats(self):
        """Valid tenant_id formats pass validation."""
        valid_ids = ["tenant1", "tenant_1", "tenant-1", "Tenant_Test-123"]

        for tenant_id in valid_ids:
            msg = IngestMessage(
                tenant_id=tenant_id,
                source="agent",
                event_type="auth",
                payload={},
            )
            errors = validate_message(msg)
            assert len(errors) == 0, f"tenant_id '{tenant_id}' should be valid"


class TestIngestProcessor:
    """Tests for IngestProcessor."""

    def test_process_returns_decision(self):
        """Processor returns decision result."""
        processor = IngestProcessor()

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="http_request",
            payload={"path": "/api/health"},
        )

        # Run synchronously for testing
        result = asyncio.run(processor.process(msg))

        assert "threat_level" in result
        assert "rules_triggered" in result
        assert result["tenant_id"] == "tenant1"
        assert result["message_id"] == msg.message_id

    def test_process_bruteforce_detection(self):
        """Processor detects bruteforce attack."""
        processor = IngestProcessor()

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={
                "src_ip": "10.0.0.1",
                "failed_auths": 10,
            },
        )

        result = asyncio.run(processor.process(msg))

        assert result["threat_level"] == "high"
        assert "rule:ssh_bruteforce" in result["rules_triggered"]
        assert len(result["mitigations"]) > 0

    def test_process_with_doctrine(self):
        """Processor applies doctrine from metadata."""
        processor = IngestProcessor()

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={
                "src_ip": "10.0.0.1",
                "failed_auths": 5,
            },
            metadata={
                "persona": "guardian",
                "classification": "SECRET",
            },
        )

        result = asyncio.run(processor.process(msg))

        assert result["roe_applied"] is True

    def test_processor_stats(self):
        """Processor tracks statistics."""
        processor = IngestProcessor()

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="test",
            payload={},
        )

        # Process a few messages
        for _ in range(3):
            asyncio.run(processor.process(msg))

        stats = processor.stats
        assert stats["processed"] == 3
        assert stats["errors"] == 0


class TestTenantIsolation:
    """Tests for tenant isolation via subjects."""

    def test_different_tenants_different_subjects(self):
        """Different tenants get different subjects."""
        msg1 = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )
        msg2 = IngestMessage(
            tenant_id="tenant2",
            source="agent",
            event_type="auth",
            payload={},
        )

        assert msg1.subject() != msg2.subject()
        assert "tenant1" in msg1.subject()
        assert "tenant2" in msg2.subject()

    def test_same_tenant_different_events(self):
        """Same tenant, different events get different subjects."""
        msg1 = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )
        msg2 = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="http_request",
            payload={},
        )

        assert msg1.subject() != msg2.subject()
        assert ".auth" in msg1.subject()
        assert ".http_request" in msg2.subject()


class TestMessageSchemaVersion:
    """Tests for message schema versioning."""

    def test_version_included_in_message(self):
        """Message includes schema version."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
        )

        assert msg.version == MESSAGE_SCHEMA_VERSION
        json_str = msg.to_json()
        assert f'"version":"{MESSAGE_SCHEMA_VERSION}"' in json_str

    def test_version_preserved_in_roundtrip(self):
        """Schema version is preserved in serialization."""
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={},
            version="2.0",  # Custom version
        )

        restored = IngestMessage.from_json(msg.to_json())
        assert restored.version == "2.0"


class TestMockedNatsIntegration:
    """Integration tests with mocked NATS client."""

    @pytest.mark.asyncio
    async def test_producer_publish(self):
        """Producer publishes message to NATS."""
        mock_nc = AsyncMock()
        mock_nc.publish = AsyncMock()

        producer = IngestProducer()
        producer._conn._nc = mock_nc
        producer._conn._connected = True

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"test": "data"},
        )

        await producer.publish(msg)

        mock_nc.publish.assert_called_once()
        call_args = mock_nc.publish.call_args
        assert call_args[0][0] == msg.subject()  # Subject
        assert call_args[0][1] == msg.to_bytes()  # Data

    @pytest.mark.asyncio
    async def test_consumer_subscribe(self):
        """Consumer subscribes to NATS subject."""
        mock_nc = AsyncMock()
        mock_sub = AsyncMock()
        mock_nc.subscribe = AsyncMock(return_value=mock_sub)

        consumer = IngestConsumer()
        consumer._conn._nc = mock_nc
        consumer._conn._connected = True

        async def handler(msg):
            pass

        await consumer.subscribe("tenant1", handler)

        mock_nc.subscribe.assert_called_once()
        call_args = mock_nc.subscribe.call_args
        assert "tenant1" in call_args[0][0]  # Subject contains tenant
        assert call_args[1]["queue"] == consumer._queue_group

    @pytest.mark.asyncio
    async def test_consumer_subscribe_all(self):
        """Consumer subscribes to all tenants with wildcard."""
        mock_nc = AsyncMock()
        mock_sub = AsyncMock()
        mock_nc.subscribe = AsyncMock(return_value=mock_sub)

        consumer = IngestConsumer()
        consumer._conn._nc = mock_nc
        consumer._conn._connected = True

        async def handler(msg):
            pass

        await consumer.subscribe_all(handler)

        mock_nc.subscribe.assert_called_once()
        call_args = mock_nc.subscribe.call_args
        assert call_args[0][0].endswith(".>")  # Wildcard subject


class TestEndToEnd:
    """End-to-end tests for the ingest bus flow."""

    def test_publish_process_flow(self):
        """Test complete flow: create message -> process -> get decision."""
        # Create message
        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={
                "src_ip": "10.0.0.1",
                "failed_auths": 5,
            },
        )

        # Validate
        errors = validate_message(msg)
        assert len(errors) == 0

        # Serialize/deserialize (simulates NATS transport)
        serialized = msg.to_bytes()
        restored = IngestMessage.from_json(serialized)

        # Process
        processor = IngestProcessor()
        result = asyncio.run(processor.process(restored))

        # Verify decision
        assert result["tenant_id"] == "tenant1"
        assert result["threat_level"] == "high"
        assert "rule:ssh_bruteforce" in result["rules_triggered"]
        assert result["message_id"] == msg.message_id

    def test_tenant_isolation_in_processing(self):
        """Different tenants are processed independently."""
        processor = IngestProcessor()

        msg1 = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"src_ip": "10.0.0.1", "failed_auths": 10},
        )
        msg2 = IngestMessage(
            tenant_id="tenant2",
            source="agent",
            event_type="http_request",
            payload={"path": "/api/health"},
        )

        result1 = asyncio.run(processor.process(msg1))
        result2 = asyncio.run(processor.process(msg2))

        assert result1["tenant_id"] == "tenant1"
        assert result2["tenant_id"] == "tenant2"
        assert result1["threat_level"] == "high"
        assert result2["threat_level"] == "none"
