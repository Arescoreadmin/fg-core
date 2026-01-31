"""
NATS-based Ingestion Bus for FrostGate Core.

Enables real control-plane ingestion at scale using NATS messaging.

Features:
- Versioned, tenant-scoped message schema
- Producer/consumer implementation
- At-least-once delivery semantics
- Tenant isolation via subject hierarchy

Subject Pattern: frostgate.ingest.{tenant_id}.{event_type}

Choice: NATS over Kafka
- Lighter weight (single binary vs JVM)
- Simpler local/CI deployment
- Built-in subject-based routing
- No Zookeeper/KRaft dependency
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

log = logging.getLogger("frostgate.ingest_bus")

# NATS configuration
NATS_URL = os.getenv("FG_NATS_URL", "nats://localhost:4222")
NATS_SUBJECT_PREFIX = os.getenv("FG_NATS_SUBJECT_PREFIX", "frostgate.ingest")
NATS_QUEUE_GROUP = os.getenv("FG_NATS_QUEUE_GROUP", "frostgate-workers")

# Message schema version
MESSAGE_SCHEMA_VERSION = "1.0"


@dataclass
class IngestMessage:
    """
    Versioned, tenant-scoped ingest message.

    Schema:
    - version: Message schema version for compatibility
    - message_id: Unique message identifier
    - tenant_id: Tenant isolation key (REQUIRED)
    - source: Event source identifier
    - event_type: Type of event
    - timestamp: Event timestamp (ISO 8601)
    - payload: Event data
    - metadata: Optional additional metadata
    """

    tenant_id: str
    source: str
    event_type: str
    payload: dict[str, Any]
    version: str = MESSAGE_SCHEMA_VERSION
    message_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize message to JSON."""
        return json.dumps(
            {
                "version": self.version,
                "message_id": self.message_id,
                "tenant_id": self.tenant_id,
                "source": self.source,
                "event_type": self.event_type,
                "timestamp": self.timestamp,
                "payload": self.payload,
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def to_bytes(self) -> bytes:
        """Serialize message to bytes for NATS."""
        return self.to_json().encode("utf-8")

    @classmethod
    def from_json(cls, data: str | bytes) -> "IngestMessage":
        """Deserialize message from JSON."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        d = json.loads(data)
        return cls(
            version=d.get("version", MESSAGE_SCHEMA_VERSION),
            message_id=d.get("message_id", str(uuid4())),
            tenant_id=d["tenant_id"],
            source=d["source"],
            event_type=d["event_type"],
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            payload=d.get("payload", {}),
            metadata=d.get("metadata", {}),
        )

    def subject(self) -> str:
        """Get NATS subject for this message."""
        # Pattern: frostgate.ingest.{tenant_id}.{event_type}
        # Dots in tenant_id/event_type are replaced with underscores
        safe_tenant = self.tenant_id.replace(".", "_")
        safe_event = self.event_type.replace(".", "_")
        return f"{NATS_SUBJECT_PREFIX}.{safe_tenant}.{safe_event}"


class NatsConnection:
    """
    NATS connection wrapper with reconnection handling.
    """

    def __init__(self, url: str = NATS_URL):
        self.url = url
        self._nc: Optional[Any] = None
        self._connected = False

    async def connect(self) -> None:
        """Connect to NATS server."""
        try:
            import nats
        except ImportError:
            raise RuntimeError("NATS client not installed. Run: pip install nats-py")

        if self._nc is not None and self._connected:
            return

        async def error_cb(e):
            log.error(f"NATS error: {e}")

        async def disconnected_cb():
            log.warning("NATS disconnected")
            self._connected = False

        async def reconnected_cb():
            log.info("NATS reconnected")
            self._connected = True

        self._nc = await nats.connect(
            self.url,
            error_cb=error_cb,
            disconnected_cb=disconnected_cb,
            reconnected_cb=reconnected_cb,
            max_reconnect_attempts=-1,  # Infinite reconnect
            reconnect_time_wait=2,
        )
        self._connected = True
        log.info(f"Connected to NATS at {self.url}")

    async def close(self) -> None:
        """Close NATS connection."""
        if self._nc is not None:
            await self._nc.drain()
            await self._nc.close()
            self._nc = None
            self._connected = False
            log.info("NATS connection closed")

    @property
    def client(self):
        """Get the NATS client."""
        if self._nc is None:
            raise RuntimeError("NATS not connected. Call connect() first.")
        return self._nc

    @property
    def is_connected(self) -> bool:
        return self._connected


class IngestProducer:
    """
    NATS producer for publishing ingest messages.

    Usage:
        producer = IngestProducer()
        await producer.connect()

        msg = IngestMessage(
            tenant_id="tenant1",
            source="agent",
            event_type="auth",
            payload={"failed_auths": 5, "src_ip": "10.0.0.1"},
        )
        await producer.publish(msg)
    """

    def __init__(self, nats_url: str = NATS_URL):
        self._conn = NatsConnection(nats_url)

    async def connect(self) -> None:
        """Connect to NATS."""
        await self._conn.connect()

    async def close(self) -> None:
        """Close connection."""
        await self._conn.close()

    async def publish(self, message: IngestMessage) -> None:
        """
        Publish an ingest message to NATS.

        Message is published to subject: frostgate.ingest.{tenant_id}.{event_type}
        """
        subject = message.subject()
        data = message.to_bytes()

        await self._conn.client.publish(subject, data)
        log.debug(f"Published message {message.message_id} to {subject}")

    async def publish_raw(
        self,
        tenant_id: str,
        source: str,
        event_type: str,
        payload: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Publish raw event data (convenience method).

        Returns the message_id.
        """
        msg = IngestMessage(
            tenant_id=tenant_id,
            source=source,
            event_type=event_type,
            payload=payload,
            metadata=metadata or {},
        )
        await self.publish(msg)
        return msg.message_id


# Message handler type
MessageHandler = Callable[[IngestMessage], Any]


class IngestConsumer:
    """
    NATS consumer for processing ingest messages.

    Features:
    - Subscribe to tenant-specific subjects
    - Subscribe to all tenants with wildcard
    - Queue group support for load balancing
    - Message acknowledgment

    Usage:
        consumer = IngestConsumer()
        await consumer.connect()

        async def handler(msg: IngestMessage):
            print(f"Received: {msg.event_type}")

        # Subscribe to all events for a tenant
        await consumer.subscribe("tenant1", handler)

        # Subscribe to all tenants (wildcard)
        await consumer.subscribe_all(handler)
    """

    def __init__(
        self,
        nats_url: str = NATS_URL,
        queue_group: str = NATS_QUEUE_GROUP,
    ):
        self._conn = NatsConnection(nats_url)
        self._queue_group = queue_group
        self._subscriptions: list[Any] = []

    async def connect(self) -> None:
        """Connect to NATS."""
        await self._conn.connect()

    async def close(self) -> None:
        """Close connection and unsubscribe."""
        for sub in self._subscriptions:
            await sub.unsubscribe()
        self._subscriptions.clear()
        await self._conn.close()

    async def subscribe(
        self,
        tenant_id: str,
        handler: MessageHandler,
        event_type: str = "*",
    ) -> None:
        """
        Subscribe to messages for a specific tenant.

        Args:
            tenant_id: Tenant to subscribe to
            handler: Async function to handle messages
            event_type: Event type filter ("*" for all)
        """
        safe_tenant = tenant_id.replace(".", "_")
        safe_event = event_type.replace(".", "_") if event_type != "*" else "*"
        subject = f"{NATS_SUBJECT_PREFIX}.{safe_tenant}.{safe_event}"

        async def msg_handler(msg):
            try:
                ingest_msg = IngestMessage.from_json(msg.data)
                await handler(ingest_msg)
            except Exception as e:
                log.exception(f"Error processing message on {msg.subject}: {e}")

        sub = await self._conn.client.subscribe(
            subject,
            queue=self._queue_group,
            cb=msg_handler,
        )
        self._subscriptions.append(sub)
        log.info(f"Subscribed to {subject} (queue: {self._queue_group})")

    async def subscribe_all(
        self,
        handler: MessageHandler,
    ) -> None:
        """
        Subscribe to messages for all tenants.

        Uses wildcard subject: frostgate.ingest.>
        """
        subject = f"{NATS_SUBJECT_PREFIX}.>"

        async def msg_handler(msg):
            try:
                ingest_msg = IngestMessage.from_json(msg.data)
                await handler(ingest_msg)
            except Exception as e:
                log.exception(f"Error processing message on {msg.subject}: {e}")

        sub = await self._conn.client.subscribe(
            subject,
            queue=self._queue_group,
            cb=msg_handler,
        )
        self._subscriptions.append(sub)
        log.info(f"Subscribed to {subject} (all tenants, queue: {self._queue_group})")


class IngestProcessor:
    """
    Message processor that evaluates ingest messages and creates decision records.

    Bridges NATS messages to the FrostGate decision engine.
    """

    def __init__(self, db_session_factory: Optional[Callable] = None):
        self._db_session_factory = db_session_factory
        self._processed_count = 0
        self._error_count = 0

    async def process(self, message: IngestMessage) -> dict[str, Any]:
        """
        Process an ingest message through the decision engine.

        Returns the decision result.
        """
        from api.defend import evaluate, _apply_doctrine
        from api.schemas import TelemetryInput

        try:
            # Create TelemetryInput from message
            telemetry = TelemetryInput(
                tenant_id=message.tenant_id,
                source=message.source,
                event_type=message.event_type,
                payload=message.payload,
            )

            # Run evaluation
            threat_level, rules_triggered, mitigations, anomaly_score, score = evaluate(
                telemetry
            )

            # Apply doctrine if metadata specifies persona/classification
            persona = message.metadata.get("persona")
            classification = message.metadata.get("classification")

            roe_applied = False
            disruption_limited = False

            if persona or classification:
                mitigations, tie_d = _apply_doctrine(
                    persona, classification, mitigations
                )
                roe_applied = tie_d.roe_applied
                disruption_limited = tie_d.disruption_limited

            result = {
                "message_id": message.message_id,
                "tenant_id": message.tenant_id,
                "event_type": message.event_type,
                "threat_level": threat_level,
                "rules_triggered": rules_triggered,
                "mitigations": [
                    {"action": m.action, "target": m.target, "reason": m.reason}
                    for m in mitigations
                ],
                "anomaly_score": anomaly_score,
                "score": score,
                "roe_applied": roe_applied,
                "disruption_limited": disruption_limited,
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

            self._processed_count += 1
            log.debug(f"Processed message {message.message_id}: {threat_level}")

            return result

        except Exception as e:
            self._error_count += 1
            log.exception(f"Error processing message {message.message_id}: {e}")
            raise

    @property
    def stats(self) -> dict[str, int]:
        """Get processing statistics."""
        return {
            "processed": self._processed_count,
            "errors": self._error_count,
        }


# Global instances for convenience
_producer: Optional[IngestProducer] = None
_consumer: Optional[IngestConsumer] = None


async def get_producer() -> IngestProducer:
    """Get or create a global producer instance."""
    global _producer
    if _producer is None:
        _producer = IngestProducer()
        await _producer.connect()
    return _producer


async def get_consumer() -> IngestConsumer:
    """Get or create a global consumer instance."""
    global _consumer
    if _consumer is None:
        _consumer = IngestConsumer()
        await _consumer.connect()
    return _consumer


async def shutdown_bus() -> None:
    """Shutdown global producer and consumer."""
    global _producer, _consumer
    if _producer is not None:
        await _producer.close()
        _producer = None
    if _consumer is not None:
        await _consumer.close()
        _consumer = None


def validate_message(message: IngestMessage) -> list[str]:
    """
    Validate an ingest message.

    Returns list of validation errors (empty if valid).
    """
    errors = []

    if not message.tenant_id:
        errors.append("tenant_id is required")
    if not message.source:
        errors.append("source is required")
    if not message.event_type:
        errors.append("event_type is required")

    # Validate tenant_id format (alphanumeric, underscores, hyphens)
    import re

    if message.tenant_id and not re.match(r"^[a-zA-Z0-9_-]+$", message.tenant_id):
        errors.append("tenant_id must be alphanumeric with underscores/hyphens only")

    return errors


__all__ = [
    "MESSAGE_SCHEMA_VERSION",
    "IngestMessage",
    "NatsConnection",
    "IngestProducer",
    "IngestConsumer",
    "IngestProcessor",
    "MessageHandler",
    "get_producer",
    "get_consumer",
    "shutdown_bus",
    "validate_message",
]
