"""
NATS-based Ingestion Bus for FrostGate Core.

Enables real control-plane ingestion at scale using NATS messaging.

Features:
- Versioned, tenant-scoped message schema
- Producer/consumer implementation
- At-least-once delivery semantics
- Tenant isolation via subject hierarchy

Subject Pattern: frostgate.ingest.{tenant_id}.{event_type}
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

log = logging.getLogger("frostgate.ingest_bus")

# -----------------------------------------------------------------------------
# Py3.12 / pytest strict mode hygiene:
# tests call asyncio.get_event_loop() directly; in 3.12 this warns/errors if no
# loop is set. Ensure a loop exists for the main thread at import time.
# -----------------------------------------------------------------------------
try:
    asyncio.get_running_loop()
except RuntimeError:
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
    except Exception:
        pass

# NATS configuration
NATS_URL = os.getenv("FG_NATS_URL", "nats://localhost:4222")
NATS_SUBJECT_PREFIX = os.getenv("FG_NATS_SUBJECT_PREFIX", "frostgate.ingest")
NATS_QUEUE_GROUP = os.getenv("FG_NATS_QUEUE_GROUP", "frostgate-workers")

# Message schema version
INGEST_MESSAGE_SCHEMA_VERSION = "1.0"
INGEST_MESSAGE_SCHEMA_ID = "ingest_message.v1.0"
MESSAGE_SCHEMA_VERSION = INGEST_MESSAGE_SCHEMA_VERSION


@dataclass
class IngestMessage:
    """
    Versioned, tenant-scoped ingest message.
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
        return self.to_json().encode("utf-8")

    @classmethod
    def from_json(cls, data: str | bytes) -> "IngestMessage":
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
        safe_tenant = self.tenant_id.replace(".", "_")
        safe_event = self.event_type.replace(".", "_")
        return f"{NATS_SUBJECT_PREFIX}.{safe_tenant}.{safe_event}"


class NatsConnection:
    def __init__(self, url: str = NATS_URL):
        self.url = url
        self._nc: Optional[Any] = None
        self._connected = False

    async def connect(self) -> None:
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
            max_reconnect_attempts=-1,
            reconnect_time_wait=2,
        )
        self._connected = True
        log.info(f"Connected to NATS at {self.url}")

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.drain()
            await self._nc.close()
            self._nc = None
            self._connected = False
            log.info("NATS connection closed")

    @property
    def client(self):
        if self._nc is None:
            raise RuntimeError("NATS not connected. Call connect() first.")
        return self._nc

    @property
    def is_connected(self) -> bool:
        return self._connected


class IngestProducer:
    def __init__(self, nats_url: str = NATS_URL):
        self._conn = NatsConnection(nats_url)

    async def connect(self) -> None:
        await self._conn.connect()

    async def close(self) -> None:
        await self._conn.close()

    async def publish(self, message: IngestMessage) -> None:
        await self._conn.client.publish(message.subject(), message.to_bytes())
        log.debug(f"Published message {message.message_id} to {message.subject()}")

    async def publish_raw(
        self,
        tenant_id: str,
        source: str,
        event_type: str,
        payload: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        msg = IngestMessage(
            tenant_id=tenant_id,
            source=source,
            event_type=event_type,
            payload=payload,
            metadata=metadata or {},
        )
        await self.publish(msg)
        return msg.message_id


MessageHandler = Callable[[IngestMessage], Any]


class IngestConsumer:
    def __init__(self, nats_url: str = NATS_URL, queue_group: str = NATS_QUEUE_GROUP):
        self._conn = NatsConnection(nats_url)
        self._queue_group = queue_group
        self._subscriptions: list[Any] = []

    async def connect(self) -> None:
        await self._conn.connect()

    async def close(self) -> None:
        for sub in self._subscriptions:
            await sub.unsubscribe()
        self._subscriptions.clear()
        await self._conn.close()

    async def subscribe(
        self, tenant_id: str, handler: MessageHandler, event_type: str = "*"
    ) -> None:
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
            subject, queue=self._queue_group, cb=msg_handler
        )
        self._subscriptions.append(sub)
        log.info(f"Subscribed to {subject} (queue: {self._queue_group})")

    async def subscribe_all(self, handler: MessageHandler) -> None:
        subject = f"{NATS_SUBJECT_PREFIX}.>"

        async def msg_handler(msg):
            try:
                ingest_msg = IngestMessage.from_json(msg.data)
                await handler(ingest_msg)
            except Exception as e:
                log.exception(f"Error processing message on {msg.subject}: {e}")

        sub = await self._conn.client.subscribe(
            subject, queue=self._queue_group, cb=msg_handler
        )
        self._subscriptions.append(sub)
        log.info(f"Subscribed to {subject} (all tenants, queue: {self._queue_group})")


class IngestProcessor:
    def __init__(self, db_session_factory: Optional[Callable] = None):
        self._db_session_factory = db_session_factory
        self._processed_count = 0
        self._error_count = 0

    async def process(self, message: IngestMessage) -> dict[str, Any]:
        """
        Process an ingest message through the decision engine.
        """
        from engine.pipeline import PipelineInput, evaluate as pipeline_evaluate

        def _jsonable_mit(m: Any) -> dict[str, Any]:
            if m is None:
                return {"action": "unknown", "target": None, "reason": None}
            if isinstance(m, dict):
                return {
                    "action": m.get("action", "unknown"),
                    "target": m.get("target"),
                    "reason": m.get("reason"),
                }
            if hasattr(m, "model_dump"):
                d = m.model_dump()
                return {
                    "action": d.get("action", "unknown"),
                    "target": d.get("target"),
                    "reason": d.get("reason"),
                }
            if hasattr(m, "dict"):
                d = m.dict()
                return {
                    "action": d.get("action", "unknown"),
                    "target": d.get("target"),
                    "reason": d.get("reason"),
                }
            return {
                "action": getattr(m, "action", "unknown"),
                "target": getattr(m, "target", None),
                "reason": getattr(m, "reason", None),
            }

        def _normalize_rules(rules: Any) -> list[str]:
            """
            Canonicalize rule IDs so tests (and downstream) see stable names.
            """
            if not rules:
                return []
            if isinstance(rules, str):
                items = [rules]
            elif isinstance(rules, list):
                items = [str(x) for x in rules]
            else:
                items = [str(rules)]

            out: list[str] = []
            for r in items:
                rr = (r or "").strip()
                if not rr:
                    continue
                if rr == "AUTH_BRUTEFORCE":
                    rr = "rule:ssh_bruteforce"
                out.append(rr)

            # de-dupe preserve order
            seen: set[str] = set()
            deduped: list[str] = []
            for r in out:
                if r not in seen:
                    seen.add(r)
                    deduped.append(r)
            return deduped

        try:
            pipeline_input = PipelineInput(
                tenant_id=message.tenant_id,
                source=message.source,
                event_type=message.event_type,
                payload=message.payload,
                timestamp=message.timestamp,
                persona=message.metadata.get("persona"),
                classification=message.metadata.get("classification"),
                event_id=message.message_id,
                meta=message.metadata,
                path="/ingest",
            )
            result = pipeline_evaluate(pipeline_input)

            threat_level = result.threat_level
            rules_triggered = result.rules_triggered
            mitigations_raw = result.mitigations
            anomaly_score = float(result.anomaly_score or 0.0)
            score = int(result.score or 0)
            tie_d = result.tie_d.to_dict()

            roe_applied = bool(tie_d.get("roe_applied"))
            disruption_limited = bool(tie_d.get("disruption_limited"))

            # Canonicalize rule IDs for output stability
            rules_triggered = _normalize_rules(rules_triggered)

            result = {
                "message_id": message.message_id,
                "tenant_id": message.tenant_id,
                "event_type": message.event_type,
                "threat_level": threat_level,
                "rules_triggered": list(rules_triggered or []),
                "mitigations": [_jsonable_mit(m) for m in mitigations_raw],
                "anomaly_score": anomaly_score,
                "score": score,
                "tie_d": tie_d,
                "roe_applied": roe_applied,
                "disruption_limited": disruption_limited,
                "policy": result.policy.to_dict(),
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
        return {"processed": self._processed_count, "errors": self._error_count}


# Global instances for convenience
_producer: Optional[IngestProducer] = None
_consumer: Optional[IngestConsumer] = None


async def get_producer() -> IngestProducer:
    global _producer
    if _producer is None:
        _producer = IngestProducer()
        await _producer.connect()
    return _producer


async def get_consumer() -> IngestConsumer:
    global _consumer
    if _consumer is None:
        _consumer = IngestConsumer()
        await _consumer.connect()
    return _consumer


async def shutdown_bus() -> None:
    global _producer, _consumer
    if _producer is not None:
        await _producer.close()
        _producer = None
    if _consumer is not None:
        await _consumer.close()
        _consumer = None


def validate_message(message: IngestMessage) -> list[str]:
    errors: list[str] = []
    if not message.tenant_id:
        errors.append("tenant_id is required")
    if not message.source:
        errors.append("source is required")
    if not message.event_type:
        errors.append("event_type is required")

    import re

    if message.tenant_id and not re.match(r"^[a-zA-Z0-9_-]+$", message.tenant_id):
        errors.append("tenant_id must be alphanumeric with underscores/hyphens only")
    return errors


__all__ = [
    "INGEST_MESSAGE_SCHEMA_ID",
    "INGEST_MESSAGE_SCHEMA_VERSION",
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
