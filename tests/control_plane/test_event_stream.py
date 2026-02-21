"""
Tests for services/event_stream.py

Covers:
- Event IDs: content_hash deterministic, event_instance_id unique
- Tenant scoping: tenant admin cannot see other tenants' events
- Global admin can subscribe to all, payloads include tenant_id
- Per-tenant subscriber cap enforced
- Slow consumer disconnected
- Event history filtered by tenant
"""
from __future__ import annotations

import asyncio
import threading

import pytest

from services.event_stream import (
    MAX_SUBSCRIBERS_PER_TENANT,
    ControlEvent,
    ControlEventBus,
    make_event,
    _compute_content_hash,
    _compute_instance_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bus() -> ControlEventBus:
    return ControlEventBus()


def _make_event(
    event_type: str = "module_state_changed",
    module_id: str = "mod-a",
    tenant_id: str = "tenant-a",
) -> ControlEvent:
    return make_event(event_type, module_id=module_id, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Event ID semantics
# ---------------------------------------------------------------------------


class TestEventIDs:
    def test_content_hash_is_deterministic_for_same_content(self):
        """Same content at same timestamp must yield same content_hash."""
        ev1 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "ready"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        ev2 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "ready"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        assert ev1.content_hash == ev2.content_hash

    def test_event_instance_ids_are_unique_for_same_content(self):
        """Even with identical content, instance IDs must be distinct (nonce)."""
        ev1 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "ready"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        ev2 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "ready"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        assert ev1.event_instance_id != ev2.event_instance_id

    def test_content_hash_changes_on_payload_change(self):
        ev1 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "ready"},
        )
        ev2 = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-x",
            tenant_id="tenant-a",
            payload={"state": "failed"},
        )
        assert ev1.content_hash != ev2.content_hash

    def test_event_dict_has_both_ids(self):
        ev = _make_event()
        d = ev.to_dict()
        assert "content_hash" in d
        assert "event_instance_id" in d
        assert d["content_hash"]
        assert d["event_instance_id"]

    def test_invalid_event_type_raises(self):
        with pytest.raises(ValueError):
            make_event("invalid_event_type", module_id="mod", tenant_id="tenant")


# ---------------------------------------------------------------------------
# Publish and receive
# ---------------------------------------------------------------------------


class TestPublishReceive:
    def test_subscriber_receives_own_tenant_event(self):
        bus = _make_bus()
        sub = bus.add_subscriber("tenant-a", is_global_admin=False)
        ev = _make_event(tenant_id="tenant-a")
        count = bus.publish(ev)
        assert count >= 1
        item = sub.queue.get_nowait()
        assert item["tenant_id"] == "tenant-a"

    def test_tenant_subscriber_does_not_receive_other_tenant_events(self):
        """P0: Tenant admin cannot see other tenants' events."""
        bus = _make_bus()
        sub_a = bus.add_subscriber("tenant-a", is_global_admin=False)
        ev_b = _make_event(tenant_id="tenant-b")
        bus.publish(ev_b)
        assert sub_a.queue.empty()

    def test_global_admin_receives_all_events(self):
        """Global admin can see all tenant events; payloads include tenant_id."""
        bus = _make_bus()
        sub_global = bus.add_subscriber(None, is_global_admin=True)
        ev_a = _make_event(tenant_id="tenant-a")
        ev_b = _make_event(tenant_id="tenant-b")
        bus.publish(ev_a)
        bus.publish(ev_b)
        assert sub_global.queue.qsize() == 2

        item1 = sub_global.queue.get_nowait()
        item2 = sub_global.queue.get_nowait()
        tenants = {item1["tenant_id"], item2["tenant_id"]}
        assert "tenant-a" in tenants
        assert "tenant-b" in tenants

    def test_global_admin_event_payloads_include_tenant_id(self):
        """Audit requirement: global admin events must carry tenant_id."""
        bus = _make_bus()
        sub_global = bus.add_subscriber(None, is_global_admin=True)
        ev = _make_event(tenant_id="tenant-xyz")
        bus.publish(ev)
        item = sub_global.queue.get_nowait()
        assert item["tenant_id"] == "tenant-xyz"


# ---------------------------------------------------------------------------
# Subscriber management + limits
# ---------------------------------------------------------------------------


class TestSubscriberManagement:
    def test_remove_subscriber(self):
        bus = _make_bus()
        sub = bus.add_subscriber("tenant-a")
        bus.remove_subscriber(sub.subscriber_id)
        # After removal, events should not reach removed subscriber
        ev = _make_event(tenant_id="tenant-a")
        bus.publish(ev)
        assert sub.queue.empty()

    def test_per_tenant_subscriber_cap_enforced(self):
        """P1: Per-tenant subscriber cap prevents fan-out amplifier abuse."""
        bus = _make_bus()
        subs = []
        for _ in range(MAX_SUBSCRIBERS_PER_TENANT):
            subs.append(bus.add_subscriber("tenant-cap", is_global_admin=False))

        with pytest.raises(ValueError) as exc:
            bus.add_subscriber("tenant-cap", is_global_admin=False)
        assert "TENANT_SUBSCRIBER_LIMIT" in str(exc.value)

    def test_tenant_cannot_subscribe_to_other_tenant_events_by_guessing_id(self):
        """
        P0: Even if attacker guesses another tenant's locker IDs, the event bus
        must filter events server-side by authenticated tenant_id.
        """
        bus = _make_bus()
        # Attacker subscribes as tenant-attacker
        sub_attacker = bus.add_subscriber("tenant-attacker", is_global_admin=False)

        # Victim's event broadcast
        ev_victim = _make_event(tenant_id="tenant-victim")
        bus.publish(ev_victim)

        # Attacker should not receive victim's event
        assert sub_attacker.queue.empty()

    def test_subscriber_count_decrements_on_removal(self):
        bus = _make_bus()
        initial = bus.subscriber_count()
        sub = bus.add_subscriber("tenant-count")
        assert bus.subscriber_count() == initial + 1
        bus.remove_subscriber(sub.subscriber_id)
        assert bus.subscriber_count() == initial


# ---------------------------------------------------------------------------
# Slow consumer handling
# ---------------------------------------------------------------------------


class TestSlowConsumer:
    def test_slow_consumer_disconnected_on_full_queue(self):
        """
        When a subscriber's queue is full, they are disconnected.
        The slow consumer must not block other subscribers.
        """
        from services.event_stream import SUBSCRIBER_QUEUE_DEPTH
        bus = _make_bus()
        # Create a subscriber and fill its queue to capacity
        slow_sub = bus.add_subscriber("tenant-slow")

        # Fill queue
        for i in range(SUBSCRIBER_QUEUE_DEPTH):
            ev = _make_event(tenant_id="tenant-slow")
            bus.publish(ev)

        # One more should trigger disconnect
        last_ev = _make_event(tenant_id="tenant-slow")
        bus.publish(last_ev)  # Should disconnect slow_sub, not raise

        # Slow sub should be removed
        assert slow_sub.subscriber_id not in bus._subscribers


# ---------------------------------------------------------------------------
# Event history / audit
# ---------------------------------------------------------------------------


class TestEventHistory:
    def test_get_history_filtered_by_tenant(self):
        bus = _make_bus()
        bus.publish(_make_event(tenant_id="tenant-a"))
        bus.publish(_make_event(tenant_id="tenant-b"))

        history = bus.get_history(
            tenant_id="tenant-a", is_global_admin=False, limit=100
        )
        assert all(e["tenant_id"] == "tenant-a" for e in history)

    def test_global_admin_history_sees_all_tenants(self):
        bus = _make_bus()
        bus.publish(_make_event(tenant_id="tenant-x"))
        bus.publish(_make_event(tenant_id="tenant-y"))

        history = bus.get_history(
            tenant_id=None, is_global_admin=True, limit=100
        )
        tenants = {e["tenant_id"] for e in history}
        assert "tenant-x" in tenants
        assert "tenant-y" in tenants

    def test_history_since_filter(self):
        bus = _make_bus()
        past_event = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-past",
            tenant_id="tenant-a",
            payload={},
            timestamp="2020-01-01T00:00:00+00:00",
        )
        future_event = ControlEvent(
            event_type="module_state_changed",
            module_id="mod-future",
            tenant_id="tenant-a",
            payload={},
            timestamp="2030-01-01T00:00:00+00:00",
        )
        bus._history.extend([past_event, future_event])

        history = bus.get_history(
            since="2025-01-01T00:00:00",
            tenant_id="tenant-a",
            is_global_admin=False,
            limit=100,
        )
        module_ids = [e["module_id"] for e in history]
        assert "mod-future" in module_ids
        assert "mod-past" not in module_ids

    def test_no_tenant_no_global_returns_empty_history(self):
        bus = _make_bus()
        bus.publish(_make_event(tenant_id="tenant-a"))
        history = bus.get_history(
            tenant_id=None, is_global_admin=False, limit=100
        )
        assert history == []

    def test_history_limit_respected(self):
        bus = _make_bus()
        for _ in range(20):
            bus.publish(_make_event(tenant_id="tenant-a"))

        history = bus.get_history(
            tenant_id=None, is_global_admin=True, limit=5
        )
        assert len(history) <= 5
