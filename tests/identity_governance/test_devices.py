"""tests/identity_governance/test_devices.py — Device trust registry tests."""

from __future__ import annotations

import pytest

from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.models import DeviceTrustState


@pytest.fixture
def registry() -> DeviceTrustRegistry:
    return DeviceTrustRegistry()


def test_register_device_succeeds(registry: DeviceTrustRegistry) -> None:
    record = registry.register_device(
        subject="user-1",
        tenant_id="tenant-a",
        fingerprint_hash="fp-hash-abc",
        user_agent_hash="ua-hash-xyz",
        ip_metadata="192.0.2.1/32",
    )
    assert record.trust_state == DeviceTrustState.KNOWN
    assert record.risk_score == 0.1
    assert record.tenant_id == "tenant-a"
    assert record.fingerprint_hash == "fp-hash-abc"


def test_register_requires_subject(registry: DeviceTrustRegistry) -> None:
    with pytest.raises(ValueError, match="subject is required"):
        registry.register_device(
            subject="",
            tenant_id="t",
            fingerprint_hash="h",
            user_agent_hash="u",
            ip_metadata="ip",
        )


def test_register_requires_tenant(registry: DeviceTrustRegistry) -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        registry.register_device(
            subject="u",
            tenant_id="",
            fingerprint_hash="h",
            user_agent_hash="u",
            ip_metadata="ip",
        )


def test_register_requires_fingerprint_hash(registry: DeviceTrustRegistry) -> None:
    with pytest.raises(ValueError, match="fingerprint_hash is required"):
        registry.register_device(
            subject="u",
            tenant_id="t",
            fingerprint_hash="",
            user_agent_hash="u",
            ip_metadata="ip",
        )


def test_update_trust_state_persists(registry: DeviceTrustRegistry) -> None:
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    updated = registry.update_trust_state(
        d.device_id,
        "t",
        DeviceTrustState.TRUSTED,
        reason="reviewed",
        actor="admin",
    )
    assert updated.trust_state == DeviceTrustState.TRUSTED
    assert updated.risk_score == 0.0
    fetched = registry.get_device(d.device_id, "t")
    assert fetched is not None
    assert fetched.trust_state == DeviceTrustState.TRUSTED


def test_cross_tenant_lookup_denied(registry: DeviceTrustRegistry) -> None:
    d = registry.register_device(
        subject="u",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    assert registry.get_device(d.device_id, "tenant-b") is None
    assert registry.get_device(d.device_id, "tenant-a") is not None


def test_cross_tenant_update_denied(registry: DeviceTrustRegistry) -> None:
    d = registry.register_device(
        subject="u",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    with pytest.raises(ValueError, match="not registered for tenant"):
        registry.update_trust_state(
            d.device_id,
            "tenant-b",
            DeviceTrustState.REVOKED,
            reason="r",
            actor="a",
        )


def test_revoke_device_sets_revoked(registry: DeviceTrustRegistry) -> None:
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    revoked = registry.revoke_device(d.device_id, "t", reason="lost", actor="admin")
    assert revoked.trust_state == DeviceTrustState.REVOKED
    assert revoked.risk_score == 1.0


def test_risk_score_deterministic(registry: DeviceTrustRegistry) -> None:
    r1 = registry._compute_risk_score(DeviceTrustState.COMPROMISED)
    r2 = registry._compute_risk_score(DeviceTrustState.COMPROMISED)
    assert r1 == r2 == 0.95


def test_state_to_risk_ordering(registry: DeviceTrustRegistry) -> None:
    assert (
        registry._compute_risk_score(DeviceTrustState.TRUSTED)
        < registry._compute_risk_score(DeviceTrustState.KNOWN)
        < registry._compute_risk_score(DeviceTrustState.UNKNOWN)
        < registry._compute_risk_score(DeviceTrustState.SUSPICIOUS)
        < registry._compute_risk_score(DeviceTrustState.COMPROMISED)
        < registry._compute_risk_score(DeviceTrustState.REVOKED)
    )


def test_list_devices_deterministic_order(registry: DeviceTrustRegistry) -> None:
    ids = []
    for i in range(5):
        d = registry.register_device(
            subject="u",
            tenant_id="t",
            fingerprint_hash=f"h{i}",
            user_agent_hash="u",
            ip_metadata="i",
        )
        ids.append(d.device_id)
    listed = registry.list_devices_for_subject("u", "t")
    assert [x.device_id for x in listed] == sorted(ids)


def test_no_raw_fingerprint_in_repr(registry: DeviceTrustRegistry) -> None:
    raw_fingerprint = "raw-fp-should-never-appear-if-caller-hashes-first"
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="already-hashed-value",
        user_agent_hash="u",
        ip_metadata="i",
    )
    # Registry only ever sees the hashed value.
    assert raw_fingerprint not in repr(d)
    assert d.fingerprint_hash == "already-hashed-value"


def test_update_requires_reason_and_actor(registry: DeviceTrustRegistry) -> None:
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    with pytest.raises(ValueError, match="reason is required"):
        registry.update_trust_state(
            d.device_id, "t", DeviceTrustState.TRUSTED, reason="", actor="a"
        )
    with pytest.raises(ValueError, match="actor is required"):
        registry.update_trust_state(
            d.device_id, "t", DeviceTrustState.TRUSTED, reason="r", actor=""
        )
