"""tests/identity_governance/test_digital_twin.py — Digital twin exporter tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.digital_twin import IdentityDigitalTwinExporter
from api.identity_governance.models import (
    IdentityLifecycleState,
    RiskBand,
    RiskScore,
)
from api.identity_governance.timeline import IdentityTimeline
from api.identity_governance.models import IdentityTimelineEventType


@pytest.fixture
def exporter() -> IdentityDigitalTwinExporter:
    return IdentityDigitalTwinExporter()


def test_basic_export(exporter: IdentityDigitalTwinExporter) -> None:
    snap = exporter.export(
        subject="user-1",
        tenant_id="tenant-a",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=["assessor"],
        permissions=["read:evidence"],
        capabilities=["assessment.write"],
    )
    assert snap.subject == "user-1"
    assert snap.tenant_id == "tenant-a"
    assert snap.lifecycle_state == IdentityLifecycleState.ACTIVE
    assert "assessor" in snap.roles
    assert snap.fingerprint != ""


def test_fingerprint_deterministic(exporter: IdentityDigitalTwinExporter) -> None:
    kwargs: dict[str, Any] = dict(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=["a", "b"],
        permissions=["p1", "p2"],
    )
    a = exporter.export(**kwargs)
    b = exporter.export(**kwargs)
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_by_roles(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    a = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=["a"],
    )
    b = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=["b"],
    )
    assert a.fingerprint != b.fingerprint


def test_no_secrets_in_summary(exporter: IdentityDigitalTwinExporter) -> None:
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        identity_summary={
            "email": "u@example.com",
            "password": "hunter2",
            "token": "abc",
            "secret": "shh",
        },
    )
    keys = [k for k, _ in snap.identity_summary]
    assert "password" not in keys
    assert "token" not in keys
    assert "secret" not in keys
    assert "email" in keys


def test_cross_tenant_devices_filtered(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    registry = DeviceTrustRegistry()
    d_a = registry.register_device(
        subject="u",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    d_b = registry.register_device(
        subject="u",
        tenant_id="tenant-b",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    snap = exporter.export(
        subject="u",
        tenant_id="tenant-a",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        devices=[d_a, d_b],
    )
    # Only device from tenant-a is included.
    device_ids = [dict(dev).get("device_id") for dev in snap.device_records]
    assert d_a.device_id in device_ids
    assert d_b.device_id not in device_ids


def test_no_raw_fingerprint_in_device_records(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    registry = DeviceTrustRegistry()
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="hashed-fp",
        user_agent_hash="u",
        ip_metadata="i",
    )
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        devices=[d],
    )
    for dev in snap.device_records:
        keys = [k for k, _ in dev]
        assert "fingerprint" not in keys
        assert "fingerprint_hash" not in keys


def test_recent_timeline_capped_at_20(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    tl = IdentityTimeline()
    events = []
    for _ in range(30):
        events.append(
            tl.emit(
                IdentityTimelineEventType.LOGIN,
                subject="u",
                tenant_id="t",
                actor="u",
            )
        )
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        recent_timeline_events=events,
    )
    assert len(snap.recent_timeline_events) == 20


def test_cross_tenant_events_filtered(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    tl = IdentityTimeline()
    tl.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="tenant-a",
        actor="u",
    )
    other = tl.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="tenant-b",
        actor="u",
    )
    all_events = tl.query("tenant-a") + [other]
    snap = exporter.export(
        subject="u",
        tenant_id="tenant-a",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        recent_timeline_events=all_events,
    )
    for e in snap.recent_timeline_events:
        assert e.tenant_id == "tenant-a"


def test_risk_score_carried(exporter: IdentityDigitalTwinExporter) -> None:
    risk = RiskScore(
        subject="u",
        tenant_id="t",
        score=0.4,
        band=RiskBand.MEDIUM,
        factors=(),
        evaluator_version="1.0.0",
        evaluated_at=datetime.now(tz=timezone.utc),
    )
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        risk_score=risk,
    )
    assert snap.risk_score is not None
    assert snap.risk_score.band == RiskBand.MEDIUM


def test_subject_required(exporter: IdentityDigitalTwinExporter) -> None:
    with pytest.raises(ValueError, match="subject is required"):
        exporter.export(
            subject="",
            tenant_id="t",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
        )


def test_tenant_required(exporter: IdentityDigitalTwinExporter) -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        exporter.export(
            subject="u",
            tenant_id="",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
        )


def test_deterministic_ordering_of_roles(
    exporter: IdentityDigitalTwinExporter,
) -> None:
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=["z", "a", "m"],
    )
    assert list(snap.roles) == sorted(snap.roles)


def test_counts_carried(exporter: IdentityDigitalTwinExporter) -> None:
    snap = exporter.export(
        subject="u",
        tenant_id="t",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        active_sessions_count=3,
        active_break_glass_count=1,
        assessments_count=5,
        evidence_count=7,
    )
    assert snap.active_sessions_count == 3
    assert snap.active_break_glass_count == 1
    assert snap.assessments_count == 5
    assert snap.evidence_count == 7
