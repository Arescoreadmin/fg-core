"""tests/identity_governance/test_risk.py — Deterministic risk engine tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from api.identity_governance.models import (
    DeviceTrustState,
    IdentityLifecycleState,
    RiskBand,
    RiskContext,
)
from api.identity_governance.risk import EVALUATOR_VERSION, IdentityRiskEngine


@pytest.fixture
def engine() -> IdentityRiskEngine:
    return IdentityRiskEngine()


def _ctx(**overrides: Any) -> RiskContext:
    defaults: dict[str, Any] = dict(
        subject="user-1",
        tenant_id="tenant-a",
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        device_state=DeviceTrustState.TRUSTED,
        mfa_verified=True,
        tenant_requires_mfa=True,
        active_break_glass=0,
        evaluated_at=datetime.now(tz=timezone.utc),
    )
    defaults.update(overrides)
    return RiskContext(**defaults)


def test_active_trusted_low(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx())
    assert r.band == RiskBand.LOW
    assert r.score == 0.0
    assert r.evaluator_version == EVALUATOR_VERSION


def test_disabled_identity_high(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(lifecycle_state=IdentityLifecycleState.DISABLED))
    assert r.score >= 0.9
    assert r.band == RiskBand.CRITICAL


def test_suspended_high_medium(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(lifecycle_state=IdentityLifecycleState.SUSPENDED))
    assert r.band == RiskBand.HIGH
    assert r.score == 0.6


def test_missing_mfa_adds_030(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(mfa_verified=False, tenant_requires_mfa=True))
    assert r.score == pytest.approx(0.3, abs=1e-9)


def test_missing_mfa_not_required(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(mfa_verified=False, tenant_requires_mfa=False))
    assert r.score == 0.0


def test_compromised_device_adds_050(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(device_state=DeviceTrustState.COMPROMISED))
    assert r.score == 0.5
    assert r.band == RiskBand.HIGH


def test_unknown_device_adds_020(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(device_state=DeviceTrustState.UNKNOWN))
    assert r.score == pytest.approx(0.2, abs=1e-9)


def test_break_glass_adds_020(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(active_break_glass=1))
    assert r.score == pytest.approx(0.2, abs=1e-9)


def test_score_capped_at_1(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(
        _ctx(
            lifecycle_state=IdentityLifecycleState.DISABLED,
            device_state=DeviceTrustState.COMPROMISED,
            mfa_verified=False,
            tenant_requires_mfa=True,
            active_break_glass=1,
        )
    )
    assert r.score == 1.0
    assert r.band == RiskBand.CRITICAL


def test_deterministic(engine: IdentityRiskEngine) -> None:
    ctx = _ctx()
    r1 = engine.score_identity(ctx)
    r2 = engine.score_identity(ctx)
    assert r1.score == r2.score
    assert r1.band == r2.band
    assert r1.factors == r2.factors


def test_band_boundaries(engine: IdentityRiskEngine) -> None:
    # Just below MEDIUM
    r_low = engine.score_identity(
        _ctx(mfa_verified=False, tenant_requires_mfa=False)
    )  # 0.0
    assert r_low.band == RiskBand.LOW

    # MEDIUM: 0.25 <= score < 0.5
    r_med = engine.score_identity(
        _ctx(mfa_verified=False, tenant_requires_mfa=True)
    )  # 0.3
    assert r_med.band == RiskBand.MEDIUM

    # HIGH: 0.5 <= score < 0.75
    r_high = engine.score_identity(
        _ctx(device_state=DeviceTrustState.COMPROMISED)
    )  # 0.5
    assert r_high.band == RiskBand.HIGH


def test_factors_populated(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(
        _ctx(
            device_state=DeviceTrustState.UNKNOWN,
            mfa_verified=False,
            tenant_requires_mfa=True,
        )
    )
    keys = [k for k, _ in r.factors]
    assert "device_state" in keys
    assert "missing_mfa" in keys


def test_no_factors_when_pristine(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx())
    assert r.factors == ()


def test_tenant_carried_on_result(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx(tenant_id="tenant-x"))
    assert r.tenant_id == "tenant-x"


def test_no_secrets_in_result(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx())
    dump = repr(r)
    for banned in ("password", "token=", "PORTAL_PASSWORD"):
        assert banned not in dump


def test_result_immutable(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx())
    with pytest.raises(Exception):
        r.score = 0.999  # type: ignore[misc]


def test_evaluator_version_present(engine: IdentityRiskEngine) -> None:
    r = engine.score_identity(_ctx())
    assert r.evaluator_version == EVALUATOR_VERSION
