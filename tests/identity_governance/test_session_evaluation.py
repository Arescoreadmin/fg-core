"""tests/identity_governance/test_session_evaluation.py — Session evaluation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.models import (
    DeviceTrustState,
    IdentityLifecycleState,
    RiskBand,
    RiskScore,
    SessionEvaluationContext,
    SessionEvaluationDecision,
)
from api.identity_governance.session_evaluation import SessionEvaluator


def _risk(band: RiskBand, score: float = 0.0) -> RiskScore:
    return RiskScore(
        subject="s",
        tenant_id="t",
        score=score,
        band=band,
        factors=(),
        evaluator_version="1.0.0",
        evaluated_at=datetime.now(tz=timezone.utc),
    )


def _context(**overrides: Any) -> SessionEvaluationContext:
    defaults: dict[str, Any] = dict(
        subject="user-1",
        tenant_id="tenant-a",
        session_id="sess-1",
        identity_state=IdentityLifecycleState.ACTIVE,
        session_expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=1),
        session_revoked=False,
        device=None,
        mfa_verified=True,
        tenant_requires_mfa=True,
        risk_score=_risk(RiskBand.LOW),
        evaluated_at=datetime.now(tz=timezone.utc),
    )
    defaults.update(overrides)
    return SessionEvaluationContext(**defaults)


@pytest.fixture
def evaluator() -> SessionEvaluator:
    return SessionEvaluator()


def test_allow_all_checks_pass(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(_context())
    assert result.decision == SessionEvaluationDecision.ALLOW
    assert result.stopped_at_check == ""


def test_deny_suspended_identity(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(
        _context(identity_state=IdentityLifecycleState.SUSPENDED)
    )
    assert result.decision == SessionEvaluationDecision.DENY
    assert result.stopped_at_check == "identity_state"


def test_deny_disabled_identity(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(
        _context(identity_state=IdentityLifecycleState.DISABLED)
    )
    assert result.decision == SessionEvaluationDecision.DENY


def test_deny_expired_session(evaluator: SessionEvaluator) -> None:
    ctx = _context(
        session_expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1)
    )
    result = evaluator.evaluate(ctx)
    assert result.decision == SessionEvaluationDecision.DENY
    assert result.stopped_at_check == "session_expiry"


def test_deny_revoked_session(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(_context(session_revoked=True))
    assert result.decision == SessionEvaluationDecision.DENY
    assert result.stopped_at_check == "session_revocation"


def test_deny_revoked_device(evaluator: SessionEvaluator) -> None:
    registry = DeviceTrustRegistry()
    d = registry.register_device(
        subject="user-1",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    d = registry.update_trust_state(
        d.device_id, "tenant-a", DeviceTrustState.REVOKED, "lost", "admin"
    )
    result = evaluator.evaluate(_context(device=d))
    assert result.decision == SessionEvaluationDecision.DENY
    assert result.stopped_at_check == "device_state"


def test_step_up_on_compromised_device(evaluator: SessionEvaluator) -> None:
    registry = DeviceTrustRegistry()
    d = registry.register_device(
        subject="user-1",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    d = registry.update_trust_state(
        d.device_id, "tenant-a", DeviceTrustState.COMPROMISED, "malware", "admin"
    )
    result = evaluator.evaluate(_context(device=d))
    assert result.decision == SessionEvaluationDecision.STEP_UP_REQUIRED
    assert result.stopped_at_check == "device_state"


def test_step_up_missing_mfa(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(_context(mfa_verified=False, tenant_requires_mfa=True))
    assert result.decision == SessionEvaluationDecision.STEP_UP_REQUIRED
    assert result.stopped_at_check == "mfa"


def test_mfa_not_required_no_step_up(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(_context(mfa_verified=False, tenant_requires_mfa=False))
    assert result.decision == SessionEvaluationDecision.ALLOW


def test_deny_critical_risk(evaluator: SessionEvaluator) -> None:
    result = evaluator.evaluate(_context(risk_score=_risk(RiskBand.CRITICAL, 0.9)))
    assert result.decision == SessionEvaluationDecision.DENY
    assert result.stopped_at_check == "risk"


def test_deterministic(evaluator: SessionEvaluator) -> None:
    ctx = _context()
    r1 = evaluator.evaluate(ctx)
    r2 = evaluator.evaluate(ctx)
    assert r1.decision == r2.decision
    assert r1.stopped_at_check == r2.stopped_at_check


def test_evaluation_result_immutable(evaluator: SessionEvaluator) -> None:
    r = evaluator.evaluate(_context())
    with pytest.raises(Exception):
        r.decision = SessionEvaluationDecision.DENY  # type: ignore[misc]


def test_no_secrets_in_result(evaluator: SessionEvaluator) -> None:
    r = evaluator.evaluate(_context())
    dump = repr(r)
    for banned in ("password", "token=", "PORTAL_PASSWORD", "secret_key"):
        assert banned not in dump


def test_priority_identity_first(evaluator: SessionEvaluator) -> None:
    # Identity SUSPENDED must trigger before expired session.
    r = evaluator.evaluate(
        _context(
            identity_state=IdentityLifecycleState.SUSPENDED,
            session_expires_at=datetime.now(tz=timezone.utc) - timedelta(hours=1),
        )
    )
    assert r.stopped_at_check == "identity_state"
