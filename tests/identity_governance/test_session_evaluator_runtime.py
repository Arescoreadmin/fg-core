"""Tests for the SessionEvaluator wiring in the runtime path.

Exercises :func:`api.identity_governance.runtime.apply_governance_checks`
which is the sole runtime entry point invoked by
``api.auth_dispatch.get_actor_context``.

Every case runs with FG_SESSION_EVALUATOR_ENABLED=1 unless the test
explicitly checks flag-off behavior.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from api.actor_context import ActorContext
from api.identity_governance import reset_services
from api.identity_governance.error_codes import IdentityErrorCode
from api.identity_governance.models import (
    DeviceRecord,
    DeviceTrustState,
    IdentityLifecycleState,
    RiskBand,
    RiskScore,
    SessionEvaluationContext,
    SessionEvaluationDecision,
    SessionEvaluationResult,
)
from api.identity_governance import runtime as runtime_module
from api.identity_governance.runtime import apply_governance_checks


NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _reset_services(monkeypatch: pytest.MonkeyPatch):
    reset_services()
    for flag in (
        "FG_IDENTITY_AUTHORITY_ENABLED",
        "FG_SESSION_EVALUATOR_ENABLED",
        "FG_DEVICE_TRUST_ENFORCEMENT_ENABLED",
        "FG_RISK_ENGINE_ENABLED",
        "FG_CONDITIONAL_ACCESS_ENABLED",
        "FG_BREAK_GLASS_RUNTIME_ENABLED",
        "FG_IDENTITY_TIMELINE_ENABLED",
        "FG_IDENTITY_PERSISTENCE_ENABLED",
    ):
        monkeypatch.delenv(flag, raising=False)
    yield
    reset_services()


def _actor(
    tenant_id: str = "tenant-a",
    subject: str = "user:1",
    auth_source: str = "api_key",
) -> ActorContext:
    return ActorContext(
        subject=subject,
        email="u@example.com",
        name="U",
        permissions=frozenset({"assessment.read"}),
        roles=["assessor"],
        auth_source=auth_source,
        tenant_id=tenant_id,
    )


def _request(
    headers: dict[str, str] | None = None,
    session_id: str = "sess-1",
) -> MagicMock:
    req = MagicMock()
    req.headers = headers or {}
    req.state.session_id = session_id
    return req


def _stub_session_result(
    decision: SessionEvaluationDecision,
    stopped_at: str = "identity_state",
) -> SessionEvaluationResult:
    return SessionEvaluationResult(
        decision=decision,
        reason="stub",
        checks_run=("identity_state",),
        stopped_at_check=stopped_at,
        evaluated_at=NOW,
    )


# ---------------------------------------------------------------------------
# Flag gating
# ---------------------------------------------------------------------------


def test_apply_is_noop_when_all_flags_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # No flags set → no governance evaluation.
    result = apply_governance_checks(_actor(), _request())
    assert result is not None
    assert result.subject == "user:1"


def test_apply_is_noop_for_anonymous_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "1")
    anon = ActorContext(
        subject="anonymous",
        email="",
        name="",
        permissions=frozenset(),
        roles=[],
        auth_source="none",
        tenant_id=None,
    )
    # No evaluator runs; anonymous is passed through untouched.
    result = apply_governance_checks(anon, _request())
    assert result.subject == "anonymous"


def test_apply_is_noop_for_dev_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "1")
    actor = _actor(auth_source="dev_bypass")
    result = apply_governance_checks(actor, _request())
    assert result.auth_source == "dev_bypass"


# ---------------------------------------------------------------------------
# Deny outcomes
# ---------------------------------------------------------------------------


def _install_evaluator_stub(
    monkeypatch: pytest.MonkeyPatch, result: SessionEvaluationResult
) -> None:
    from api.identity_governance.services import get_services

    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "1")
    services = get_services()
    monkeypatch.setattr(services.session_evaluator, "evaluate", lambda ctx: result)


def test_deny_identity_suspended(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_module,
        "_identity_lifecycle_state",
        lambda actor: IdentityLifecycleState.SUSPENDED,
    )
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.DENY, "identity_state"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.IDENTITY_SUSPENDED.value


def test_deny_identity_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_module,
        "_identity_lifecycle_state",
        lambda actor: IdentityLifecycleState.DISABLED,
    )
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.DENY, "identity_state"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.IDENTITY_DISABLED.value


def test_deny_session_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.DENY, "session_expiry"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.SESSION_EXPIRED.value


def test_revoke_session_returns_401_and_revoked_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(
            SessionEvaluationDecision.REVOKE_SESSION, "session_revocation"
        ),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail["code"] == IdentityErrorCode.SESSION_REVOKED.value


def test_deny_device_revoked_state(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.DENY, "device_state"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.DEVICE_REVOKED.value


def test_step_up_from_device_maps_to_device_compromised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(
            SessionEvaluationDecision.STEP_UP_REQUIRED, "device_state"
        ),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.DEVICE_COMPROMISED.value


def test_step_up_from_mfa_maps_to_mfa_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.STEP_UP_REQUIRED, "mfa"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.MFA_STEP_UP_REQUIRED.value


def test_critical_risk_deny_maps_to_policy_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.DENY, "risk"),
    )
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail["code"] == IdentityErrorCode.POLICY_DENIED.value


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


def test_allow_returns_actor_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_evaluator_stub(
        monkeypatch,
        _stub_session_result(SessionEvaluationDecision.ALLOW, ""),
    )
    actor = _actor()
    result = apply_governance_checks(actor, _request())
    assert result is actor


# ---------------------------------------------------------------------------
# Fail-closed on internal error
# ---------------------------------------------------------------------------


def test_internal_error_fails_closed_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "1")
    from api.identity_governance.services import get_services

    def boom(_ctx: SessionEvaluationContext) -> SessionEvaluationResult:
        raise RuntimeError("evaluator boom")

    services = get_services()
    monkeypatch.setattr(services.session_evaluator, "evaluate", boom)
    with pytest.raises(HTTPException) as excinfo:
        apply_governance_checks(_actor(), _request())
    assert excinfo.value.status_code == 500
    assert (
        excinfo.value.detail["code"] == IdentityErrorCode.GOVERNANCE_UNAVAILABLE.value
    )


# ---------------------------------------------------------------------------
# Direct SessionEvaluator surface (unit-style) for parity
# ---------------------------------------------------------------------------


def _low_risk() -> RiskScore:
    return RiskScore(
        subject="user:1",
        tenant_id="tenant-a",
        score=0.0,
        band=RiskBand.LOW,
        factors=(),
        evaluator_version="1.0.0",
        evaluated_at=NOW,
    )


def _critical_risk() -> RiskScore:
    return RiskScore(
        subject="user:1",
        tenant_id="tenant-a",
        score=0.95,
        band=RiskBand.CRITICAL,
        factors=(("lifecycle_state", 0.9), ("missing_mfa", 0.3)),
        evaluator_version="1.0.0",
        evaluated_at=NOW,
    )


def _base_context(**overrides) -> SessionEvaluationContext:
    data = dict(
        subject="user:1",
        tenant_id="tenant-a",
        session_id="sess",
        identity_state=IdentityLifecycleState.ACTIVE,
        session_expires_at=NOW + timedelta(hours=1),
        session_revoked=False,
        device=None,
        mfa_verified=True,
        tenant_requires_mfa=False,
        risk_score=_low_risk(),
        evaluated_at=NOW,
    )
    data.update(overrides)
    return SessionEvaluationContext(**data)


def test_evaluator_low_risk_active_allows() -> None:
    from api.identity_governance.session_evaluation import SessionEvaluator

    result = SessionEvaluator().evaluate(_base_context())
    assert result.decision == SessionEvaluationDecision.ALLOW


def test_evaluator_critical_risk_denies() -> None:
    from api.identity_governance.session_evaluation import SessionEvaluator

    result = SessionEvaluator().evaluate(_base_context(risk_score=_critical_risk()))
    assert result.decision == SessionEvaluationDecision.DENY


def test_evaluator_missing_mfa_when_required_stepup() -> None:
    from api.identity_governance.session_evaluation import SessionEvaluator

    result = SessionEvaluator().evaluate(
        _base_context(mfa_verified=False, tenant_requires_mfa=True)
    )
    assert result.decision == SessionEvaluationDecision.STEP_UP_REQUIRED


def test_evaluator_compromised_device_stepup() -> None:
    from api.identity_governance.session_evaluation import SessionEvaluator

    device = DeviceRecord(
        device_id="d",
        tenant_id="tenant-a",
        subject="user:1",
        fingerprint_hash="fpr",
        user_agent_hash="ua",
        ip_metadata="",
        trust_state=DeviceTrustState.COMPROMISED,
        risk_score=0.95,
        registered_at=NOW,
        updated_at=NOW,
        last_reason="compromise_detected",
    )
    result = SessionEvaluator().evaluate(_base_context(device=device))
    assert result.decision == SessionEvaluationDecision.STEP_UP_REQUIRED


def test_evaluator_revoked_device_denies() -> None:
    from api.identity_governance.session_evaluation import SessionEvaluator

    device = DeviceRecord(
        device_id="d",
        tenant_id="tenant-a",
        subject="user:1",
        fingerprint_hash="fpr",
        user_agent_hash="ua",
        ip_metadata="",
        trust_state=DeviceTrustState.REVOKED,
        risk_score=1.0,
        registered_at=NOW,
        updated_at=NOW,
        last_reason="admin_revoked",
    )
    result = SessionEvaluator().evaluate(_base_context(device=device))
    assert result.decision == SessionEvaluationDecision.DENY
