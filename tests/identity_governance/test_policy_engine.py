"""tests/identity_governance/test_policy_engine.py — Policy engine tests."""

from __future__ import annotations

from typing import Any

import pytest

from api.identity_governance.models import (
    IdentityLifecycleState,
    PolicyCondition,
    PolicyDecision,
    PolicyEvaluationContext,
    PolicyRecord,
)
from api.identity_governance.policy_engine import ConditionalAccessPolicyEngine


@pytest.fixture
def engine() -> ConditionalAccessPolicyEngine:
    return ConditionalAccessPolicyEngine()


def _ctx(**overrides: Any) -> PolicyEvaluationContext:
    defaults: dict[str, Any] = dict(
        subject="user-1",
        tenant_id="tenant-a",
        roles=frozenset({"assessor"}),
        capabilities=frozenset({"assessment.read"}),
        mfa_verified=True,
        identity_state=IdentityLifecycleState.ACTIVE,
        ip="10.0.0.1",
        now_hour_utc=12,
    )
    defaults.update(overrides)
    return PolicyEvaluationContext(**defaults)


def _policy(**overrides: Any) -> PolicyRecord:
    defaults: dict[str, Any] = dict(
        policy_id="p1",
        tenant_id="tenant-a",
        name="default",
        priority=100,
        conditions=(),
        on_match=PolicyDecision.ALLOW,
        enabled=True,
    )
    defaults.update(overrides)
    return PolicyRecord(**defaults)


def test_no_policies_defaults_allow(engine: ConditionalAccessPolicyEngine) -> None:
    result = engine.evaluate([], _ctx())
    assert result.decision == PolicyDecision.ALLOW
    assert result.matched_policy_id is None


def test_requires_mfa_pass(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(PolicyCondition(kind="requires_mfa"),),
        on_match=PolicyDecision.ALLOW,
    )
    r = engine.evaluate([p], _ctx(mfa_verified=True))
    assert r.decision == PolicyDecision.ALLOW
    assert r.matched_policy_id == "p1"


def test_requires_mfa_no_match_default_allow(
    engine: ConditionalAccessPolicyEngine,
) -> None:
    p = _policy(
        conditions=(PolicyCondition(kind="requires_mfa"),),
        on_match=PolicyDecision.ALLOW,
    )
    r = engine.evaluate([p], _ctx(mfa_verified=False))
    # The policy did not match; default allow applies.
    assert r.decision == PolicyDecision.ALLOW
    assert r.matched_policy_id is None


def test_deny_suspended(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(PolicyCondition(kind="deny_suspended"),),
        on_match=PolicyDecision.DENY,
        priority=1,
    )
    r = engine.evaluate(
        [p],
        _ctx(identity_state=IdentityLifecycleState.SUSPENDED),
    )
    assert r.decision == PolicyDecision.DENY


def test_priority_ordering(engine: ConditionalAccessPolicyEngine) -> None:
    low = _policy(policy_id="low", priority=50, on_match=PolicyDecision.ALLOW)
    high = _policy(policy_id="high", priority=10, on_match=PolicyDecision.DENY)
    r = engine.evaluate([low, high], _ctx())
    assert r.decision == PolicyDecision.DENY
    assert r.matched_policy_id == "high"


def test_deny_overrides_allow_same_priority(
    engine: ConditionalAccessPolicyEngine,
) -> None:
    allow = _policy(policy_id="allow", priority=10, on_match=PolicyDecision.ALLOW)
    deny = _policy(policy_id="deny", priority=10, on_match=PolicyDecision.DENY)
    r = engine.evaluate([allow, deny], _ctx())
    assert r.decision == PolicyDecision.DENY


def test_tenant_isolation(engine: ConditionalAccessPolicyEngine) -> None:
    other = _policy(
        policy_id="other",
        tenant_id="tenant-b",
        on_match=PolicyDecision.DENY,
        priority=1,
    )
    r = engine.evaluate([other], _ctx(tenant_id="tenant-a"))
    assert r.decision == PolicyDecision.ALLOW
    assert r.matched_policy_id is None


def test_requires_role(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(
            PolicyCondition(kind="requires_role", params=(("role", "admin"),)),
        ),
        on_match=PolicyDecision.ALLOW,
    )
    r_no = engine.evaluate([p], _ctx(roles=frozenset({"user"})))
    assert r_no.matched_policy_id is None
    r_yes = engine.evaluate([p], _ctx(roles=frozenset({"admin"})))
    assert r_yes.matched_policy_id == "p1"


def test_requires_capability(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(
            PolicyCondition(
                kind="requires_capability",
                params=(("capability", "assessment.write"),),
            ),
        ),
        on_match=PolicyDecision.ALLOW,
    )
    r = engine.evaluate(
        [p],
        _ctx(capabilities=frozenset({"assessment.write"})),
    )
    assert r.matched_policy_id == "p1"


def test_ip_allowlist(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(
            PolicyCondition(
                kind="ip_allowlist",
                params=(("cidrs", "10.0.0.1,10.0.0.2"),),
            ),
        ),
        on_match=PolicyDecision.ALLOW,
    )
    assert engine.evaluate([p], _ctx(ip="10.0.0.1")).matched_policy_id == "p1"
    assert engine.evaluate([p], _ctx(ip="192.168.0.1")).matched_policy_id is None


def test_time_window(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(
            PolicyCondition(
                kind="time_window",
                params=(("start_hour_utc", "9"), ("end_hour_utc", "17")),
            ),
        ),
        on_match=PolicyDecision.ALLOW,
    )
    assert engine.evaluate([p], _ctx(now_hour_utc=10)).matched_policy_id == "p1"
    assert engine.evaluate([p], _ctx(now_hour_utc=22)).matched_policy_id is None


def test_break_glass_reason(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(PolicyCondition(kind="requires_break_glass_reason"),),
        on_match=PolicyDecision.ALLOW,
    )
    r_missing = engine.evaluate([p], _ctx())
    assert r_missing.matched_policy_id is None
    r_present = engine.evaluate([p], _ctx(break_glass_reason="incident-1234"))
    assert r_present.matched_policy_id == "p1"


def test_unknown_condition_never_matches(
    engine: ConditionalAccessPolicyEngine,
) -> None:
    p = _policy(
        conditions=(PolicyCondition(kind="unknown_condition"),),
        on_match=PolicyDecision.DENY,
    )
    r = engine.evaluate([p], _ctx())
    assert r.matched_policy_id is None


def test_disabled_policy_skipped(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(
        conditions=(),
        on_match=PolicyDecision.DENY,
        enabled=False,
        priority=1,
    )
    r = engine.evaluate([p], _ctx())
    assert r.decision == PolicyDecision.ALLOW


def test_deterministic(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(on_match=PolicyDecision.DENY, priority=1)
    ctx = _ctx()
    r1 = engine.evaluate([p], ctx)
    r2 = engine.evaluate([p], ctx)
    assert r1.decision == r2.decision
    assert r1.evaluated_policies == r2.evaluated_policies


def test_no_secrets_in_reason(engine: ConditionalAccessPolicyEngine) -> None:
    p = _policy(on_match=PolicyDecision.ALLOW)
    r = engine.evaluate([p], _ctx())
    dump = repr(r)
    for banned in ("password", "PORTAL_PASSWORD", "token="):
        assert banned not in dump
