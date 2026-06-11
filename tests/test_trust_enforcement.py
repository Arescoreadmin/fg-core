"""Tests for PR 1.5 — Trust Enforcement Authority.

Covers:
  Modes:
    - off: validation runs, no enforcement, always allowed
    - warn: violations produce warn decision, always allowed
    - strict: hard violations block, legacy configurable

  Trust Score:
    - deterministic scoring (0 / 25 / 50 / 75 / 100)
    - reproducible: identical inputs → identical score

  Enforcement:
    - allow (no violations)
    - warn (violations in off/warn mode)
    - block (violations in strict mode)

  Specific gates:
    - enforce_provenance_integrity
    - enforce_evidence_authority
    - enforce_report_link_authority
    - enforce_full_trust_chain

  evaluate_trust_state:
    - never raises, always returns
    - correct score and violations

  Security:
    - tenant mismatch → critical severity, score=0
    - engagement mismatch → critical severity, score=0
    - authority failure (invalid sig) → score=0, blocked in strict
    - report link failure → score=25, blocked in strict
    - replay failure → score=50, blocked in strict
    - cross-tenant inputs blocked
    - cross-engagement inputs blocked

  Legacy:
    - legacy_unsigned in off/warn: allowed
    - legacy_unsigned in strict + FG_ALLOW_LEGACY_UNSIGNED=false: blocked
    - legacy_unsigned in strict + FG_ALLOW_LEGACY_UNSIGNED=true: warned but allowed
    - legacy flag + allow_legacy_unsigned=true produces trust_score=75

  Metrics:
    - TRUST_VALIDATION_TOTAL increments on each evaluation
    - TRUST_VALIDATION_FAILED_TOTAL increments per violation type
    - TRUST_VALIDATION_WARNING_TOTAL increments on warn decisions
    - TRUST_VALIDATION_BLOCKED_TOTAL increments on block decisions
    - TRUST_CHAIN_FAILURE_TOTAL increments on chain failures
"""

from __future__ import annotations

import pytest

from services.field_assessment.trust_enforcement import (
    TRUST_CHAIN_FAILURE_TOTAL,
    TRUST_VALIDATION_BLOCKED_TOTAL,
    TRUST_VALIDATION_FAILED_TOTAL,
    TRUST_VALIDATION_TOTAL,
    TRUST_VALIDATION_WARNING_TOTAL,
    ProvenanceMode,
    TrustDecision,
    TrustEnforcementError,
    TrustInputs,
    _collect_all_violations,
    _collect_hard_violations,
    _compute_trust_score,
    enforce_evidence_authority,
    enforce_full_trust_chain,
    enforce_provenance_integrity,
    enforce_report_link_authority,
    evaluate_trust_state,
)

TENANT_A = "te-tenant-001"
TENANT_B = "te-tenant-002"
ENG_A = "te-eng-001"
ENG_B = "te-eng-002"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_valid(**overrides) -> TrustInputs:
    defaults = dict(
        chain_valid=True,
        signature_valid=True,
        link_valid=True,
        replay_valid=True,
        tenant_valid=True,
        engagement_valid=True,
        is_legacy=False,
    )
    defaults.update(overrides)
    return TrustInputs(**defaults)


def _call_full(inputs: TrustInputs, mode: ProvenanceMode) -> TrustDecision:
    return enforce_full_trust_chain(
        inputs, mode=mode, tenant_id=TENANT_A, engagement_id=ENG_A
    )


# ---------------------------------------------------------------------------
# ProvenanceMode.from_env
# ---------------------------------------------------------------------------


class TestProvenanceModeFromEnv:
    def test_default_is_warn(self, monkeypatch):
        monkeypatch.delenv("FG_PROVENANCE_MODE", raising=False)
        assert ProvenanceMode.from_env() == ProvenanceMode.WARN

    def test_off(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "off")
        assert ProvenanceMode.from_env() == ProvenanceMode.OFF

    def test_strict(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
        assert ProvenanceMode.from_env() == ProvenanceMode.STRICT

    def test_invalid_falls_back_to_warn(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "invalid_value")
        assert ProvenanceMode.from_env() == ProvenanceMode.WARN

    def test_uppercase_accepted(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "STRICT")
        assert ProvenanceMode.from_env() == ProvenanceMode.STRICT


# ---------------------------------------------------------------------------
# Trust score — deterministic
# ---------------------------------------------------------------------------


class TestTrustScore:
    def test_fully_trusted_is_100(self):
        inputs = _all_valid()
        assert _compute_trust_score(inputs) == 100

    def test_legacy_unsigned_is_75(self):
        inputs = _all_valid(signature_valid=None)
        assert _compute_trust_score(inputs) == 75

    def test_replay_failure_is_50(self):
        inputs = _all_valid(replay_valid=False)
        assert _compute_trust_score(inputs) == 50

    def test_link_failure_is_25(self):
        inputs = _all_valid(link_valid=False)
        assert _compute_trust_score(inputs) == 25

    def test_chain_failure_is_0(self):
        inputs = _all_valid(chain_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_invalid_signature_is_0(self):
        inputs = _all_valid(signature_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_tenant_mismatch_is_0(self):
        inputs = _all_valid(tenant_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_engagement_mismatch_is_0(self):
        inputs = _all_valid(engagement_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_score_deterministic_across_calls(self):
        inputs = _all_valid(replay_valid=False)
        scores = [_compute_trust_score(inputs) for _ in range(10)]
        assert all(s == 50 for s in scores)

    def test_worst_failure_wins_chain_beats_link(self):
        inputs = _all_valid(chain_valid=False, link_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_worst_failure_wins_link_beats_replay(self):
        inputs = _all_valid(link_valid=False, replay_valid=False)
        assert _compute_trust_score(inputs) == 25

    def test_worst_failure_wins_replay_beats_legacy(self):
        inputs = _all_valid(replay_valid=False, signature_valid=None)
        assert _compute_trust_score(inputs) == 50


# ---------------------------------------------------------------------------
# Violation collection
# ---------------------------------------------------------------------------


class TestViolationCollection:
    def test_no_violations_when_all_valid(self):
        inputs = _all_valid()
        assert _collect_hard_violations(inputs) == []
        assert _collect_all_violations(inputs) == []

    def test_chain_failure_collected(self):
        inputs = _all_valid(chain_valid=False)
        assert "chain_failure" in _collect_hard_violations(inputs)

    def test_tenant_mismatch_collected(self):
        inputs = _all_valid(tenant_valid=False)
        assert "tenant_mismatch" in _collect_hard_violations(inputs)

    def test_engagement_mismatch_collected(self):
        inputs = _all_valid(engagement_valid=False)
        assert "engagement_mismatch" in _collect_hard_violations(inputs)

    def test_authority_failure_collected(self):
        inputs = _all_valid(signature_valid=False)
        assert "authority_failure" in _collect_hard_violations(inputs)

    def test_link_failure_collected(self):
        inputs = _all_valid(link_valid=False)
        assert "report_link_failure" in _collect_hard_violations(inputs)

    def test_replay_failure_collected(self):
        inputs = _all_valid(replay_valid=False)
        assert "replay_failure" in _collect_hard_violations(inputs)

    def test_legacy_unsigned_is_soft_violation_not_hard(self):
        inputs = _all_valid(signature_valid=None)
        hard = _collect_hard_violations(inputs)
        soft = _collect_all_violations(inputs)
        assert "legacy_unsigned" not in hard
        assert "legacy_unsigned" in soft

    def test_multiple_violations_all_collected(self):
        inputs = _all_valid(chain_valid=False, tenant_valid=False, link_valid=False)
        v = _collect_hard_violations(inputs)
        assert "chain_failure" in v
        assert "tenant_mismatch" in v
        assert "report_link_failure" in v


# ---------------------------------------------------------------------------
# evaluate_trust_state — never raises, WARN semantics
# ---------------------------------------------------------------------------


class TestEvaluateTrustState:
    def test_all_valid_returns_allow(self):
        inputs = _all_valid()
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.allowed is True
        assert d.decision == "allow"
        assert d.trust_score == 100

    def test_chain_failure_returns_warn_not_block(self):
        inputs = _all_valid(chain_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.allowed is True  # never blocks — just evaluates
        assert d.decision == "warn"
        assert d.trust_score == 0

    def test_never_raises_even_with_all_failures(self):
        inputs = TrustInputs(
            chain_valid=False,
            signature_valid=False,
            link_valid=False,
            replay_valid=False,
            tenant_valid=False,
            engagement_valid=False,
        )
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert isinstance(d, TrustDecision)
        assert d.trust_score == 0

    def test_violations_listed(self):
        inputs = _all_valid(chain_valid=False, link_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert "chain_failure" in d.violations
        assert "report_link_failure" in d.violations

    def test_mode_is_warn(self):
        inputs = _all_valid()
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.mode == ProvenanceMode.WARN.value

    def test_verified_at_is_set(self):
        inputs = _all_valid()
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.verified_at  # non-empty ISO8601 string


# ---------------------------------------------------------------------------
# OFF mode — never enforces, always allows
# ---------------------------------------------------------------------------


class TestOffMode:
    def test_all_valid_allowed(self):
        d = _call_full(_all_valid(), ProvenanceMode.OFF)
        assert d.allowed is True
        assert d.decision == "allow"

    def test_chain_failure_still_allowed(self):
        d = _call_full(_all_valid(chain_valid=False), ProvenanceMode.OFF)
        assert d.allowed is True
        assert d.decision == "allow"
        assert d.trust_score == 0

    def test_authority_failure_still_allowed(self):
        d = _call_full(_all_valid(signature_valid=False), ProvenanceMode.OFF)
        assert d.allowed is True
        assert d.decision == "allow"

    def test_tenant_mismatch_still_allowed(self):
        d = _call_full(_all_valid(tenant_valid=False), ProvenanceMode.OFF)
        assert d.allowed is True

    def test_violations_recorded_even_in_off(self):
        d = _call_full(_all_valid(chain_valid=False), ProvenanceMode.OFF)
        assert "chain_failure" in d.violations

    def test_off_never_raises(self):
        inputs = TrustInputs(
            chain_valid=False,
            signature_valid=False,
            link_valid=False,
            replay_valid=False,
            tenant_valid=False,
            engagement_valid=False,
        )
        d = _call_full(inputs, ProvenanceMode.OFF)
        assert d.allowed is True


# ---------------------------------------------------------------------------
# WARN mode — violations produce warn, always allowed
# ---------------------------------------------------------------------------


class TestWarnMode:
    def test_all_valid_is_allow(self):
        d = _call_full(_all_valid(), ProvenanceMode.WARN)
        assert d.decision == "allow"
        assert d.allowed is True

    def test_chain_failure_produces_warn(self):
        d = _call_full(_all_valid(chain_valid=False), ProvenanceMode.WARN)
        assert d.decision == "warn"
        assert d.allowed is True

    def test_authority_failure_produces_warn(self):
        d = _call_full(_all_valid(signature_valid=False), ProvenanceMode.WARN)
        assert d.decision == "warn"
        assert d.allowed is True

    def test_link_failure_produces_warn(self):
        d = _call_full(_all_valid(link_valid=False), ProvenanceMode.WARN)
        assert d.decision == "warn"
        assert d.allowed is True

    def test_legacy_unsigned_produces_warn(self):
        d = _call_full(_all_valid(signature_valid=None), ProvenanceMode.WARN)
        assert d.decision == "warn"
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations

    def test_warn_mode_never_raises(self):
        inputs = TrustInputs(
            chain_valid=False,
            signature_valid=False,
            link_valid=False,
            replay_valid=False,
            tenant_valid=False,
            engagement_valid=False,
        )
        d = _call_full(inputs, ProvenanceMode.WARN)
        assert d.allowed is True


# ---------------------------------------------------------------------------
# STRICT mode — hard violations block
# ---------------------------------------------------------------------------


class TestStrictMode:
    def test_all_valid_is_allowed(self):
        d = _call_full(_all_valid(), ProvenanceMode.STRICT)
        assert d.allowed is True
        assert d.decision == "allow"

    def test_chain_failure_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(chain_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert d.allowed is False
        assert d.trust_score == 0

    def test_authority_failure_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(signature_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert "authority_failure" in d.violations

    def test_link_failure_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(link_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert d.trust_score == 25

    def test_replay_failure_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(replay_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert d.trust_score == 50

    def test_tenant_mismatch_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(tenant_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert "tenant_mismatch" in d.violations

    def test_engagement_mismatch_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(engagement_valid=False), ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.decision == "block"
        assert "engagement_mismatch" in d.violations

    def test_decision_accessible_from_exception(self):
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(_all_valid(chain_valid=False), ProvenanceMode.STRICT)
        assert isinstance(exc_info.value.decision, TrustDecision)

    def test_multiple_violations_all_in_decision(self):
        inputs = _all_valid(chain_valid=False, link_valid=False, replay_valid=False)
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(inputs, ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert "chain_failure" in d.violations
        assert "report_link_failure" in d.violations
        assert "replay_failure" in d.violations


# ---------------------------------------------------------------------------
# Security — tenant and engagement isolation
# ---------------------------------------------------------------------------


class TestSecurityIsolation:
    def test_tenant_mismatch_critical_severity(self):
        inputs = _all_valid(tenant_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.severity == "critical"
        assert d.trust_score == 0

    def test_engagement_mismatch_critical_severity(self):
        inputs = _all_valid(engagement_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.severity == "critical"
        assert d.trust_score == 0

    def test_authority_failure_high_severity(self):
        inputs = _all_valid(signature_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.severity == "high"

    def test_link_failure_medium_severity(self):
        inputs = _all_valid(link_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.severity == "medium"

    def test_replay_failure_medium_severity(self):
        inputs = _all_valid(replay_valid=False)
        d = evaluate_trust_state(inputs, tenant_id=TENANT_A, engagement_id=ENG_A)
        assert d.severity == "medium"

    def test_cross_tenant_fails_closed_in_strict(self):
        with pytest.raises(TrustEnforcementError):
            _call_full(_all_valid(tenant_valid=False), ProvenanceMode.STRICT)

    def test_cross_engagement_fails_closed_in_strict(self):
        with pytest.raises(TrustEnforcementError):
            _call_full(_all_valid(engagement_valid=False), ProvenanceMode.STRICT)

    def test_tenant_mismatch_score_zero(self):
        inputs = _all_valid(tenant_valid=False)
        assert _compute_trust_score(inputs) == 0

    def test_engagement_mismatch_score_zero(self):
        inputs = _all_valid(engagement_valid=False)
        assert _compute_trust_score(inputs) == 0


# ---------------------------------------------------------------------------
# Legacy records
# ---------------------------------------------------------------------------


class TestLegacyRecords:
    def test_legacy_unsigned_allowed_in_off(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "false")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        d = _call_full(inputs, ProvenanceMode.OFF)
        assert d.allowed is True

    def test_legacy_unsigned_allowed_with_warn_in_warn_mode(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "false")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        d = _call_full(inputs, ProvenanceMode.WARN)
        assert d.allowed is True
        assert d.decision == "warn"

    def test_legacy_unsigned_blocked_in_strict_by_default(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "false")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(inputs, ProvenanceMode.STRICT)
        assert exc_info.value.decision.decision == "block"

    def test_legacy_unsigned_allowed_in_strict_when_configured(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "true")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        d = _call_full(inputs, ProvenanceMode.STRICT)
        assert d.allowed is True
        assert d.decision == "warn"

    def test_legacy_unsigned_trust_score_is_75(self):
        inputs = _all_valid(signature_valid=None)
        assert _compute_trust_score(inputs) == 75

    def test_legacy_blocked_has_legacy_unsigned_in_violations(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "false")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(inputs, ProvenanceMode.STRICT)
        assert "legacy_unsigned" in exc_info.value.decision.violations

    def test_legacy_allowed_produces_warn_not_block(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "true")
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        d = _call_full(inputs, ProvenanceMode.STRICT)
        assert d.decision == "warn"
        assert d.allowed is True


# ---------------------------------------------------------------------------
# Gate-specific functions
# ---------------------------------------------------------------------------


class TestEnforceProvenanceIntegrity:
    def test_valid_chain_allowed(self):
        inputs = _all_valid()
        d = enforce_provenance_integrity(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_broken_chain_blocked_in_strict(self):
        inputs = _all_valid(chain_valid=False)
        with pytest.raises(TrustEnforcementError):
            enforce_provenance_integrity(
                inputs,
                mode=ProvenanceMode.STRICT,
                tenant_id=TENANT_A,
                engagement_id=ENG_A,
            )

    def test_signature_failure_ignored_by_this_gate(self):
        # enforce_provenance_integrity does not evaluate signature
        inputs = _all_valid(signature_valid=False)
        d = enforce_provenance_integrity(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_link_failure_ignored_by_this_gate(self):
        inputs = _all_valid(link_valid=False)
        d = enforce_provenance_integrity(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_tenant_mismatch_blocked(self):
        inputs = _all_valid(tenant_valid=False)
        with pytest.raises(TrustEnforcementError):
            enforce_provenance_integrity(
                inputs,
                mode=ProvenanceMode.STRICT,
                tenant_id=TENANT_A,
                engagement_id=ENG_A,
            )


class TestEnforceEvidenceAuthority:
    def test_valid_signature_allowed(self):
        inputs = _all_valid()
        d = enforce_evidence_authority(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_invalid_signature_blocked_in_strict(self):
        inputs = _all_valid(signature_valid=False)
        with pytest.raises(TrustEnforcementError) as exc_info:
            enforce_evidence_authority(
                inputs,
                mode=ProvenanceMode.STRICT,
                tenant_id=TENANT_A,
                engagement_id=ENG_A,
            )
        assert "authority_failure" in exc_info.value.decision.violations

    def test_legacy_unsigned_warns_in_warn_mode(self):
        inputs = _all_valid(signature_valid=None, is_legacy=True)
        d = enforce_evidence_authority(
            inputs, mode=ProvenanceMode.WARN, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.decision == "warn"
        assert d.allowed is True

    def test_chain_failure_ignored_by_this_gate(self):
        inputs = _all_valid(chain_valid=False)
        d = enforce_evidence_authority(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_tenant_mismatch_blocked_by_this_gate(self):
        inputs = _all_valid(tenant_valid=False)
        with pytest.raises(TrustEnforcementError):
            enforce_evidence_authority(
                inputs,
                mode=ProvenanceMode.STRICT,
                tenant_id=TENANT_A,
                engagement_id=ENG_A,
            )


class TestEnforceReportLinkAuthority:
    def test_valid_link_allowed(self):
        inputs = _all_valid()
        d = enforce_report_link_authority(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_invalid_link_blocked_in_strict(self):
        inputs = _all_valid(link_valid=False)
        with pytest.raises(TrustEnforcementError) as exc_info:
            enforce_report_link_authority(
                inputs,
                mode=ProvenanceMode.STRICT,
                tenant_id=TENANT_A,
                engagement_id=ENG_A,
            )
        assert "report_link_failure" in exc_info.value.decision.violations

    def test_chain_failure_ignored_by_this_gate(self):
        inputs = _all_valid(chain_valid=False)
        d = enforce_report_link_authority(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_signature_failure_ignored_by_this_gate(self):
        inputs = _all_valid(signature_valid=False)
        d = enforce_report_link_authority(
            inputs, mode=ProvenanceMode.STRICT, tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert d.allowed is True

    def test_link_failure_trust_score_25(self):
        inputs = _all_valid(link_valid=False)
        assert _compute_trust_score(inputs) == 25


class TestEnforceFullTrustChain:
    def test_all_valid_allowed_in_all_modes(self):
        for mode in ProvenanceMode:
            d = _call_full(_all_valid(), mode)
            assert d.allowed is True

    def test_all_failures_blocked_in_strict(self):
        inputs = TrustInputs(
            chain_valid=False,
            signature_valid=False,
            link_valid=False,
            replay_valid=False,
            tenant_valid=False,
            engagement_valid=False,
        )
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(inputs, ProvenanceMode.STRICT)
        d = exc_info.value.decision
        assert d.trust_score == 0
        assert d.severity == "critical"

    def test_gate_name_in_error(self):
        inputs = _all_valid(chain_valid=False)
        with pytest.raises(TrustEnforcementError) as exc_info:
            _call_full(inputs, ProvenanceMode.STRICT)
        assert "trust_enforcement_blocked" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TrustDecision structure
# ---------------------------------------------------------------------------


class TestTrustDecisionFields:
    def test_all_fields_present(self):
        d = _call_full(_all_valid(), ProvenanceMode.WARN)
        assert isinstance(d.allowed, bool)
        assert isinstance(d.mode, str)
        assert d.mode in {m.value for m in ProvenanceMode}
        assert d.decision in {"allow", "warn", "block"}
        assert d.severity in {"low", "medium", "high", "critical"}
        assert isinstance(d.violations, list)
        assert isinstance(d.verified_at, str)
        assert isinstance(d.trust_score, int)
        assert 0 <= d.trust_score <= 100

    def test_decision_frozen(self):
        d = _call_full(_all_valid(), ProvenanceMode.WARN)
        with pytest.raises((AttributeError, TypeError)):
            d.allowed = False  # type: ignore[misc]

    def test_violation_types_are_strings(self):
        inputs = _all_valid(chain_valid=False, link_valid=False)
        d = _call_full(inputs, ProvenanceMode.WARN)
        assert all(isinstance(v, str) for v in d.violations)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    """Verify Prometheus counters increment on enforcement evaluations."""

    @staticmethod
    def _val(counter, **labels) -> float:
        return counter.labels(**labels)._value.get()

    def test_total_increments_on_allow(self):
        before = self._val(TRUST_VALIDATION_TOTAL, mode="warn", decision="allow")
        _call_full(_all_valid(), ProvenanceMode.WARN)
        assert self._val(TRUST_VALIDATION_TOTAL, mode="warn", decision="allow") > before

    def test_total_increments_on_warn(self):
        before = self._val(TRUST_VALIDATION_TOTAL, mode="warn", decision="warn")
        _call_full(_all_valid(chain_valid=False), ProvenanceMode.WARN)
        assert self._val(TRUST_VALIDATION_TOTAL, mode="warn", decision="warn") > before

    def test_failed_total_increments_on_violation(self):
        before = self._val(
            TRUST_VALIDATION_FAILED_TOTAL, mode="warn", violation_type="chain_failure"
        )
        _call_full(_all_valid(chain_valid=False), ProvenanceMode.WARN)
        assert (
            self._val(
                TRUST_VALIDATION_FAILED_TOTAL,
                mode="warn",
                violation_type="chain_failure",
            )
            > before
        )

    def test_warning_total_increments_on_warn_decision(self):
        before = self._val(TRUST_VALIDATION_WARNING_TOTAL, mode="warn")
        _call_full(_all_valid(chain_valid=False), ProvenanceMode.WARN)
        assert self._val(TRUST_VALIDATION_WARNING_TOTAL, mode="warn") > before

    def test_blocked_total_increments_on_block(self):
        before = self._val(TRUST_VALIDATION_BLOCKED_TOTAL, mode="strict")
        try:
            _call_full(_all_valid(chain_valid=False), ProvenanceMode.STRICT)
        except TrustEnforcementError:
            pass
        assert self._val(TRUST_VALIDATION_BLOCKED_TOTAL, mode="strict") > before

    def test_chain_failure_total_increments(self):
        before = self._val(
            TRUST_CHAIN_FAILURE_TOTAL, mode="warn", violation_type="chain_failure"
        )
        _call_full(_all_valid(chain_valid=False), ProvenanceMode.WARN)
        assert (
            self._val(
                TRUST_CHAIN_FAILURE_TOTAL, mode="warn", violation_type="chain_failure"
            )
            > before
        )

    def test_blocked_metric_not_incremented_when_allowed(self):
        before = self._val(TRUST_VALIDATION_BLOCKED_TOTAL, mode="strict")
        _call_full(_all_valid(), ProvenanceMode.STRICT)
        assert self._val(TRUST_VALIDATION_BLOCKED_TOTAL, mode="strict") == before


# ---------------------------------------------------------------------------
# Mode escalation safety
# ---------------------------------------------------------------------------


class TestModeEscalation:
    """FG_PROVENANCE_MODE must only accept valid values; invalid falls back to warn."""

    def test_unknown_mode_env_falls_back_to_warn(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "enterprise")
        assert ProvenanceMode.from_env() == ProvenanceMode.WARN

    def test_empty_mode_env_falls_back_to_warn(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "")
        # Empty string → ValueError → WARN
        assert ProvenanceMode.from_env() == ProvenanceMode.WARN

    def test_off_mode_cannot_block(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "off")
        mode = ProvenanceMode.from_env()
        inputs = _all_valid(chain_valid=False, tenant_valid=False)
        d = _call_full(inputs, mode)
        assert d.allowed is True
        assert d.decision == "allow"
