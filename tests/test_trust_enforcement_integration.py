"""Integration tests for Trust Enforcement Adapter — PR 1.5A.

Verifies the adapter layer's correctness across all 6 protected operations,
all enforcement modes, all decision outcomes, and all security isolation scenarios.

Coverage Matrix (verified by this suite)
-----------------------------------------
  Evidence Creation      Protected  enforce_evidence_creation()
  Evidence Review        Protected  enforce_evidence_review()
  Evidence Approval      Protected  enforce_evidence_approval()
  Report Finalization    Protected  enforce_report_finalization()
  Report Export          Protected  enforce_report_export()
  Trust Replay           Protected  enforce_trust_replay()
"""

from __future__ import annotations


import pytest

from services.field_assessment.trust_enforcement import (
    ProvenanceMode,
    TrustEnforcementError,
)
from services.field_assessment.trust_enforcement_adapter import (
    ENFORCEMENT_ALLOWED_TOTAL,
    ENFORCEMENT_BLOCKED_TOTAL,
    ENFORCEMENT_OPERATIONS_TOTAL,
    ENFORCEMENT_WARNED_TOTAL,
    _trust_inputs_from_replay_result,
    enforce_evidence_approval,
    enforce_evidence_creation,
    enforce_evidence_review,
    enforce_report_export,
    enforce_report_finalization,
    enforce_trust_replay,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T = "tenant-a"
_E = "engagement-x"


def _replay_result(
    *,
    chain_valid: bool = True,
    score: int = 100,
    failed_nodes: list | None = None,
    invalid_links: list | None = None,
    link_status: str = "unlinked",
    engagement_id: str = _E,
) -> dict:
    return {
        "chain_valid": chain_valid,
        "chain_replay_score": score,
        "failed_nodes": failed_nodes or [],
        "invalid_report_links": invalid_links or [],
        "report_link_status": link_status,
        "engagement_id": engagement_id,
    }


def _counter_value(counter, **labels) -> float:
    try:
        return counter.labels(**labels)._value.get()
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# _trust_inputs_from_replay_result
# ---------------------------------------------------------------------------


class TestReplayResultConversion:
    def test_score_100_all_valid(self):
        inputs = _trust_inputs_from_replay_result(_replay_result(score=100))
        assert inputs.chain_valid is True
        assert inputs.signature_valid is True
        assert inputs.link_valid is True
        assert inputs.replay_valid is True
        assert inputs.is_legacy is False

    def test_score_75_warnings_not_sig_failure(self):
        inputs = _trust_inputs_from_replay_result(_replay_result(score=75))
        assert inputs.chain_valid is True
        assert inputs.signature_valid is True
        assert inputs.is_legacy is False

    def test_score_50_legacy_unsigned(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(score=50, chain_valid=True)
        )
        assert inputs.chain_valid is True
        assert inputs.signature_valid is None
        assert inputs.is_legacy is True

    def test_score_0_chain_failure_no_sig(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(
                score=0,
                chain_valid=False,
                failed_nodes=[{"node_id": "n1", "reason": "hash_mismatch"}],
            )
        )
        assert inputs.chain_valid is False
        assert inputs.signature_valid is True  # not a sig failure

    def test_score_0_signature_failure(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(
                score=0,
                chain_valid=False,
                failed_nodes=[
                    {
                        "node_id": "n1",
                        "reason": "hash_mismatch",
                        "signature_status": "invalid_signature",
                    }
                ],
            )
        )
        assert inputs.chain_valid is False
        assert inputs.signature_valid is False

    def test_invalid_links_sets_link_valid_false(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(
                invalid_links=[{"link_id": "l1", "reason": "hash_mismatch"}],
                link_status="invalid",
            )
        )
        assert inputs.link_valid is False

    def test_link_status_invalid_sets_link_valid_false(self):
        inputs = _trust_inputs_from_replay_result(_replay_result(link_status="invalid"))
        assert inputs.link_valid is False

    def test_verified_links_sets_link_valid_true(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(link_status="verified", invalid_links=[])
        )
        assert inputs.link_valid is True

    def test_broken_chain_replay_not_valid(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(chain_valid=False, score=0)
        )
        assert inputs.replay_valid is False

    def test_healthy_chain_replay_valid(self):
        inputs = _trust_inputs_from_replay_result(
            _replay_result(chain_valid=True, score=100)
        )
        assert inputs.replay_valid is True


# ---------------------------------------------------------------------------
# enforce_evidence_creation — modes and decisions
# ---------------------------------------------------------------------------


class TestEnforceEvidenceCreation:
    def test_off_mode_always_allows(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True
        assert d.decision == "allow"

    def test_warn_mode_clean_allows(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert d.decision == "allow"

    def test_warn_mode_invalid_sig_warns(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert d.decision == "warn"
        assert "authority_failure" in d.violations

    def test_strict_mode_clean_allows(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True

    def test_strict_mode_invalid_sig_blocks(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "false")
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert exc.value.decision.decision == "block"
        assert "authority_failure" in exc.value.decision.violations

    def test_strict_mode_legacy_unsigned_blocked_by_default(self, monkeypatch):
        monkeypatch.delenv("FG_ALLOW_LEGACY_UNSIGNED", raising=False)
        with pytest.raises(TrustEnforcementError):
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            )

    def test_strict_mode_legacy_allowed_with_env_flag(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "true")
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True
        assert d.decision == "warn"

    def test_returns_trust_decision(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            mode=ProvenanceMode.WARN,
        )
        assert isinstance(d.trust_score, int)
        assert isinstance(d.violations, list)
        assert isinstance(d.verified_at, str)

    def test_mode_defaults_to_env(self, monkeypatch):
        monkeypatch.setenv("FG_PROVENANCE_MODE", "off")
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
        )
        assert d.decision == "allow"

    def test_cross_tenant_denied_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                tenant_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "tenant_mismatch" in exc.value.decision.violations

    def test_cross_engagement_denied_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                engagement_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "engagement_mismatch" in exc.value.decision.violations

    def test_cross_tenant_warns_in_warn_mode(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            tenant_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "tenant_mismatch" in d.violations


# ---------------------------------------------------------------------------
# enforce_evidence_review — modes and decisions
# ---------------------------------------------------------------------------


class TestEnforceEvidenceReview:
    def test_off_mode_allows_all(self):
        d = enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True

    def test_warn_mode_unsigned_warns(self):
        d = enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations

    def test_strict_mode_invalid_sig_blocks(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_review(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "authority_failure" in exc.value.decision.violations

    def test_strict_mode_clean_allows(self):
        d = enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True

    def test_trust_score_100_when_clean(self):
        d = enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.trust_score == 100

    def test_trust_score_0_on_invalid_sig(self):
        d = enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.trust_score == 0


# ---------------------------------------------------------------------------
# enforce_evidence_approval — all dimensions
# ---------------------------------------------------------------------------


class TestEnforceEvidenceApproval:
    def test_clean_state_allows(self):
        d = enforce_evidence_approval(
            None,
            tenant_id=_T,
            engagement_id=_E,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert d.decision == "allow"

    def test_broken_chain_warns_in_warn_mode(self):
        d = enforce_evidence_approval(
            None,
            tenant_id=_T,
            engagement_id=_E,
            chain_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "chain_failure" in d.violations

    def test_broken_chain_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_approval(
                None,
                tenant_id=_T,
                engagement_id=_E,
                chain_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "chain_failure" in exc.value.decision.violations

    def test_invalid_link_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_approval(
                None,
                tenant_id=_T,
                engagement_id=_E,
                link_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "report_link_failure" in exc.value.decision.violations

    def test_replay_failure_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_approval(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "replay_failure" in exc.value.decision.violations

    def test_off_mode_ignores_all_failures(self):
        d = enforce_evidence_approval(
            None,
            tenant_id=_T,
            engagement_id=_E,
            chain_valid=False,
            signature_valid=False,
            link_valid=False,
            replay_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True
        assert d.decision == "allow"


# ---------------------------------------------------------------------------
# enforce_report_finalization — full gate
# ---------------------------------------------------------------------------


class TestEnforceReportFinalization:
    def test_signed_report_allows_strict(self):
        d = enforce_report_finalization(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True

    def test_unsigned_report_warns_in_warn_mode(self):
        d = enforce_report_finalization(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations

    def test_unsigned_report_blocks_strict(self, monkeypatch):
        monkeypatch.delenv("FG_ALLOW_LEGACY_UNSIGNED", raising=False)
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_finalization(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            )
        assert "legacy_unsigned" in exc.value.decision.violations

    def test_invalid_signature_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_finalization(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "authority_failure" in exc.value.decision.violations

    def test_chain_failure_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_finalization(
                None,
                tenant_id=_T,
                engagement_id=_E,
                chain_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "chain_failure" in exc.value.decision.violations

    def test_off_mode_allows_broken_chain(self):
        d = enforce_report_finalization(
            None,
            tenant_id=_T,
            engagement_id=_E,
            chain_valid=False,
            signature_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True


# ---------------------------------------------------------------------------
# enforce_report_export — full gate
# ---------------------------------------------------------------------------


class TestEnforceReportExport:
    def test_signed_report_allows_strict(self):
        d = enforce_report_export(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True

    def test_unsigned_warns_in_warn_mode(self):
        d = enforce_report_export(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations

    def test_unsigned_blocks_strict(self, monkeypatch):
        monkeypatch.delenv("FG_ALLOW_LEGACY_UNSIGNED", raising=False)
        with pytest.raises(TrustEnforcementError):
            enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            )

    def test_invalid_sig_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "authority_failure" in exc.value.decision.violations

    def test_link_tampering_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                link_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "report_link_failure" in exc.value.decision.violations

    def test_off_mode_exports_with_violations(self):
        d = enforce_report_export(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            link_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True


# ---------------------------------------------------------------------------
# enforce_trust_replay — replay result conversion + modes
# ---------------------------------------------------------------------------


class TestEnforceTrustReplay:
    def test_perfect_chain_allows(self):
        d = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=_replay_result(score=100, chain_valid=True),
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True
        assert d.trust_score == 100

    def test_broken_chain_warns_in_warn_mode(self):
        d = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=_replay_result(score=0, chain_valid=False),
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "chain_failure" in d.violations

    def test_broken_chain_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_trust_replay(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_result=_replay_result(score=0, chain_valid=False),
                mode=ProvenanceMode.STRICT,
            )
        assert "chain_failure" in exc.value.decision.violations

    def test_sig_failure_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_trust_replay(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_result=_replay_result(
                    score=0,
                    chain_valid=False,
                    failed_nodes=[
                        {"node_id": "n1", "signature_status": "invalid_signature"}
                    ],
                ),
                mode=ProvenanceMode.STRICT,
            )
        assert "authority_failure" in exc.value.decision.violations

    def test_invalid_links_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_trust_replay(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_result=_replay_result(
                    invalid_links=[{"link_id": "l1"}], link_status="invalid"
                ),
                mode=ProvenanceMode.STRICT,
            )
        assert "report_link_failure" in exc.value.decision.violations

    def test_legacy_unsigned_score_50(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "true")
        d = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=_replay_result(score=50, chain_valid=True),
            mode=ProvenanceMode.STRICT,
        )
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations

    def test_off_mode_allows_all(self):
        d = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=_replay_result(score=0, chain_valid=False),
            mode=ProvenanceMode.OFF,
        )
        assert d.allowed is True


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_allowed_counter_increments(self):
        before = _counter_value(
            ENFORCEMENT_ALLOWED_TOTAL, operation="evidence_creation"
        )
        enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.WARN,
        )
        after = _counter_value(ENFORCEMENT_ALLOWED_TOTAL, operation="evidence_creation")
        assert after > before

    def test_warned_counter_increments(self):
        before = _counter_value(ENFORCEMENT_WARNED_TOTAL, operation="evidence_review")
        enforce_evidence_review(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.WARN,
        )
        after = _counter_value(ENFORCEMENT_WARNED_TOTAL, operation="evidence_review")
        assert after > before

    def test_blocked_counter_increments(self):
        before = _counter_value(
            ENFORCEMENT_BLOCKED_TOTAL, operation="evidence_creation"
        )
        with pytest.raises(TrustEnforcementError):
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        after = _counter_value(ENFORCEMENT_BLOCKED_TOTAL, operation="evidence_creation")
        assert after > before

    def test_operations_counter_increments_every_call(self):
        before = _counter_value(
            ENFORCEMENT_OPERATIONS_TOTAL,
            operation="report_export",
            mode="warn",
            decision="allow",
        )
        enforce_report_export(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.WARN,
        )
        after = _counter_value(
            ENFORCEMENT_OPERATIONS_TOTAL,
            operation="report_export",
            mode="warn",
            decision="allow",
        )
        assert after > before

    def test_finalization_metrics_emitted(self):
        before = _counter_value(
            ENFORCEMENT_ALLOWED_TOTAL, operation="report_finalization"
        )
        enforce_report_finalization(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=True,
            mode=ProvenanceMode.WARN,
        )
        after = _counter_value(
            ENFORCEMENT_ALLOWED_TOTAL, operation="report_finalization"
        )
        assert after > before

    def test_replay_metrics_emitted(self):
        before = _counter_value(ENFORCEMENT_ALLOWED_TOTAL, operation="trust_replay")
        enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=_replay_result(score=100, chain_valid=True),
            mode=ProvenanceMode.WARN,
        )
        after = _counter_value(ENFORCEMENT_ALLOWED_TOTAL, operation="trust_replay")
        assert after > before

    def test_approval_blocked_counter(self):
        before = _counter_value(
            ENFORCEMENT_BLOCKED_TOTAL, operation="evidence_approval"
        )
        with pytest.raises(TrustEnforcementError):
            enforce_evidence_approval(
                None,
                tenant_id=_T,
                engagement_id=_E,
                chain_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        after = _counter_value(ENFORCEMENT_BLOCKED_TOTAL, operation="evidence_approval")
        assert after > before


# ---------------------------------------------------------------------------
# Security isolation
# ---------------------------------------------------------------------------


class TestSecurityIsolation:
    def test_cross_tenant_denial_strict_creation(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id="tenant-a",
                engagement_id="eng-a",
                tenant_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "tenant_mismatch" in exc.value.decision.violations
        assert exc.value.decision.trust_score == 0

    def test_cross_engagement_denial_strict_creation(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id="tenant-a",
                engagement_id="eng-a",
                engagement_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "engagement_mismatch" in exc.value.decision.violations

    def test_cross_tenant_warn_in_warn_mode(self):
        d = enforce_evidence_creation(
            None,
            tenant_id="tenant-a",
            engagement_id="eng-a",
            tenant_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "tenant_mismatch" in d.violations
        assert d.trust_score == 0

    def test_signature_tampering_blocks_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_review(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "authority_failure" in exc.value.decision.violations

    def test_replay_corruption_blocks_strict(self):
        with pytest.raises(TrustEnforcementError):
            enforce_trust_replay(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_result=_replay_result(chain_valid=False, score=0),
                mode=ProvenanceMode.STRICT,
            )

    def test_link_tampering_blocks_export_strict(self):
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                link_valid=False,
                mode=ProvenanceMode.STRICT,
            )
        assert "report_link_failure" in exc.value.decision.violations

    def test_legacy_bypass_denied_by_default_strict(self, monkeypatch):
        monkeypatch.delenv("FG_ALLOW_LEGACY_UNSIGNED", raising=False)
        with pytest.raises(TrustEnforcementError) as exc:
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            )
        assert "legacy_unsigned" in exc.value.decision.violations

    def test_mode_escalation_off_to_strict(self):
        d_off = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.OFF,
        )
        assert d_off.allowed is True

        with pytest.raises(TrustEnforcementError):
            enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=False,
                mode=ProvenanceMode.STRICT,
            )

    def test_authority_failure_severity_high(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.severity == "high"

    def test_chain_failure_severity_critical(self):
        d = enforce_evidence_approval(
            None,
            tenant_id=_T,
            engagement_id=_E,
            chain_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.severity == "critical"

    def test_tenant_mismatch_severity_critical(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            tenant_valid=False,
            mode=ProvenanceMode.WARN,
        )
        assert d.severity == "critical"


# ---------------------------------------------------------------------------
# Legacy record compatibility
# ---------------------------------------------------------------------------


class TestLegacyRecords:
    def test_off_mode_allows_legacy(self):
        for fn in [
            lambda: enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.OFF,
            ),
            lambda: enforce_evidence_review(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.OFF,
            ),
            lambda: enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.OFF,
            ),
        ]:
            d = fn()
            assert d.allowed is True

    def test_warn_mode_warns_on_legacy(self):
        d = enforce_evidence_creation(
            None,
            tenant_id=_T,
            engagement_id=_E,
            signature_valid=None,
            is_legacy=True,
            mode=ProvenanceMode.WARN,
        )
        assert d.allowed is True
        assert "legacy_unsigned" in d.violations
        assert d.trust_score == 75

    def test_strict_mode_permits_legacy_when_flagged(self, monkeypatch):
        monkeypatch.setenv("FG_ALLOW_LEGACY_UNSIGNED", "true")
        for fn in [
            lambda: enforce_evidence_creation(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            ),
            lambda: enforce_report_finalization(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            ),
        ]:
            d = fn()
            assert d.allowed is True
            assert d.decision == "warn"

    def test_strict_mode_blocks_legacy_without_flag(self, monkeypatch):
        monkeypatch.delenv("FG_ALLOW_LEGACY_UNSIGNED", raising=False)
        with pytest.raises(TrustEnforcementError):
            enforce_report_export(
                None,
                tenant_id=_T,
                engagement_id=_E,
                signature_valid=None,
                is_legacy=True,
                mode=ProvenanceMode.STRICT,
            )


# ---------------------------------------------------------------------------
# Mode escalation across all operations
# ---------------------------------------------------------------------------


class TestModeEscalation:
    @pytest.mark.parametrize(
        "fn_name,kwargs",
        [
            ("enforce_evidence_creation", {"signature_valid": False}),
            ("enforce_evidence_review", {"signature_valid": False}),
            ("enforce_evidence_approval", {"chain_valid": False}),
            ("enforce_report_finalization", {"chain_valid": False}),
            ("enforce_report_export", {"signature_valid": False}),
        ],
    )
    def test_off_warn_allow_strict_block(self, fn_name, kwargs):
        fn_map = {
            "enforce_evidence_creation": enforce_evidence_creation,
            "enforce_evidence_review": enforce_evidence_review,
            "enforce_evidence_approval": enforce_evidence_approval,
            "enforce_report_finalization": enforce_report_finalization,
            "enforce_report_export": enforce_report_export,
        }
        fn = fn_map[fn_name]

        d_off = fn(
            None, tenant_id=_T, engagement_id=_E, mode=ProvenanceMode.OFF, **kwargs
        )
        assert d_off.allowed is True

        d_warn = fn(
            None, tenant_id=_T, engagement_id=_E, mode=ProvenanceMode.WARN, **kwargs
        )
        assert d_warn.allowed is True

        with pytest.raises(TrustEnforcementError):
            fn(
                None,
                tenant_id=_T,
                engagement_id=_E,
                mode=ProvenanceMode.STRICT,
                **kwargs,
            )

    def test_replay_escalates(self):
        broken = _replay_result(score=0, chain_valid=False)

        d_off = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=broken,
            mode=ProvenanceMode.OFF,
        )
        assert d_off.allowed is True

        d_warn = enforce_trust_replay(
            None,
            tenant_id=_T,
            engagement_id=_E,
            replay_result=broken,
            mode=ProvenanceMode.WARN,
        )
        assert d_warn.allowed is True

        with pytest.raises(TrustEnforcementError):
            enforce_trust_replay(
                None,
                tenant_id=_T,
                engagement_id=_E,
                replay_result=broken,
                mode=ProvenanceMode.STRICT,
            )
