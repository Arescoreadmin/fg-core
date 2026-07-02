"""Tests for services/governance_intelligence/policy_lifecycle.py

GIPL-1 to GIPL-250 — tests for VALID_TRANSITIONS, validate_transition,
and is_mutable covering all states and transitions.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.policy_lifecycle import (
    VALID_TRANSITIONS,
    is_mutable,
    validate_transition,
)
from services.governance_intelligence.models import PolicyLifecycleState, MUTABLE_POLICY_STATES
from services.governance_intelligence.schemas import GovernanceIntelligencePolicyError


# ---------------------------------------------------------------------------
# GIPL-1 — GIPL-30: VALID_TRANSITIONS structure
# ---------------------------------------------------------------------------


class TestValidTransitionsStructure:
    """GIPL-1 to GIPL-30: validate VALID_TRANSITIONS dict structure."""

    def test_gipl_1_is_dict(self):
        """GIPL-1: VALID_TRANSITIONS is a dict."""
        assert isinstance(VALID_TRANSITIONS, dict)

    def test_gipl_2_has_all_lifecycle_states(self):
        """GIPL-2: VALID_TRANSITIONS has entries for all PolicyLifecycleState values."""
        for state in PolicyLifecycleState:
            assert state.value in VALID_TRANSITIONS

    def test_gipl_3_values_are_frozensets(self):
        """GIPL-3: each value in VALID_TRANSITIONS is a frozenset."""
        for allowed in VALID_TRANSITIONS.values():
            assert isinstance(allowed, frozenset)

    def test_gipl_4_draft_can_go_to_review(self):
        """GIPL-4: DRAFT → REVIEW is valid."""
        assert PolicyLifecycleState.REVIEW.value in VALID_TRANSITIONS[PolicyLifecycleState.DRAFT.value]

    def test_gipl_5_draft_can_go_to_archived(self):
        """GIPL-5: DRAFT → ARCHIVED is valid."""
        assert PolicyLifecycleState.ARCHIVED.value in VALID_TRANSITIONS[PolicyLifecycleState.DRAFT.value]

    def test_gipl_6_draft_cannot_go_to_active(self):
        """GIPL-6: DRAFT → ACTIVE is invalid."""
        assert PolicyLifecycleState.ACTIVE.value not in VALID_TRANSITIONS[PolicyLifecycleState.DRAFT.value]

    def test_gipl_7_review_can_go_to_approved(self):
        """GIPL-7: REVIEW → APPROVED is valid."""
        assert PolicyLifecycleState.APPROVED.value in VALID_TRANSITIONS[PolicyLifecycleState.REVIEW.value]

    def test_gipl_8_review_can_go_to_draft(self):
        """GIPL-8: REVIEW → DRAFT is valid (rollback)."""
        assert PolicyLifecycleState.DRAFT.value in VALID_TRANSITIONS[PolicyLifecycleState.REVIEW.value]

    def test_gipl_9_review_can_go_to_archived(self):
        """GIPL-9: REVIEW → ARCHIVED is valid."""
        assert PolicyLifecycleState.ARCHIVED.value in VALID_TRANSITIONS[PolicyLifecycleState.REVIEW.value]

    def test_gipl_10_approved_can_go_to_active(self):
        """GIPL-10: APPROVED → ACTIVE is valid."""
        assert PolicyLifecycleState.ACTIVE.value in VALID_TRANSITIONS[PolicyLifecycleState.APPROVED.value]

    def test_gipl_11_approved_can_go_to_archived(self):
        """GIPL-11: APPROVED → ARCHIVED is valid."""
        assert PolicyLifecycleState.ARCHIVED.value in VALID_TRANSITIONS[PolicyLifecycleState.APPROVED.value]

    def test_gipl_12_active_can_go_to_deprecated(self):
        """GIPL-12: ACTIVE → DEPRECATED is valid."""
        assert PolicyLifecycleState.DEPRECATED.value in VALID_TRANSITIONS[PolicyLifecycleState.ACTIVE.value]

    def test_gipl_13_active_can_go_to_superseded(self):
        """GIPL-13: ACTIVE → SUPERSEDED is valid."""
        assert PolicyLifecycleState.SUPERSEDED.value in VALID_TRANSITIONS[PolicyLifecycleState.ACTIVE.value]

    def test_gipl_14_active_cannot_go_to_draft(self):
        """GIPL-14: ACTIVE → DRAFT is invalid."""
        assert PolicyLifecycleState.DRAFT.value not in VALID_TRANSITIONS[PolicyLifecycleState.ACTIVE.value]

    def test_gipl_15_deprecated_can_go_to_archived(self):
        """GIPL-15: DEPRECATED → ARCHIVED is valid."""
        assert PolicyLifecycleState.ARCHIVED.value in VALID_TRANSITIONS[PolicyLifecycleState.DEPRECATED.value]

    def test_gipl_16_deprecated_cannot_go_to_active(self):
        """GIPL-16: DEPRECATED → ACTIVE is invalid."""
        assert PolicyLifecycleState.ACTIVE.value not in VALID_TRANSITIONS[PolicyLifecycleState.DEPRECATED.value]

    def test_gipl_17_superseded_can_go_to_archived(self):
        """GIPL-17: SUPERSEDED → ARCHIVED is valid."""
        assert PolicyLifecycleState.ARCHIVED.value in VALID_TRANSITIONS[PolicyLifecycleState.SUPERSEDED.value]

    def test_gipl_18_archived_is_terminal_empty_frozenset(self):
        """GIPL-18: ARCHIVED → (none) — empty frozenset."""
        assert VALID_TRANSITIONS[PolicyLifecycleState.ARCHIVED.value] == frozenset()

    def test_gipl_19_review_cannot_go_to_active(self):
        """GIPL-19: REVIEW → ACTIVE is invalid (must go through APPROVED)."""
        assert PolicyLifecycleState.ACTIVE.value not in VALID_TRANSITIONS[PolicyLifecycleState.REVIEW.value]

    def test_gipl_20_approved_cannot_go_to_deprecated(self):
        """GIPL-20: APPROVED → DEPRECATED is invalid."""
        assert PolicyLifecycleState.DEPRECATED.value not in VALID_TRANSITIONS[PolicyLifecycleState.APPROVED.value]


# ---------------------------------------------------------------------------
# GIPL-31 — GIPL-130: validate_transition
# ---------------------------------------------------------------------------


class TestValidateTransition:
    """GIPL-31 to GIPL-130: validate_transition function tests."""

    # Valid transitions (should not raise)
    @pytest.mark.parametrize(
        "current,target",
        [
            ("DRAFT", "REVIEW"),
            ("DRAFT", "ARCHIVED"),
            ("REVIEW", "APPROVED"),
            ("REVIEW", "DRAFT"),
            ("REVIEW", "ARCHIVED"),
            ("APPROVED", "ACTIVE"),
            ("APPROVED", "ARCHIVED"),
            ("ACTIVE", "DEPRECATED"),
            ("ACTIVE", "SUPERSEDED"),
            ("DEPRECATED", "ARCHIVED"),
            ("SUPERSEDED", "ARCHIVED"),
        ],
    )
    def test_gipl_31_valid_transitions_no_raise(self, current, target):
        """GIPL-31: valid transitions do not raise."""
        validate_transition(current, target)  # no exception

    # Invalid transitions (should raise)
    @pytest.mark.parametrize(
        "current,target",
        [
            ("DRAFT", "ACTIVE"),
            ("DRAFT", "APPROVED"),
            ("DRAFT", "DEPRECATED"),
            ("DRAFT", "SUPERSEDED"),
            ("REVIEW", "ACTIVE"),
            ("REVIEW", "SUPERSEDED"),
            ("REVIEW", "DEPRECATED"),
            ("APPROVED", "DRAFT"),
            ("APPROVED", "REVIEW"),
            ("APPROVED", "DEPRECATED"),
            ("APPROVED", "SUPERSEDED"),
            ("ACTIVE", "DRAFT"),
            ("ACTIVE", "REVIEW"),
            ("ACTIVE", "APPROVED"),
            ("ACTIVE", "ARCHIVED"),
            ("DEPRECATED", "DRAFT"),
            ("DEPRECATED", "ACTIVE"),
            ("DEPRECATED", "SUPERSEDED"),
            ("SUPERSEDED", "DRAFT"),
            ("SUPERSEDED", "ACTIVE"),
            ("SUPERSEDED", "DEPRECATED"),
            ("ARCHIVED", "DRAFT"),
            ("ARCHIVED", "REVIEW"),
            ("ARCHIVED", "APPROVED"),
            ("ARCHIVED", "ACTIVE"),
            ("ARCHIVED", "DEPRECATED"),
            ("ARCHIVED", "SUPERSEDED"),
            ("ARCHIVED", "ARCHIVED"),
        ],
    )
    def test_gipl_51_invalid_transitions_raise(self, current, target):
        """GIPL-51: invalid transitions raise GovernanceIntelligencePolicyError."""
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition(current, target)

    def test_gipl_71_unknown_current_state_raises(self):
        """GIPL-71: unknown current state raises GovernanceIntelligencePolicyError."""
        with pytest.raises(GovernanceIntelligencePolicyError, match="Unknown policy lifecycle state"):
            validate_transition("UNKNOWN_STATE", "REVIEW")

    def test_gipl_72_empty_current_state_raises(self):
        """GIPL-72: empty string current state raises."""
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition("", "REVIEW")

    def test_gipl_73_lowercase_current_state_raises(self):
        """GIPL-73: lowercase 'draft' raises (case sensitive)."""
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition("draft", "REVIEW")

    def test_gipl_74_terminal_archived_raises_with_terminal_message(self):
        """GIPL-74: ARCHIVED → anything raises with 'terminal state' in message."""
        with pytest.raises(GovernanceIntelligencePolicyError, match="terminal"):
            validate_transition("ARCHIVED", "REVIEW")

    def test_gipl_75_error_mentions_allowed_transitions(self):
        """GIPL-75: error for invalid transition mentions allowed transitions."""
        with pytest.raises(GovernanceIntelligencePolicyError, match="Allowed"):
            validate_transition("DRAFT", "ACTIVE")

    def test_gipl_76_error_mentions_target_state(self):
        """GIPL-76: error for invalid transition mentions the target state."""
        with pytest.raises(GovernanceIntelligencePolicyError, match="ACTIVE"):
            validate_transition("DRAFT", "ACTIVE")

    def test_gipl_77_error_mentions_current_state(self):
        """GIPL-77: error for invalid transition mentions the current state."""
        with pytest.raises(GovernanceIntelligencePolicyError, match="DRAFT"):
            validate_transition("DRAFT", "ACTIVE")

    def test_gipl_78_same_state_transition_raises(self):
        """GIPL-78: transitioning to same state raises (self-loops not allowed)."""
        # Most states can't self-loop
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition("DRAFT", "DRAFT")

    def test_gipl_79_exception_is_policy_error(self):
        """GIPL-79: exception is GovernanceIntelligencePolicyError."""
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition("ARCHIVED", "DRAFT")


# ---------------------------------------------------------------------------
# GIPL-131 — GIPL-200: is_mutable
# ---------------------------------------------------------------------------


class TestIsMutable:
    """GIPL-131 to GIPL-200: is_mutable function tests."""

    def test_gipl_131_returns_bool(self):
        """GIPL-131: result is a bool."""
        result = is_mutable("DRAFT")
        assert isinstance(result, bool)

    def test_gipl_132_draft_is_mutable(self):
        """GIPL-132: DRAFT is mutable."""
        assert is_mutable("DRAFT") is True

    def test_gipl_133_review_is_mutable(self):
        """GIPL-133: REVIEW is mutable."""
        assert is_mutable("REVIEW") is True

    def test_gipl_134_approved_is_not_mutable(self):
        """GIPL-134: APPROVED is not mutable."""
        assert is_mutable("APPROVED") is False

    def test_gipl_135_active_is_not_mutable(self):
        """GIPL-135: ACTIVE is not mutable."""
        assert is_mutable("ACTIVE") is False

    def test_gipl_136_deprecated_is_not_mutable(self):
        """GIPL-136: DEPRECATED is not mutable."""
        assert is_mutable("DEPRECATED") is False

    def test_gipl_137_superseded_is_not_mutable(self):
        """GIPL-137: SUPERSEDED is not mutable."""
        assert is_mutable("SUPERSEDED") is False

    def test_gipl_138_archived_is_not_mutable(self):
        """GIPL-138: ARCHIVED is not mutable."""
        assert is_mutable("ARCHIVED") is False

    def test_gipl_139_unknown_state_not_mutable(self):
        """GIPL-139: unknown state returns False (not mutable)."""
        assert is_mutable("UNKNOWN_STATE") is False

    def test_gipl_140_empty_string_not_mutable(self):
        """GIPL-140: empty string returns False."""
        assert is_mutable("") is False

    def test_gipl_141_lowercase_draft_not_mutable(self):
        """GIPL-141: lowercase 'draft' returns False (case sensitive)."""
        assert is_mutable("draft") is False

    def test_gipl_142_mutable_policy_states_frozenset(self):
        """GIPL-142: MUTABLE_POLICY_STATES contains exactly DRAFT and REVIEW."""
        from services.governance_intelligence.models import PolicyLifecycleState
        assert PolicyLifecycleState.DRAFT in MUTABLE_POLICY_STATES
        assert PolicyLifecycleState.REVIEW in MUTABLE_POLICY_STATES
        # Non-mutable states must not be in there
        for state in [
            PolicyLifecycleState.APPROVED,
            PolicyLifecycleState.ACTIVE,
            PolicyLifecycleState.DEPRECATED,
            PolicyLifecycleState.SUPERSEDED,
            PolicyLifecycleState.ARCHIVED,
        ]:
            assert state not in MUTABLE_POLICY_STATES

    @pytest.mark.parametrize("state", ["DRAFT", "REVIEW"])
    def test_gipl_143_mutable_states_are_true(self, state):
        """GIPL-143: mutable states return True."""
        assert is_mutable(state) is True

    @pytest.mark.parametrize(
        "state", ["APPROVED", "ACTIVE", "DEPRECATED", "SUPERSEDED", "ARCHIVED"]
    )
    def test_gipl_144_immutable_states_are_false(self, state):
        """GIPL-144: immutable states return False."""
        assert is_mutable(state) is False


# ---------------------------------------------------------------------------
# GIPL-201 — GIPL-250: Integration-level lifecycle flow tests
# ---------------------------------------------------------------------------


class TestPolicyLifecycleFlow:
    """GIPL-201 to GIPL-250: full lifecycle flow tests."""

    def test_gipl_201_full_happy_path_draft_to_archived(self):
        """GIPL-201: full happy path DRAFT→REVIEW→APPROVED→ACTIVE→DEPRECATED→ARCHIVED."""
        path = [
            ("DRAFT", "REVIEW"),
            ("REVIEW", "APPROVED"),
            ("APPROVED", "ACTIVE"),
            ("ACTIVE", "DEPRECATED"),
            ("DEPRECATED", "ARCHIVED"),
        ]
        for current, target in path:
            validate_transition(current, target)  # no exception

    def test_gipl_202_superseded_path(self):
        """GIPL-202: DRAFT→REVIEW→APPROVED→ACTIVE→SUPERSEDED→ARCHIVED."""
        path = [
            ("DRAFT", "REVIEW"),
            ("REVIEW", "APPROVED"),
            ("APPROVED", "ACTIVE"),
            ("ACTIVE", "SUPERSEDED"),
            ("SUPERSEDED", "ARCHIVED"),
        ]
        for current, target in path:
            validate_transition(current, target)

    def test_gipl_203_rollback_review_to_draft(self):
        """GIPL-203: can roll back from REVIEW to DRAFT."""
        validate_transition("REVIEW", "DRAFT")

    def test_gipl_204_draft_directly_to_archived(self):
        """GIPL-204: can archive directly from DRAFT."""
        validate_transition("DRAFT", "ARCHIVED")

    def test_gipl_205_review_directly_to_archived(self):
        """GIPL-205: can archive directly from REVIEW."""
        validate_transition("REVIEW", "ARCHIVED")

    def test_gipl_206_approved_directly_to_archived(self):
        """GIPL-206: can archive from APPROVED without activating."""
        validate_transition("APPROVED", "ARCHIVED")

    def test_gipl_207_mutable_before_approved(self):
        """GIPL-207: is_mutable returns True for DRAFT and REVIEW, False after."""
        assert is_mutable("DRAFT") is True
        assert is_mutable("REVIEW") is True
        assert is_mutable("APPROVED") is False
        assert is_mutable("ACTIVE") is False

    def test_gipl_208_cannot_resurrect_archived(self):
        """GIPL-208: cannot transition out of ARCHIVED to any state."""
        for state in PolicyLifecycleState:
            with pytest.raises(GovernanceIntelligencePolicyError):
                validate_transition("ARCHIVED", state.value)

    def test_gipl_209_active_cannot_skip_to_archived(self):
        """GIPL-209: ACTIVE cannot go directly to ARCHIVED (must deprecate/supersede first)."""
        with pytest.raises(GovernanceIntelligencePolicyError):
            validate_transition("ACTIVE", "ARCHIVED")
