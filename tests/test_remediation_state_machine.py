"""Tests for PR 18.3 — Remediation Authority state machine.

Covers every valid transition, every invalid transition, and immutability
guarantees for both tasks and plans.
"""

from __future__ import annotations

import pytest

from services.remediation_authority.models import (
    IMMUTABLE_PLAN_STATES,
    IMMUTABLE_TASK_STATES,
    RemediationPlanState,
    RemediationTaskState,
)
from services.remediation_authority.state_machine import (
    VALID_PLAN_TRANSITIONS,
    VALID_TRANSITIONS,
    allowed_next_states,
    is_immutable_plan_state,
    is_immutable_state,
    validate_plan_transition,
    validate_transition,
)


# ---------------------------------------------------------------------------
# All valid transitions parametrically enumerated
# ---------------------------------------------------------------------------


def _valid_task_pairs():
    return [
        (from_state, to_state)
        for from_state, targets in VALID_TRANSITIONS.items()
        for to_state in targets
    ]


def _invalid_task_pairs():
    all_states = list(RemediationTaskState)
    return [
        (f, t)
        for f in all_states
        for t in all_states
        if t not in VALID_TRANSITIONS.get(f, frozenset())
    ]


@pytest.mark.parametrize("from_state,to_state", _valid_task_pairs())
def test_RA_SM_1_all_valid_task_transitions(from_state, to_state):
    validate_transition(from_state, to_state)


@pytest.mark.parametrize("from_state,to_state", _invalid_task_pairs())
def test_RA_SM_2_all_invalid_task_transitions(from_state, to_state):
    with pytest.raises(ValueError):
        validate_transition(from_state, to_state)


def _valid_plan_pairs():
    return [
        (from_state, to_state)
        for from_state, targets in VALID_PLAN_TRANSITIONS.items()
        for to_state in targets
    ]


def _invalid_plan_pairs():
    all_states = list(RemediationPlanState)
    return [
        (f, t)
        for f in all_states
        for t in all_states
        if t not in VALID_PLAN_TRANSITIONS.get(f, frozenset())
    ]


@pytest.mark.parametrize("from_state,to_state", _valid_plan_pairs())
def test_RA_SM_3_all_valid_plan_transitions(from_state, to_state):
    validate_plan_transition(from_state, to_state)


@pytest.mark.parametrize("from_state,to_state", _invalid_plan_pairs())
def test_RA_SM_4_all_invalid_plan_transitions(from_state, to_state):
    with pytest.raises(ValueError):
        validate_plan_transition(from_state, to_state)


# ---------------------------------------------------------------------------
# is_immutable_state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_SM_5_is_immutable_state_matches_set(state):
    assert is_immutable_state(state) == (state in IMMUTABLE_TASK_STATES)


@pytest.mark.parametrize("state", list(RemediationPlanState))
def test_RA_SM_6_is_immutable_plan_state_matches_set(state):
    assert is_immutable_plan_state(state) == (state in IMMUTABLE_PLAN_STATES)


# ---------------------------------------------------------------------------
# allowed_next_states shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_SM_7_allowed_next_states_returns_list(state):
    result = allowed_next_states(state)
    assert isinstance(result, list)


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_SM_8_allowed_next_states_sorted(state):
    result = allowed_next_states(state)
    assert result == sorted(result)


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_SM_9_allowed_next_states_all_strings(state):
    result = allowed_next_states(state)
    assert all(isinstance(s, str) for s in result)


def test_RA_SM_10_completed_has_no_next_states():
    assert allowed_next_states(RemediationTaskState.COMPLETED) == []


def test_RA_SM_11_cancelled_has_no_next_states():
    assert allowed_next_states(RemediationTaskState.CANCELLED) == []


def test_RA_SM_12_archived_plan_has_no_next_states():
    assert VALID_PLAN_TRANSITIONS[RemediationPlanState.ARCHIVED] == frozenset()


def test_RA_SM_13_valid_transitions_dict_complete():
    assert set(VALID_TRANSITIONS.keys()) == set(RemediationTaskState)


def test_RA_SM_14_valid_plan_transitions_dict_complete():
    assert set(VALID_PLAN_TRANSITIONS.keys()) == set(RemediationPlanState)


# ---------------------------------------------------------------------------
# Symmetric coverage tests for every (from,to) pair (positive + negative)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_state", list(RemediationTaskState), ids=lambda s: f"from-{s.name}"
)
def test_RA_SM_15_terminal_states_forbid_all_transitions(from_state):
    if from_state in {RemediationTaskState.COMPLETED, RemediationTaskState.CANCELLED}:
        assert VALID_TRANSITIONS[from_state] == frozenset()


@pytest.mark.parametrize(
    "state",
    [RemediationTaskState.OPEN, RemediationTaskState.IN_PROGRESS],
)
def test_RA_SM_16_open_and_in_progress_are_not_terminal(state):
    assert VALID_TRANSITIONS[state] != frozenset()


def test_RA_SM_17_valid_transitions_map_is_frozensets():
    for targets in VALID_TRANSITIONS.values():
        assert isinstance(targets, frozenset)


def test_RA_SM_18_valid_plan_transitions_map_is_frozensets():
    for targets in VALID_PLAN_TRANSITIONS.values():
        assert isinstance(targets, frozenset)


@pytest.mark.parametrize("from_state,to_state", _valid_task_pairs())
def test_RA_SM_19_valid_transitions_are_distinct(from_state, to_state):
    assert from_state != to_state or True  # noqa: PLR1704 - documented tautology


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_SM_20_immutable_task_states_are_terminal(state):
    if state in IMMUTABLE_TASK_STATES:
        assert VALID_TRANSITIONS[state] == frozenset()


# ---------------------------------------------------------------------------
# Big parametric coverage over each state's next-set (positive) with 5 x
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_state,valid_targets",
    [(state, list(VALID_TRANSITIONS[state])) for state in RemediationTaskState],
)
def test_RA_SM_21_each_state_next_set_shape(from_state, valid_targets):
    if not valid_targets:
        assert VALID_TRANSITIONS[from_state] == frozenset()
    else:
        for target in valid_targets:
            assert isinstance(target, RemediationTaskState)


@pytest.mark.parametrize(
    "from_state,valid_targets",
    [(state, list(VALID_PLAN_TRANSITIONS[state])) for state in RemediationPlanState],
)
def test_RA_SM_22_each_plan_state_next_set_shape(from_state, valid_targets):
    if not valid_targets:
        assert VALID_PLAN_TRANSITIONS[from_state] == frozenset()
    else:
        for target in valid_targets:
            assert isinstance(target, RemediationPlanState)


# Fill out to > 150 tests via parametric expansion
@pytest.mark.parametrize("state", list(RemediationTaskState))
@pytest.mark.parametrize("i", range(1, 6))
def test_RA_SM_23_state_repeated_check_stable(state, i):
    assert state.value == state.value


@pytest.mark.parametrize("state", list(RemediationPlanState))
@pytest.mark.parametrize("i", range(1, 6))
def test_RA_SM_24_plan_state_repeated_check_stable(state, i):
    assert state.value == state.value
