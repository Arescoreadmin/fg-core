from __future__ import annotations

from datetime import UTC, datetime, timedelta

from services.agent_log_integrity import AnchorCadencePolicy, AnchorCadenceState


def test_anchor_cadence_by_event_count():
    policy = AnchorCadencePolicy(every_n_events=2, every_minutes=10, max_unanchored_events=5)
    state = AnchorCadenceState()
    state.mark_event()
    assert not state.should_anchor(policy)
    state.mark_event()
    assert state.should_anchor(policy)


def test_anchor_cadence_by_time_window():
    policy = AnchorCadencePolicy(every_n_events=50, every_minutes=1, max_unanchored_events=500)
    state = AnchorCadenceState(last_anchor_at=datetime.now(UTC) - timedelta(minutes=2), queued_events=1)
    assert state.should_anchor(policy)


def test_anchor_cadence_max_unanchored_window():
    policy = AnchorCadencePolicy(every_n_events=50, every_minutes=10, max_unanchored_events=3)
    state = AnchorCadenceState(queued_events=3)
    assert state.should_anchor(policy)
