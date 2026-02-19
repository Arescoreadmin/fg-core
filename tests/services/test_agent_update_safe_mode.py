from __future__ import annotations

from services.agent_update.safe_mode import UpdateSafeMode


def test_safe_mode_blocks_after_repeated_failures_same_manifest():
    sm = UpdateSafeMode(failure_threshold=2)
    assert sm.can_attempt("2.0.0")
    sm.record_failure("2.0.0")
    assert sm.can_attempt("2.0.0")
    sm.record_failure("2.0.0")
    assert not sm.can_attempt("2.0.0")


def test_safe_mode_unblocks_on_new_manifest_version():
    sm = UpdateSafeMode(failure_threshold=2)
    sm.record_failure("2.0.0")
    sm.record_failure("2.0.0")
    assert not sm.can_attempt("2.0.0")
    assert sm.can_attempt("2.0.1")


def test_safe_mode_reset_on_success():
    sm = UpdateSafeMode(failure_threshold=2)
    sm.record_failure("2.0.0")
    sm.record_success("2.0.0")
    assert sm.can_attempt("2.0.0")
    assert sm.consecutive_failures == 0
