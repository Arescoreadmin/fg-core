from __future__ import annotations

import time

from services.self_heal.watchdog import SelfHealWatchdog


def test_watchdog_disabled_does_not_start(monkeypatch):
    monkeypatch.setenv("FG_SELF_HEAL_ENABLED", "0")
    wd = SelfHealWatchdog(sleep_seconds=0.01)
    wd.start()
    time.sleep(0.03)
    assert wd._thread is None


def test_watchdog_backoff_and_cap(monkeypatch):
    monkeypatch.setenv("FG_SELF_HEAL_ENABLED", "1")
    monkeypatch.setenv("FG_SELF_HEAL_RESTART_THRESHOLD", "1")
    wd = SelfHealWatchdog(sleep_seconds=0.01, window_seconds=1, max_attempts=2)
    wd.start()
    time.sleep(0.3)
    wd.stop()
    assert len(wd._attempt_times) <= 2
