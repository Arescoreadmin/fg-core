from __future__ import annotations

import time

from services.self_heal.watchdog import SelfHealWatchdog


def test_watchdog_noop_when_disabled(monkeypatch) -> None:
    monkeypatch.setenv("FG_SELF_HEAL_ENABLED", "0")
    wd = SelfHealWatchdog()
    wd.start()
    wd.stop()


def test_watchdog_runs_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("FG_SELF_HEAL_ENABLED", "1")
    monkeypatch.setenv("FG_SELF_HEAL_RESTART_THRESHOLD", "1")
    wd = SelfHealWatchdog()
    wd.start()
    time.sleep(0.05)
    wd.stop()
