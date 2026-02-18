from __future__ import annotations

import logging
import threading
import time
from collections import deque

from services.self_heal.restart_policy import restart_threshold, self_heal_enabled

log = logging.getLogger("frostgate.self_heal")


class SelfHealWatchdog:
    def __init__(self, *, sleep_seconds: float = 1.0, window_seconds: int = 600, max_attempts: int = 3) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ticks = 0
        self._sleep_seconds = max(0.01, float(sleep_seconds))
        self._window_seconds = max(1, int(window_seconds))
        self._max_attempts = max(1, int(max_attempts))
        self._attempt_times: deque[float] = deque()
        self._next_allowed_at = 0.0

    def start(self) -> None:
        if not self_heal_enabled() or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _can_emit_action(self, now: float) -> bool:
        while self._attempt_times and now - self._attempt_times[0] > self._window_seconds:
            self._attempt_times.popleft()
        if now < self._next_allowed_at:
            return False
        if len(self._attempt_times) >= self._max_attempts:
            return False
        return True

    def _record_action(self, now: float) -> None:
        self._attempt_times.append(now)
        attempt = len(self._attempt_times)
        backoff = min(60, 2 ** max(0, attempt - 1))
        self._next_allowed_at = now + backoff
        log.info(
            "self_heal_action event=self_heal action=tick attempt=%s backoff_seconds=%s window_seconds=%s",
            attempt,
            backoff,
            self._window_seconds,
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            self._ticks += 1
            now = time.monotonic()
            if self._ticks % max(1, restart_threshold()) == 0 and self._can_emit_action(now):
                self._record_action(now)
            time.sleep(self._sleep_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
