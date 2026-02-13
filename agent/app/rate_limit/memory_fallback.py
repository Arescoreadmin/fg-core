from __future__ import annotations

import time


class MemoryLimiter:
    def __init__(self):
        self._buckets: dict[str, tuple[int, float]] = {}

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        count, reset = self._buckets.get(key, (0, now + window_seconds))
        if now >= reset:
            count, reset = 0, now + window_seconds
        if count >= limit:
            return False
        self._buckets[key] = (count + 1, reset)
        return True
