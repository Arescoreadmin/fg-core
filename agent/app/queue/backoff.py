from __future__ import annotations

import random


def backoff_delay(attempt: int, base: float = 1.0, cap: float = 300.0) -> float:
    exp = min(cap, base * (2 ** max(0, attempt)))
    jitter = random.uniform(0, exp * 0.25)
    return exp + jitter
