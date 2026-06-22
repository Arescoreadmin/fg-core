# services/remediation_portal/rate_limit.py
"""Portal rate-limiter abstraction and in-memory implementation.

Architecture:
  PortalRateLimiterBackend — ABC; swap in Redis / NATS KV for multi-node prod
  MemoryPortalRateLimiter  — in-memory fixed-window counter (dev / test / single-node)

Key format:
  portal:rl:{tenant_id}:{client_id}:{operation}

Window epoch (floor(now / window_seconds)) is appended inside the backend so
callers never see it — the opaque key passed to increment_and_check is stable
across the lifetime of one window.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable


class PortalRateLimiterBackend(ABC):
    """Abstract backend for rate-limit storage.

    Implementations must be safe for concurrent calls from multiple threads.
    For distributed deployments, implement against Redis (Lua atomic scripts)
    or NATS KV. The interface is intentionally minimal — add observability
    hooks (e.g. get_stats()) as the moat expands.
    """

    @abstractmethod
    def increment_and_check(
        self, key: str, limit: int, window_seconds: int
    ) -> tuple[bool, int]:
        """Atomically increment counter and check against limit.

        Returns:
            (allowed, retry_after_seconds)
            allowed=False → request rejected; retry_after_seconds > 0.
            allowed=True  → request accepted; retry_after_seconds == 0.
        """

    @abstractmethod
    def reset(self, key: str) -> None:
        """Reset all window counters for key — for tests and admin tooling."""

    @abstractmethod
    def backend_name(self) -> str:
        """Human-readable backend identifier for observability."""


class MemoryPortalRateLimiter(PortalRateLimiterBackend):
    """Thread-safe in-memory fixed-window rate limiter.

    Suitable for single-node deployments (dev, test, small-scale prod).
    Replace with a Redis backend for multi-node / Kubernetes deployments —
    the PortalRateLimiterBackend interface is stable.

    Args:
        clock: Injectable time source (float seconds). Defaults to time.time.
               Inject a fixed-value callable in tests for deterministic windows.
    """

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._clock = clock or time.time

    def _window_key(self, key: str, window_seconds: int) -> str:
        epoch = int(self._clock() // window_seconds)
        return f"{key}:{epoch}"

    def increment_and_check(
        self, key: str, limit: int, window_seconds: int
    ) -> tuple[bool, int]:
        wk = self._window_key(key, window_seconds)
        with self._lock:
            self._counters[wk] += 1
            count = self._counters[wk]

        if count > limit:
            now = self._clock()
            epoch = int(now // window_seconds)
            next_window = (epoch + 1) * window_seconds
            retry_after = max(1, int(next_window - now))
            return False, retry_after

        return True, 0

    def preseed(self, key: str, count: int, window_seconds: int) -> None:
        """Pre-fill counter to simulate N previous requests in the current window.

        Used by tests (inject a near-exhausted bucket) and admin tooling.
        Not part of the PortalRateLimiterBackend protocol.
        """
        epoch = int(self._clock() // window_seconds)
        wk = f"{key}:{epoch}"
        with self._lock:
            self._counters[wk] = count

    def reset(self, key: str) -> None:
        with self._lock:
            to_delete = [k for k in self._counters if k.startswith(f"{key}:")]
            for k in to_delete:
                del self._counters[k]

    def backend_name(self) -> str:
        return "memory"


# ---------------------------------------------------------------------------
# Module-level singleton — one limiter per process.
# Replace via _set_portal_rate_limiter() in tests and integration harnesses.
# ---------------------------------------------------------------------------

_LIMITER: PortalRateLimiterBackend = MemoryPortalRateLimiter()
_LIMITER_LOCK = threading.Lock()


def get_portal_rate_limiter() -> PortalRateLimiterBackend:
    return _LIMITER


def _set_portal_rate_limiter(backend: PortalRateLimiterBackend) -> None:
    """Override the process-level rate limiter. Tests and tooling only."""
    global _LIMITER
    with _LIMITER_LOCK:
        _LIMITER = backend


def make_rate_limit_key(tenant_id: str, client_id: str, operation: str) -> str:
    """Stable key for the rate-limit bucket.

    Tenant-scoped and client-scoped so Tenant A's exhaustion never affects
    Tenant B, and Client A's throttle never affects Client B within the same
    tenant.
    """
    return f"portal:rl:{tenant_id}:{client_id}:{operation}"
