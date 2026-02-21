from __future__ import annotations

import logging
import os

from agent.app.rate_limit.memory_fallback import MemoryLimiter

log = logging.getLogger("frostgate.rate_limit")

try:
    import redis
except Exception:  # pragma: no cover
    redis = None  # type: ignore[assignment]


def _fail_open_allowed() -> bool:
    """Return True only when FG_RL_FAIL_OPEN=1 is explicitly set (dev/test override).

    FG-AUD-007 patch: previously the limiter silently fell back to in-memory
    when Redis was unavailable, creating a DoS-bypass (attacker crashes Redis →
    no effective rate limiting).  Default is now fail-CLOSED: if Redis is
    configured but unreachable, all requests are DENIED until Redis recovers,
    unless the operator has explicitly set FG_RL_FAIL_OPEN=1.
    """
    return os.getenv("FG_RL_FAIL_OPEN", "0").strip() == "1"


class RedisFirstLimiter:
    def __init__(self, redis_url: str | None = None):
        self.fallback = MemoryLimiter()
        self.client = None
        self._redis_configured = bool(redis_url)
        if redis and redis_url:
            try:
                self.client = redis.Redis.from_url(redis_url)
            except Exception as exc:
                log.error(
                    "RedisFirstLimiter: failed to initialise Redis client (%s). "
                    "Rate limiting will %s.",
                    exc,
                    "use memory fallback (FG_RL_FAIL_OPEN=1)"
                    if _fail_open_allowed()
                    else "DENY ALL requests (fail-closed)",
                )
                self.client = None

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        if not self.client:
            if not self._redis_configured:
                # Redis was never configured — use in-memory limiter as intended.
                return self.fallback.allow(key, limit, window_seconds)
            if _fail_open_allowed():
                # Explicit operator opt-in to memory fallback during Redis outage.
                return self.fallback.allow(key, limit, window_seconds)
            # FG-AUD-007: fail-closed when Redis is configured but unavailable
            # and no explicit fail-open override is set.
            log.warning(
                "RedisFirstLimiter: Redis unavailable and FG_RL_FAIL_OPEN not set; "
                "denying request (fail-closed) for key prefix %r",
                (key or "")[:32],
            )
            return False
        try:
            pipe = self.client.pipeline()
            pipe.incr(key, 1)
            pipe.expire(key, window_seconds)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception as exc:
            if _fail_open_allowed():
                log.warning(
                    "RedisFirstLimiter: Redis error (%s); falling back to memory limiter "
                    "(FG_RL_FAIL_OPEN=1 override active)",
                    exc,
                )
                return self.fallback.allow(key, limit, window_seconds)
            # FG-AUD-007: fail-closed by default on Redis errors.
            log.error(
                "RedisFirstLimiter: Redis error (%s); denying request (fail-closed). "
                "Set FG_RL_FAIL_OPEN=1 to use memory fallback (dev only).",
                exc,
            )
            return False
