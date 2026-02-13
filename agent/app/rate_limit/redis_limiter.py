from __future__ import annotations

from agent.app.rate_limit.memory_fallback import MemoryLimiter

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class RedisFirstLimiter:
    def __init__(self, redis_url: str | None = None):
        self.fallback = MemoryLimiter()
        self.client = None
        if redis and redis_url:
            try:
                self.client = redis.Redis.from_url(redis_url)
            except Exception:
                self.client = None

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        if not self.client:
            return self.fallback.allow(key, limit, window_seconds)
        try:
            pipe = self.client.pipeline()
            pipe.incr(key, 1)
            pipe.expire(key, window_seconds)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception:
            return self.fallback.allow(key, limit, window_seconds)
