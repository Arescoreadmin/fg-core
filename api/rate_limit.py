"""
Redis-backed token bucket rate limiter for FrostGate.

Supports:
- Per-IP rate limiting
- Per-API-key rate limiting
- Configurable limits via environment variables
- Graceful fallback to in-memory when Redis unavailable
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request
from loguru import logger

# Configuration from environment
RATE_LIMIT_ENABLED = os.getenv("FG_RATE_LIMIT_ENABLED", "1").strip() == "1"
RATE_LIMIT_REQUESTS = int(os.getenv("FG_RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("FG_RATE_LIMIT_WINDOW", "60"))
REDIS_URL = os.getenv("FG_REDIS_URL", os.getenv("REDIS_URL", "")).strip()


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_at: float
    limit: int


class InMemoryRateLimiter:
    """Fallback rate limiter when Redis is unavailable."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        cutoff = now - window_seconds

        # Clean old entries
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

        current_count = len(self._buckets[key])
        allowed = current_count < limit

        if allowed:
            self._buckets[key].append(now)
            current_count += 1

        # Calculate reset time (when oldest entry expires)
        reset_at = now + window_seconds
        if self._buckets[key]:
            reset_at = self._buckets[key][0] + window_seconds

        return RateLimitResult(
            allowed=allowed,
            remaining=max(0, limit - current_count),
            reset_at=reset_at,
            limit=limit,
        )


class RedisRateLimiter:
    """Redis-backed sliding window rate limiter using sorted sets."""

    def __init__(self, redis_client):
        self._redis = redis_client

    def check(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"frostgate:ratelimit:{key}"

        pipe = self._redis.pipeline()
        # Remove old entries
        pipe.zremrangebyscore(redis_key, 0, cutoff)
        # Count current entries
        pipe.zcard(redis_key)
        # Add new entry (will be rolled back if not allowed)
        pipe.zadd(redis_key, {f"{now}": now})
        # Set expiry
        pipe.expire(redis_key, window_seconds + 1)

        results = pipe.execute()
        current_count = results[1]

        allowed = current_count < limit
        if not allowed:
            # Remove the entry we just added
            self._redis.zrem(redis_key, f"{now}")
        else:
            current_count += 1

        # Get oldest entry for reset time
        oldest = self._redis.zrange(redis_key, 0, 0, withscores=True)
        reset_at = now + window_seconds
        if oldest:
            reset_at = oldest[0][1] + window_seconds

        return RateLimitResult(
            allowed=allowed,
            remaining=max(0, limit - current_count),
            reset_at=reset_at,
            limit=limit,
        )


# Global limiter instance
_limiter: Optional[InMemoryRateLimiter | RedisRateLimiter] = None


def _get_limiter() -> InMemoryRateLimiter | RedisRateLimiter:
    global _limiter
    if _limiter is not None:
        return _limiter

    if REDIS_URL:
        try:
            import redis

            client = redis.from_url(REDIS_URL, decode_responses=True)
            client.ping()
            _limiter = RedisRateLimiter(client)
            logger.info(
                "rate_limit: using Redis backend", extra={"url": REDIS_URL[:20] + "..."}
            )
            return _limiter
        except Exception as e:
            logger.warning(
                "rate_limit: Redis unavailable, falling back to in-memory",
                extra={"error": str(e)},
            )

    _limiter = InMemoryRateLimiter()
    logger.info("rate_limit: using in-memory backend")
    return _limiter


def _extract_client_key(request: Request) -> str:
    """Extract a unique key for the client (API key hash or IP)."""
    # Prefer API key if present
    api_key = request.headers.get("x-api-key") or request.headers.get(
        "authorization", ""
    ).replace("Bearer ", "")
    if api_key:
        return f"key:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"

    # Fall back to IP
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "unknown"

    return f"ip:{ip}"


def rate_limit_guard(
    limit: Optional[int] = None,
    window_seconds: Optional[int] = None,
):
    """
    FastAPI dependency for rate limiting.

    Usage:
        @app.get("/endpoint")
        async def endpoint(
            _: None = Depends(rate_limit_guard())
        ):
            ...
    """
    _limit = limit or RATE_LIMIT_REQUESTS
    _window = window_seconds or RATE_LIMIT_WINDOW_SECONDS

    async def _dep(request: Request) -> None:
        if not RATE_LIMIT_ENABLED:
            return None

        limiter = _get_limiter()
        client_key = _extract_client_key(request)
        result = limiter.check(client_key, _limit, _window)

        # Set rate limit headers
        request.state.rate_limit_remaining = result.remaining
        request.state.rate_limit_limit = result.limit
        request.state.rate_limit_reset = int(result.reset_at)

        if not result.allowed:
            logger.warning(
                "rate_limit: request rejected",
                extra={
                    "client_key": client_key,
                    "limit": result.limit,
                    "window": _window,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit exceeded. Try again in {int(result.reset_at - time.time())} seconds.",
                    "retry_after": int(result.reset_at - time.time()),
                },
                headers={
                    "X-RateLimit-Limit": str(result.limit),
                    "X-RateLimit-Remaining": str(result.remaining),
                    "X-RateLimit-Reset": str(int(result.reset_at)),
                    "Retry-After": str(int(result.reset_at - time.time())),
                },
            )

        return None

    return _dep


def add_rate_limit_headers(request: Request, response):
    """Add rate limit headers to response (call from middleware)."""
    if hasattr(request.state, "rate_limit_limit"):
        response.headers["X-RateLimit-Limit"] = str(request.state.rate_limit_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            request.state.rate_limit_remaining
        )
        response.headers["X-RateLimit-Reset"] = str(request.state.rate_limit_reset)
