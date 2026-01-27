from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, HTTPException, Request

from api.auth_scopes import verify_api_key

log = logging.getLogger("frostgate.ratelimit")

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None


# -----------------------------
# In-Memory Token Bucket (for dev/testing)
# -----------------------------


@dataclass
class MemoryBucket:
    """Token bucket state for in-memory rate limiting."""

    tokens: float
    last_ts: float


class MemoryRateLimiter:
    """
    Thread-safe in-memory token bucket rate limiter.
    Suitable for single-instance development/testing.
    For production, use Redis backend for distributed rate limiting.
    """

    def __init__(self) -> None:
        self._buckets: Dict[str, MemoryBucket] = {}
        self._lock = threading.Lock()
        self._cleanup_interval = 300  # cleanup every 5 minutes
        self._last_cleanup = time.time()

    def _cleanup_expired(self, capacity: float, rate: float) -> None:
        """Remove buckets that have been idle too long."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        # Calculate max idle time (time to refill from 0 to capacity * 2)
        max_idle = (capacity * 2) / rate if rate > 0 else 3600

        with self._lock:
            expired = [
                k for k, v in self._buckets.items() if now - v.last_ts > max_idle
            ]
            for k in expired:
                del self._buckets[k]
            self._last_cleanup = now

    def allow(
        self, key: str, rate_per_sec: float, capacity: float, cost: float = 1.0
    ) -> Tuple[bool, int, int, int]:
        """
        Check if request is allowed under rate limit.

        Returns:
            (allowed, limit, remaining, reset_seconds)
        """
        now = time.time()
        self._cleanup_expired(capacity, rate_per_sec)

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = MemoryBucket(tokens=capacity, last_ts=now)
                self._buckets[key] = bucket

            # Refill tokens
            delta = max(0.0, now - bucket.last_ts)
            bucket.tokens = min(capacity, bucket.tokens + (delta * rate_per_sec))
            bucket.last_ts = now

            # Check if allowed
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                remaining = int(bucket.tokens)
                return True, int(capacity), remaining, 0
            else:
                # Calculate reset time
                needed = cost - bucket.tokens
                reset = int(max(1, needed / rate_per_sec)) if rate_per_sec > 0 else 1
                return False, int(capacity), 0, reset


# Global memory limiter instance
_memory_limiter: Optional[MemoryRateLimiter] = None


def _get_memory_limiter() -> MemoryRateLimiter:
    global _memory_limiter
    if _memory_limiter is None:
        _memory_limiter = MemoryRateLimiter()
    return _memory_limiter


# -----------------------------
# Config
# -----------------------------


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return float(v)


def _env_csv(name: str, default: str = "") -> set[str]:
    v = os.getenv(name, default).strip()
    if not v:
        return set()
    return {s.strip() for s in v.split(",") if s.strip()}


@dataclass(frozen=True)
class RLConfig:
    enabled: bool
    backend: str  # "redis" (recommended) | "memory" (not provided here)
    scope: str  # "tenant" | "source" | "ip"
    paths: set[str]
    bypass_keys: set[str]

    # Token bucket
    rate_per_sec: float  # refill rate (tokens/sec)
    burst: int  # extra burst capacity

    # Redis
    redis_url: str
    prefix: str  # key namespace

    # Failure behavior
    fail_open: bool  # if redis fails, allow requests


def load_config() -> RLConfig:
    enabled = _env_bool("FG_RL_ENABLED", True)
    backend = os.getenv("FG_RL_BACKEND", "redis").strip().lower()
    scope = os.getenv("FG_RL_SCOPE", "tenant").strip().lower()
    paths = _env_csv("FG_RL_PATHS", "/defend")
    bypass_keys = _env_csv("FG_RL_BYPASS_KEYS", "")

    rate = _env_float("FG_RL_RATE_PER_SEC", 2.0)
    burst = _env_int("FG_RL_BURST", 60)

    redis_url = os.getenv("FG_REDIS_URL", "redis://localhost:6379/0").strip()
    prefix = os.getenv("FG_RL_PREFIX", "fg:rl").strip()

    fail_open = _env_bool("FG_RL_FAIL_OPEN", True)

    if backend not in ("redis", "memory"):
        backend = "memory"  # Default to memory for dev/test
    if scope not in ("tenant", "source", "ip"):
        scope = "tenant"

    if rate <= 0:
        rate = 1.0
    if burst < 0:
        burst = 0

    return RLConfig(
        enabled=enabled,
        backend=backend,
        scope=scope,
        paths=paths,
        bypass_keys=bypass_keys,
        rate_per_sec=rate,
        burst=burst,
        redis_url=redis_url,
        prefix=prefix,
        fail_open=fail_open,
    )


# -----------------------------
# Keying
# -----------------------------


def _api_key_from_request(request: Request) -> str:
    return (request.headers.get("x-api-key") or "").strip()


def _extract_client_ip(request: Request) -> str:
    """
    Extract client IP from request, handling common proxy headers.

    Priority:
    1. X-Forwarded-For (first IP in chain)
    2. X-Real-IP
    3. CF-Connecting-IP (Cloudflare)
    4. True-Client-IP (Akamai/Cloudflare)
    5. request.client.host

    Security: Only trust proxy headers in production if behind a trusted proxy.
    """
    # Try proxy headers in order of preference
    for header in (
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
    ):
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For can be comma-separated, take first (client) IP
            ip = value.split(",")[0].strip()
            # Basic validation: must be non-empty and reasonable length
            if ip and len(ip) <= 45:
                # Sanitize: only allow valid IP characters
                if all(c.isalnum() or c in ".:" for c in ip):
                    return ip

    # Fallback to direct client
    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _key_from_request(request: Request, cfg: RLConfig) -> str:
    body = getattr(request.state, "telemetry_body", None)
    tenant = None
    source = None
    if isinstance(body, dict):
        tenant = body.get("tenant_id")
        source = body.get("source")

    if cfg.scope == "tenant" and tenant:
        return f"tenant:{tenant}"
    if cfg.scope == "source" and source:
        return f"source:{source}"

    # IP-based rate limiting (improved extraction)
    client_ip = _extract_client_ip(request)
    return f"ip:{client_ip}"


# -----------------------------
# Redis token bucket (atomic)
# -----------------------------
# State per key:
#  - tokens (float)
#  - last_ts (float seconds)
#
# Capacity = burst + rate_per_sec (optional) ??? No, keep it simple:
# capacity = burst + rate_per_sec * 1 second? not meaningful.
# Standard token bucket: capacity = burst (or burst + base). Here:
# capacity = burst + (rate_per_sec) so you can always do at least ~1s worth after idle.
#
# We'll set capacity = burst + max(1, rate_per_sec) to avoid tiny caps.
#
# Returns:
#  allowed (0/1), limit, remaining, reset_seconds
#
_LUA_TOKEN_BUCKET = r"""
-- KEYS[1] = bucket key
-- ARGV[1] = now (float seconds)
-- ARGV[2] = rate_per_sec (float)
-- ARGV[3] = capacity (float)
-- ARGV[4] = cost (float) (usually 1)

local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call("HMGET", key, "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  ts = now
end

-- refill
local delta = now - ts
if delta < 0 then
  delta = 0
end

tokens = math.min(capacity, tokens + (delta * rate))
ts = now

local allowed = 0
local remaining = tokens

if tokens >= cost then
  allowed = 1
  tokens = tokens - cost
  remaining = tokens
else
  allowed = 0
  remaining = 0
end

-- compute reset: time until 1 token available
local reset = 0
if allowed == 0 then
  local needed = cost - tokens
  reset = math.ceil(needed / rate)
  if reset < 1 then reset = 1 end
end

-- persist
redis.call("HMSET", key, "tokens", tokens, "ts", ts)

-- set expiry to avoid infinite key growth:
-- expire after enough time to refill to capacity plus some slack
local ttl = math.ceil((capacity / rate) * 2)
if ttl < 60 then ttl = 60 end
redis.call("EXPIRE", key, ttl)

-- "limit" here is effectively capacity per burst, not a window cap.
-- We'll present it as a per-second rate + burst in headers in a consistent way.
return {allowed, capacity, math.floor(remaining), reset}
"""

_redis_client = None
_redis_script = None


def _get_redis(cfg: RLConfig):
    global _redis_client, _redis_script
    if _redis_client is not None:
        return _redis_client, _redis_script

    if redis is None:
        raise RuntimeError("redis package not installed")

    _redis_client = redis.Redis.from_url(cfg.redis_url, decode_responses=True)
    _redis_script = _redis_client.register_script(_LUA_TOKEN_BUCKET)
    return _redis_client, _redis_script


def _capacity(cfg: RLConfig) -> float:
    # Give at least 1 token base, plus burst.
    base = max(1.0, cfg.rate_per_sec)
    return float(cfg.burst) + base


def _allow_redis(key: str, cfg: RLConfig) -> Tuple[bool, int, int, int]:
    r, script = _get_redis(cfg)

    now = time.time()
    cap = _capacity(cfg)
    cost = 1.0

    redis_key = f"{cfg.prefix}:{key}:tb"
    allowed, limit, remaining, reset = script(
        keys=[redis_key],
        args=[f"{now}", f"{cfg.rate_per_sec}", f"{cap}", f"{cost}"],
    )

    ok = bool(int(allowed))
    # limit as int for headers
    return ok, int(float(limit)), int(float(remaining)), int(float(reset))


def _allow_memory(key: str, cfg: RLConfig) -> Tuple[bool, int, int, int]:
    """Use in-memory token bucket for rate limiting."""
    limiter = _get_memory_limiter()
    cap = _capacity(cfg)
    return limiter.allow(key, cfg.rate_per_sec, cap, cost=1.0)


def _allow(key: str, cfg: RLConfig) -> Tuple[bool, int, int, int]:
    """Route to appropriate backend based on config."""
    if cfg.backend == "memory":
        return _allow_memory(key, cfg)
    return _allow_redis(key, cfg)


# -----------------------------
# FastAPI dependency
# -----------------------------


async def rate_limit_guard(
    request: Request,
    _: Any = Depends(verify_api_key),
) -> None:
    cfg = load_config()
    if not cfg.enabled:
        return

    if request.url.path not in cfg.paths:
        return

    api_key = _api_key_from_request(request)
    if api_key and api_key in cfg.bypass_keys:
        return

    key = _key_from_request(request, cfg)

    try:
        ok, limit, remaining, reset = _allow(key, cfg)
    except Exception as e:
        log.warning(f"Rate limiter error: {e}")
        if cfg.fail_open:
            return
        raise HTTPException(status_code=503, detail="Rate limiter unavailable")

    headers = {
        "Retry-After": str(reset if not ok else 0),
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset if not ok else 0),
        # helpful for debugging clients:
        "X-RateLimit-Policy": f"tb;rate={cfg.rate_per_sec}/s;burst={cfg.burst};scope={cfg.scope}",
    }

    if not ok:
        raise HTTPException(
            status_code=429, detail="Rate limit exceeded", headers=headers
        )
