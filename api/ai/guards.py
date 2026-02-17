from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

from api.ai.policy import error_response
from api.auth_scopes.resolution import is_prod_like_env

_security_log = logging.getLogger("frostgate.security")


@dataclass(frozen=True)
class IdempotencyCacheEntry:
    request_hash: str
    response_json: str
    response_hash: str


class GuardBackendUnavailable(RuntimeError):
    def __init__(
        self,
        operation: str,
        *,
        prod_like: bool,
        class_name: str,
        error_family: str,
        exc_fingerprint: str,
    ):
        super().__init__(operation)
        self.operation = operation
        self.prod_like = prod_like
        self.class_name = class_name
        self.error_family = error_family
        self.exc_fingerprint = exc_fingerprint


class _MemoryStore:
    def __init__(self) -> None:
        self._kv: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> str | None:
        now = time.time()
        with self._lock:
            item = self._kv.get(key)
            if item is None:
                return None
            expires_at, value = item
            if now >= expires_at:
                self._kv.pop(key, None)
                return None
            return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        with self._lock:
            self._kv[key] = (time.time() + max(1, ttl_seconds), value)

    def incrby(self, key: str, amount: int, ttl_seconds: int) -> int:
        now = time.time()
        with self._lock:
            item = self._kv.get(key)
            base = 0
            if item is not None and now < item[0]:
                base = int(item[1])
            total = base + amount
            self._kv[key] = (now + max(1, ttl_seconds), str(total))
            return total


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def _guards_backend() -> str:
    return (os.getenv("FG_AI_GUARDS_BACKEND") or "redis").strip().lower()


def _guard_fail_open_requested() -> bool:
    return _env_bool("FG_AI_GUARD_FAIL_OPEN_FOR_DEV", False)


def _guard_fail_open_for_dev_allowed() -> bool:
    return _guard_fail_open_requested() and not is_prod_like_env()


def _redis_client():
    if _guards_backend() != "redis":
        return None
    if redis is None:
        return None
    url = (os.getenv("FG_REDIS_URL") or "").strip()
    if not url:
        return None
    return redis.Redis.from_url(url, decode_responses=True)


def _exc_metadata(exc: Exception | None) -> tuple[str, str, str]:
    if exc is None:
        return ("UnavailableError", "backend_unavailable", "none")
    class_name = type(exc).__name__
    family = type(exc).__module__.split(".", 1)[0] or "unknown"
    fp = hashlib.sha256(
        f"{type(exc).__module__}:{class_name}".encode("utf-8")
    ).hexdigest()[:16]
    return class_name, family, fp


def _on_guard_backend_error(operation: str, exc: Exception | None = None) -> None:
    class_name, error_family, exc_fingerprint = _exc_metadata(exc)
    if _guard_fail_open_for_dev_allowed():
        _security_log.critical(
            "ai_guard_fail_open_dev_override_enabled",
            extra={
                "event": "ai_guard_fail_open_dev_override_enabled",
                "operation": operation,
                "backend": _guards_backend(),
                "env": (os.getenv("FG_ENV") or "").strip().lower() or "unknown",
                "class_name": class_name,
                "error_family": error_family,
                "exc_fingerprint": exc_fingerprint,
                "dev_only": True,
                "dev_only_marker": "DEV_ONLY",
                "ttl_seconds": idempotency_ttl_seconds(),
            },
        )
        _security_log.critical(
            "ai_guard_fail_open_dev_override",
            extra={
                "event": "ai_guard_fail_open_dev_override",
                "operation": operation,
                "backend": _guards_backend(),
                "env": (os.getenv("FG_ENV") or "").strip().lower() or "unknown",
                "class_name": class_name,
                "error_family": error_family,
                "exc_fingerprint": exc_fingerprint,
                "dev_only": True,
            },
        )
        return

    if _guard_fail_open_requested() and is_prod_like_env():
        _security_log.critical(
            "ai_guard_fail_open_rejected",
            extra={
                "event": "ai_guard_fail_open_rejected",
                "operation": operation,
                "backend": _guards_backend(),
                "env": (os.getenv("FG_ENV") or "").strip().lower() or "unknown",
                "class_name": class_name,
                "error_family": error_family,
                "exc_fingerprint": exc_fingerprint,
                "dev_only": False,
            },
        )

    raise GuardBackendUnavailable(
        operation,
        prod_like=is_prod_like_env(),
        class_name=class_name,
        error_family=error_family,
        exc_fingerprint=exc_fingerprint,
    ) from exc


_memory_store = _MemoryStore()


def idempotency_ttl_seconds() -> int:
    return min(900, max(300, _env_int("FG_AI_IDEMPOTENCY_TTL_SECONDS", 600)))


def _idempotency_key(tenant_id: str, actor_id: str, key: str) -> str:
    return f"fg:ai:idem:{tenant_id}:{actor_id}:{key}"


def get_cached_idempotent_response(
    *, tenant_id: str, actor_id: str, idempotency_key: str
) -> IdempotencyCacheEntry | None:
    cache_key = _idempotency_key(tenant_id, actor_id, idempotency_key)
    client = _redis_client()
    if client is not None:
        try:
            raw = client.get(cache_key)
        except Exception as exc:
            _on_guard_backend_error("idempotency_get", exc)
            return None
        if not raw:
            return None
        payload = json.loads(raw)
        return IdempotencyCacheEntry(
            request_hash=str(payload["request_hash"]),
            response_json=str(payload["response_json"]),
            response_hash=str(payload["response_hash"]),
        )

    if _guards_backend() == "redis":
        _on_guard_backend_error("idempotency_get")
        return None

    raw = _memory_store.get(cache_key)
    if not raw:
        return None
    payload = json.loads(raw)
    return IdempotencyCacheEntry(
        request_hash=str(payload["request_hash"]),
        response_json=str(payload["response_json"]),
        response_hash=str(payload["response_hash"]),
    )


def set_cached_idempotent_response(
    *,
    tenant_id: str,
    actor_id: str,
    idempotency_key: str,
    entry: IdempotencyCacheEntry,
) -> None:
    cache_key = _idempotency_key(tenant_id, actor_id, idempotency_key)
    ttl = idempotency_ttl_seconds()
    encoded = json.dumps(
        {
            "request_hash": entry.request_hash,
            "response_json": entry.response_json,
            "response_hash": entry.response_hash,
        },
        separators=(",", ":"),
    )

    client = _redis_client()
    if client is not None:
        try:
            client.setex(cache_key, ttl, encoded)
            return
        except Exception as exc:
            _on_guard_backend_error("idempotency_set", exc)
            return

    if _guards_backend() == "redis":
        _on_guard_backend_error("idempotency_set")
        return

    _memory_store.set(cache_key, encoded, ttl)


def enforce_ai_rate_limit(tenant_id: str) -> None:
    limit = max(1, _env_int("FG_AI_RATE_LIMIT_PER_MIN", 30))
    key = f"fg:ai:rl:{tenant_id}:{int(time.time() // 60)}"
    client = _redis_client()

    if client is not None:
        try:
            with client.pipeline() as pipe:
                pipe.incr(key)
                pipe.expire(key, 120)
                current, _ = pipe.execute()
        except Exception as exc:
            _on_guard_backend_error("rate_limit", exc)
            return
    else:
        if _guards_backend() == "redis":
            _on_guard_backend_error("rate_limit")
            return
        current = _memory_store.incrby(key, 1, 120)

    if int(current) > limit:
        raise error_response(429, "AI_RATE_LIMITED", "AI rate limit exceeded")


def enforce_ai_token_budget(tenant_id: str, estimated_tokens: int) -> None:
    per_hour = max(1, _env_int("FG_AI_BUDGET_TOKENS_PER_HOUR", 60000))
    per_day = max(1, _env_int("FG_AI_BUDGET_TOKENS_PER_DAY", 500000))
    hour_key = f"fg:ai:budget:h:{tenant_id}:{int(time.time() // 3600)}"
    day_key = f"fg:ai:budget:d:{tenant_id}:{int(time.time() // 86400)}"
    client = _redis_client()

    if client is not None:
        try:
            with client.pipeline() as pipe:
                pipe.incrby(hour_key, estimated_tokens)
                pipe.expire(hour_key, 7200)
                hour_total, _ = pipe.execute()
            with client.pipeline() as pipe:
                pipe.incrby(day_key, estimated_tokens)
                pipe.expire(day_key, 172800)
                day_total, _ = pipe.execute()
        except Exception as exc:
            _on_guard_backend_error("token_budget", exc)
            return
    else:
        if _guards_backend() == "redis":
            _on_guard_backend_error("token_budget")
            return
        hour_total = _memory_store.incrby(hour_key, estimated_tokens, 7200)
        day_total = _memory_store.incrby(day_key, estimated_tokens, 172800)

    if int(hour_total) > per_hour or int(day_total) > per_day:
        raise error_response(429, "AI_BUDGET_EXCEEDED", "AI token budget exceeded")
