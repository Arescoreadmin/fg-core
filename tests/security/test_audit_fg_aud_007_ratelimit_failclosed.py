"""
Regression tests for FG-AUD-007.

FG-AUD-007: RedisFirstLimiter previously failed open — when Redis was unavailable
it silently fell back to in-memory limiting, creating a DoS-bypass vector where an
attacker could crash Redis and then hammer the API without effective rate limiting.

These tests prove:
  1. When Redis is configured but unavailable and FG_RL_FAIL_OPEN is NOT set,
     allow() returns False (fail-closed).
  2. When FG_RL_FAIL_OPEN=1, allow() falls back to memory limiter (opt-in).
  3. When Redis is NOT configured at all, memory limiter is used (no Redis = no penalty).
  4. Redis errors during allow() also fail closed (not just init errors).
  5. The fail-open flag is read from the environment, not hardcoded.
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock, patch


class TestRedisFirstLimiterFailClosed:
    """FG-AUD-007: Rate limiter must fail closed on Redis unavailability."""

    def test_redis_unavailable_no_override_denies(self, monkeypatch):
        """When Redis is configured but unreachable and FG_RL_FAIL_OPEN is not set,
        allow() must return False (fail-closed)."""
        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.client = None
        limiter._redis_configured = True  # simulates: Redis was configured but failed

        result = limiter.allow("key:user123", limit=100, window_seconds=60)

        assert result is False, (
            "RedisFirstLimiter must fail CLOSED (return False) when Redis is "
            "configured but unavailable and FG_RL_FAIL_OPEN is not set"
        )
        limiter.fallback.allow.assert_not_called()

    def test_redis_unavailable_with_fail_open_uses_memory(self, monkeypatch):
        """When FG_RL_FAIL_OPEN=1, falling back to memory limiter is allowed."""
        monkeypatch.setenv("FG_RL_FAIL_OPEN", "1")

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock(return_value=True)
        limiter.fallback.allow = MagicMock(return_value=True)
        limiter.client = None
        limiter._redis_configured = True

        result = limiter.allow("key:user123", limit=100, window_seconds=60)

        assert result is True
        limiter.fallback.allow.assert_called_once()

    def test_no_redis_configured_uses_memory(self, monkeypatch):
        """When Redis is not configured at all, memory limiter is used (no penalty)."""
        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.fallback.allow = MagicMock(return_value=True)
        limiter.client = None
        limiter._redis_configured = False  # Redis was never configured

        result = limiter.allow("key:test", limit=10, window_seconds=60)

        assert result is True
        limiter.fallback.allow.assert_called_once()

    def test_redis_runtime_error_fails_closed_without_override(self, monkeypatch):
        """A Redis error during allow() fails closed when FG_RL_FAIL_OPEN is not set."""
        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        mock_client = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = Exception("connection reset by peer")
        mock_client.pipeline.return_value = mock_pipe

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.fallback.allow = MagicMock(return_value=True)
        limiter.client = mock_client
        limiter._redis_configured = True

        result = limiter.allow("key:user456", limit=100, window_seconds=60)

        assert result is False, (
            "RedisFirstLimiter must fail CLOSED on Redis runtime errors "
            "when FG_RL_FAIL_OPEN is not set"
        )
        limiter.fallback.allow.assert_not_called()

    def test_redis_runtime_error_falls_back_with_override(self, monkeypatch):
        """A Redis error during allow() uses memory fallback when FG_RL_FAIL_OPEN=1."""
        monkeypatch.setenv("FG_RL_FAIL_OPEN", "1")

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        mock_client = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = Exception("timeout")
        mock_client.pipeline.return_value = mock_pipe

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.fallback.allow = MagicMock(return_value=True)
        limiter.client = mock_client
        limiter._redis_configured = True

        result = limiter.allow("key:user789", limit=100, window_seconds=60)

        assert result is True
        limiter.fallback.allow.assert_called_once()

    def test_fail_open_flag_from_env_not_hardcoded(self, monkeypatch):
        """_fail_open_allowed() reads FG_RL_FAIL_OPEN from env — not hardcoded."""
        from agent.app.rate_limit.redis_limiter import _fail_open_allowed

        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)
        assert _fail_open_allowed() is False

        monkeypatch.setenv("FG_RL_FAIL_OPEN", "1")
        assert _fail_open_allowed() is True

        monkeypatch.setenv("FG_RL_FAIL_OPEN", "0")
        assert _fail_open_allowed() is False

        monkeypatch.setenv("FG_RL_FAIL_OPEN", "true")
        assert _fail_open_allowed() is False  # only "1" is accepted

    def test_successful_redis_allow_works_normally(self, monkeypatch):
        """When Redis is available and count <= limit, allow() returns True."""
        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        mock_client = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = (5, True)
        mock_client.pipeline.return_value = mock_pipe

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.client = mock_client
        limiter._redis_configured = True

        result = limiter.allow("key:user", limit=10, window_seconds=60)
        assert result is True

    def test_successful_redis_deny_works_normally(self, monkeypatch):
        """When Redis is available and count > limit, allow() returns False."""
        monkeypatch.delenv("FG_RL_FAIL_OPEN", raising=False)

        from agent.app.rate_limit.redis_limiter import RedisFirstLimiter

        mock_client = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = (11, True)
        mock_client.pipeline.return_value = mock_pipe

        limiter = RedisFirstLimiter.__new__(RedisFirstLimiter)
        limiter.fallback = MagicMock()
        limiter.client = mock_client
        limiter._redis_configured = True

        result = limiter.allow("key:user", limit=10, window_seconds=60)
        assert result is False
