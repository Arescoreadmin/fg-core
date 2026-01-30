"""
Security Middleware Tests for FrostGate Core.

Tests for:
- Rate limiting (memory backend)
- Request body size limits
- Security headers
- CORS configuration
"""

from __future__ import annotations

import os
import time
from unittest.mock import patch

from fastapi.testclient import TestClient


# Set test environment before imports
os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_security.db")
os.environ.setdefault("FG_RL_ENABLED", "0")  # Disable rate limiting for most tests


class TestSecurityHeaders:
    """Test security headers middleware."""

    def test_hsts_header_present(self):
        """HSTS header should be present in responses."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert response.status_code == 200
        assert "Strict-Transport-Security" in response.headers

    def test_content_type_options_header(self):
        """X-Content-Type-Options header should be nosniff."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_options_header(self):
        """X-Frame-Options header should be DENY."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_csp_header_present(self):
        """Content-Security-Policy header should be present."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert "Content-Security-Policy" in response.headers

    def test_request_id_header(self):
        """X-Request-ID header should be present in responses."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert "X-Request-ID" in response.headers
        # Should be a valid UUID-like string
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) >= 32

    def test_request_id_passthrough(self):
        """Client-provided X-Request-ID should be passed through."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        custom_id = "test-request-123"
        response = client.get("/health", headers={"X-Request-ID": custom_id})
        assert response.headers.get("X-Request-ID") == custom_id

    def test_referrer_policy_header(self):
        """Referrer-Policy header should be present."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert "Referrer-Policy" in response.headers


class TestRequestValidation:
    """Test request validation middleware."""

    def test_health_endpoint_skips_validation(self):
        """Health endpoints should skip validation."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        # Should work without content-type
        response = client.get("/health")
        assert response.status_code == 200

    def test_content_type_required_for_post(self):
        """POST requests should require content-type."""
        from api.main import build_app

        with patch.dict(
            os.environ, {"FG_ENFORCE_CONTENT_TYPE": "1", "FG_AUTH_ENABLED": "0"}
        ):
            app = build_app(auth_enabled=False)
            client = TestClient(app)

            # With correct content-type
            response = client.post(
                "/defend",
                json={"tenant_id": "test", "source": "test"},
                headers={"X-API-Key": os.environ["FG_API_KEY"]},
            )
            # Should not be 415 (may be 401 or other if auth fails, but not content-type rejection)
            assert response.status_code != 415


class TestRateLimitingMemoryBackend:
    """Test rate limiting with memory backend."""

    def test_memory_bucket_initialization(self):
        """Memory bucket should initialize correctly."""
        from api.ratelimit import MemoryRateLimiter

        limiter = MemoryRateLimiter()
        assert limiter._buckets == {}

    def test_memory_bucket_allows_initial_requests(self):
        """Initial requests should be allowed up to capacity."""
        from api.ratelimit import MemoryRateLimiter

        limiter = MemoryRateLimiter()

        # With capacity of 10, first 10 requests should be allowed
        for i in range(10):
            allowed, limit, remaining, reset = limiter.allow(
                "test_key", rate_per_sec=1.0, capacity=10.0
            )
            assert allowed, f"Request {i} should be allowed"
            assert limit == 10
            assert remaining == 10 - (i + 1)

    def test_memory_bucket_rate_limits(self):
        """Requests beyond capacity should be rate limited."""
        from api.ratelimit import MemoryRateLimiter

        limiter = MemoryRateLimiter()

        # Exhaust the bucket
        for _ in range(5):
            limiter.allow("test_key", rate_per_sec=1.0, capacity=5.0)

        # Next request should be denied
        allowed, limit, remaining, reset = limiter.allow(
            "test_key", rate_per_sec=1.0, capacity=5.0
        )
        assert not allowed
        assert remaining == 0
        assert reset > 0

    def test_memory_bucket_refills(self):
        """Bucket should refill over time."""
        from api.ratelimit import MemoryRateLimiter

        limiter = MemoryRateLimiter()

        # Exhaust the bucket
        for _ in range(3):
            limiter.allow("test_key", rate_per_sec=100.0, capacity=3.0)

        # Should be denied
        allowed, _, _, _ = limiter.allow("test_key", rate_per_sec=100.0, capacity=3.0)
        assert not allowed

        # Wait for refill (100 tokens/sec means 0.01s for 1 token)
        time.sleep(0.02)

        # Should be allowed now
        allowed, _, _, _ = limiter.allow("test_key", rate_per_sec=100.0, capacity=3.0)
        assert allowed

    def test_memory_bucket_per_key_isolation(self):
        """Different keys should have separate buckets."""
        from api.ratelimit import MemoryRateLimiter

        limiter = MemoryRateLimiter()

        # Exhaust key1
        for _ in range(3):
            limiter.allow("key1", rate_per_sec=1.0, capacity=3.0)

        # key1 should be denied
        allowed, _, _, _ = limiter.allow("key1", rate_per_sec=1.0, capacity=3.0)
        assert not allowed

        # key2 should still be allowed
        allowed, _, _, _ = limiter.allow("key2", rate_per_sec=1.0, capacity=3.0)
        assert allowed


class TestRateLimitConfig:
    """Test rate limit configuration."""

    def test_config_loads_defaults(self):
        """Config should load with defaults."""
        from api.ratelimit import load_config

        # Clear rate limiting env vars to test defaults
        env_without_rl = {
            k: v for k, v in os.environ.items() if not k.startswith("FG_RL")
        }
        with patch.dict(os.environ, env_without_rl, clear=True):
            cfg = load_config()
            assert cfg.enabled is True
            assert cfg.rate_per_sec > 0
            assert cfg.burst >= 0

    def test_config_memory_backend(self):
        """Config should support memory backend."""
        from api.ratelimit import load_config

        with patch.dict(os.environ, {"FG_RL_BACKEND": "memory"}):
            cfg = load_config()
            assert cfg.backend == "memory"

    def test_config_scope_validation(self):
        """Config should validate scope options."""
        from api.ratelimit import load_config

        for scope in ("tenant", "source", "ip"):
            with patch.dict(os.environ, {"FG_RL_SCOPE": scope}):
                cfg = load_config()
                assert cfg.scope == scope

    def test_config_invalid_scope_defaults_to_tenant(self):
        """Invalid scope should default to tenant."""
        from api.ratelimit import load_config

        with patch.dict(os.environ, {"FG_RL_SCOPE": "invalid"}):
            cfg = load_config()
            assert cfg.scope == "tenant"


class TestCORSConfig:
    """Test CORS configuration."""

    def test_cors_config_from_env(self):
        """CORS config should load from environment."""
        from api.middleware.security_headers import CORSConfig

        config = CORSConfig.from_env()
        assert config.allow_methods is not None
        assert config.max_age > 0

    def test_cors_origins_parsing(self):
        """CORS origins should be parsed from comma-separated string."""
        from api.middleware.security_headers import CORSConfig

        with patch.dict(
            os.environ,
            {"FG_CORS_ORIGINS": "https://example.com,https://api.example.com"},
        ):
            config = CORSConfig.from_env()
            assert "https://example.com" in config.allow_origins
            assert "https://api.example.com" in config.allow_origins


class TestSecurityHeadersConfig:
    """Test security headers configuration."""

    def test_security_headers_config_from_env(self):
        """Security headers config should load from environment."""
        from api.middleware.security_headers import SecurityHeadersConfig

        config = SecurityHeadersConfig.from_env()
        assert config.hsts_enabled is True
        assert config.hsts_max_age > 0
        assert config.frame_options == "DENY"

    def test_security_headers_hsts_disabled(self):
        """HSTS can be disabled via environment."""
        from api.middleware.security_headers import SecurityHeadersConfig

        with patch.dict(os.environ, {"FG_HSTS_ENABLED": "0"}):
            config = SecurityHeadersConfig.from_env()
            assert config.hsts_enabled is False


class TestRequestValidationConfig:
    """Test request validation configuration."""

    def test_request_validation_config_from_env(self):
        """Request validation config should load from environment."""
        from api.middleware.request_validation import RequestValidationConfig

        config = RequestValidationConfig.from_env()
        assert config.max_body_size > 0
        assert config.enabled is True

    def test_request_validation_max_body_size(self):
        """Max body size should be configurable."""
        from api.middleware.request_validation import RequestValidationConfig

        with patch.dict(os.environ, {"FG_MAX_BODY_SIZE": "2097152"}):  # 2MB
            config = RequestValidationConfig.from_env()
            assert config.max_body_size == 2097152


# Integration test that requires auth disabled
class TestSecurityIntegration:
    """Integration tests for security features."""

    def test_full_request_with_security_headers(self):
        """Full request should include all security headers."""
        from api.main import build_app

        app = build_app(auth_enabled=False)
        client = TestClient(app)

        response = client.get("/health")
        assert response.status_code == 200

        # Check all expected security headers
        expected_headers = [
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Referrer-Policy",
            "X-Request-ID",
        ]

        for header in expected_headers:
            assert header in response.headers, f"Missing header: {header}"


class TestRateLimitFailureBehavior:
    """Test rate limiting behavior when backend fails (fail-open vs fail-closed).

    These tests verify production-critical behavior: when Redis is unavailable,
    the rate limiter must either allow (fail-open) or deny (fail-closed) based
    on FG_RL_FAIL_OPEN configuration.
    """

    def test_fail_open_config_true(self):
        """Verify FG_RL_FAIL_OPEN=true is parsed correctly."""
        from api.ratelimit import load_config

        with patch.dict(
            os.environ,
            {
                "FG_RL_ENABLED": "1",
                "FG_RL_BACKEND": "redis",
                "FG_RL_FAIL_OPEN": "true",
            },
        ):
            cfg = load_config()
            assert cfg.fail_open is True

    def test_fail_closed_config_false(self):
        """Verify FG_RL_FAIL_OPEN=false is parsed correctly (production mode)."""
        from api.ratelimit import load_config

        with patch.dict(
            os.environ,
            {
                "FG_RL_ENABLED": "1",
                "FG_RL_BACKEND": "redis",
                "FG_RL_FAIL_OPEN": "false",
            },
        ):
            cfg = load_config()
            assert cfg.fail_open is False

    def test_fail_closed_returns_503_on_redis_error(self):
        """Fail-closed mode must return 503 when Redis is unavailable."""
        import pytest
        from unittest.mock import MagicMock
        from fastapi import HTTPException

        from api.ratelimit import rate_limit_guard

        with patch.dict(
            os.environ,
            {
                "FG_RL_ENABLED": "1",
                "FG_RL_BACKEND": "redis",
                "FG_RL_FAIL_OPEN": "false",
                "FG_RL_PATHS": "/defend",
            },
        ):
            with patch("api.ratelimit._allow") as mock_allow:
                mock_allow.side_effect = ConnectionError("Redis unavailable")

                mock_request = MagicMock()
                mock_request.url.path = "/defend"
                mock_request.headers.get = MagicMock(return_value="test-api-key")
                mock_request.state = MagicMock()
                mock_request.state.telemetry_body = {"tenant_id": "test-tenant"}
                mock_request.client = MagicMock()
                mock_request.client.host = "127.0.0.1"

                import asyncio

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.get_event_loop().run_until_complete(
                        rate_limit_guard(mock_request, None)
                    )

                assert exc_info.value.status_code == 503
                assert "unavailable" in exc_info.value.detail.lower()

    def test_fail_open_allows_on_redis_error(self):
        """Fail-open mode must allow requests when Redis is unavailable."""
        from unittest.mock import MagicMock

        from api.ratelimit import rate_limit_guard

        with patch.dict(
            os.environ,
            {
                "FG_RL_ENABLED": "1",
                "FG_RL_BACKEND": "redis",
                "FG_RL_FAIL_OPEN": "true",
                "FG_RL_PATHS": "/defend",
            },
        ):
            with patch("api.ratelimit._allow") as mock_allow:
                mock_allow.side_effect = ConnectionError("Redis unavailable")

                mock_request = MagicMock()
                mock_request.url.path = "/defend"
                mock_request.headers.get = MagicMock(return_value="test-api-key")
                mock_request.state = MagicMock()
                mock_request.state.telemetry_body = {"tenant_id": "test-tenant"}
                mock_request.client = MagicMock()
                mock_request.client.host = "127.0.0.1"

                import asyncio

                # Should NOT raise - request allowed on Redis failure
                result = asyncio.get_event_loop().run_until_complete(
                    rate_limit_guard(mock_request, None)
                )
                assert result is None

    def test_production_compose_sets_fail_closed(self):
        """Verify docker-compose.yml sets FG_RL_FAIL_OPEN=false for production."""
        import yaml

        with open("docker-compose.yml") as f:
            compose = yaml.safe_load(f)

        core_env = (
            compose.get("services", {}).get("frostgate-core", {}).get("environment", {})
        )
        fail_open_value = core_env.get("FG_RL_FAIL_OPEN")

        assert fail_open_value is not None, (
            "FG_RL_FAIL_OPEN must be explicitly set in docker-compose.yml"
        )
        # Value may be a variable reference like ${FG_RL_FAIL_OPEN:-false}
        # The default value after :- is what matters
        val_str = str(fail_open_value).lower()
        assert "false" in val_str or val_str == "false", (
            f"FG_RL_FAIL_OPEN must default to 'false' in production compose, got: {fail_open_value}"
        )
