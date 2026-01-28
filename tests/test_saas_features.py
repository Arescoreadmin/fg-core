# tests/test_saas_features.py
"""
Tests for SaaS-ready features:
- Tenant usage metering and quotas
- Webhook signature verification
- Circuit breaker pattern
- Graceful shutdown
- Security alerts
- Key rotation
"""

import os
import time
from unittest.mock import patch

import pytest


# =============================================================================
# Tenant Usage Tests
# =============================================================================


class TestTenantUsage:
    """Tests for tenant usage metering and quota enforcement."""

    def test_usage_tracker_init(self):
        """Test usage tracker initialization."""
        from api.tenant_usage import TenantUsageTracker

        tracker = TenantUsageTracker()
        assert tracker is not None
        assert tracker._usage == {}
        assert tracker._tenant_tiers == {}

    def test_record_usage(self):
        """Test recording tenant usage."""
        from api.tenant_usage import TenantUsageTracker

        tracker = TenantUsageTracker()
        record = tracker.record_usage("tenant-1", request_count=1, decision_count=1)

        assert record.tenant_id == "tenant-1"
        assert record.request_count == 1
        assert record.decision_count == 1

    def test_quota_check_within_limit(self):
        """Test quota check when within limits."""
        from api.tenant_usage import TenantUsageTracker

        tracker = TenantUsageTracker()
        result = tracker.check_quota("tenant-1")

        assert result.allowed is True
        assert result.limit > 0

    def test_quota_check_suspended_tenant(self):
        """Test quota check for suspended tenant."""
        from api.tenant_usage import TenantUsageTracker

        tracker = TenantUsageTracker()
        tracker.suspend_tenant("tenant-1")
        result = tracker.check_quota("tenant-1")

        assert result.allowed is False
        assert "suspended" in result.message.lower()

    def test_tenant_tier_setting(self):
        """Test setting tenant subscription tier."""
        from api.tenant_usage import SubscriptionTier, TenantUsageTracker

        tracker = TenantUsageTracker()
        tracker.set_tenant_tier("tenant-1", SubscriptionTier.PRO)

        assert tracker._tenant_tiers["tenant-1"] == SubscriptionTier.PRO

    def test_custom_quota_override(self):
        """Test custom quota override."""
        from api.tenant_usage import TenantUsageTracker

        tracker = TenantUsageTracker()
        tracker.set_custom_quota("tenant-1", 5000)

        quota = tracker._get_quota_for_tenant("tenant-1")
        assert quota == 5000


# =============================================================================
# Webhook Security Tests
# =============================================================================


class TestWebhookSecurity:
    """Tests for webhook signature verification."""

    def test_compute_signature(self):
        """Test signature computation."""
        from api.webhook_security import compute_signature

        payload = b'{"test": "data"}'
        secret = "test-secret-key"
        timestamp = 1704067200

        signature = compute_signature(payload, secret, timestamp)

        assert signature.startswith("v1=")
        assert len(signature) > 3

    def test_verify_signature_valid(self):
        """Test verification of valid signature."""
        from api.webhook_security import compute_signature, verify_signature

        payload = b'{"test": "data"}'
        secret = "test-secret-key"
        timestamp = int(time.time())

        signature = compute_signature(payload, secret, timestamp)
        result = verify_signature(payload, signature, timestamp, secret=secret)

        assert result.valid is True

    def test_verify_signature_invalid(self):
        """Test verification of invalid signature."""
        from api.webhook_security import verify_signature

        payload = b'{"test": "data"}'
        secret = "test-secret-key"
        timestamp = int(time.time())

        result = verify_signature(payload, "v1=invalid", timestamp, secret=secret)

        assert result.valid is False

    def test_verify_signature_expired(self):
        """Test verification of expired timestamp."""
        from api.webhook_security import compute_signature, verify_signature

        payload = b'{"test": "data"}'
        secret = "test-secret-key"
        timestamp = int(time.time()) - 600  # 10 minutes ago

        signature = compute_signature(payload, secret, timestamp)
        result = verify_signature(
            payload, signature, timestamp, secret=secret, tolerance=300
        )

        assert result.valid is False
        assert "tolerance" in result.error.lower()


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


class TestCircuitBreaker:
    """Tests for circuit breaker pattern."""

    def test_circuit_breaker_init(self):
        """Test circuit breaker initialization."""
        from api.circuit_breaker import CircuitBreaker, CircuitState

        cb = CircuitBreaker("test-service")

        assert cb.name == "test-service"
        assert cb.state == CircuitState.CLOSED

    def test_circuit_breaker_success(self):
        """Test circuit breaker on successful calls."""
        from api.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker("test-service")

        @cb.protect
        def success_func():
            return "success"

        result = success_func()
        assert result == "success"

        stats = cb.get_stats()
        assert stats.success_count == 1
        assert stats.failure_count == 0

    def test_circuit_breaker_failure(self):
        """Test circuit breaker on failed calls."""
        from api.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("test-service", config)

        @cb.protect
        def fail_func():
            raise ValueError("test error")

        for _ in range(2):
            try:
                fail_func()
            except ValueError:
                pass

        stats = cb.get_stats()
        assert stats.failure_count == 2

    def test_circuit_breaker_opens_on_threshold(self):
        """Test circuit breaker opens after failure threshold."""
        from api.circuit_breaker import (
            CircuitBreaker,
            CircuitBreakerConfig,
            CircuitBreakerError,
            CircuitState,
        )

        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("test-service", config)

        @cb.protect
        def fail_func():
            raise ValueError("test error")

        # Trigger failures to open circuit
        for _ in range(2):
            try:
                fail_func()
            except ValueError:
                pass

        assert cb.state == CircuitState.OPEN

        # Next call should raise CircuitBreakerError
        with pytest.raises(CircuitBreakerError):
            fail_func()

    def test_circuit_breaker_reset(self):
        """Test circuit breaker manual reset."""
        from api.circuit_breaker import (
            CircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker("test-service", config)

        @cb.protect
        def fail_func():
            raise ValueError("test error")

        try:
            fail_func()
        except ValueError:
            pass

        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# Graceful Shutdown Tests
# =============================================================================


class TestGracefulShutdown:
    """Tests for graceful shutdown handling."""

    def test_shutdown_manager_init(self):
        """Test shutdown manager initialization."""
        from api.graceful_shutdown import GracefulShutdownManager, ShutdownState

        manager = GracefulShutdownManager()

        assert manager.state == ShutdownState.RUNNING
        assert manager.is_running is True
        assert manager.is_shutting_down is False

    def test_shutdown_state_transitions(self):
        """Test shutdown state transitions."""
        from api.graceful_shutdown import GracefulShutdownManager, ShutdownState

        manager = GracefulShutdownManager()

        # Initially running
        assert manager.state == ShutdownState.RUNNING
        assert manager.is_healthy is True

    def test_connection_tracking(self):
        """Test connection counting."""
        from api.graceful_shutdown import GracefulShutdownManager

        manager = GracefulShutdownManager()

        manager.increment_connections()
        assert manager._active_connections == 1

        manager.increment_connections()
        assert manager._active_connections == 2

        manager.decrement_connections()
        assert manager._active_connections == 1

    def test_cleanup_hook_registration(self):
        """Test cleanup hook registration."""
        from api.graceful_shutdown import GracefulShutdownManager

        manager = GracefulShutdownManager()

        def cleanup():
            pass

        manager.register_cleanup_hook(cleanup)
        assert cleanup in manager._cleanup_hooks


# =============================================================================
# Security Alerts Tests
# =============================================================================


class TestSecurityAlerts:
    """Tests for security event alerting."""

    def test_alert_severity_comparison(self):
        """Test alert severity comparison."""
        from api.security_alerts import AlertSeverity

        assert AlertSeverity.CRITICAL >= AlertSeverity.ERROR
        assert AlertSeverity.ERROR >= AlertSeverity.WARNING
        assert AlertSeverity.WARNING >= AlertSeverity.INFO
        assert not (AlertSeverity.INFO >= AlertSeverity.WARNING)

    def test_security_alert_creation(self):
        """Test security alert creation."""
        from datetime import datetime, timezone

        from api.security_alerts import AlertCategory, AlertSeverity, SecurityAlert

        alert = SecurityAlert(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.WARNING,
            category=AlertCategory.AUTHENTICATION,
            title="Test Alert",
            message="Test message",
        )

        assert alert.severity == AlertSeverity.WARNING
        assert alert.category == AlertCategory.AUTHENTICATION
        assert alert.title == "Test Alert"

    def test_alert_fingerprint(self):
        """Test alert fingerprint generation."""
        from datetime import datetime, timezone

        from api.security_alerts import AlertCategory, AlertSeverity, SecurityAlert

        alert1 = SecurityAlert(
            id="test-1",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.WARNING,
            category=AlertCategory.AUTHENTICATION,
            title="Test Alert",
            message="Test message",
            tenant_id="tenant-1",
        )

        alert2 = SecurityAlert(
            id="test-2",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.WARNING,
            category=AlertCategory.AUTHENTICATION,
            title="Test Alert",
            message="Different message",
            tenant_id="tenant-1",
        )

        # Same fingerprint for deduplication
        assert alert1.fingerprint() == alert2.fingerprint()

    def test_alert_manager_rate_limiting(self):
        """Test alert manager rate limiting."""
        from api.security_alerts import AlertSeverity, SecurityAlertManager

        manager = SecurityAlertManager(
            min_severity=AlertSeverity.INFO,
            rate_limit_window=60,
            rate_limit_max=2,
        )

        # Should be within limit initially
        assert manager._check_rate_limit() is True
        assert manager._check_rate_limit() is True
        # Third should be rate limited
        assert manager._check_rate_limit() is False


# =============================================================================
# Startup Validation Tests
# =============================================================================


class TestStartupValidation:
    """Tests for startup configuration validation."""

    def test_validation_report(self):
        """Test validation report structure."""
        from api.config.startup_validation import StartupValidationReport

        report = StartupValidationReport()
        report.add("test", True, "Test passed")

        assert len(report.results) == 1
        assert report.has_errors is False
        assert report.has_warnings is False

    def test_api_key_validation(self):
        """Test API key security validation."""
        from api.config.startup_validation import StartupValidator

        validator = StartupValidator()

        # Check that default insecure keys are detected
        assert "changeme" in validator.INSECURE_API_KEYS
        assert "password" in validator.INSECURE_API_KEYS

    def test_validation_with_env(self):
        """Test validation with environment variables."""
        from api.config.startup_validation import validate_startup_config

        with patch.dict(os.environ, {"FG_ENV": "dev", "FG_API_KEY": "CHANGEME"}):
            report = validate_startup_config(log_results=False)

            assert report is not None
            assert report.env == "dev"


# =============================================================================
# Integration Tests
# =============================================================================


class TestSaaSIntegration:
    """Integration tests for SaaS features."""

    def test_admin_router_import(self):
        """Test admin router can be imported."""
        from api.admin import router

        assert router is not None
        assert router.prefix == "/admin"

    def test_usage_tracking_convenience_functions(self):
        """Test convenience functions for usage tracking."""
        from api.tenant_usage import check_tenant_quota, record_tenant_request

        # Check quota for unknown tenant (should allow)
        allowed, error = check_tenant_quota("new-tenant")
        assert allowed is True
        assert error is None

        # Record request
        record = record_tenant_request("new-tenant")
        assert record is not None
        assert record.request_count == 1

    def test_circuit_breaker_registry(self):
        """Test circuit breaker registry."""
        from api.circuit_breaker import get_circuit_breaker_registry

        registry = get_circuit_breaker_registry()

        cb1 = registry.get_or_create("service-1")
        cb2 = registry.get_or_create("service-1")

        # Should return same instance
        assert cb1 is cb2

        # Stats should work
        stats = registry.get_all_stats()
        assert "service-1" in stats
