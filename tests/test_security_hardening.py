"""
Security Hardening Tests for FrostGate Core.

Validates critical security controls:
- API key extraction restrictions (no query params)
- Canary token detection
- Honeypot path detection
- CORS default configuration
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock, patch


class TestApiKeyExtraction:
    """Test that API keys are only accepted from secure sources."""

    def test_query_param_key_not_extracted(self):
        """CRITICAL: API keys in query params must NOT be extracted."""
        from api.auth_scopes import _extract_key

        # Create mock request with query param but no header/cookie
        mock_request = MagicMock()
        mock_request.query_params = {"api_key": "secret_key_in_url"}
        mock_request.cookies = {}

        # No header provided
        result = _extract_key(mock_request, x_api_key=None)

        # Key should NOT be extracted from query param
        assert result is None, (
            "API key was extracted from query param - security vulnerability!"
        )

    def test_query_param_key_param_not_extracted(self):
        """CRITICAL: 'key' query param must NOT be extracted."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {"key": "another_secret_key"}
        mock_request.cookies = {}

        result = _extract_key(mock_request, x_api_key=None)
        assert result is None, (
            "API key was extracted from 'key' query param - security vulnerability!"
        )

    def test_header_key_extracted(self):
        """Header-based API key should be extracted."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}

        result = _extract_key(mock_request, x_api_key="valid_header_key")
        assert result == "valid_header_key"

    def test_cookie_key_extracted(self):
        """Cookie-based API key should be extracted for UI sessions."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {"fg_api_key": "valid_cookie_key"}

        result = _extract_key(mock_request, x_api_key=None)
        assert result == "valid_cookie_key"

    def test_header_takes_precedence_over_cookie(self):
        """Header should take precedence over cookie."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {"fg_api_key": "cookie_key"}

        result = _extract_key(mock_request, x_api_key="header_key")
        assert result == "header_key"


class TestCanaryTokenDetection:
    """Test canary token tripwire detection."""

    def test_canary_key_detected(self):
        """Canary key prefix should trigger detection."""
        from api.tripwires import check_canary_key, CANARY_KEY_PREFIX

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_canary_key(f"{CANARY_KEY_PREFIX}abc123")

            assert result is True, "Canary key should be detected"
            mock_alert.assert_called_once()

            # Verify alert details
            alert = mock_alert.call_args[0][0]
            assert alert.alert_type == "CANARY_TOKEN_ACCESSED"
            assert alert.severity == "CRITICAL"

    def test_normal_key_not_flagged(self):
        """Normal key prefix should not trigger canary detection."""
        from api.tripwires import check_canary_key

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_canary_key("fgk_normal_key")

            assert result is False
            mock_alert.assert_not_called()

    def test_none_key_handled(self):
        """None key should not trigger detection."""
        from api.tripwires import check_canary_key

        result = check_canary_key(None)
        assert result is False


class TestHoneypotPathDetection:
    """Test honeypot endpoint detection."""

    @pytest.mark.parametrize(
        "path",
        [
            "/admin/backup",
            "/admin/export",
            "/.git/config",
            "/.env",
            "/wp-admin",
            "/phpmyadmin",
            "/actuator/env",
            "/debug/vars",
        ],
    )
    def test_honeypot_paths_detected(self, path):
        """Known honeypot paths should trigger detection."""
        from api.tripwires import check_honeypot_path

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_honeypot_path(path)

            assert result is True, f"Honeypot path {path} should be detected"
            mock_alert.assert_called_once()

    def test_normal_paths_not_flagged(self):
        """Normal API paths should not trigger detection."""
        from api.tripwires import check_honeypot_path

        normal_paths = ["/health", "/defend", "/decisions", "/api/v1/data"]

        for path in normal_paths:
            with patch("api.tripwires._emit_alert") as mock_alert:
                result = check_honeypot_path(path)

                assert result is False, f"Normal path {path} should not trigger"
                mock_alert.assert_not_called()


class TestCorsConfig:
    """Test CORS configuration defaults."""

    def test_cors_default_not_allow_all(self):
        """CORS should NOT default to allow all origins."""
        from api.middleware.security_headers import CORSConfig

        config = CORSConfig()

        # Default should be empty list, not ["*"]
        assert config.allow_origins == [], (
            "CORS default should be empty list (deny all), not allow all"
        )

    def test_cors_from_env_parses_origins(self):
        """CORS should parse origins from environment."""
        from api.middleware.security_headers import CORSConfig

        with patch.dict(
            os.environ,
            {"FG_CORS_ORIGINS": "https://app.example.com,https://admin.example.com"},
        ):
            config = CORSConfig.from_env()

            assert "https://app.example.com" in config.allow_origins
            assert "https://admin.example.com" in config.allow_origins


class TestAuthAnomalyDetection:
    """Test authentication anomaly detection."""

    def test_high_failure_rate_detected(self):
        """High auth failure rate should trigger alert."""
        from api.tripwires import check_auth_anomaly

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_auth_anomaly(
                client_ip="192.168.1.100",
                failed_attempts=15,
                threshold=10,
            )

            assert result is True
            mock_alert.assert_called_once()

            alert = mock_alert.call_args[0][0]
            assert alert.alert_type == "AUTH_ANOMALY_DETECTED"
            assert alert.severity == "HIGH"

    def test_normal_failure_rate_not_flagged(self):
        """Normal auth failure rate should not trigger alert."""
        from api.tripwires import check_auth_anomaly

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_auth_anomaly(
                client_ip="192.168.1.100",
                failed_attempts=5,
                threshold=10,
            )

            assert result is False
            mock_alert.assert_not_called()
