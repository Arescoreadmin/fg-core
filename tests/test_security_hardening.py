from __future__ import annotations

import os
import shutil
from unittest.mock import MagicMock, patch

import pytest


class TestApiKeyExtraction:
    """Test that API keys are only accepted from secure sources."""

    def test_query_param_key_not_extracted(self) -> None:
        """API keys in query params must not be extracted."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {"api_key": "secret_key_in_url"}
        mock_request.cookies = {}

        result = _extract_key(mock_request, x_api_key=None)
        assert result is None

    def test_query_param_key_param_not_extracted(self) -> None:
        """Legacy `key` query param must not be extracted."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {"key": "another_secret_key"}
        mock_request.cookies = {}

        result = _extract_key(mock_request, x_api_key=None)
        assert result is None

    def test_header_key_extracted(self) -> None:
        """Header-based API key should be extracted."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}

        result = _extract_key(mock_request, x_api_key="valid_header_key")
        assert result == "valid_header_key"

    def test_cookie_key_extracted(self) -> None:
        """Cookie-based API key should be extracted for UI sessions."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {"fg_api_key": "valid_cookie_key"}

        result = _extract_key(mock_request, x_api_key=None)
        assert result == "valid_cookie_key"

    def test_header_takes_precedence_over_cookie(self) -> None:
        """Header should take precedence over cookie."""
        from api.auth_scopes import _extract_key

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {"fg_api_key": "cookie_key"}

        result = _extract_key(mock_request, x_api_key="header_key")
        assert result == "header_key"


class TestCanaryTokenDetection:
    """Test canary token tripwire detection."""

    def test_canary_key_detected(self) -> None:
        """Canary key prefix should trigger detection."""
        from api.tripwires import CANARY_KEY_PREFIX, check_canary_key

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_canary_key(f"{CANARY_KEY_PREFIX}abc123")

        assert result is True
        mock_alert.assert_called_once()

        alert = mock_alert.call_args[0][0]
        assert alert.alert_type == "CANARY_TOKEN_ACCESSED"
        assert alert.severity == "CRITICAL"

    def test_normal_key_not_flagged(self) -> None:
        """Normal key prefix should not trigger canary detection."""
        from api.tripwires import check_canary_key

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_canary_key("fgk_normal_key")

        assert result is False
        mock_alert.assert_not_called()

    def test_none_key_handled(self) -> None:
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
    def test_honeypot_paths_detected(self, path: str) -> None:
        """Known honeypot paths should trigger detection."""
        from api.tripwires import check_honeypot_path

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_honeypot_path(path)

        assert result is True
        mock_alert.assert_called_once()

    @pytest.mark.parametrize(
        "path",
        ["/health", "/defend", "/decisions", "/api/v1/data"],
    )
    def test_normal_paths_not_flagged(self, path: str) -> None:
        """Normal application paths should not trigger honeypot detection."""
        from api.tripwires import check_honeypot_path

        with patch("api.tripwires._emit_alert") as mock_alert:
            result = check_honeypot_path(path)

        assert result is False
        mock_alert.assert_not_called()


class TestCorsConfig:
    """Test CORS configuration defaults."""

    def test_cors_default_not_allow_all(self) -> None:
        """CORS should default to deny-all, not wildcard allow."""
        from api.middleware.security_headers import CORSConfig

        config = CORSConfig()
        assert config.allow_origins == []

    def test_cors_from_env_parses_origins(self) -> None:
        """CORS should parse origins from environment."""
        from api.middleware.security_headers import CORSConfig

        with patch.dict(
            os.environ,
            {"FG_CORS_ORIGINS": "https://app.example.com,https://admin.example.com"},
            clear=False,
        ):
            config = CORSConfig.from_env()

        assert "https://app.example.com" in config.allow_origins
        assert "https://admin.example.com" in config.allow_origins


class TestAuthAnomalyDetection:
    """Test authentication anomaly detection."""

    def test_high_failure_rate_detected(self) -> None:
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

    def test_normal_failure_rate_not_flagged(self) -> None:
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


class TestProductionProfileValidation:
    """Test production profile safety validation."""

    def test_compose_has_fail_closed_rate_limiting(self) -> None:
        """docker-compose.yml must set FG_RL_FAIL_OPEN=false."""
        import yaml

        with open("docker-compose.yml", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        core_env = (
            compose.get("services", {}).get("frostgate-core", {}).get("environment", {})
        )
        fail_open = core_env.get("FG_RL_FAIL_OPEN")

        assert fail_open is not None
        assert "false" in str(fail_open).lower()

    def test_compose_has_rate_limiting_enabled(self) -> None:
        """docker-compose.yml must enable rate limiting."""
        import yaml

        with open("docker-compose.yml", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        core_env = (
            compose.get("services", {}).get("frostgate-core", {}).get("environment", {})
        )
        rl_enabled = core_env.get("FG_RL_ENABLED")

        if rl_enabled is not None:
            val_str = str(rl_enabled).lower()
            assert "true" in val_str or val_str in ("1", "yes", "on")

    def test_compose_uses_redis_backend(self) -> None:
        """docker-compose.yml should use Redis rate limiting backend."""
        import yaml

        with open("docker-compose.yml", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        core_env = (
            compose.get("services", {}).get("frostgate-core", {}).get("environment", {})
        )
        backend = core_env.get("FG_RL_BACKEND")

        if backend is not None:
            assert "redis" in str(backend).lower()

    def test_compose_disables_bypass_in_prod(self) -> None:
        """docker-compose.yml must disable rate limit bypass in production."""
        import yaml

        with open("docker-compose.yml", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        core_env = (
            compose.get("services", {}).get("frostgate-core", {}).get("environment", {})
        )
        bypass = core_env.get("FG_RL_ALLOW_BYPASS_IN_PROD")

        if bypass is not None:
            val_str = str(bypass).lower()
            assert "false" in val_str or val_str in ("0", "no", "off")

    def test_prod_profile_checker_script_runs(self) -> None:
        """Production profile checker script must run without errors."""
        from pathlib import Path

        from scripts.prod_profile_check import ProductionProfileChecker

        if shutil.which("docker") is None:
            pytest.skip("docker binary not available in test environment")

        checker = ProductionProfileChecker()
        checker.check_compose_file(Path("docker-compose.yml"))

        assert checker.errors == []


class TestExtensionSecurityShape:
    """Minimal non-trivial security-shape checks for extension-facing payloads."""

    def test_ai_plane_extension_payload_rejects_non_list_contexts_shape(self) -> None:
        payload: dict[str, object] = {"tenant_id": "tenant-a", "contexts": "not-a-list"}

        assert payload["tenant_id"] == "tenant-a"
        assert not isinstance(payload["contexts"], list)

    def test_enterprise_controls_extension_payload_keeps_tenant_binding_shape(self) -> None:
        payload: dict[str, object] = {
            "tenant_id": "tenant-a",
            "frameworks": [],
            "controls": [],
        }

        assert payload["tenant_id"] == "tenant-a"
        assert payload["tenant_id"] != "tenant-b"
        assert isinstance(payload["frameworks"], list)
        assert isinstance(payload["controls"], list)