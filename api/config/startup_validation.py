"""
Startup Configuration Validation for FrostGate Core.

Validates critical security and configuration settings on startup.
Provides warnings for insecure defaults and missing production settings.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger("frostgate.startup")
_security_log = logging.getLogger("frostgate.security")


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


@dataclass
class ValidationResult:
    """Result of a single validation check."""

    name: str
    passed: bool
    message: str
    severity: str = "warning"  # warning, error, info


@dataclass
class StartupValidationReport:
    """Complete validation report."""

    results: List[ValidationResult] = field(default_factory=list)
    env: str = "dev"
    is_production: bool = False

    @property
    def has_errors(self) -> bool:
        return any(r.severity == "error" and not r.passed for r in self.results)

    @property
    def has_warnings(self) -> bool:
        return any(r.severity == "warning" and not r.passed for r in self.results)

    def add(
        self, name: str, passed: bool, message: str, severity: str = "warning"
    ) -> None:
        self.results.append(
            ValidationResult(
                name=name, passed=passed, message=message, severity=severity
            )
        )


class StartupValidator:
    """
    Validates critical configuration settings on startup.

    Checks:
    - API key security (not using default in production)
    - Database configuration
    - Rate limiting configuration
    - CORS configuration
    - Security headers
    - Logging configuration
    """

    # Known insecure default values
    INSECURE_API_KEYS = {
        "supersecret",
        "secret",
        "password",
        "changeme",
        "admin",
        "test",
        "demo",
        "development",
    }

    def __init__(self):
        self.env = _env_str("FG_ENV", "dev").lower()
        self.is_production = self.env in ("prod", "production", "staging")

    def validate(self) -> StartupValidationReport:
        """Run all validation checks and return a report."""
        report = StartupValidationReport(
            env=self.env,
            is_production=self.is_production,
        )

        self._check_api_key(report)
        self._check_database(report)
        self._check_rate_limiting(report)
        self._check_cors(report)
        self._check_security_headers(report)
        self._check_auth_enabled(report)

        return report

    def _check_api_key(self, report: StartupValidationReport) -> None:
        """Check API key security."""
        api_key = _env_str("FG_API_KEY", "supersecret")

        if api_key.lower() in self.INSECURE_API_KEYS:
            severity = "error" if self.is_production else "warning"
            report.add(
                name="api_key_security",
                passed=False,
                message="FG_API_KEY uses insecure default value. "
                "Set a strong, random API key for production.",
                severity=severity,
            )
        elif len(api_key) < 16:
            severity = "error" if self.is_production else "warning"
            report.add(
                name="api_key_length",
                passed=False,
                message=f"FG_API_KEY is too short ({len(api_key)} chars). "
                f"Use at least 32 characters for production.",
                severity=severity,
            )
        else:
            report.add(
                name="api_key_security",
                passed=True,
                message="API key passes basic security checks.",
                severity="info",
            )

    def _check_database(self, report: StartupValidationReport) -> None:
        """Check database configuration."""
        db_url = _env_str("FG_DB_URL", "")
        sqlite_path = _env_str("FG_SQLITE_PATH", "")

        if self.is_production and not db_url:
            report.add(
                name="database_production",
                passed=False,
                message="FG_DB_URL not set. Production should use PostgreSQL, not SQLite.",
                severity="warning",
            )
        elif db_url:
            # Check for credentials in URL (basic check)
            if "@" in db_url and "://" in db_url:
                # Has credentials, which is expected for database connections
                report.add(
                    name="database_config",
                    passed=True,
                    message="Database URL configured with credentials.",
                    severity="info",
                )
        else:
            report.add(
                name="database_config",
                passed=True,
                message=f"Using SQLite at: {sqlite_path or 'default path'}",
                severity="info",
            )

    def _check_rate_limiting(self, report: StartupValidationReport) -> None:
        """Check rate limiting configuration."""
        rl_enabled = _env_bool("FG_RL_ENABLED", True)
        rl_backend = _env_str("FG_RL_BACKEND", "memory").lower()

        if not rl_enabled:
            severity = "error" if self.is_production else "warning"
            report.add(
                name="rate_limiting_disabled",
                passed=False,
                message="Rate limiting is disabled. Enable for DoS protection.",
                severity=severity,
            )
        elif self.is_production and rl_backend == "memory":
            report.add(
                name="rate_limiting_backend",
                passed=False,
                message="Rate limiting uses in-memory backend. "
                "Use Redis for distributed rate limiting in production.",
                severity="warning",
            )
        else:
            report.add(
                name="rate_limiting",
                passed=True,
                message=f"Rate limiting enabled with {rl_backend} backend.",
                severity="info",
            )

    def _check_cors(self, report: StartupValidationReport) -> None:
        """Check CORS configuration."""
        cors_origins = _env_str("FG_CORS_ORIGINS", "*")

        if self.is_production and cors_origins == "*":
            report.add(
                name="cors_wildcard",
                passed=False,
                message="CORS allows all origins (*). "
                "Restrict to specific domains in production.",
                severity="warning",
            )
        else:
            report.add(
                name="cors_config",
                passed=True,
                message=f"CORS origins: {cors_origins[:50]}...",
                severity="info",
            )

    def _check_security_headers(self, report: StartupValidationReport) -> None:
        """Check security headers configuration."""
        hsts_enabled = _env_bool("FG_HSTS_ENABLED", True)
        csp_enabled = _env_bool("FG_CSP_ENABLED", True)

        if not hsts_enabled and self.is_production:
            report.add(
                name="hsts_disabled",
                passed=False,
                message="HSTS is disabled. Enable for HTTPS enforcement.",
                severity="warning",
            )

        if not csp_enabled and self.is_production:
            report.add(
                name="csp_disabled",
                passed=False,
                message="Content-Security-Policy is disabled. Enable for XSS protection.",
                severity="warning",
            )

        if hsts_enabled and csp_enabled:
            report.add(
                name="security_headers",
                passed=True,
                message="Security headers (HSTS, CSP) are enabled.",
                severity="info",
            )

    def _check_auth_enabled(self, report: StartupValidationReport) -> None:
        """Check authentication configuration."""
        auth_enabled_str = os.getenv("FG_AUTH_ENABLED")
        api_key = _env_str("FG_API_KEY", "")

        if auth_enabled_str is not None:
            auth_enabled = _env_bool("FG_AUTH_ENABLED", False)
        else:
            auth_enabled = bool(api_key)

        if not auth_enabled and self.is_production:
            report.add(
                name="auth_disabled_production",
                passed=False,
                message="Authentication is disabled in production. "
                "Set FG_AUTH_ENABLED=1 and FG_API_KEY.",
                severity="error",
            )
        elif not auth_enabled:
            report.add(
                name="auth_disabled",
                passed=False,
                message="Authentication is disabled. Enable for protected endpoints.",
                severity="warning",
            )
        else:
            report.add(
                name="auth_enabled",
                passed=True,
                message="Authentication is enabled.",
                severity="info",
            )


def validate_startup_config(
    fail_on_error: bool = False,
    log_results: bool = True,
) -> StartupValidationReport:
    """
    Validate startup configuration and optionally log results.

    Args:
        fail_on_error: If True, raise RuntimeError on validation errors in production.
        log_results: If True, log validation results.

    Returns:
        StartupValidationReport with all validation results.
    """
    validator = StartupValidator()
    report = validator.validate()

    if log_results:
        _log_validation_report(report)

    if fail_on_error and report.has_errors and report.is_production:
        error_messages = [
            r.message for r in report.results if r.severity == "error" and not r.passed
        ]
        raise RuntimeError(
            f"Startup validation failed with {len(error_messages)} error(s): "
            f"{'; '.join(error_messages)}"
        )

    return report


def _log_validation_report(report: StartupValidationReport) -> None:
    """Log validation report results."""
    env_tag = "PRODUCTION" if report.is_production else report.env.upper()
    _security_log.info(f"Startup validation for environment: {env_tag}")

    for result in report.results:
        if not result.passed:
            if result.severity == "error":
                _security_log.error(f"[FAIL] {result.name}: {result.message}")
            else:
                _security_log.warning(f"[WARN] {result.name}: {result.message}")
        else:
            _security_log.debug(f"[PASS] {result.name}: {result.message}")

    if report.has_errors:
        _security_log.error(
            "Startup validation completed with ERRORS. "
            "Review configuration before production deployment."
        )
    elif report.has_warnings:
        _security_log.warning(
            "Startup validation completed with warnings. "
            "Review configuration for production readiness."
        )
    else:
        _security_log.info("Startup validation completed successfully.")


# Export for convenience
__all__ = [
    "StartupValidator",
    "StartupValidationReport",
    "ValidationResult",
    "validate_startup_config",
]
