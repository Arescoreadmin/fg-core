"""
Startup Configuration Validation for FrostGate Core.

Validates critical security and configuration settings on startup.
Provides warnings for insecure defaults and missing production settings.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Dict, List, Optional

from api.config.env import resolve_env

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


@dataclass(frozen=True)
class ResourceRequirement:
    name: str
    kind: str  # "file" or "dir"
    path: Optional[str] = None
    env_var: Optional[str] = None


@dataclass(frozen=True)
class ComplianceModuleSpec:
    key: str
    display_name: str
    required_env_flags: Dict[str, bool]
    required_imports: List[str]
    required_resources: List[ResourceRequirement]


@dataclass(frozen=True)
class ComplianceModuleState:
    key: str
    display_name: str
    enabled: bool
    import_errors: List[str]
    resource_errors: List[str]


COMPLIANCE_MODULE_SPECS: Dict[str, ComplianceModuleSpec] = {
    "governance": ComplianceModuleSpec(
        key="governance",
        display_name="Governance",
        required_env_flags={"FG_GOVERNANCE_ENABLED": True},
        required_imports=["api.governance"],
        required_resources=[
            ResourceRequirement(name="migrations", kind="dir", path="migrations"),
            ResourceRequirement(name="policy", kind="dir", path="policy"),
        ],
    ),
    "roe_engine": ComplianceModuleSpec(
        key="roe_engine",
        display_name="ROE Engine",
        required_env_flags={"FG_ROE_ENGINE_ENABLED": True},
        required_imports=["api.roe_engine", "engine.doctrine", "engine.pipeline"],
        required_resources=[
            ResourceRequirement(
                name="roe_doctrine", kind="file", path="engine/doctrine.py"
            ),
            ResourceRequirement(
                name="roe_pipeline", kind="file", path="engine/pipeline.py"
            ),
        ],
    ),
    "ring_router": ComplianceModuleSpec(
        key="ring_router",
        display_name="Ring Router",
        required_env_flags={"FG_RING_ROUTER_ENABLED": True},
        required_imports=["api.ring_router"],
        required_resources=[
            ResourceRequirement(
                name="ring_state_dir",
                kind="dir",
                env_var="FG_RING_STATE_DIR",
            ),
            ResourceRequirement(
                name="ring_model_dir",
                kind="dir",
                env_var="FG_RING_MODEL_DIR",
            ),
        ],
    ),
    "mission_envelope": ComplianceModuleSpec(
        key="mission_envelope",
        display_name="Mission Envelope",
        required_env_flags={"FG_MISSION_ENVELOPE_ENABLED": True},
        required_imports=["api.mission_envelope"],
        required_resources=[
            ResourceRequirement(
                name="mission_envelope_path",
                kind="file",
                env_var="FG_MISSION_ENVELOPE_PATH",
            )
        ],
    ),
}


def compliance_module_enabled(key: str) -> bool:
    spec = COMPLIANCE_MODULE_SPECS.get(key)
    if not spec:
        return False
    for env_name, required_value in spec.required_env_flags.items():
        raw = os.getenv(env_name)
        if raw is None:
            return False
        if _env_bool(env_name, default=False) is not bool(required_value):
            return False
    return True


def resolve_compliance_module_states() -> Dict[str, ComplianceModuleState]:
    states: Dict[str, ComplianceModuleState] = {}
    for key, spec in COMPLIANCE_MODULE_SPECS.items():
        enabled = compliance_module_enabled(key)
        import_errors: List[str] = []
        resource_errors: List[str] = []

        for module_path in spec.required_imports:
            try:
                import_module(module_path)
            except Exception:
                import_errors.append(module_path)

        for resource in spec.required_resources:
            resolved_path = None
            if resource.env_var:
                raw = (os.getenv(resource.env_var) or "").strip()
                if not raw:
                    resource_errors.append(f"{resource.env_var} not set")
                    continue
                resolved_path = raw
            elif resource.path:
                resolved_path = resource.path

            if resolved_path:
                path = Path(resolved_path)
                if resource.kind == "file" and not path.is_file():
                    resource_errors.append(f"{resource.name} missing at {resolved_path}")
                elif resource.kind == "dir" and not path.is_dir():
                    resource_errors.append(f"{resource.name} missing at {resolved_path}")

        states[key] = ComplianceModuleState(
            key=spec.key,
            display_name=spec.display_name,
            enabled=enabled,
            import_errors=import_errors,
            resource_errors=resource_errors,
        )
    return states


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
    compliance_modules: Dict[str, "ComplianceModuleState"] = field(default_factory=dict)

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
        "secret",
        "password",
        "changeme",
        "admin",
        "test",
        "demo",
        "development",
    }

    def __init__(self):
        self.env = resolve_env()
        self.is_production = self.env in ("prod", "production", "staging")

    def validate(self) -> StartupValidationReport:
        """Run all validation checks and return a report."""
        report = StartupValidationReport(
            env=self.env,
            is_production=self.is_production,
        )

        self._check_compliance_modules(report)
        self._check_api_key(report)
        self._check_database(report)
        self._check_rate_limiting(report)
        self._check_cors(report)
        self._check_security_headers(report)
        self._check_auth_enabled(report)
        self._check_key_ttl(report)
        self._check_brute_force_protection(report)
        self._check_audit_logging(report)
        self._check_webhook_security(report)
        self._check_redis_config(report)
        self._check_quota_enforcement(report)
        self._check_encryption_keys(report)
        self._check_dos_hardening(report)

        return report

    def _check_compliance_modules(self, report: StartupValidationReport) -> None:
        """Check compliance-critical module requirements."""
        states = resolve_compliance_module_states()
        report.compliance_modules = dict(states)

        for name, state in states.items():
            if not state.enabled:
                report.add(
                    name=f"compliance_{name}_disabled",
                    passed=False,
                    message=f"{state.display_name} disabled. "
                    "Compliance-critical modules must be enabled.",
                    severity="error" if self.is_production else "warning",
                )

            if state.import_errors:
                report.add(
                    name=f"compliance_{name}_imports",
                    passed=False,
                    message=f"{state.display_name} missing imports: "
                    f"{', '.join(state.import_errors)}",
                    severity="error" if self.is_production else "warning",
                )

            if state.resource_errors:
                report.add(
                    name=f"compliance_{name}_resources",
                    passed=False,
                    message=f"{state.display_name} missing resources: "
                    f"{', '.join(state.resource_errors)}",
                    severity="error" if self.is_production else "warning",
                )

    def _check_api_key(self, report: StartupValidationReport) -> None:
        """Check API key security."""
        api_key = _env_str("FG_API_KEY", "")

        if not api_key:
            severity = "error" if self.is_production else "warning"
            report.add(
                name="api_key_missing",
                passed=False,
                message="FG_API_KEY not set. Set a strong, random API key.",
                severity=severity,
            )
            return

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
        db_backend = _env_str("FG_DB_BACKEND", "").lower()
        tenant_mode = _env_str("FG_TENANT_CONTEXT_MODE", "db_session").lower()

        if tenant_mode not in {"db_session", "app_only"}:
            report.add(
                name="tenant_context_mode",
                passed=False,
                message="FG_TENANT_CONTEXT_MODE must be 'db_session' or 'app_only'.",
                severity="error" if self.is_production else "warning",
            )

        if self.is_production and tenant_mode != "db_session":
            report.add(
                name="tenant_context_mode_production",
                passed=False,
                message="Production requires FG_TENANT_CONTEXT_MODE=db_session.",
                severity="error",
            )

        if self.is_production:
            if not db_backend:
                report.add(
                    name="database_backend_missing",
                    passed=False,
                    message="Production requires FG_DB_BACKEND=postgres.",
                    severity="error",
                )
            elif db_backend != "postgres":
                report.add(
                    name="database_backend",
                    passed=False,
                    message="Production requires FG_DB_BACKEND=postgres.",
                    severity="error",
                )
            if not db_url:
                report.add(
                    name="database_production",
                    passed=False,
                    message="FG_DB_URL not set. Production must use PostgreSQL.",
                    severity="error",
                )
                return

        if db_url:
            if "@" in db_url and "://" in db_url:
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
        cors_origins = _env_str("FG_CORS_ORIGINS", "")

        if self.is_production and (not cors_origins or cors_origins == "*"):
            report.add(
                name="cors_wildcard",
                passed=False,
                message="CORS must be explicitly configured in production "
                "(no wildcard, no empty value).",
                severity="error",
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

    def _check_key_ttl(self, report: StartupValidationReport) -> None:
        """Check API key TTL configuration."""
        default_ttl = _env_int("FG_KEY_DEFAULT_TTL", 24 * 3600)  # 24 hours default

        if self.is_production:
            # Production should have reasonable key TTL
            if default_ttl > 7 * 24 * 3600:  # > 7 days
                report.add(
                    name="key_ttl_long",
                    passed=False,
                    message=f"API key TTL is very long ({default_ttl // 3600}h). "
                    "Consider shorter TTL for production (< 7 days).",
                    severity="warning",
                )
            else:
                report.add(
                    name="key_ttl",
                    passed=True,
                    message=f"API key TTL configured: {default_ttl // 3600}h",
                    severity="info",
                )

    def _check_brute_force_protection(self, report: StartupValidationReport) -> None:
        """Check brute force protection settings."""
        bf_threshold = _env_int("FG_BRUTE_FORCE_THRESHOLD", 10)
        bf_window = _env_int("FG_BRUTE_FORCE_WINDOW", 300)

        if bf_threshold > 50:
            report.add(
                name="brute_force_threshold_high",
                passed=False,
                message=f"Brute force threshold is high ({bf_threshold}). "
                "Consider lower threshold (10-20) for better protection.",
                severity="warning",
            )
        elif bf_threshold < 3:
            report.add(
                name="brute_force_threshold_low",
                passed=False,
                message=f"Brute force threshold is very low ({bf_threshold}). "
                "May cause false positives for legitimate users.",
                severity="warning",
            )
        else:
            report.add(
                name="brute_force_protection",
                passed=True,
                message=f"Brute force protection: {bf_threshold} attempts / {bf_window}s",
                severity="info",
            )

    def _check_audit_logging(self, report: StartupValidationReport) -> None:
        """Check audit logging configuration."""
        audit_db = _env_bool("FG_AUDIT_PERSIST_DB", True)
        log_level = _env_str("FG_LOG_LEVEL", "INFO").upper()

        if self.is_production and not audit_db:
            report.add(
                name="audit_logging_disabled",
                passed=False,
                message="Security audit DB persistence is disabled. "
                "Enable FG_AUDIT_PERSIST_DB for compliance.",
                severity="error",
            )
        else:
            report.add(
                name="audit_logging",
                passed=True,
                message=f"Audit logging enabled (DB: {audit_db}, Level: {log_level})",
                severity="info",
            )

        # Check if debug logging in production
        if self.is_production and log_level == "DEBUG":
            report.add(
                name="debug_logging_production",
                passed=False,
                message="DEBUG logging in production may expose sensitive data. "
                "Use INFO or WARNING.",
                severity="warning",
            )

    def _check_webhook_security(self, report: StartupValidationReport) -> None:
        """Check webhook security configuration."""
        webhook_secret = _env_str("FG_WEBHOOK_SECRET", "")

        if self.is_production and not webhook_secret:
            report.add(
                name="webhook_secret_missing",
                passed=False,
                message="FG_WEBHOOK_SECRET not set. Required for secure webhook integration.",
                severity="error",
            )
        elif webhook_secret and len(webhook_secret) < 32:
            report.add(
                name="webhook_secret_weak",
                passed=False,
                message=f"FG_WEBHOOK_SECRET is weak ({len(webhook_secret)} chars). "
                "Use at least 32 characters.",
                severity="warning" if not self.is_production else "error",
            )
        elif webhook_secret:
            report.add(
                name="webhook_security",
                passed=True,
                message="Webhook secret configured.",
                severity="info",
            )

    def _check_redis_config(self, report: StartupValidationReport) -> None:
        """Check Redis configuration for production."""
        redis_url = _env_str("FG_REDIS_URL", "")
        rl_backend = _env_str("FG_RL_BACKEND", "memory").lower()

        if self.is_production:
            if not redis_url and rl_backend == "redis":
                report.add(
                    name="redis_url_missing",
                    passed=False,
                    message="FG_REDIS_URL not set but rate limiting backend is redis.",
                    severity="error",
                )
            elif not redis_url:
                report.add(
                    name="redis_recommended",
                    passed=True,
                    message="Redis not configured. Recommended for distributed deployments.",
                    severity="info",
                )
            else:
                # Check for TLS in Redis URL
                if not redis_url.startswith("rediss://"):
                    report.add(
                        name="redis_tls",
                        passed=False,
                        message="Redis URL doesn't use TLS (rediss://). "
                        "Consider using TLS for production.",
                        severity="warning",
                    )
                else:
                    report.add(
                        name="redis_config",
                        passed=True,
                        message="Redis configured with TLS.",
                        severity="info",
                    )

    def _check_quota_enforcement(self, report: StartupValidationReport) -> None:
        """Check tenant quota enforcement configuration."""
        quota_enabled = _env_bool("FG_QUOTA_ENFORCEMENT_ENABLED", True)
        quota_free = _env_int("FG_QUOTA_FREE_DAILY", 1000)

        if self.is_production and not quota_enabled:
            report.add(
                name="quota_enforcement_disabled",
                passed=False,
                message="Quota enforcement is disabled. Enable for SaaS billing protection.",
                severity="error",
            )
        elif quota_enabled:
            report.add(
                name="quota_enforcement",
                passed=True,
                message=f"Quota enforcement enabled (free tier: {quota_free}/day).",
                severity="info",
            )

    def _check_encryption_keys(self, report: StartupValidationReport) -> None:
        """Check for encryption key configuration."""
        encryption_key = _env_str("FG_ENCRYPTION_KEY", "")
        jwt_secret = _env_str("FG_JWT_SECRET", "")

        if self.is_production:
            if not encryption_key:
                report.add(
                    name="encryption_key_missing",
                    passed=False,
                    message="FG_ENCRYPTION_KEY not set. Required for encrypting sensitive data.",
                    severity="error",
                )
            elif len(encryption_key) < 32:
                report.add(
                    name="encryption_key_weak",
                    passed=False,
                    message="FG_ENCRYPTION_KEY is too short. Use at least 32 characters.",
                    severity="error",
                )

            if not jwt_secret:
                report.add(
                    name="jwt_secret_missing",
                    passed=False,
                    message="FG_JWT_SECRET not set. Required for JWT token signing.",
                    severity="error",
                )
            elif len(jwt_secret) < 32:
                report.add(
                    name="jwt_secret_weak",
                    passed=False,
                    message="FG_JWT_SECRET is too short. Use at least 32 characters.",
                    severity="error",
                )

    def _check_dos_hardening(self, report: StartupValidationReport) -> None:
        """Check DoS guard and transport hardening configuration."""
        enabled = _env_bool("FG_DOS_GUARD_ENABLED", True)
        if self.is_production and not enabled:
            report.add(
                name="dos_guard_enabled",
                passed=False,
                message="FG_DOS_GUARD_ENABLED must be true in production.",
                severity="error",
            )

        required_positive_ints = {
            "FG_MAX_BODY_BYTES": 1024 * 1024,
            "FG_MAX_QUERY_BYTES": 8 * 1024,
            "FG_MAX_PATH_BYTES": 2 * 1024,
            "FG_MAX_HEADERS_COUNT": 100,
            "FG_MAX_HEADERS_BYTES": 16 * 1024,
            "FG_MAX_HEADER_LINE_BYTES": 8 * 1024,
            "FG_MULTIPART_MAX_BYTES": 5 * 1024 * 1024,
            "FG_MULTIPART_MAX_PARTS": 50,
            "FG_MAX_CONCURRENT_REQUESTS": 100,
            "FG_KEEPALIVE_TIMEOUT_SEC": 5,
        }
        for key, default in required_positive_ints.items():
            raw = os.getenv(key)
            value = _env_int(key, default)
            if value <= 0:
                report.add(
                    name=f"{key.lower()}_invalid",
                    passed=False,
                    message=f"{key} must be > 0.",
                    severity="error" if self.is_production else "warning",
                )
                continue
            if self.is_production and (raw is None or raw.strip() == ""):
                report.add(
                    name=f"{key.lower()}_missing",
                    passed=False,
                    message=f"{key} must be explicitly set in production.",
                    severity="error",
                )

        request_timeout_raw = os.getenv("FG_REQUEST_TIMEOUT_SEC")
        request_timeout = _env_int("FG_REQUEST_TIMEOUT_SEC", 15)
        if request_timeout <= 0:
            report.add(
                name="request_timeout_invalid",
                passed=False,
                message="FG_REQUEST_TIMEOUT_SEC must be > 0.",
                severity="error" if self.is_production else "warning",
            )
        elif self.is_production and (
            request_timeout_raw is None or request_timeout_raw.strip() == ""
        ):
            report.add(
                name="request_timeout_missing",
                passed=False,
                message="FG_REQUEST_TIMEOUT_SEC must be explicitly set in production.",
                severity="error",
            )

        if not self.is_production:
            report.add(
                name="dos_hardening",
                passed=True,
                message="DoS hardening checks completed.",
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

    if fail_on_error and report.has_errors:
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
    "ComplianceModuleSpec",
    "ComplianceModuleState",
    "COMPLIANCE_MODULE_SPECS",
    "compliance_module_enabled",
    "resolve_compliance_module_states",
    "validate_startup_config",
]
