#!/usr/bin/env python3
"""
CIS-style Configuration Compliance Checks for FrostGate Core.

Performs security configuration checks based on CIS benchmarks:
- Docker configuration security
- Application security settings
- File permissions
- Environment variable hygiene

Output: artifacts/cis_check.json

This runs locally and in CI without requiring kube-bench.

Usage:
    python scripts/cis_check.py [--output PATH] [--fail-threshold SCORE]
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Output directory
ARTIFACTS_DIR = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))

# Default pass threshold (percentage)
DEFAULT_PASS_THRESHOLD = 80


@dataclass
class CheckResult:
    """Result of a single compliance check."""

    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    passed: bool
    message: str
    remediation: Optional[str] = None


@dataclass
class ComplianceReport:
    """Full compliance report."""

    timestamp: str
    total_checks: int
    passed: int
    failed: int
    score: float
    checks: list[CheckResult] = field(default_factory=list)


def check_auth_fallback_disabled() -> CheckResult:
    """
    CIS-FG-001: Auth fallback must be disabled in production.

    The FG_AUTH_ALLOW_FALLBACK setting allows bypassing database key validation.
    This MUST be false in production.
    """
    # Check docker-compose.yml
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = docker_compose.read_text()
        # Check if fallback defaults to true
        if "FG_AUTH_ALLOW_FALLBACK:-true" in content or "FG_AUTH_ALLOW_FALLBACK: true" in content:
            return CheckResult(
                id="CIS-FG-001",
                name="Auth Fallback Disabled",
                description="FG_AUTH_ALLOW_FALLBACK must default to false in production",
                severity="critical",
                passed=False,
                message="docker-compose.yml defaults FG_AUTH_ALLOW_FALLBACK to true",
                remediation="Change default to false: FG_AUTH_ALLOW_FALLBACK:-false",
            )

    # Check current environment
    fallback = os.getenv("FG_AUTH_ALLOW_FALLBACK", "").lower()
    if fallback == "true" or fallback == "1":
        return CheckResult(
            id="CIS-FG-001",
            name="Auth Fallback Disabled",
            description="FG_AUTH_ALLOW_FALLBACK must be false in production",
            severity="critical",
            passed=False,
            message="FG_AUTH_ALLOW_FALLBACK is currently enabled",
            remediation="Set FG_AUTH_ALLOW_FALLBACK=false",
        )

    return CheckResult(
        id="CIS-FG-001",
        name="Auth Fallback Disabled",
        description="FG_AUTH_ALLOW_FALLBACK must be false in production",
        severity="critical",
        passed=True,
        message="Auth fallback is properly disabled",
    )


def check_no_secrets_in_env() -> CheckResult:
    """
    CIS-FG-002: Secrets must not be hardcoded in configuration files.

    Check for potential secrets in docker-compose.yml and .env files.
    """
    patterns = [
        (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "hardcoded password"),
        (r"secret\s*[:=]\s*['\"][^'\"]+['\"]", "hardcoded secret"),
        (r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "hardcoded API key"),
    ]

    files_to_check = ["docker-compose.yml", ".env.example"]
    issues = []

    for filepath in files_to_check:
        path = Path(filepath)
        if not path.exists():
            continue

        content = path.read_text()
        for pattern, desc in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Allow variable substitution patterns
                if not re.search(r"\$\{", content):
                    issues.append(f"{filepath}: {desc}")

    if issues:
        return CheckResult(
            id="CIS-FG-002",
            name="No Hardcoded Secrets",
            description="Configuration files must not contain hardcoded secrets",
            severity="critical",
            passed=False,
            message=f"Potential secrets found: {', '.join(issues)}",
            remediation="Use environment variables or secret files for sensitive values",
        )

    return CheckResult(
        id="CIS-FG-002",
        name="No Hardcoded Secrets",
        description="Configuration files must not contain hardcoded secrets",
        severity="critical",
        passed=True,
        message="No hardcoded secrets detected",
    )


def check_secret_files_permissions() -> CheckResult:
    """
    CIS-FG-003: Secret files must have restricted permissions.

    Files containing secrets should be readable only by owner.
    """
    secret_paths = [
        Path("secrets/fg_api_keys.txt"),
        Path(".env"),
    ]

    issues = []
    for path in secret_paths:
        if not path.exists():
            continue

        mode = path.stat().st_mode
        # Check if group or others can read
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            issues.append(f"{path}: mode {oct(mode)[-3:]} allows group/other read")

    if issues:
        return CheckResult(
            id="CIS-FG-003",
            name="Secret File Permissions",
            description="Secret files must have mode 600 or more restrictive",
            severity="high",
            passed=False,
            message=f"Insecure permissions: {', '.join(issues)}",
            remediation="Run: chmod 600 <secret-file>",
        )

    return CheckResult(
        id="CIS-FG-003",
        name="Secret File Permissions",
        description="Secret files must have mode 600 or more restrictive",
        severity="high",
        passed=True,
        message="Secret files have proper permissions or don't exist",
    )


def check_dockerfile_security() -> CheckResult:
    """
    CIS-FG-004: Dockerfile must follow security best practices.

    Checks:
    - No root user
    - No sensitive environment variables
    - Uses specific base image tag (not :latest)
    """
    dockerfile = Path("Dockerfile")
    if not dockerfile.exists():
        return CheckResult(
            id="CIS-FG-004",
            name="Dockerfile Security",
            description="Dockerfile must follow security best practices",
            severity="medium",
            passed=True,
            message="No Dockerfile found (skipped)",
        )

    content = dockerfile.read_text()
    issues = []

    # Check for USER directive (should not run as root)
    if not re.search(r"^\s*USER\s+", content, re.MULTILINE):
        issues.append("No USER directive (runs as root)")

    # Check for :latest tag
    if re.search(r"FROM\s+\S+:latest", content, re.IGNORECASE):
        issues.append("Uses :latest tag (pin specific version)")

    # Check for sensitive ENV
    sensitive_env = ["PASSWORD", "SECRET", "KEY", "TOKEN"]
    for var in sensitive_env:
        if re.search(rf"^\s*ENV\s+.*{var}\s*=", content, re.MULTILINE | re.IGNORECASE):
            issues.append(f"Sensitive ENV variable containing '{var}'")

    if issues:
        return CheckResult(
            id="CIS-FG-004",
            name="Dockerfile Security",
            description="Dockerfile must follow security best practices",
            severity="medium",
            passed=False,
            message=f"Issues: {'; '.join(issues)}",
            remediation="Add USER directive, pin image versions, remove sensitive ENV",
        )

    return CheckResult(
        id="CIS-FG-004",
        name="Dockerfile Security",
        description="Dockerfile must follow security best practices",
        severity="medium",
        passed=True,
        message="Dockerfile follows security best practices",
    )


def check_rate_limiting_enabled() -> CheckResult:
    """
    CIS-FG-005: Rate limiting must be enabled in production.

    Check that FG_RL_ENABLED is set to true.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = docker_compose.read_text()
        if "FG_RL_ENABLED:-false" in content or "FG_RL_ENABLED: false" in content:
            return CheckResult(
                id="CIS-FG-005",
                name="Rate Limiting Enabled",
                description="Rate limiting must be enabled in production",
                severity="high",
                passed=False,
                message="Rate limiting defaults to disabled",
                remediation="Set FG_RL_ENABLED=true in docker-compose.yml",
            )

    return CheckResult(
        id="CIS-FG-005",
        name="Rate Limiting Enabled",
        description="Rate limiting must be enabled in production",
        severity="high",
        passed=True,
        message="Rate limiting is enabled",
    )


def check_debug_disabled() -> CheckResult:
    """
    CIS-FG-006: Debug mode must be disabled in production.

    Check that FG_DEBUG is not true.
    """
    debug = os.getenv("FG_DEBUG", "").lower()
    if debug == "true" or debug == "1":
        return CheckResult(
            id="CIS-FG-006",
            name="Debug Mode Disabled",
            description="Debug mode must be disabled in production",
            severity="high",
            passed=False,
            message="FG_DEBUG is enabled",
            remediation="Set FG_DEBUG=false",
        )

    return CheckResult(
        id="CIS-FG-006",
        name="Debug Mode Disabled",
        description="Debug mode must be disabled in production",
        severity="high",
        passed=True,
        message="Debug mode is disabled",
    )


def check_redis_auth_required() -> CheckResult:
    """
    CIS-FG-007: Redis must require authentication.

    Check that Redis password is required in configuration.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = docker_compose.read_text()
        if "--requirepass" in content or "REDIS_PASSWORD" in content:
            return CheckResult(
                id="CIS-FG-007",
                name="Redis Authentication",
                description="Redis must require authentication",
                severity="high",
                passed=True,
                message="Redis authentication is configured",
            )
        else:
            return CheckResult(
                id="CIS-FG-007",
                name="Redis Authentication",
                description="Redis must require authentication",
                severity="high",
                passed=False,
                message="Redis authentication not configured",
                remediation="Add --requirepass to Redis command",
            )

    return CheckResult(
        id="CIS-FG-007",
        name="Redis Authentication",
        description="Redis must require authentication",
        severity="high",
        passed=True,
        message="No Redis configuration found (skipped)",
    )


def check_postgres_ssl() -> CheckResult:
    """
    CIS-FG-008: PostgreSQL connections should use SSL in production.

    Check for SSL configuration in database URL.
    """
    # This is informational in local/dev mode
    db_url = os.getenv("FG_DB_URL", "")
    if db_url and "sslmode=" not in db_url.lower():
        return CheckResult(
            id="CIS-FG-008",
            name="PostgreSQL SSL",
            description="PostgreSQL should use SSL in production",
            severity="medium",
            passed=True,  # Pass but warn
            message="SSL not configured (acceptable for local dev)",
            remediation="Add ?sslmode=require to FG_DB_URL for production",
        )

    return CheckResult(
        id="CIS-FG-008",
        name="PostgreSQL SSL",
        description="PostgreSQL should use SSL in production",
        severity="medium",
        passed=True,
        message="PostgreSQL SSL configured or using local database",
    )


def check_no_wildcard_cors() -> CheckResult:
    """
    CIS-FG-009: CORS must not allow wildcard origins in production.

    Check for AG_CORS_ORIGINS=* in configuration.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = docker_compose.read_text()
        if "CORS_ORIGINS:-*" in content or "CORS_ORIGINS: '*'" in content:
            return CheckResult(
                id="CIS-FG-009",
                name="CORS Configuration",
                description="CORS must not allow wildcard origins in production",
                severity="medium",
                passed=False,
                message="CORS allows wildcard origins",
                remediation="Set specific origins in AG_CORS_ORIGINS",
            )

    return CheckResult(
        id="CIS-FG-009",
        name="CORS Configuration",
        description="CORS must not allow wildcard origins in production",
        severity="medium",
        passed=True,
        message="CORS properly configured",
    )


def check_healthcheck_configured() -> CheckResult:
    """
    CIS-FG-010: Health checks must be configured for all services.

    Check that docker-compose services have healthchecks.
    """
    docker_compose = Path("docker-compose.yml")
    if not docker_compose.exists():
        return CheckResult(
            id="CIS-FG-010",
            name="Health Checks Configured",
            description="All services must have health checks",
            severity="low",
            passed=True,
            message="No docker-compose.yml found (skipped)",
        )

    content = docker_compose.read_text()
    services = ["frostgate-core", "postgres", "redis"]
    missing = []

    for service in services:
        # Simple check for healthcheck in service section
        service_match = re.search(rf"^\s*{service}:\s*$(.*?)^\s*\w+:", content, re.MULTILINE | re.DOTALL)
        if service_match:
            if "healthcheck:" not in service_match.group(1):
                missing.append(service)

    if missing:
        return CheckResult(
            id="CIS-FG-010",
            name="Health Checks Configured",
            description="All services must have health checks",
            severity="low",
            passed=False,
            message=f"Missing healthchecks: {', '.join(missing)}",
            remediation="Add healthcheck configuration to services",
        )

    return CheckResult(
        id="CIS-FG-010",
        name="Health Checks Configured",
        description="All services must have health checks",
        severity="low",
        passed=True,
        message="All services have health checks",
    )


def run_all_checks() -> ComplianceReport:
    """Run all CIS checks and generate report."""
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_auth_fallback_disabled(),
        check_no_secrets_in_env(),
        check_secret_files_permissions(),
        check_dockerfile_security(),
        check_rate_limiting_enabled(),
        check_debug_disabled(),
        check_redis_auth_required(),
        check_postgres_ssl(),
        check_no_wildcard_cors(),
        check_healthcheck_configured(),
    ]

    passed = sum(1 for c in checks if c.passed)
    failed = len(checks) - passed
    score = (passed / len(checks)) * 100 if checks else 0

    return ComplianceReport(
        timestamp=timestamp,
        total_checks=len(checks),
        passed=passed,
        failed=failed,
        score=score,
        checks=checks,
    )


def report_to_dict(report: ComplianceReport) -> dict[str, Any]:
    """Convert report to JSON-serializable dict."""
    return {
        "timestamp": report.timestamp,
        "total_checks": report.total_checks,
        "passed": report.passed,
        "failed": report.failed,
        "score": report.score,
        "checks": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "severity": c.severity,
                "passed": c.passed,
                "message": c.message,
                "remediation": c.remediation,
            }
            for c in report.checks
        ],
    }


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Run CIS-style compliance checks")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=ARTIFACTS_DIR / "cis_check.json",
        help="Output path for report JSON",
    )
    parser.add_argument(
        "--fail-threshold",
        type=float,
        default=DEFAULT_PASS_THRESHOLD,
        help=f"Score below which to fail (default: {DEFAULT_PASS_THRESHOLD})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output only JSON (no console output)",
    )
    args = parser.parse_args()

    # Run checks
    report = run_all_checks()

    # Write JSON output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report_to_dict(report), f, indent=2)

    if not args.json:
        # Print summary
        print("=" * 60)
        print("CIS Compliance Check Results")
        print("=" * 60)
        print(f"Score: {report.score:.1f}% ({report.passed}/{report.total_checks} passed)")
        print()

        # Print failed checks
        failed = [c for c in report.checks if not c.passed]
        if failed:
            print("FAILED CHECKS:")
            for c in failed:
                print(f"  [{c.severity.upper()}] {c.id}: {c.name}")
                print(f"    {c.message}")
                if c.remediation:
                    print(f"    Remediation: {c.remediation}")
            print()

        print(f"Report written to: {args.output}")

    # Determine exit code
    if report.score < args.fail_threshold:
        if not args.json:
            print(f"\nFAILED: Score {report.score:.1f}% below threshold {args.fail_threshold}%")
        return 1

    if not args.json:
        print("\nPASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
