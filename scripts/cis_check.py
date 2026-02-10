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

import yaml

# Output directory
ARTIFACTS_DIR = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))

# Default pass threshold (percentage)
DEFAULT_PASS_THRESHOLD = 80.0


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


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _truthy_env(val: str | None) -> bool:
    if val is None:
        return False
    v = val.strip().lower()
    return v in {"1", "true", "yes", "on"}


def _load_compose() -> dict[str, Any]:
    compose_path = Path("docker-compose.yml")
    if not compose_path.exists():
        return {}
    try:
        data = yaml.safe_load(_read_text(compose_path))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def check_auth_fallback_disabled() -> CheckResult:
    """
    CIS-FG-001: Auth fallback must be disabled in production.

    The FG_AUTH_ALLOW_FALLBACK setting allows bypassing database key validation.
    This MUST be false in production.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = _read_text(docker_compose)
        if (
            "FG_AUTH_ALLOW_FALLBACK:-true" in content
            or re.search(r"FG_AUTH_ALLOW_FALLBACK:\s*true\b", content) is not None
        ):
            return CheckResult(
                id="CIS-FG-001",
                name="Auth Fallback Disabled",
                description="FG_AUTH_ALLOW_FALLBACK must default to false in production",
                severity="critical",
                passed=False,
                message="docker-compose.yml defaults FG_AUTH_ALLOW_FALLBACK to true",
                remediation="Change default to false: FG_AUTH_ALLOW_FALLBACK:-false",
            )

    fallback = os.getenv("FG_AUTH_ALLOW_FALLBACK", "").lower()
    if fallback in {"true", "1"}:
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

    Check for potential secrets in docker-compose.yml and .env.example files.
    """
    patterns: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(r"password\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
            "hardcoded password",
        ),
        (
            re.compile(r"secret\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
            "hardcoded secret",
        ),
        (
            re.compile(
                r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", re.IGNORECASE
            ),
            "hardcoded API key",
        ),
    ]

    files_to_check = [Path("docker-compose.yml"), Path(".env.example")]
    issues: list[str] = []

    for path in files_to_check:
        if not path.exists():
            continue
        content = _read_text(path)

        for rx, desc in patterns:
            for m in rx.finditer(content):
                # If this match is on a line with ${VAR...} substitution, ignore it.
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                if line_end == -1:
                    line_end = len(content)
                line = content[line_start:line_end]

                if "${" in line:
                    continue

                issues.append(f"{path.name}: {desc}")

    if issues:
        return CheckResult(
            id="CIS-FG-002",
            name="No Hardcoded Secrets",
            description="Configuration files must not contain hardcoded secrets",
            severity="critical",
            passed=False,
            message=f"Potential secrets found: {', '.join(sorted(set(issues)))}",
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

    issues: list[str] = []
    for path in secret_paths:
        if not path.exists():
            continue

        mode = path.stat().st_mode
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

    content = _read_text(dockerfile)
    issues: list[str] = []

    if not re.search(r"^\s*USER\s+", content, re.MULTILINE):
        issues.append("No USER directive (runs as root)")

    if re.search(r"FROM\s+\S+:latest\b", content, re.IGNORECASE):
        issues.append("Uses :latest tag (pin specific version)")

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

    Check that FG_RL_ENABLED is set to true in compose defaults.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = _read_text(docker_compose)
        if "FG_RL_ENABLED:-false" in content or re.search(
            r"FG_RL_ENABLED:\s*false\b", content
        ):
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
    if debug in {"true", "1"}:
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

    Check that Redis config requires a password in compose.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = _read_text(docker_compose)
        if "--requirepass" in content or "REDIS_PASSWORD" in content:
            return CheckResult(
                id="CIS-FG-007",
                name="Redis Authentication",
                description="Redis must require authentication",
                severity="high",
                passed=True,
                message="Redis authentication is configured",
            )

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
        message="No docker-compose.yml found (skipped)",
    )


def check_postgres_ssl() -> CheckResult:
    """
    CIS-FG-008: PostgreSQL connections should use SSL in production.

    Informational: pass with remediation if sslmode is missing.
    """
    db_url = os.getenv("FG_DB_URL", "")
    if db_url and "sslmode=" not in db_url.lower():
        return CheckResult(
            id="CIS-FG-008",
            name="PostgreSQL SSL",
            description="PostgreSQL should use SSL in production",
            severity="medium",
            passed=True,
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

    Check for CORS origins explicitly set to wildcard.
    """
    docker_compose = Path("docker-compose.yml")
    if docker_compose.exists():
        content = _read_text(docker_compose)
        if re.search(r"CORS_ORIGINS\s*:\s*['\"]?\*['\"]?\s*$", content, re.MULTILINE):
            return CheckResult(
                id="CIS-FG-009",
                name="CORS Configuration",
                description="CORS must not allow wildcard origins in production",
                severity="medium",
                passed=False,
                message="CORS allows wildcard origins",
                remediation="Set specific origins in AG_CORS_ORIGINS / CORS_ORIGINS",
            )

        if "CORS_ORIGINS:-*" in content:
            return CheckResult(
                id="CIS-FG-009",
                name="CORS Configuration",
                description="CORS must not allow wildcard origins in production",
                severity="medium",
                passed=False,
                message="CORS defaults to wildcard origins",
                remediation="Set specific origins in AG_CORS_ORIGINS / CORS_ORIGINS",
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
    CIS-FG-010: Health checks must be configured for critical services.

    Uses YAML parsing (not regex) to avoid false negatives.
    Requires healthcheck to be a dict containing a 'test' field.
    Accepts either 'core' or 'frostgate-core' as the core service name.
    """
    compose = _load_compose()
    services = (
        compose.get("services") if isinstance(compose.get("services"), dict) else {}
    )
    if not services:
        return CheckResult(
            id="CIS-FG-010",
            name="Health Checks Configured",
            description="Critical services must have health checks",
            severity="low",
            passed=True,
            message="No docker-compose.yml found or no services defined (skipped)",
        )

    core_name = "frostgate-core" if "frostgate-core" in services else "core"
    required = {
        core_name: "frostgate-core",
        "postgres": "postgres",
        "redis": "redis",
    }

    missing: list[str] = []
    for svc_name, label in required.items():
        svc = services.get(svc_name)
        if not isinstance(svc, dict):
            missing.append(label)
            continue
        hc = svc.get("healthcheck")
        if not (isinstance(hc, dict) and hc.get("test")):
            missing.append(label)

    if missing:
        return CheckResult(
            id="CIS-FG-010",
            name="Health Checks Configured",
            description="Critical services must have health checks",
            severity="low",
            passed=False,
            message=f"Missing healthchecks: {', '.join(missing)}",
            remediation="Add healthcheck configuration (with 'test') to missing services",
        )

    return CheckResult(
        id="CIS-FG-010",
        name="Health Checks Configured",
        description="Critical services must have health checks",
        severity="low",
        passed=True,
        message="Healthchecks present for critical services",
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
    score = (passed / len(checks)) * 100 if checks else 0.0

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
        "--output",
        "-o",
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

    report = run_all_checks()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_to_dict(report), f, indent=2)

    if not args.json:
        print("=" * 60)
        print("CIS Compliance Check Results")
        print("=" * 60)
        print(
            f"Score: {report.score:.1f}% ({report.passed}/{report.total_checks} passed)"
        )
        print()

        failed_checks = [c for c in report.checks if not c.passed]
        if failed_checks:
            print("FAILED CHECKS:")
            for c in failed_checks:
                print(f"  [{c.severity.upper()}] {c.id}: {c.name}")
                print(f"    {c.message}")
                if c.remediation:
                    print(f"    Remediation: {c.remediation}")
            print()

        print(f"Report written to: {args.output}")

    if report.score < args.fail_threshold:
        if not args.json:
            print(
                f"\nFAILED: Score {report.score:.1f}% below threshold {args.fail_threshold}%"
            )
        return 1

    if not args.json:
        print("\nPASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
