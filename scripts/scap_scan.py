#!/usr/bin/env python3
"""
SCAP-style Static Security Scan for FrostGate Core.

Performs static analysis checks for security vulnerabilities:
- Code pattern scanning (SQL injection, XSS, command injection)
- Dependency vulnerability indicators
- Hardcoded credentials detection
- Unsafe function usage

Output: artifacts/scap_scan.json

This runs locally and in CI without requiring external SCAP tools.

Usage:
    python scripts/scap_scan.py [--output PATH] [--fail-on-high]
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Output directory
ARTIFACTS_DIR = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))

# File patterns to scan
SCAN_PATTERNS = ["**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"]

# Directories to exclude
EXCLUDE_DIRS = {
    ".venv",
    "node_modules",
    ".git",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}


@dataclass
class Finding:
    """A single security finding."""

    rule_id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    file: str
    line: int
    match: str
    remediation: Optional[str] = None


@dataclass
class ScanResult:
    """Results of a security scan."""

    timestamp: str
    files_scanned: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings: list[Finding] = field(default_factory=list)


# Security rules to check
SECURITY_RULES = [
    # SQL Injection patterns
    {
        "id": "SCAP-SQL-001",
        "title": "Potential SQL Injection (string concatenation)",
        "severity": "critical",
        "pattern": r"execute\s*\(\s*['\"].*\s*\+\s*|\.format\s*\([^)]*\)\s*\)|\%\s*\(",
        "description": "SQL query built with string concatenation or format may be vulnerable to injection",
        "remediation": "Use parameterized queries with ? or %s placeholders",
        "extensions": [".py"],
    },
    {
        "id": "SCAP-SQL-002",
        "title": "Raw SQL with f-string",
        "severity": "critical",
        "pattern": r"execute\s*\(\s*f['\"]",
        "description": "SQL query using f-string is vulnerable to injection",
        "remediation": "Use parameterized queries instead of f-strings",
        "extensions": [".py"],
    },
    # Command Injection
    {
        "id": "SCAP-CMD-001",
        "title": "Potential Command Injection (os.system)",
        "severity": "high",
        "pattern": r"os\.system\s*\(",
        "description": "os.system() can lead to command injection",
        "remediation": "Use subprocess.run() with shell=False and list arguments",
        "extensions": [".py"],
    },
    {
        "id": "SCAP-CMD-002",
        "title": "Potential Command Injection (shell=True)",
        "severity": "high",
        "pattern": r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
        "description": "subprocess with shell=True can lead to command injection",
        "remediation": "Use shell=False with command as list",
        "extensions": [".py"],
    },
    # Hardcoded credentials
    {
        "id": "SCAP-CRED-001",
        "title": "Hardcoded Password",
        "severity": "critical",
        "pattern": r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
        "description": "Hardcoded password detected",
        "remediation": "Use environment variables or secret management",
        "extensions": [".py", ".js", ".ts"],
    },
    {
        "id": "SCAP-CRED-002",
        "title": "Hardcoded API Key",
        "severity": "critical",
        "pattern": r"(?:api[_-]?key|apikey|secret[_-]?key)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "description": "Hardcoded API key detected",
        "remediation": "Use environment variables or secret management",
        "extensions": [".py", ".js", ".ts"],
    },
    # Unsafe deserialization
    {
        "id": "SCAP-DESER-001",
        "title": "Unsafe Pickle Deserialization",
        "severity": "critical",
        "pattern": r"pickle\.loads?\s*\(",
        "description": "pickle.load() is vulnerable to arbitrary code execution",
        "remediation": "Use json or other safe serialization formats",
        "extensions": [".py"],
    },
    {
        "id": "SCAP-DESER-002",
        "title": "Unsafe YAML Load",
        "severity": "high",
        "pattern": r"yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)",
        "description": "yaml.load() without SafeLoader can execute arbitrary code",
        "remediation": "Use yaml.safe_load() or specify Loader=yaml.SafeLoader",
        "extensions": [".py"],
    },
    # Crypto weaknesses
    {
        "id": "SCAP-CRYPTO-001",
        "title": "Weak Hash Algorithm (MD5)",
        "severity": "medium",
        "pattern": r"hashlib\.md5\s*\(|MD5\s*\(",
        "description": "MD5 is cryptographically broken for security purposes",
        "remediation": "Use SHA-256 or stronger hash algorithms",
        "extensions": [".py", ".js", ".ts"],
    },
    {
        "id": "SCAP-CRYPTO-002",
        "title": "Weak Hash Algorithm (SHA1)",
        "severity": "medium",
        "pattern": r"hashlib\.sha1\s*\(|SHA1\s*\(",
        "description": "SHA-1 is deprecated for security purposes",
        "remediation": "Use SHA-256 or stronger hash algorithms",
        "extensions": [".py", ".js", ".ts"],
    },
    # XSS patterns (JavaScript/TypeScript)
    {
        "id": "SCAP-XSS-001",
        "title": "Potential XSS (innerHTML)",
        "severity": "high",
        "pattern": r"\.innerHTML\s*=(?!\s*['\"])",
        "description": "Setting innerHTML with dynamic content can lead to XSS",
        "remediation": "Use textContent or sanitize HTML content",
        "extensions": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "SCAP-XSS-002",
        "title": "Potential XSS (dangerouslySetInnerHTML)",
        "severity": "high",
        "pattern": r"dangerouslySetInnerHTML",
        "description": "dangerouslySetInnerHTML can lead to XSS if not sanitized",
        "remediation": "Sanitize HTML content or avoid using dangerouslySetInnerHTML",
        "extensions": [".jsx", ".tsx"],
    },
    # Unsafe random
    {
        "id": "SCAP-RAND-001",
        "title": "Insecure Random for Security",
        "severity": "medium",
        "pattern": r"random\.random\s*\(|random\.randint\s*\(",
        "description": "random module is not cryptographically secure",
        "remediation": "Use secrets module for security-sensitive random values",
        "extensions": [".py"],
    },
    # Eval usage
    {
        "id": "SCAP-EVAL-001",
        "title": "Dangerous eval() Usage",
        "severity": "critical",
        "pattern": r"(?<!ast\.literal_)eval\s*\(",
        "description": "eval() can execute arbitrary code",
        "remediation": "Use ast.literal_eval() for safe evaluation or avoid eval entirely",
        "extensions": [".py"],
    },
    # Debug/development settings
    {
        "id": "SCAP-DEBUG-001",
        "title": "Debug Setting Enabled",
        "severity": "medium",
        "pattern": r"DEBUG\s*=\s*True|debug\s*=\s*true",
        "description": "Debug mode should be disabled in production",
        "remediation": "Set DEBUG=False for production",
        "extensions": [".py", ".js", ".ts"],
    },
    # Sensitive data logging
    {
        "id": "SCAP-LOG-001",
        "title": "Potential Sensitive Data Logging",
        "severity": "medium",
        "pattern": r"(?:log|print|console\.log)\s*\([^)]*(?:password|secret|token|key)[^)]*\)",
        "description": "Logging potentially sensitive data",
        "remediation": "Mask or redact sensitive data before logging",
        "extensions": [".py", ".js", ".ts"],
    },
]


def should_scan_file(filepath: Path) -> bool:
    """Check if file should be scanned."""
    # Skip excluded directories
    for part in filepath.parts:
        if part in EXCLUDE_DIRS:
            return False

    return True


def scan_file(filepath: Path) -> list[Finding]:
    """Scan a single file for security issues."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
    except Exception:
        return findings

    ext = filepath.suffix.lower()

    for rule in SECURITY_RULES:
        # Check if rule applies to this file type
        if "extensions" in rule and ext not in rule["extensions"]:
            continue

        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            continue

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        file=str(filepath),
                        line=i,
                        match=match.group(0)[:100],  # Truncate long matches
                        remediation=rule.get("remediation"),
                    )
                )

    return findings


def run_scan(project_dir: Path) -> ScanResult:
    """Run security scan on project."""
    timestamp = datetime.now(timezone.utc).isoformat()
    all_findings: list[Finding] = []
    files_scanned = 0

    for pattern in SCAN_PATTERNS:
        for filepath in project_dir.glob(pattern):
            if should_scan_file(filepath):
                files_scanned += 1
                findings = scan_file(filepath)
                all_findings.extend(findings)

    # Count by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in all_findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    return ScanResult(
        timestamp=timestamp,
        files_scanned=files_scanned,
        total_findings=len(all_findings),
        findings_by_severity=severity_counts,
        findings=all_findings,
    )


def result_to_dict(result: ScanResult) -> dict[str, Any]:
    """Convert scan result to JSON-serializable dict."""
    return {
        "timestamp": result.timestamp,
        "files_scanned": result.files_scanned,
        "total_findings": result.total_findings,
        "findings_by_severity": result.findings_by_severity,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "match": f.match,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Run SCAP-style security scan")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=ARTIFACTS_DIR / "scap_scan.json",
        help="Output path for scan results",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path.cwd(),
        help="Project directory to scan",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Fail if any high or critical findings",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Fail only on critical findings",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output only JSON",
    )
    args = parser.parse_args()

    # Run scan
    result = run_scan(args.project_dir)

    # Write JSON output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result_to_dict(result), f, indent=2)

    if not args.json:
        # Print summary
        print("=" * 60)
        print("SCAP Security Scan Results")
        print("=" * 60)
        print(f"Files scanned: {result.files_scanned}")
        print(f"Total findings: {result.total_findings}")
        print()
        print("Findings by severity:")
        for sev, count in result.findings_by_severity.items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        print()

        # Print critical and high findings
        important = [f for f in result.findings if f.severity in ("critical", "high")]
        if important:
            print("CRITICAL/HIGH FINDINGS:")
            for f in important[:10]:  # Limit output
                print(f"  [{f.severity.upper()}] {f.rule_id}: {f.title}")
                print(f"    File: {f.file}:{f.line}")
                print(f"    Match: {f.match}")
                if f.remediation:
                    print(f"    Remediation: {f.remediation}")
            if len(important) > 10:
                print(f"  ... and {len(important) - 10} more")
            print()

        print(f"Report written to: {args.output}")

    # Determine exit code
    if args.fail_on_high:
        high_or_critical = result.findings_by_severity.get(
            "critical", 0
        ) + result.findings_by_severity.get("high", 0)
        if high_or_critical > 0:
            if not args.json:
                print(f"\nFAILED: {high_or_critical} high/critical findings")
            return 1

    if args.fail_on_critical:
        critical = result.findings_by_severity.get("critical", 0)
        if critical > 0:
            if not args.json:
                print(f"\nFAILED: {critical} critical findings")
            return 1

    if not args.json:
        print("\nSCAN COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
