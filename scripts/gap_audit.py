#!/usr/bin/env python3
"""Gap audit enforcement for FrostGate production readiness.

This script parses docs/GAP_MATRIX.md and enforces gap severity rules:
- Production-blocking gaps → CI FAILS
- Launch-risk gaps → CI WARNS (unless waived)
- Post-launch gaps → INFORMATIONAL

Waiver-aware: Cross-references docs/RISK_WAIVERS.md to suppress allowed gaps.

Severity Classification Rules (canonical):
-----------------------------------------
Production-blocking if ANY are true:
  - Cross-tenant data access possible
  - Auth fallback enabled in production
  - Audit or integrity claims not verifiable
  - CI cannot detect unsafe production config
  - Security-critical blueprint promise unimplemented

Launch-risk if:
  - Incident response incomplete
  - Compliance evidence is manual
  - Placeholder jobs exist for resilience/integrity

Post-launch if:
  - UX, analytics, optimizations only
  - No immediate security/compliance impact
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

# Valid severity levels (canonical)
SEVERITY_LEVELS = frozenset({"Production-blocking", "Launch-risk", "Post-launch"})

# Valid owner values
VALID_OWNERS = frozenset({"repo", "infra", "docs"})

# Waiver expiration warning threshold (days)
WAIVER_WARNING_DAYS = 14

# Gap ID pattern: G followed by exactly 3 digits (e.g., G001)
GAP_ID_PATTERN = re.compile(r"^G\d{3}$")

# Legacy GAP ID pattern for backward compatibility parsing (GAP-001, GAP-999, etc.)
LEGACY_GAP_ID_PATTERN = re.compile(r"^GAP-(\d+)$")


def normalize_gap_id(gap_id: str) -> str:
    """Normalize gap ID to G### format.

    Supports both new format (G001) and legacy format (GAP-001).
    Returns normalized G### format for internal use.

    Examples:
        G001 -> G001
        GAP-001 -> G001
        GAP-42 -> G042
    """
    gap_id = gap_id.strip()

    # Already in new format
    if GAP_ID_PATTERN.match(gap_id):
        return gap_id

    # Legacy format: GAP-NNN -> G0NN (zero-padded to 3 digits)
    legacy_match = LEGACY_GAP_ID_PATTERN.match(gap_id)
    if legacy_match:
        num = int(legacy_match.group(1))
        if 1 <= num <= 999:
            return f"G{num:03d}"

    # Return as-is if unrecognized (validation will catch it)
    return gap_id

# Expected GAP_MATRIX table header columns (canonical)
EXPECTED_MATRIX_COLUMNS = [
    "ID",
    "Gap",
    "Severity",
    "Evidence (file / test / CI lane)",
    "Owner",
    "ETA / Milestone",
    "Definition of Done",
]

# Known CI lanes (from Makefile and .github/workflows/)
# This is the default set; dynamic discovery can supplement this
KNOWN_CI_LANES = frozenset(
    {
        "unit",
        "integration",
        "ci",
        "ci-integration",
        "ci-evidence",
        "ci-pt",
        "ci-admin",
        "ci-console",
        "fg-fast",
        "fg-lint",
        "fg-contract",
        "gap-audit",
        "release-gate",
        "evidence",
        "admin",
        "console",
        "pt",
        "generate-scorecard",
        "prod-profile-check",
        "contracts-gen",
        "venv",
    }
)

# Infra-related path prefixes (for owner=infra validation)
INFRA_PATH_PREFIXES = (".github/", "Makefile", "docker-compose", "Dockerfile", "k8s/", "infra/")

# Docs-related path prefixes (for owner=docs validation)
DOCS_PATH_PREFIXES = ("docs/", "README", "CHANGELOG", "LICENSE", "*.md")


def extract_file_paths(evidence: str) -> list[str]:
    """Extract potential file paths from evidence string.

    Looks for patterns like:
    - api/foo.py
    - api/foo.py:123 (with line number)
    - `path/to/file.ext`
    - .github/workflows/ci.yml
    - docker-compose.yml (root level files)
    - Makefile:123 (with line number)
    """
    paths: list[str] = []

    # Pattern for file paths: word chars, /, ., -, _ with optional :line_number
    # Must have an extension (.) or be a well-known file like Makefile
    path_pattern = re.compile(
        r"(?:`)?([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+)(?::\d+)?(?:`)?"
    )

    for match in path_pattern.finditer(evidence):
        candidate = match.group(1)
        # Accept if it has a directory separator, starts with ., or looks like a known file
        if "/" in candidate or candidate.startswith(".") or "." in candidate:
            paths.append(candidate)

    # Also check for Makefile references (no extension)
    makefile_pattern = re.compile(r"(?:`)?Makefile(?::\d+)?(?:`)?")
    if makefile_pattern.search(evidence):
        paths.append("Makefile")

    return paths


def extract_test_references(evidence: str) -> list[str]:
    """Extract test function/file references from evidence.

    Looks for patterns like:
    - test_foo
    - tests/test_foo.py::test_bar
    - test_security_hardening
    """
    refs: list[str] = []

    # Test file pattern: tests/test_*.py or just test_*
    test_pattern = re.compile(r"(tests?/)?test_[a-zA-Z0-9_]+(?:\.py)?(?:::test_[a-zA-Z0-9_]+)?")

    for match in test_pattern.finditer(evidence):
        refs.append(match.group(0))

    return refs


def extract_ci_lane_references(evidence: str) -> list[str]:
    """Extract CI lane references from evidence.

    Looks for known CI lane names in evidence string.
    """
    refs: list[str] = []
    evidence_lower = evidence.lower()

    for lane in KNOWN_CI_LANES:
        if lane in evidence_lower:
            refs.append(lane)

    return refs


def verify_file_exists(path: str, repo_root: Path | None = None) -> bool:
    """Check if a file exists in the repo.

    Args:
        path: Relative path to check
        repo_root: Repository root (defaults to cwd)
    """
    if repo_root is None:
        repo_root = Path.cwd()

    # Strip backticks and line numbers
    clean_path = path.strip("`").split(":")[0]
    full_path = repo_root / clean_path

    return full_path.exists()


def verify_test_exists(test_ref: str, repo_root: Path | None = None) -> bool:
    """Verify a test reference exists in the tests/ directory.

    Uses grep to search for test functions/files.

    Args:
        test_ref: Test reference (e.g., "test_foo" or "tests/test_bar.py::test_baz")
        repo_root: Repository root (defaults to cwd)
    """
    if repo_root is None:
        repo_root = Path.cwd()

    tests_dir = repo_root / "tests"
    if not tests_dir.exists():
        return False

    # Extract test function name if present
    if "::" in test_ref:
        # Format: tests/test_file.py::test_function
        parts = test_ref.split("::")
        test_file = parts[0]
        test_func = parts[1] if len(parts) > 1 else None

        # Check file exists
        file_path = repo_root / test_file if "/" in test_file else tests_dir / test_file
        if not file_path.exists():
            return False

        # If function specified, grep for it
        if test_func:
            try:
                result = subprocess.run(
                    ["grep", "-q", f"def {test_func}", str(file_path)],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False
        return True

    # Just a test name like "test_foo" - search for it
    # First check if it's a file
    if test_ref.endswith(".py"):
        test_path = test_ref if "/" in test_ref else f"tests/{test_ref}"
        return (repo_root / test_path).exists()

    # Search for test function definition
    try:
        result = subprocess.run(
            ["grep", "-rq", f"def {test_ref}", str(tests_dir)],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def verify_ci_lane_exists(lane: str, repo_root: Path | None = None) -> bool:
    """Verify a CI lane exists in Makefile or GitHub workflows.

    Args:
        lane: CI lane name to verify
        repo_root: Repository root (defaults to cwd)
    """
    if repo_root is None:
        repo_root = Path.cwd()

    # Check if in static KNOWN_CI_LANES
    if lane.lower() in {l.lower() for l in KNOWN_CI_LANES}:
        return True

    # Check Makefile for target
    makefile = repo_root / "Makefile"
    if makefile.exists():
        content = makefile.read_text()
        # Look for .PHONY declarations or target definitions
        if re.search(rf"^\.PHONY:.*\b{re.escape(lane)}\b", content, re.MULTILINE):
            return True
        if re.search(rf"^{re.escape(lane)}:", content, re.MULTILINE):
            return True

    # Check GitHub workflows for job names
    workflows_dir = repo_root / ".github" / "workflows"
    if workflows_dir.exists():
        for yml_file in workflows_dir.glob("*.yml"):
            content = yml_file.read_text()
            # Look for job names
            if re.search(rf"^\s+{re.escape(lane)}:", content, re.MULTILINE):
                return True
            # Look for job name attributes
            if re.search(rf'name:\s*["\']?{re.escape(lane)}', content, re.IGNORECASE):
                return True

    return False


def is_infra_path(path: str) -> bool:
    """Check if a path is an infra-related path."""
    for prefix in INFRA_PATH_PREFIXES:
        if path.startswith(prefix) or prefix in path:
            return True
    return False


def is_docs_path(path: str) -> bool:
    """Check if a path is a docs-related path."""
    for prefix in DOCS_PATH_PREFIXES:
        if prefix.startswith("*"):
            # Wildcard pattern
            if path.endswith(prefix[1:]):
                return True
        elif path.startswith(prefix) or prefix in path:
            return True
    return False


def validate_owner_evidence_match(owner: str, evidence: str) -> list[str]:
    """Validate that evidence matches the owner type.

    Owner semantics:
    - repo: evidence must include a repo file path or test reference
    - infra: evidence must include a workflow YAML reference or infra path
    - docs: evidence must reference a docs path

    Returns list of errors if mismatched.
    """
    errors: list[str] = []

    file_paths = extract_file_paths(evidence)
    test_refs = extract_test_references(evidence)
    ci_lanes = extract_ci_lane_references(evidence)

    if owner == "repo":
        # Must have repo file path or test reference (not infra/docs paths)
        has_repo_file = any(
            p for p in file_paths
            if not is_infra_path(p) and not is_docs_path(p)
        )
        has_test = len(test_refs) > 0
        has_ci = len(ci_lanes) > 0

        if not (has_repo_file or has_test or has_ci):
            errors.append(
                f"Owner=repo requires evidence with repo file path, test reference, or CI lane. "
                f"Found: {evidence}"
            )

    elif owner == "infra":
        # Must have workflow YAML, Makefile, or infra path reference
        has_infra_path = any(is_infra_path(p) for p in file_paths)
        has_workflow = any(".yml" in p or ".yaml" in p for p in file_paths)
        has_ci = len(ci_lanes) > 0

        if not (has_infra_path or has_workflow or has_ci):
            errors.append(
                f"Owner=infra requires evidence with workflow YAML, Makefile, or infra path. "
                f"Found: {evidence}"
            )

    elif owner == "docs":
        # Must have docs path reference
        has_docs_path = any(is_docs_path(p) for p in file_paths)

        if not has_docs_path:
            errors.append(
                f"Owner=docs requires evidence with docs path reference. "
                f"Found: {evidence}"
            )

    return errors


@dataclass
class Gap:
    """Represents a production gap from GAP_MATRIX.md."""

    id: str
    description: str
    severity: str
    evidence: str
    owner: str
    eta: str
    definition_of_done: str


@dataclass
class Waiver:
    """Represents a risk waiver from RISK_WAIVERS.md."""

    gap_id: str
    severity: str
    reason: str
    approved_by: str
    expiration: str
    review_date: str


def validate_matrix_header(content: str) -> list[str]:
    """Validate that GAP_MATRIX.md has the expected table header."""
    errors: list[str] = []

    # Find header row: | ID | Gap | Severity | ... |
    header_match = None

    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("|") and "ID" in line and "Gap" in line:
            header_match = line
            break

    if not header_match:
        errors.append("GAP_MATRIX: No table header found (expected | ID | Gap | ...)")
        return errors

    # Extract columns from header
    columns = [col.strip() for col in header_match.split("|") if col.strip()]

    if len(columns) != len(EXPECTED_MATRIX_COLUMNS):
        errors.append(
            f"GAP_MATRIX: Header has {len(columns)} columns, expected {len(EXPECTED_MATRIX_COLUMNS)}"
        )
        return errors

    for i, (actual, expected) in enumerate(zip(columns, EXPECTED_MATRIX_COLUMNS)):
        if actual != expected:
            errors.append(
                f"GAP_MATRIX: Column {i + 1} is '{actual}', expected '{expected}'"
            )

    return errors


def validate_evidence_artifact(evidence: str) -> bool:
    """Check if evidence includes at least one repo-backed artifact.

    Valid evidence includes:
    - A file path containing "/" and a "." extension (e.g., api/auth.py)
    - A test name containing "test_" (e.g., tests/test_auth.py::test_x)
    - A CI lane name that matches a known lane in Makefile/CI
    """
    if not evidence.strip():
        return False

    # Check for file path: contains "/" and "." (e.g., api/auth.py)
    if "/" in evidence and "." in evidence:
        return True

    # Check for test reference: contains "test_"
    if "test_" in evidence:
        return True

    # Check for known CI lane references
    evidence_lower = evidence.lower()
    for lane in KNOWN_CI_LANES:
        if lane in evidence_lower:
            return True

    # Check for CI-related patterns (yaml files, workflow references)
    if ".yml" in evidence or ".yaml" in evidence:
        return True

    return False


@dataclass
class EvidenceVerificationResult:
    """Result of evidence verification."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    verified_artifacts: list[str]


def verify_evidence_artifacts(
    evidence: str,
    repo_root: Path | None = None,
    skip_file_checks: bool = False,
) -> EvidenceVerificationResult:
    """Verify that evidence references verifiable repo-backed artifacts.

    This function performs deep verification:
    1. If evidence contains a file path, verify the file exists
    2. If evidence references a test, verify it exists via grep
    3. If evidence references a CI lane, verify it exists in Makefile or workflows
    4. At least one verifiable artifact is required

    Args:
        evidence: Evidence string from GAP_MATRIX
        repo_root: Repository root path (defaults to cwd)
        skip_file_checks: Skip filesystem checks (for unit tests)

    Returns:
        EvidenceVerificationResult with validation details
    """
    if repo_root is None:
        repo_root = Path.cwd()

    errors: list[str] = []
    warnings: list[str] = []
    verified: list[str] = []

    file_paths = extract_file_paths(evidence)
    test_refs = extract_test_references(evidence)
    ci_lanes = extract_ci_lane_references(evidence)

    # Verify file paths
    for path in file_paths:
        if skip_file_checks:
            verified.append(f"file:{path}")
        elif verify_file_exists(path, repo_root):
            verified.append(f"file:{path}")
        else:
            errors.append(f"Evidence file not found: {path}")

    # Verify test references
    for test_ref in test_refs:
        if skip_file_checks:
            verified.append(f"test:{test_ref}")
        elif verify_test_exists(test_ref, repo_root):
            verified.append(f"test:{test_ref}")
        else:
            # Check if it's a file reference that exists
            if test_ref.endswith(".py"):
                test_path = test_ref if "/" in test_ref else f"tests/{test_ref}"
                if verify_file_exists(test_path, repo_root):
                    verified.append(f"test:{test_ref}")
                    continue
            errors.append(f"Evidence test reference not found: {test_ref}")

    # Verify CI lanes
    for lane in ci_lanes:
        if skip_file_checks:
            verified.append(f"ci:{lane}")
        elif verify_ci_lane_exists(lane, repo_root):
            verified.append(f"ci:{lane}")
        else:
            errors.append(f"Evidence CI lane not found: {lane}")

    # Check if at least one artifact was verified
    if not verified and not errors:
        errors.append(
            "Evidence must contain at least one verifiable repo-backed artifact "
            "(file path, test reference, or CI lane)"
        )

    return EvidenceVerificationResult(
        valid=len(errors) == 0 and len(verified) > 0,
        errors=errors,
        warnings=warnings,
        verified_artifacts=verified,
    )


def parse_gap_matrix(path: Path) -> list[Gap]:
    """Parse GAP_MATRIX.md and extract gap entries."""
    if not path.exists():
        return []

    content = path.read_text()
    gaps: list[Gap] = []

    # Find the gap matrix table rows (ID pattern: G followed by 3 digits OR legacy GAP-NNN)
    table_pattern = re.compile(
        r"^\|\s*(G\d{3}|GAP-\d+)\s*\|"  # ID column (G001 or legacy GAP-001)
        r"\s*([^|]+)\|"  # Gap description
        r"\s*([^|]+)\|"  # Severity
        r"\s*([^|]+)\|"  # Evidence
        r"\s*([^|]+)\|"  # Owner
        r"\s*([^|]+)\|"  # ETA
        r"\s*([^|]+)\|",  # Definition of Done
        re.MULTILINE,
    )

    for match in table_pattern.finditer(content):
        gap_id = normalize_gap_id(match.group(1).strip())
        description = match.group(2).strip()
        severity = match.group(3).strip()
        evidence = match.group(4).strip()
        owner = match.group(5).strip()
        eta = match.group(6).strip()
        dod = match.group(7).strip()

        gaps.append(
            Gap(
                id=gap_id,
                description=description,
                severity=severity,
                evidence=evidence,
                owner=owner,
                eta=eta,
                definition_of_done=dod,
            )
        )

    return gaps


def parse_waivers(path: Path) -> list[Waiver]:
    """Parse RISK_WAIVERS.md and extract waiver entries."""
    if not path.exists():
        return []

    content = path.read_text()
    waivers: list[Waiver] = []

    # Find waiver table rows (ID pattern: G followed by 3 digits OR legacy GAP-NNN)
    table_pattern = re.compile(
        r"^\|\s*(G\d{3}|GAP-\d+)\s*\|"  # Gap ID (G001 or legacy GAP-001)
        r"\s*([^|]+)\|"  # Severity
        r"\s*([^|]+)\|"  # Reason
        r"\s*([^|]+)\|"  # Approved By
        r"\s*([^|]+)\|"  # Expiration
        r"\s*([^|]+)\|",  # Review Date
        re.MULTILINE,
    )

    for match in table_pattern.finditer(content):
        gap_id = normalize_gap_id(match.group(1).strip())
        severity = match.group(2).strip()
        reason = match.group(3).strip()
        approved_by = match.group(4).strip()
        expiration = match.group(5).strip()
        review_date = match.group(6).strip()

        waivers.append(
            Waiver(
                gap_id=gap_id,
                severity=severity,
                reason=reason,
                approved_by=approved_by,
                expiration=expiration,
                review_date=review_date,
            )
        )

    return waivers


def parse_date(date_str: str) -> datetime | None:
    """Parse date string in YYYY-MM-DD format."""
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d")
    except ValueError:
        return None


def is_waiver_valid(waiver: Waiver, today: datetime) -> bool:
    """Check if a waiver is currently valid (not expired)."""
    expiration = parse_date(waiver.expiration)
    if expiration is None:
        return False  # Invalid date format = invalid waiver
    return expiration >= today


def is_waiver_expiring_soon(waiver: Waiver, today: datetime) -> bool:
    """Check if a waiver expires within the warning threshold."""
    expiration = parse_date(waiver.expiration)
    if expiration is None:
        return False
    warning_date = today + timedelta(days=WAIVER_WARNING_DAYS)
    return expiration <= warning_date


def validate_gap(gap: Gap) -> list[str]:
    """Validate gap entry format."""
    errors: list[str] = []

    # Validate ID format: must match G[0-9]{3}
    if not GAP_ID_PATTERN.match(gap.id):
        errors.append(
            f"{gap.id}: Invalid ID format. Must match G[0-9]{{3}} (e.g., G001)"
        )

    # Validate severity
    if gap.severity not in SEVERITY_LEVELS:
        errors.append(
            f"{gap.id}: Invalid severity '{gap.severity}'. "
            f"Must be one of: {', '.join(sorted(SEVERITY_LEVELS))}"
        )

    # Validate owner
    if gap.owner not in VALID_OWNERS:
        errors.append(
            f"{gap.id}: Invalid owner '{gap.owner}'. "
            f"Must be one of: {', '.join(sorted(VALID_OWNERS))}"
        )

    # Validate non-empty description
    if not gap.description.strip():
        errors.append(f"{gap.id}: Gap description is required")

    # Validate evidence is non-empty
    if not gap.evidence.strip():
        errors.append(f"{gap.id}: Evidence is required")
    elif not validate_evidence_artifact(gap.evidence):
        errors.append(
            f"{gap.id}: Evidence '{gap.evidence}' must include a repo-backed artifact "
            "(file path with '/' and '.', test name with 'test_', or CI lane name)"
        )

    # Validate ETA is non-empty
    if not gap.eta.strip():
        errors.append(f"{gap.id}: ETA / Milestone is required")

    # Validate Definition of Done is non-empty
    if not gap.definition_of_done.strip():
        errors.append(f"{gap.id}: Definition of Done is required")

    return errors


class GapAuditResult:
    """Collects audit results."""

    def __init__(self) -> None:
        self.blocking_gaps: list[Gap] = []
        self.launch_risk_gaps: list[Gap] = []
        self.post_launch_gaps: list[Gap] = []
        self.waived_gaps: list[tuple[Gap, Waiver]] = []
        self.expired_waivers: list[Waiver] = []
        self.expiring_soon_waivers: list[Waiver] = []
        self.validation_errors: list[str] = []
        self.invalid_waiver_attempts: list[Waiver] = []  # Production-blocking waivers
        self.evidence_verification_errors: list[str] = []  # Deep evidence verification
        self.owner_evidence_mismatches: list[str] = []  # Owner/evidence semantic errors


def validate_waiver(waiver: Waiver, gap_lookup: dict[str, Gap]) -> list[str]:
    """Validate waiver entry format and cross-references."""
    errors: list[str] = []

    # Gap ID must exist in GAP_MATRIX
    if waiver.gap_id not in gap_lookup:
        errors.append(
            f"Waiver {waiver.gap_id}: Gap ID does not exist in GAP_MATRIX (phantom waiver)"
        )
        return errors  # Can't validate further without the gap

    gap = gap_lookup[waiver.gap_id]

    # Severity in waiver must match gap's actual severity
    if waiver.severity != gap.severity:
        errors.append(
            f"Waiver {waiver.gap_id}: Severity mismatch - waiver says '{waiver.severity}', "
            f"gap is '{gap.severity}'"
        )

    # Approved By must be non-empty and contain '@' OR '/' OR ' ' (human identifier)
    approved = waiver.approved_by.strip()
    if not approved:
        errors.append(f"Waiver {waiver.gap_id}: Approved By is required")
    elif not ("@" in approved or "/" in approved or " " in approved):
        errors.append(
            f"Waiver {waiver.gap_id}: Approved By '{approved}' must contain '@', '/', or ' ' "
            "(human identifier format)"
        )

    # Expiration must be valid ISO date YYYY-MM-DD
    exp_date = parse_date(waiver.expiration)
    if exp_date is None:
        errors.append(
            f"Waiver {waiver.gap_id}: Expiration '{waiver.expiration}' is not a valid "
            "ISO date (YYYY-MM-DD)"
        )

    return errors


def run_gap_audit(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
    repo_root: Path | None = None,
    skip_evidence_verification: bool = False,
) -> GapAuditResult:
    """Run the gap audit and return results.

    Args:
        matrix_path: Path to GAP_MATRIX.md
        waivers_path: Path to RISK_WAIVERS.md
        today: Override for current date (for testing)
        repo_root: Repository root for evidence verification (defaults to cwd)
        skip_evidence_verification: Skip deep evidence file checks (for unit tests)
    """
    if today is None:
        today = datetime.now()

    if repo_root is None:
        repo_root = Path.cwd()

    result = GapAuditResult()

    # Validate matrix header first
    if matrix_path.exists():
        content = matrix_path.read_text()
        header_errors = validate_matrix_header(content)
        result.validation_errors.extend(header_errors)

    # Parse files
    gaps = parse_gap_matrix(matrix_path)
    waivers = parse_waivers(waivers_path)

    # Check for duplicate gap IDs
    seen_ids: set[str] = set()
    for gap in gaps:
        if gap.id in seen_ids:
            result.validation_errors.append(f"{gap.id}: Duplicate gap ID")
        seen_ids.add(gap.id)

    # Build gap lookup for waiver validation
    gap_lookup: dict[str, Gap] = {gap.id: gap for gap in gaps}

    # Build waiver lookup and validate waivers
    waiver_by_gap: dict[str, Waiver] = {}
    for waiver in waivers:
        # Validate waiver format and cross-references
        waiver_errors = validate_waiver(waiver, gap_lookup)
        result.validation_errors.extend(waiver_errors)

        # Check for invalid Production-blocking waiver attempts
        if waiver.severity == "Production-blocking":
            result.invalid_waiver_attempts.append(waiver)
            continue

        # Check waiver validity (expiration)
        if not is_waiver_valid(waiver, today):
            result.expired_waivers.append(waiver)
            continue

        if is_waiver_expiring_soon(waiver, today):
            result.expiring_soon_waivers.append(waiver)

        waiver_by_gap[waiver.gap_id] = waiver

    # Process gaps
    for gap in gaps:
        # Validate gap format
        errors = validate_gap(gap)
        result.validation_errors.extend(errors)

        # Validate owner/evidence semantic match
        owner_errors = validate_owner_evidence_match(gap.owner, gap.evidence)
        for err in owner_errors:
            result.owner_evidence_mismatches.append(f"{gap.id}: {err}")

        # Deep evidence verification (skip if disabled for unit tests)
        if not skip_evidence_verification:
            evidence_result = verify_evidence_artifacts(
                gap.evidence,
                repo_root=repo_root,
                skip_file_checks=False,
            )
            for err in evidence_result.errors:
                result.evidence_verification_errors.append(f"{gap.id}: {err}")

        # Check if waived
        waiver = waiver_by_gap.get(gap.id)
        if waiver and gap.severity != "Production-blocking":
            result.waived_gaps.append((gap, waiver))
            continue

        # Categorize by severity
        if gap.severity == "Production-blocking":
            result.blocking_gaps.append(gap)
        elif gap.severity == "Launch-risk":
            result.launch_risk_gaps.append(gap)
        elif gap.severity == "Post-launch":
            result.post_launch_gaps.append(gap)

    return result


def format_gap_table(gaps: list[Gap], header: str) -> str:
    """Format gaps as a simple text table."""
    if not gaps:
        return ""

    lines = [header, "=" * len(header)]
    for gap in gaps:
        lines.append(f"  {gap.id}: {gap.description}")
        lines.append(f"    Evidence: {gap.evidence}")
        lines.append(f"    Owner: {gap.owner}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    """Run gap audit and return exit code."""
    # Paths relative to repo root
    matrix_path = Path("docs/GAP_MATRIX.md")
    waivers_path = Path("docs/RISK_WAIVERS.md")
    repo_root = Path.cwd()

    # Check if matrix exists
    if not matrix_path.exists():
        print("ERROR: docs/GAP_MATRIX.md not found")
        print("Create the gap matrix before running audit.")
        return 1

    result = run_gap_audit(
        matrix_path,
        waivers_path,
        repo_root=repo_root,
        skip_evidence_verification=False,
    )

    # Print report
    print("=" * 60)
    print("GAP AUDIT REPORT")
    print("=" * 60)
    print()

    # Validation errors (always fail)
    if result.validation_errors:
        print("VALIDATION ERRORS:")
        for error in result.validation_errors:
            print(f"  [ERROR] {error}")
        print()

    # Evidence verification errors (always fail)
    if result.evidence_verification_errors:
        print("EVIDENCE VERIFICATION ERRORS:")
        for error in result.evidence_verification_errors:
            print(f"  [ERROR] {error}")
        print()

    # Owner/evidence mismatch errors (always fail)
    if result.owner_evidence_mismatches:
        print("OWNER/EVIDENCE MISMATCH ERRORS:")
        for error in result.owner_evidence_mismatches:
            print(f"  [ERROR] {error}")
        print()

    # Invalid waiver attempts (always fail)
    if result.invalid_waiver_attempts:
        print("INVALID WAIVER ATTEMPTS (Production-blocking cannot be waived):")
        for waiver in result.invalid_waiver_attempts:
            print(f"  [ERROR] {waiver.gap_id}: Attempted waiver rejected")
        print()

    # Expired waivers (always fail)
    if result.expired_waivers:
        print("EXPIRED WAIVERS:")
        for waiver in result.expired_waivers:
            print(f"  [ERROR] {waiver.gap_id}: Waiver expired {waiver.expiration}")
        print()

    # Production-blocking gaps (fail)
    if result.blocking_gaps:
        print(
            format_gap_table(
                result.blocking_gaps, "PRODUCTION-BLOCKING GAPS (CI FAILS)"
            )
        )

    # Launch-risk gaps (warn)
    if result.launch_risk_gaps:
        print(format_gap_table(result.launch_risk_gaps, "LAUNCH-RISK GAPS (Warning)"))

    # Expiring soon waivers (warn)
    if result.expiring_soon_waivers:
        print("WAIVERS EXPIRING SOON:")
        for waiver in result.expiring_soon_waivers:
            print(f"  [WARN] {waiver.gap_id}: Expires {waiver.expiration}")
        print()

    # Waived gaps (info)
    if result.waived_gaps:
        print("WAIVED GAPS:")
        for gap, waiver in result.waived_gaps:
            print(f"  [WAIVED] {gap.id}: {gap.description}")
            print(
                f"    Approved by: {waiver.approved_by}, Expires: {waiver.expiration}"
            )
        print()

    # Post-launch gaps (info)
    if result.post_launch_gaps:
        print(
            format_gap_table(
                result.post_launch_gaps, "POST-LAUNCH GAPS (Informational)"
            )
        )

    # Summary
    print("-" * 60)
    print("SUMMARY:")
    print(f"  Production-blocking: {len(result.blocking_gaps)}")
    print(f"  Launch-risk: {len(result.launch_risk_gaps)}")
    print(f"  Post-launch: {len(result.post_launch_gaps)}")
    print(f"  Waived: {len(result.waived_gaps)}")
    print(f"  Expired waivers: {len(result.expired_waivers)}")
    print(f"  Evidence errors: {len(result.evidence_verification_errors)}")
    print(f"  Owner mismatches: {len(result.owner_evidence_mismatches)}")
    print()

    # Determine exit code
    has_errors = (
        len(result.blocking_gaps) > 0
        or len(result.validation_errors) > 0
        or len(result.expired_waivers) > 0
        or len(result.invalid_waiver_attempts) > 0
        or len(result.evidence_verification_errors) > 0
        or len(result.owner_evidence_mismatches) > 0
    )

    if has_errors:
        print("=" * 60)
        print("GAP AUDIT: FAILED")
        print("=" * 60)
        if result.blocking_gaps:
            print(
                f"\nCI blocked by {len(result.blocking_gaps)} Production-blocking gap(s)."
            )
            print("Remediate gaps or escalate for business review.")
        if result.evidence_verification_errors:
            print(
                f"\nCI blocked by {len(result.evidence_verification_errors)} evidence verification error(s)."
            )
            print("Fix evidence paths to reference existing repo artifacts.")
        if result.owner_evidence_mismatches:
            print(
                f"\nCI blocked by {len(result.owner_evidence_mismatches)} owner/evidence mismatch(es)."
            )
            print("Ensure evidence matches the owner type (repo/infra/docs).")
        return 1
    else:
        print("=" * 60)
        print("GAP AUDIT: PASSED")
        print("=" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
