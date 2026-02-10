#!/usr/bin/env python3
"""
Gap audit enforcement for FrostGate production readiness.

Parses docs/GAP_MATRIX.md and enforces gap severity rules:
- Production-blocking gaps -> CI FAILS
- Launch-risk gaps -> CI WARNS (unless waived)
- Post-launch gaps -> INFORMATIONAL

Waiver-aware: Cross-references docs/RISK_WAIVERS.md to suppress allowed gaps.

Severity Classification Rules (canonical)
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
from typing import Dict, Iterable, Optional, Set

# -----------------------
# Constants / Canonical
# -----------------------

SEVERITY_LEVELS = frozenset({"Production-blocking", "Launch-risk", "Post-launch"})
VALID_OWNERS = frozenset({"repo", "infra", "docs"})
WAIVER_WARNING_DAYS = 14

GAP_ID_PATTERN = re.compile(r"^G\d{3}$")
LEGACY_GAP_ID_PATTERN = re.compile(r"^GAP-(\d+)$")

EXPECTED_MATRIX_COLUMNS = [
    "ID",
    "Gap",
    "Severity",
    "Evidence (file / test / CI lane)",
    "Owner",
    "ETA / Milestone",
    "Definition of Done",
]

# Static known lanes. Discovery augments this at runtime.
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

INFRA_PATH_PREFIXES = (
    ".github/",
    "Makefile",
    "docker-compose",
    "Dockerfile",
    "k8s/",
    "infra/",
)

DOCS_PATH_PREFIXES = ("docs/", "README", "CHANGELOG", "LICENSE", "*.md")


# -----------------------
# Utilities
# -----------------------


def normalize_gap_id(gap_id: str) -> str:
    """Normalize gap ID to G### format; supports legacy GAP-###."""
    gap_id = gap_id.strip()
    if GAP_ID_PATTERN.match(gap_id):
        return gap_id

    m = LEGACY_GAP_ID_PATTERN.match(gap_id)
    if m:
        num = int(m.group(1))
        if 1 <= num <= 999:
            return f"G{num:03d}"

    return gap_id


def parse_date(date_str: str) -> datetime | None:
    """Parse YYYY-MM-DD. Returns None if invalid."""
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d")
    except ValueError:
        return None


def is_waiver_valid(waiver: "Waiver", today: datetime) -> bool:
    exp = parse_date(waiver.expiration)
    return exp is not None and exp >= today


def is_waiver_expiring_soon(waiver: "Waiver", today: datetime) -> bool:
    exp = parse_date(waiver.expiration)
    if exp is None:
        return False
    return exp <= (today + timedelta(days=WAIVER_WARNING_DAYS))


def is_infra_path(path: str) -> bool:
    for prefix in INFRA_PATH_PREFIXES:
        if path.startswith(prefix) or prefix in path:
            return True
    return False


def is_docs_path(path: str) -> bool:
    for prefix in DOCS_PATH_PREFIXES:
        if prefix.startswith("*"):
            if path.endswith(prefix[1:]):
                return True
        elif path.startswith(prefix) or prefix in path:
            return True
    return False


def _normalize_known_lanes(known_lanes: Iterable[str] | None) -> Set[str]:
    """
    Normalize lanes to lowercase set. If None, fallback to static KNOWN_CI_LANES.
    This keeps unit tests happy when they call functions without passing lanes.
    """
    if known_lanes is None:
        return {x.lower() for x in KNOWN_CI_LANES}
    return {x.lower() for x in known_lanes if x and str(x).strip()}


# -----------------------
# CI Lane discovery
# -----------------------


def discover_ci_lanes(repo_root: Path) -> Set[str]:
    """
    Discover CI lanes from:
      - Makefile targets
      - .github/workflows job ids (top-level jobs: keys)
    Returns a lowercased set.
    """
    lanes: set[str] = set()

    # Makefile: simple target definitions "^name:"
    makefile = repo_root / "Makefile"
    if makefile.exists():
        try:
            content = makefile.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = makefile.read_text(errors="ignore")
        for m in re.finditer(r"^([A-Za-z0-9_.-]+)\s*:", content, re.MULTILINE):
            lanes.add(m.group(1).strip().lower())

        # .PHONY: x y z
        for m in re.finditer(r"^\.PHONY:\s*(.+)$", content, re.MULTILINE):
            toks = [t.strip().lower() for t in m.group(1).split() if t.strip()]
            lanes.update(toks)

    # GitHub workflows: jobs: then "  job_id:"
    wf_dir = repo_root / ".github" / "workflows"
    if wf_dir.exists():
        for yml in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
            try:
                content = yml.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = yml.read_text(errors="ignore")

            # crude but deterministic enough: find "jobs:" block and then job keys
            in_jobs = False
            jobs_indent: Optional[int] = None

            for line in content.splitlines():
                if re.match(r"^\s*jobs:\s*$", line):
                    in_jobs = True
                    jobs_indent = len(line) - len(line.lstrip(" "))
                    continue

                if not in_jobs:
                    continue

                # exit jobs block if indent decreases to <= jobs_indent
                indent = len(line) - len(line.lstrip(" "))
                if jobs_indent is not None and indent <= jobs_indent and line.strip():
                    in_jobs = False
                    jobs_indent = None
                    continue

                # job id: "  build:" (indent > jobs_indent)
                jm = re.match(r"^\s{2,}([A-Za-z0-9_.-]+)\s*:\s*$", line)
                if jm:
                    lanes.add(jm.group(1).strip().lower())

    return lanes


def merged_known_lanes(repo_root: Path | None = None) -> Set[str]:
    rr = repo_root or Path.cwd()
    discovered = discover_ci_lanes(rr)
    static = {x.lower() for x in KNOWN_CI_LANES}
    return static | discovered


# -----------------------
# Evidence extraction
# -----------------------


def extract_file_paths(evidence: str) -> list[str]:
    """Extract possible file paths from evidence text."""
    paths: list[str] = []

    path_pattern = re.compile(r"(?:`)?([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+)(?::\d+)?(?:`)?")
    for m in path_pattern.finditer(evidence):
        candidate = m.group(1)
        if "/" in candidate or candidate.startswith(".") or "." in candidate:
            paths.append(candidate)

    # Makefile references (no extension)
    if re.search(r"(?:`)?Makefile(?::\d+)?(?:`)?", evidence):
        paths.append("Makefile")

    return paths


def extract_test_references(evidence: str) -> list[str]:
    refs: list[str] = []
    test_pattern = re.compile(
        r"(tests?/)?test_[a-zA-Z0-9_]+(?:\.py)?(?:::test_[a-zA-Z0-9_]+)?"
    )
    for m in test_pattern.finditer(evidence):
        refs.append(m.group(0))
    return refs


def extract_ci_lane_references(
    evidence: str, known_lanes: Set[str] | None = None
) -> list[str]:
    """
    Extract CI lane references from evidence.

    Rules:
    - Avoid false positives from file path segments (e.g., Makefile target "api" matching "api/auth.py").
    - BUT allow the canonical lane "ci" to be inferred from workflow files like "ci.yml"/"ci.yaml"
      because tests expect ".github/workflows/ci.yml" to count as lane "ci".
    """
    refs: list[str] = []
    lanes = _normalize_known_lanes(known_lanes)
    e = (evidence or "").lower()

    # Special-case: workflow file names like ci.yml / ci.yaml should imply lane "ci"
    # because we use that filename as a conventional lane marker.
    if re.search(r"(?:^|/)(ci)\.(yml|yaml)(?::\w+)?(?:$|\s|`)", e):
        if "ci" in lanes:
            refs.append("ci")

    # If evidence includes file paths, collect path tokens to avoid false lane matches.
    path_tokens: set[str] = set()
    file_paths = extract_file_paths(evidence or "")
    if file_paths:
        for p in file_paths:
            p_clean = p.split(":", 1)[0]
            for tok in re.split(r"[\/\.\-_:]+", p_clean.lower()):
                if tok:
                    path_tokens.add(tok)

    for lane in sorted(lanes):
        if not lane:
            continue
        lane_l = lane.lower()

        # If we already added "ci" from ci.yml, don't add again.
        if lane_l == "ci" and "ci" in refs:
            continue

        # Prevent false positives from file path tokens, EXCEPT:
        # - allow "ci" if it appears as a real token reference (handled above for ci.yml),
        #   otherwise normal boundary matching applies.
        if lane_l in path_tokens and lane_l != "ci":
            continue

        # token-ish match, not substring inside a longer identifier
        pattern = rf"(?<![a-z0-9_.-]){re.escape(lane_l)}(?![a-z0-9_.-])"
        if re.search(pattern, e):
            refs.append(lane_l)

    # deterministic unique order
    out: list[str] = []
    seen: set[str] = set()
    for r in refs:
        if r not in seen:
            out.append(r)
            seen.add(r)
    return out


# -----------------------
# Evidence verification
# -----------------------

FileExistCache = Dict[str, bool]


def verify_file_exists(
    path: str, repo_root: Path, cache: FileExistCache | None = None
) -> bool:
    """Verify file exists, cached. Backwards-compatible cache default."""
    c: FileExistCache = cache if cache is not None else {}
    clean = path.strip("`").split(":")[0]
    key = str((repo_root / clean).resolve())
    if key in c:
        return c[key]
    exists = (repo_root / clean).exists()
    c[key] = exists
    return exists


def verify_test_exists(test_ref: str, repo_root: Path) -> bool:
    tests_dir = repo_root / "tests"
    if not tests_dir.exists():
        return False

    if "::" in test_ref:
        parts = test_ref.split("::", 1)
        test_file, test_func = parts[0], parts[1]
        file_path = repo_root / test_file if "/" in test_file else tests_dir / test_file
        if not file_path.exists():
            return False
        try:
            r = subprocess.run(
                ["grep", "-q", f"def {test_func}", str(file_path)],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # If it's a file ref
    if test_ref.endswith(".py"):
        test_path = test_ref if "/" in test_ref else f"tests/{test_ref}"
        return (repo_root / test_path).exists()

    # Otherwise grep for def test_ref
    try:
        r = subprocess.run(
            ["grep", "-rq", f"def {test_ref}", str(tests_dir)],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def verify_ci_lane_exists(
    lane: str,
    repo_root: Path | None = None,
    discovered_lanes: Set[str] | None = None,
) -> bool:
    """
    Verify lane exists by either discovery or static known set.
    Backwards-compatible: repo_root/discovered_lanes optional for unit tests.
    """
    rr = repo_root or Path.cwd()
    lanes = _normalize_known_lanes(discovered_lanes) | merged_known_lanes(rr)

    lane_l = (lane or "").lower().strip()
    if not lane_l:
        return False

    if lane_l in lanes:
        return True

    # fallback: check Makefile target explicitly (covers cases where discovery missed)
    makefile = rr / "Makefile"
    if makefile.exists():
        try:
            content = makefile.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = makefile.read_text(errors="ignore")
        if re.search(rf"^{re.escape(lane)}\s*:", content, re.MULTILINE):
            return True
        if re.search(rf"^\.PHONY:.*\b{re.escape(lane)}\b", content, re.MULTILINE):
            return True

    return False


def validate_evidence_artifact(
    evidence: str, known_lanes: Set[str] | None = None
) -> bool:
    """
    Shallow validation: must include at least one repo-backed artifact reference.
    Backwards-compatible: known_lanes optional for unit tests.
    """
    if not (evidence or "").strip():
        return False

    e = evidence.strip()

    # file-like: path or extension; allow "ci.yml:unit" and "api/auth.py:123"
    if ("/" in e and "." in e) or any(
        ext in e for ext in (".py", ".yml", ".yaml", ".md", ".toml", ".json")
    ):
        return True

    # test-like
    if e.startswith("test_") or "test_" in e or "::" in e:
        return True

    # lane-like
    lanes = _normalize_known_lanes(known_lanes)
    el = e.lower()
    return any(lane in el for lane in lanes)


@dataclass
class EvidenceVerificationResult:
    valid: bool
    errors: list[str]
    warnings: list[str]
    verified_artifacts: list[str]


def verify_evidence_artifacts(
    evidence: str,
    repo_root: Path | None = None,
    discovered_lanes: Set[str] | None = None,
    cache: FileExistCache | None = None,
    *,
    skip_file_checks: bool = False,
) -> EvidenceVerificationResult:
    """
    Deep verification:
      - file paths exist
      - tests exist
      - lanes exist
      - at least one verified artifact required

    Backwards-compatible defaults:
      verify_evidence_artifacts("...", skip_file_checks=True)
    """
    rr = repo_root or Path.cwd()
    lanes = _normalize_known_lanes(discovered_lanes) | merged_known_lanes(rr)
    c: FileExistCache = cache if cache is not None else {}

    errors: list[str] = []
    warnings: list[str] = []
    verified: list[str] = []

    if not (evidence or "").strip():
        return EvidenceVerificationResult(
            valid=False,
            errors=["Evidence is required"],
            warnings=[],
            verified_artifacts=[],
        )

    file_paths = extract_file_paths(evidence)
    test_refs = extract_test_references(evidence)
    ci_lanes = extract_ci_lane_references(evidence, lanes)

    for p in file_paths:
        if skip_file_checks:
            verified.append(f"file:{p}")
        elif verify_file_exists(p, rr, c):
            verified.append(f"file:{p}")
        else:
            errors.append(f"Evidence file not found: {p}")

    for t in test_refs:
        if skip_file_checks:
            verified.append(f"test:{t}")
        elif verify_test_exists(t, rr):
            verified.append(f"test:{t}")
        else:
            # allow test file fallback via file existence
            if t.endswith(".py"):
                test_path = t if "/" in t else f"tests/{t}"
                if verify_file_exists(test_path, rr, c):
                    verified.append(f"test:{t}")
                    continue
            errors.append(f"Evidence test reference not found: {t}")

    for lane in ci_lanes:
        if skip_file_checks:
            verified.append(f"ci:{lane}")
        elif verify_ci_lane_exists(lane, rr, lanes):
            verified.append(f"ci:{lane}")
        else:
            errors.append(f"Evidence CI lane not found: {lane}")

    if not verified and not errors:
        errors.append(
            "Evidence must contain at least one verifiable repo-backed artifact "
            "(file path, test reference, or CI lane)."
        )

    return EvidenceVerificationResult(
        valid=(len(errors) == 0 and len(verified) > 0),
        errors=errors,
        warnings=warnings,
        verified_artifacts=verified,
    )


def validate_owner_evidence_match(
    owner: str, evidence: str, known_lanes: Set[str] | None = None
) -> list[str]:
    """
    Owner semantics validation.
    Backwards-compatible: known_lanes optional for unit tests.
    """
    errors: list[str] = []
    lanes = _normalize_known_lanes(known_lanes)

    file_paths = extract_file_paths(evidence)
    test_refs = extract_test_references(evidence)
    ci_lanes = extract_ci_lane_references(evidence, lanes)

    if owner == "repo":
        has_repo_file = any(
            p for p in file_paths if not is_infra_path(p) and not is_docs_path(p)
        )
        has_test = bool(test_refs)
        has_ci = bool(ci_lanes)
        if not (has_repo_file or has_test or has_ci):
            errors.append(
                "Owner=repo requires evidence with repo code path, test reference, or CI lane. "
                f"Found: {evidence}"
            )

    elif owner == "infra":
        has_infra_path = any(is_infra_path(p) for p in file_paths)
        has_workflow = any(
            p.startswith(".github/workflows/") or p.endswith((".yml", ".yaml"))
            for p in file_paths
        )
        has_makefile = any(p == "Makefile" for p in file_paths) or (
            "makefile" in (evidence or "").lower()
        )
        has_ci = bool(ci_lanes)
        if not (has_infra_path or has_workflow or has_makefile or has_ci):
            errors.append(
                "Owner=infra requires evidence with workflow YAML, Makefile, infra path, or CI lane. "
                f"Found: {evidence}"
            )

    elif owner == "docs":
        has_docs_path = any(is_docs_path(p) for p in file_paths)
        if not has_docs_path:
            errors.append(
                "Owner=docs requires evidence with docs path reference. "
                f"Found: {evidence}"
            )

    return errors


# -----------------------
# Parsing
# -----------------------


@dataclass
class Gap:
    id: str
    description: str
    severity: str
    evidence: str
    owner: str
    eta: str
    definition_of_done: str


@dataclass
class Waiver:
    gap_id: str
    severity: str
    reason: str
    approved_by: str
    expiration: str
    review_date: str


def validate_matrix_header(content: str) -> list[str]:
    errors: list[str] = []
    header_match: Optional[str] = None

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("|") and "ID" in line and "Gap" in line:
            header_match = line
            break

    if not header_match:
        return ["GAP_MATRIX: No table header found (expected | ID | Gap | ... )"]

    columns = [c.strip() for c in header_match.split("|") if c.strip()]
    if len(columns) != len(EXPECTED_MATRIX_COLUMNS):
        return [
            f"GAP_MATRIX: Header has {len(columns)} columns, expected {len(EXPECTED_MATRIX_COLUMNS)}"
        ]

    for i, (actual, expected) in enumerate(
        zip(columns, EXPECTED_MATRIX_COLUMNS), start=1
    ):
        if actual != expected:
            errors.append(
                f"GAP_MATRIX: Column {i} is '{actual}', expected '{expected}'"
            )

    return errors


def parse_gap_matrix(path: Path) -> list[Gap]:
    if not path.exists():
        return []
    content = path.read_text()

    # Table rows
    table_pattern = re.compile(
        r"^\|\s*(G\d{3}|GAP-\d+)\s*\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|",
        re.MULTILINE,
    )

    gaps: list[Gap] = []
    for m in table_pattern.finditer(content):
        gap_id = normalize_gap_id(m.group(1).strip())
        gaps.append(
            Gap(
                id=gap_id,
                description=m.group(2).strip(),
                severity=m.group(3).strip(),
                evidence=m.group(4).strip(),
                owner=m.group(5).strip(),
                eta=m.group(6).strip(),
                definition_of_done=m.group(7).strip(),
            )
        )
    return gaps


def parse_waivers(path: Path) -> list[Waiver]:
    if not path.exists():
        return []
    content = path.read_text()

    table_pattern = re.compile(
        r"^\|\s*(G\d{3}|GAP-\d+)\s*\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|"
        r"\s*([^|]+)\|",
        re.MULTILINE,
    )

    waivers: list[Waiver] = []
    for m in table_pattern.finditer(content):
        gap_id = normalize_gap_id(m.group(1).strip())
        waivers.append(
            Waiver(
                gap_id=gap_id,
                severity=m.group(2).strip(),
                reason=m.group(3).strip(),
                approved_by=m.group(4).strip(),
                expiration=m.group(5).strip(),
                review_date=m.group(6).strip(),
            )
        )
    return waivers


# -----------------------
# Validation
# -----------------------


def validate_gap(gap: Gap, known_lanes: Set[str] | None = None) -> list[str]:
    """
    Validate gap row. Backwards-compatible: known_lanes optional for unit tests.
    """
    errors: list[str] = []
    lanes = _normalize_known_lanes(known_lanes)

    if not GAP_ID_PATTERN.match(gap.id):
        errors.append(
            f"{gap.id}: Invalid ID format. Must match G[0-9]{{3}} (e.g., G001)"
        )

    if gap.severity not in SEVERITY_LEVELS:
        errors.append(
            f"{gap.id}: Invalid severity '{gap.severity}'. Must be one of: {', '.join(sorted(SEVERITY_LEVELS))}"
        )

    if gap.owner not in VALID_OWNERS:
        errors.append(
            f"{gap.id}: Invalid owner '{gap.owner}'. Must be one of: {', '.join(sorted(VALID_OWNERS))}"
        )

    if not gap.description.strip():
        errors.append(f"{gap.id}: Gap description is required")

    if not gap.evidence.strip():
        errors.append(f"{gap.id}: Evidence is required")
    elif not validate_evidence_artifact(gap.evidence, lanes):
        errors.append(
            f"{gap.id}: Evidence '{gap.evidence}' must include a repo-backed artifact "
            "(file path, test reference, CI lane, or workflow yaml)."
        )

    if not gap.eta.strip():
        errors.append(f"{gap.id}: ETA / Milestone is required")

    if not gap.definition_of_done.strip():
        errors.append(f"{gap.id}: Definition of Done is required")

    return errors


def validate_waiver(waiver: Waiver, gap_lookup: dict[str, Gap]) -> list[str]:
    errors: list[str] = []

    if waiver.gap_id not in gap_lookup:
        return [
            f"Waiver {waiver.gap_id}: Gap ID does not exist in GAP_MATRIX (phantom waiver)"
        ]

    gap = gap_lookup[waiver.gap_id]

    if waiver.severity != gap.severity:
        errors.append(
            f"Waiver {waiver.gap_id}: Severity mismatch - waiver says '{waiver.severity}', gap is '{gap.severity}'"
        )

    approved = waiver.approved_by.strip()
    if not approved:
        errors.append(f"Waiver {waiver.gap_id}: Approved By is required")
    elif not ("@" in approved or "/" in approved or " " in approved):
        errors.append(
            f"Waiver {waiver.gap_id}: Approved By '{approved}' must contain '@', '/', or ' ' (human identifier format)"
        )

    exp = parse_date(waiver.expiration)
    if exp is None:
        errors.append(
            f"Waiver {waiver.gap_id}: Expiration '{waiver.expiration}' is not a valid ISO date (YYYY-MM-DD)"
        )

    return errors


# -----------------------
# Audit result model
# -----------------------


class GapAuditResult:
    def __init__(self) -> None:
        self.blocking_gaps: list[Gap] = []
        self.launch_risk_gaps: list[Gap] = []
        self.post_launch_gaps: list[Gap] = []

        self.waived_gaps: list[tuple[Gap, Waiver]] = []
        self.expired_waivers: list[Waiver] = []
        self.expiring_soon_waivers: list[Waiver] = []
        self.invalid_waiver_attempts: list[Waiver] = []

        self.validation_errors: list[str] = []
        self.evidence_verification_errors: list[str] = []
        self.owner_evidence_mismatches: list[str] = []


# -----------------------
# Core audit
# -----------------------


def run_gap_audit(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
    *,
    repo_root: Path | None = None,
    skip_evidence_verification: bool = False,
) -> GapAuditResult:
    """
    Run gap audit and return results.

    NOTE: 'today' is intentionally the 3rd positional argument to match existing call sites/tests.
    """
    if today is None:
        today = datetime.now()
    if repo_root is None:
        repo_root = Path.cwd()

    result = GapAuditResult()
    discovered_lanes = merged_known_lanes(repo_root)
    file_cache: FileExistCache = {}

    if matrix_path.exists():
        result.validation_errors.extend(validate_matrix_header(matrix_path.read_text()))

    gaps = parse_gap_matrix(matrix_path)
    waivers = parse_waivers(waivers_path)

    # duplicate IDs
    seen: set[str] = set()
    for g in gaps:
        if g.id in seen:
            result.validation_errors.append(f"{g.id}: Duplicate gap ID")
        seen.add(g.id)

    gap_lookup = {g.id: g for g in gaps}

    waiver_by_gap: dict[str, Waiver] = {}
    for w in waivers:
        result.validation_errors.extend(validate_waiver(w, gap_lookup))

        if w.severity == "Production-blocking":
            result.invalid_waiver_attempts.append(w)
            continue

        if not is_waiver_valid(w, today):
            result.expired_waivers.append(w)
            continue

        if is_waiver_expiring_soon(w, today):
            result.expiring_soon_waivers.append(w)

        waiver_by_gap[w.gap_id] = w

    for g in gaps:
        # Always validate; lanes optional is handled downstream.
        result.validation_errors.extend(validate_gap(g, discovered_lanes))

        # IMPORTANT: owner/evidence mismatch is LOGIC, not filesystem verification.
        # It must still run even when skip_evidence_verification=True.
        for err in validate_owner_evidence_match(g.owner, g.evidence, discovered_lanes):
            result.owner_evidence_mismatches.append(f"{g.id}: {err}")

        # Evidence verification: deep checks (filesystem/grep/make targets).
        if not skip_evidence_verification:
            ev = verify_evidence_artifacts(
                g.evidence,
                repo_root=repo_root,
                discovered_lanes=discovered_lanes,
                cache=file_cache,
                skip_file_checks=False,
            )
            for e in ev.errors:
                result.evidence_verification_errors.append(f"{g.id}: {e}")

        w = waiver_by_gap.get(g.id)
        if w and g.severity != "Production-blocking":
            result.waived_gaps.append((g, w))
            continue

        if g.severity == "Production-blocking":
            result.blocking_gaps.append(g)
        elif g.severity == "Launch-risk":
            result.launch_risk_gaps.append(g)
        else:
            result.post_launch_gaps.append(g)

    # deterministic ordering
    result.blocking_gaps.sort(key=lambda x: x.id)
    result.launch_risk_gaps.sort(key=lambda x: x.id)
    result.post_launch_gaps.sort(key=lambda x: x.id)
    result.expired_waivers.sort(key=lambda x: x.gap_id)
    result.expiring_soon_waivers.sort(key=lambda x: x.gap_id)
    result.invalid_waiver_attempts.sort(key=lambda x: x.gap_id)
    result.waived_gaps.sort(key=lambda t: t[0].id)

    return result


# -----------------------
# Scorecard (deterministic)
# -----------------------


def generate_gap_scorecard(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
    *,
    repo_root: Path | None = None,
    skip_evidence_verification: bool = False,
) -> str:
    """
    Deterministic markdown scorecard.
    NO timestamps. Stable order. This is for drift checks and CI artifacts.
    """
    res = run_gap_audit(
        matrix_path,
        waivers_path,
        today,
        repo_root=repo_root,
        skip_evidence_verification=skip_evidence_verification,
    )

    def fmt_gaps(title: str, gaps: list[Gap]) -> list[str]:
        if not gaps:
            return [f"## {title}", "", "_None_", ""]
        lines = [f"## {title}", ""]
        for g in gaps:
            lines.append(f"- **{g.id}**: {g.description} _(owner: {g.owner})_")
        lines.append("")
        return lines

    lines: list[str] = []
    lines.append("# GAP Scorecard")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Production-blocking: **{len(res.blocking_gaps)}**")
    lines.append(f"- Launch-risk: **{len(res.launch_risk_gaps)}**")
    lines.append(f"- Post-launch: **{len(res.post_launch_gaps)}**")
    lines.append(f"- Waived: **{len(res.waived_gaps)}**")
    lines.append(f"- Expired waivers: **{len(res.expired_waivers)}**")
    lines.append(f"- Evidence errors: **{len(res.evidence_verification_errors)}**")
    lines.append(f"- Owner mismatches: **{len(res.owner_evidence_mismatches)}**")
    lines.append(f"- Validation errors: **{len(res.validation_errors)}**")
    lines.append("")

    lines.extend(fmt_gaps("Production-blocking", res.blocking_gaps))
    lines.extend(fmt_gaps("Launch-risk (unwaived)", res.launch_risk_gaps))
    lines.extend(fmt_gaps("Post-launch", res.post_launch_gaps))

    if res.waived_gaps:
        lines.append("## Waived")
        lines.append("")
        for g, w in res.waived_gaps:
            lines.append(
                f"- **{g.id}**: {g.description} _(expires: {w.expiration}, approved: {w.approved_by})_"
            )
        lines.append("")
    else:
        lines.extend(["## Waived", "", "_None_", ""])

    if res.expired_waivers:
        lines.append("## Expired waivers")
        lines.append("")
        for w in res.expired_waivers:
            lines.append(f"- **{w.gap_id}** expired: {w.expiration}")
        lines.append("")

    if res.expiring_soon_waivers:
        lines.append("## Waivers expiring soon")
        lines.append("")
        for w in res.expiring_soon_waivers:
            lines.append(f"- **{w.gap_id}** expires: {w.expiration}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# -----------------------
# CLI reporting
# -----------------------


def format_gap_table(gaps: list[Gap], header: str) -> str:
    if not gaps:
        return ""
    lines = [header, "=" * len(header)]
    for g in gaps:
        lines.append(f"  {g.id}: {g.description}")
        lines.append(f"    Evidence: {g.evidence}")
        lines.append(f"    Owner: {g.owner}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    matrix_path = Path("docs/GAP_MATRIX.md")
    waivers_path = Path("docs/RISK_WAIVERS.md")
    repo_root = Path.cwd()

    if not matrix_path.exists():
        print("ERROR: docs/GAP_MATRIX.md not found")
        return 1

    result = run_gap_audit(
        matrix_path,
        waivers_path,
        datetime.now(),
        repo_root=repo_root,
        skip_evidence_verification=False,
    )

    print("=" * 60)
    print("GAP AUDIT REPORT")
    print("=" * 60)
    print()

    if result.validation_errors:
        print("VALIDATION ERRORS:")
        for e in result.validation_errors:
            print(f"  [ERROR] {e}")
        print()

    if result.evidence_verification_errors:
        print("EVIDENCE VERIFICATION ERRORS:")
        for e in result.evidence_verification_errors:
            print(f"  [ERROR] {e}")
        print()

    if result.owner_evidence_mismatches:
        print("OWNER/EVIDENCE MISMATCH ERRORS:")
        for e in result.owner_evidence_mismatches:
            print(f"  [ERROR] {e}")
        print()

    if result.invalid_waiver_attempts:
        print("INVALID WAIVER ATTEMPTS (Production-blocking cannot be waived):")
        for w in result.invalid_waiver_attempts:
            print(f"  [ERROR] {w.gap_id}: Attempted waiver rejected")
        print()

    if result.expired_waivers:
        print("EXPIRED WAIVERS:")
        for w in result.expired_waivers:
            print(f"  [ERROR] {w.gap_id}: Waiver expired {w.expiration}")
        print()

    if result.blocking_gaps:
        print(
            format_gap_table(
                result.blocking_gaps, "PRODUCTION-BLOCKING GAPS (CI FAILS)"
            )
        )

    if result.launch_risk_gaps:
        print(format_gap_table(result.launch_risk_gaps, "LAUNCH-RISK GAPS (Warning)"))

    if result.expiring_soon_waivers:
        print("WAIVERS EXPIRING SOON:")
        for w in result.expiring_soon_waivers:
            print(f"  [WARN] {w.gap_id}: Expires {w.expiration}")
        print()

    if result.waived_gaps:
        print("WAIVED GAPS:")
        for g, w in result.waived_gaps:
            print(f"  [WAIVED] {g.id}: {g.description}")
            print(f"    Approved by: {w.approved_by}, Expires: {w.expiration}")
        print()

    if result.post_launch_gaps:
        print(
            format_gap_table(
                result.post_launch_gaps, "POST-LAUNCH GAPS (Informational)"
            )
        )

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

    has_errors = (
        bool(result.blocking_gaps)
        or bool(result.validation_errors)
        or bool(result.expired_waivers)
        or bool(result.invalid_waiver_attempts)
        or bool(result.evidence_verification_errors)
        or bool(result.owner_evidence_mismatches)
    )

    if has_errors:
        print("=" * 60)
        print("GAP AUDIT: FAILED")
        print("=" * 60)
        return 1

    print("=" * 60)
    print("GAP AUDIT: PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
