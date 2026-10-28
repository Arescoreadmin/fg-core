"""
P0-DEPENDENCY-REMEDIATION-001 — Dependency audit enforcement regression tests.

Verifies that:
  01  Installed production packages are at patched minimum versions (offline, 9 packages)
  02  pip-audit version supports --ignore-vuln (>=2.10.1)
  03  Active exceptions doc matches Makefile --ignore-vuln flags
  04  Requirement specifier version floors are >= the patched minimum (5 packages)
  05  Stale exceptions are not present in Makefile
  06  constraints.txt encodes minimum versions for production transitive deps
  07  requirements-shared.txt pins starlette at >=1.3.1
  08  requirements.txt pins python-multipart at >=0.0.31
  09  pip-audit CI gate has no continue-on-error suppression
  10  Exception doc has no active entries

Scope: OFFLINE ONLY. No network I/O. No subprocess network calls.
The live pip-audit gate lives in the CI workflow step.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.version import Version

REPO = Path(__file__).resolve().parents[2]
REQUIREMENTS_PROD = REPO / "requirements.txt"
REQUIREMENTS_SHARED = REPO / "requirements-shared.txt"
REQUIREMENTS_DEV = REPO / "requirements-dev.txt"
CONSTRAINTS = REPO / "constraints.txt"
EXCEPTIONS_DOC = REPO / "docs" / "security" / "DEPENDENCY_AUDIT_EXCEPTIONS.md"
MAKEFILE = REPO / "Makefile"
FG_REQUIRED_YML = REPO / ".github" / "workflows" / "fg-required.yml"

# Stale CVEs that were suppressed before P0-DEPENDENCY-REMEDIATION-001
_STALE_SUPPRESSED = {
    "CVE-2026-54283",
    "CVE-2026-54282",
    "CVE-2026-53540",
    "CVE-2026-53539",
    "CVE-2026-53538",
    "MAL-2026-4750",
    "CVE-2026-4539",
    "PYSEC-2025-183",
}


# Packages whose installed version must be at or above the patched minimum.
# Verified offline by importing importlib.metadata — no network I/O required.
_INSTALLED_VERSION_FLOORS: list[tuple[str, str]] = [
    ("starlette", "1.3.1"),
    ("python-multipart", "0.0.31"),
    ("certifi", "2026.10.23"),
    ("pillow", "13.0.0"),
    ("urllib3", "2.8.0"),
    ("dnspython", "2.9.0"),
    ("pypdf", "6.21.2"),
    ("opentelemetry-api", "1.45.1"),
    ("opentelemetry-sdk", "1.45.1"),
]


# ===========================================================================
# Test 01 — Installed production packages are at patched minimum versions
# ===========================================================================


@pytest.mark.parametrize("package,min_version", _INSTALLED_VERSION_FLOORS)
def test_enforcement_01_installed_versions_at_minimum(
    package: str, min_version: str
) -> None:
    """Installed venv package must be at or above the patched minimum.

    Offline — reads importlib.metadata only; no network I/O, no subprocess.
    The live pip-audit gate lives in the CI workflow step.
    """
    import importlib.metadata

    try:
        installed = importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        pytest.skip(f"{package} not installed in this venv")

    assert Version(installed) >= Version(min_version), (
        f"{package}=={installed} is below patched minimum {min_version}; "
        f"run `make venv` to upgrade"
    )


# ===========================================================================
# Test 02 — pip-audit version supports --ignore-vuln
# ===========================================================================


def test_enforcement_02_pip_audit_version_supports_ignore_vuln() -> None:
    """pip-audit must be >=2.10.1 to support --ignore-vuln."""
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    version_str = result.stdout.strip() + result.stderr.strip()
    # Extract version number
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    assert match, f"Could not parse pip-audit version from: {version_str!r}"
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    version_tuple = (major, minor, patch)
    assert version_tuple >= (2, 10, 1), (
        f"pip-audit {version_str} does not support --ignore-vuln; need >=2.10.1"
    )


# ===========================================================================
# Test 03 — Makefile --ignore-vuln flags match active exceptions
# ===========================================================================


def test_enforcement_03_makefile_exceptions_match_active_doc() -> None:
    """Makefile must not suppress advisories that are not active exceptions.

    After P0-DEPENDENCY-REMEDIATION-001 all exceptions are closed, so
    --ignore-vuln must not appear at all in the pip-audit target.
    """
    makefile_text = MAKEFILE.read_text(encoding="utf-8")
    in_pip_audit = False
    ignore_vulns_found: list[str] = []
    for line in makefile_text.splitlines():
        if line.startswith("pip-audit:"):
            in_pip_audit = True
        elif in_pip_audit and not line.startswith("\t") and line.strip():
            in_pip_audit = False
        if in_pip_audit and "--ignore-vuln" in line:
            matches = re.findall(r"--ignore-vuln\s+(\S+)", line)
            ignore_vulns_found.extend(matches)

    exceptions_text = EXCEPTIONS_DOC.read_text(encoding="utf-8")
    active_section = exceptions_text.split("## Active Exceptions")[1].split(
        "## Closed Exceptions"
    )[0]
    has_active = (
        "EXC-DEP-" in active_section and "_No active exceptions_" not in active_section
    )

    if not has_active:
        assert not ignore_vulns_found, (
            f"No active exceptions in {EXCEPTIONS_DOC.name} but Makefile "
            f"still has --ignore-vuln flags: {ignore_vulns_found}"
        )


# ===========================================================================
# Test 04 — Minimum production package versions met
# ===========================================================================


@pytest.mark.parametrize(
    "package,min_version,requirement_file",
    [
        ("starlette", "1.3.1", "requirements-shared.txt"),
        ("python-multipart", "0.0.31", "requirements.txt"),
        ("certifi", "2026.10.23", "constraints.txt"),
        ("pillow", "13.0.0", "constraints.txt"),
        ("urllib3", "2.8.0", "constraints.txt"),
    ],
)
def test_enforcement_04_minimum_versions(
    package: str, min_version: str, requirement_file: str
) -> None:
    """Requirement specifier for each package must enforce a version >= the patched minimum.

    Parses the actual version specifier from the file and compares numerically —
    a name-only presence check would pass even if the floor was lowered.
    """
    path = REPO / requirement_file
    text = path.read_text(encoding="utf-8")

    # Collect all version specifiers for this package from the file
    pkg_escaped = re.escape(package)
    # Match lines like: pkg==1.2.3 or pkg>=1.2.3 or pkg>=1.2.3,<2.0
    pattern = re.compile(
        rf"^{pkg_escaped}([><=!][^#\s]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = pattern.findall(text)
    assert matches, (
        f"{package!r} not found in {requirement_file}; expected a specifier "
        f">= {min_version}"
    )

    # Verify that every lower-bound (>= or ==) specifier is >= the patched minimum
    min_ver = Version(min_version)
    lower_bounds: list[Version] = []
    for spec_str in matches:
        # spec_str is e.g. ">=1.3.1" or "==1.3.1" or ">=1.3.1,<2.0"
        for clause in spec_str.split(","):
            clause = clause.strip()
            m = re.match(r"^(>=|==|~=)(.+)$", clause)
            if m:
                lower_bounds.append(Version(m.group(2)))

    assert lower_bounds, (
        f"{package!r} in {requirement_file} has no lower-bound specifier (>=, ==, ~=); "
        f"cannot verify minimum {min_version}"
    )
    for bound in lower_bounds:
        assert bound >= min_ver, (
            f"{package!r} lower bound {bound} in {requirement_file} is below "
            f"patched minimum {min_version}"
        )


# ===========================================================================
# Test 05 — Stale --ignore-vuln IDs not present in Makefile
# ===========================================================================


def test_enforcement_05_stale_suppressions_removed_from_makefile() -> None:
    """Makefile must not contain --ignore-vuln for closed exception IDs."""
    makefile_text = MAKEFILE.read_text(encoding="utf-8")
    found_stale = [
        cve for cve in _STALE_SUPPRESSED if f"--ignore-vuln {cve}" in makefile_text
    ]
    assert not found_stale, (
        f"Makefile still contains --ignore-vuln for closed exceptions: {found_stale}"
    )


# ===========================================================================
# Test 06 — constraints.txt encodes production transitive dep floors
# ===========================================================================


def test_enforcement_06_constraints_encode_transitive_floors() -> None:
    """constraints.txt must encode minimum-version floors for certifi, pillow, urllib3."""
    text = CONSTRAINTS.read_text(encoding="utf-8")
    required_constraints = ["certifi>=", "pillow>=", "urllib3>="]
    for req in required_constraints:
        assert req in text, (
            f"constraints.txt missing floor for {req.rstrip('>=')}; "
            f"production transitive deps must have version floors"
        )


# ===========================================================================
# Test 07 — requirements-shared.txt pins starlette at >=1.3.1
# ===========================================================================


def test_enforcement_07_starlette_patched_version() -> None:
    """starlette must be pinned to >=1.3.1 (CVE-2026-54283 / CVE-2026-54282 fix)."""
    text = REQUIREMENTS_SHARED.read_text(encoding="utf-8")
    match = re.search(r"starlette==(\d+\.\d+\.\d+)", text)
    assert match, "starlette not found as pinned version in requirements-shared.txt"
    pinned = tuple(int(x) for x in match.group(1).split("."))
    assert pinned >= (1, 3, 1), (
        f"starlette=={match.group(1)} is below patched minimum 1.3.1"
    )


# ===========================================================================
# Test 08 — requirements.txt pins python-multipart at >=0.0.31
# ===========================================================================


def test_enforcement_08_multipart_patched_version() -> None:
    """python-multipart must be >=0.0.31 (CVE-2026-53540/53539/53538 fix)."""
    text = REQUIREMENTS_PROD.read_text(encoding="utf-8")
    match = re.search(r"python-multipart==(\d+\.\d+\.\d+)", text)
    assert match, "python-multipart not found as pinned version in requirements.txt"
    pinned = tuple(int(x) for x in match.group(1).split("."))
    assert pinned >= (0, 0, 31), (
        f"python-multipart=={match.group(1)} is below patched minimum 0.0.31"
    )


# ===========================================================================
# Test 09 — CI pip-audit gate has no continue-on-error suppression
# ===========================================================================


def test_enforcement_09_ci_pip_audit_is_blocking() -> None:
    """The pip-audit step in fg-required.yml must not have continue-on-error: true."""
    text = FG_REQUIRED_YML.read_text(encoding="utf-8")
    lines = text.splitlines()

    in_pip_audit_step = False
    for line in lines:
        if "Dependency vulnerability audit (pip-audit)" in line:
            in_pip_audit_step = True
        if in_pip_audit_step:
            # Next step header ends this step's scope
            if line.strip().startswith("- name:") and "pip-audit" not in line:
                break
            assert "continue-on-error: true" not in line, (
                "CI pip-audit step must not have continue-on-error: true; "
                "it must be a blocking gate"
            )


# ===========================================================================
# Test 10 — Exception doc has no active entries
# ===========================================================================


def test_enforcement_10_no_active_exceptions() -> None:
    """After P0-DEPENDENCY-REMEDIATION-001 all exceptions are closed.

    The active exceptions section must explicitly state this or contain no
    EXC-DEP-NNN entries.
    """
    text = EXCEPTIONS_DOC.read_text(encoding="utf-8")
    active_section = text.split("## Active Exceptions")[1].split(
        "## Closed Exceptions"
    )[0]
    has_exc_entry = bool(re.search(r"### EXC-DEP-\d+", active_section))
    assert not has_exc_entry, (
        "Active exceptions section still contains EXC-DEP entries; "
        "close all exceptions before shipping P0-DEPENDENCY-REMEDIATION-001"
    )
