#!/usr/bin/env python3
"""
check_operations_center.py

CI validator for PR 18.7 — Autonomous Governance Operations Center (AGOC).

Checks:
  1. Page file exists at the correct path
  2. All 10 component files exist
  3. API file exists
  4. Navigation registration: operations-center present in packages/navigation/src/registrations/console.ts
  5. MCIM metadata: page contains data-mcim="OPERATIONS-CENTER"
  6. No fake metrics: no Math.random, mockData, fakeData, demoData in component files
  7. No dangerous patterns: no dangerouslySetInnerHTML in component files
  8. No fake IDs: component files don't use crypto.randomUUID() for display ordering
  9. Automation safety: AutomationSafetyCenter.tsx contains riskScore and killSwitch
  10. Evidence freshness: EvidenceFreshnessMonitor.tsx references trustScore
  11. Briefing suppression: ExecutiveOperationalBriefing.tsx contains sufficientEvidence check
  12. Policy conflict: PolicyConflictCenter.tsx references anomalies or conflicts
  13. Widget metadata: each component file contains data-mcim
  14. No localStorage/sessionStorage authority: component files don't use localStorage.getItem
      or sessionStorage.getItem for governance state
  15. Sidebar icon: Sidebar.tsx references operations-center
  16. Workspace nav: workspaceNav.ts references operations-center

Returns exit 1 if any errors are found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

COMPONENT_DIR = REPO_ROOT / "apps" / "console" / "components" / "operations-center"
PAGE_FILE = (
    REPO_ROOT
    / "apps"
    / "console"
    / "app"
    / "dashboard"
    / "operations-center"
    / "page.tsx"
)
API_FILE = REPO_ROOT / "apps" / "console" / "lib" / "operationsCenterApi.ts"
NAV_FILE = (
    REPO_ROOT / "packages" / "navigation" / "src" / "registrations" / "console.ts"
)
SIDEBAR_FILE = REPO_ROOT / "apps" / "console" / "components" / "layout" / "Sidebar.tsx"
WORKSPACE_NAV_FILE = REPO_ROOT / "apps" / "console" / "lib" / "workspaceNav.ts"

EXPECTED_COMPONENTS = [
    "ExecutiveOperationsQueue.tsx",
    "GovernanceAutomationQueue.tsx",
    "DecisionExecutionPipeline.tsx",
    "OperationalRiskHeatmap.tsx",
    "EvidenceFreshnessMonitor.tsx",
    "PolicyConflictCenter.tsx",
    "GovernanceSLAMonitor.tsx",
    "AutomationSafetyCenter.tsx",
    "CrossAuthorityTimeline.tsx",
    "ExecutiveOperationalBriefing.tsx",
]

MCIM_AUTHORITY = "OPERATIONS-CENTER"

# Patterns prohibited in all component files
PROHIBITED_COMPONENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"Math\.random"),
        "contains Math.random() — fabricated data not allowed",
    ),
    (
        re.compile(r"Math\.floor\(Math\.random"),
        "contains Math.floor(Math.random()) — fabricated data not allowed",
    ),
    (
        re.compile(r"\bmockData\b"),
        "contains mockData — fake data arrays not allowed",
    ),
    (
        re.compile(r"\bfakeData\b"),
        "contains fakeData — fake data arrays not allowed",
    ),
    (
        re.compile(r"\bdemoData\b"),
        "contains demoData — fake data arrays not allowed",
    ),
    (
        re.compile(r"dangerouslySetInnerHTML"),
        "contains dangerouslySetInnerHTML — not allowed in governance components",
    ),
    (
        re.compile(r"localStorage\.getItem"),
        "contains localStorage.getItem — not allowed for governance state",
    ),
    (
        re.compile(r"sessionStorage\.getItem"),
        "contains sessionStorage.getItem — not allowed for governance state",
    ),
]

# crypto.randomUUID() allowed for key props but not for ordering/display IDs
# Detect non-key-prop usage: assignment to a variable used as ID or ordering
_RANDOM_UUID_FOR_ID_RE = re.compile(
    r"(?:id|order|index|position|rank)\s*[=:]\s*(?:window\.)?crypto\.randomUUID\(\)"
    r"|crypto\.randomUUID\(\)\s*(?:;|,)",
    re.IGNORECASE,
)


def _check_fake_uuid(text: str) -> bool:
    """Return True if file uses crypto.randomUUID() for display ordering."""
    return bool(_RANDOM_UUID_FOR_ID_RE.search(text))


def check_component(path: Path) -> list[str]:
    """Check a single component file and return error strings."""
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{path.name}: cannot read file: {exc}"]

    name = path.name

    # Check 13: widget metadata — data-mcim attribute
    if "data-mcim" not in text:
        errors.append(
            f"{name}: missing data-mcim attribute — all components must declare MCIM metadata"
        )

    # Check 6 & 7 & 14: prohibited patterns
    for pattern, msg in PROHIBITED_COMPONENT_PATTERNS:
        if pattern.search(text):
            errors.append(f"{name}: {msg}")

    # Check 8: no fake IDs from crypto.randomUUID for ordering
    if _check_fake_uuid(text):
        errors.append(
            f"{name}: uses crypto.randomUUID() for display ordering — "
            "IDs must come from authoritative platform state"
        )

    return errors


def check_automation_safety_center() -> list[str]:
    """Check 9: AutomationSafetyCenter.tsx contains riskScore and killSwitch."""
    errors: list[str] = []
    path = COMPONENT_DIR / "AutomationSafetyCenter.tsx"
    if not path.is_file():
        return []  # Missing file already caught in main
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"AutomationSafetyCenter.tsx: cannot read: {exc}"]

    if "riskScore" not in text:
        errors.append(
            "AutomationSafetyCenter.tsx: missing riskScore reference — "
            "safety center must display computed risk score"
        )
    if "killSwitch" not in text:
        errors.append(
            "AutomationSafetyCenter.tsx: missing killSwitch reference — "
            "safety center must expose kill switch state"
        )
    return errors


def check_evidence_freshness_monitor() -> list[str]:
    """Check 10: EvidenceFreshnessMonitor.tsx references trustScore."""
    errors: list[str] = []
    path = COMPONENT_DIR / "EvidenceFreshnessMonitor.tsx"
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"EvidenceFreshnessMonitor.tsx: cannot read: {exc}"]

    if "trustScore" not in text:
        errors.append(
            "EvidenceFreshnessMonitor.tsx: missing trustScore reference — "
            "evidence freshness must surface trust scores"
        )
    return errors


def check_executive_operational_briefing() -> list[str]:
    """Check 11: ExecutiveOperationalBriefing.tsx contains sufficientEvidence check."""
    errors: list[str] = []
    path = COMPONENT_DIR / "ExecutiveOperationalBriefing.tsx"
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"ExecutiveOperationalBriefing.tsx: cannot read: {exc}"]

    if "sufficientEvidence" not in text:
        errors.append(
            "ExecutiveOperationalBriefing.tsx: missing sufficientEvidence check — "
            "briefing must gate output on evidence sufficiency (fail closed)"
        )
    return errors


def check_policy_conflict_center() -> list[str]:
    """Check 12: PolicyConflictCenter.tsx references anomalies or conflicts."""
    errors: list[str] = []
    path = COMPONENT_DIR / "PolicyConflictCenter.tsx"
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"PolicyConflictCenter.tsx: cannot read: {exc}"]

    has_anomaly = re.search(r"\banomal", text, re.IGNORECASE) is not None
    has_conflict = re.search(r"\bconflict", text, re.IGNORECASE) is not None
    if not has_anomaly and not has_conflict:
        errors.append(
            "PolicyConflictCenter.tsx: missing anomalies or conflicts reference — "
            "panel must surface governance anomalies and policy conflicts"
        )
    return errors


def check_page_file() -> list[str]:
    """Check 1 & 5: Page file exists and contains MCIM metadata."""
    errors: list[str] = []
    if not PAGE_FILE.is_file():
        return [f"missing page file: {PAGE_FILE.relative_to(REPO_ROOT)}"]
    try:
        text = PAGE_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read page file: {exc}"]

    # Check 5: MCIM metadata
    if f'data-mcim="{MCIM_AUTHORITY}"' not in text:
        errors.append(
            f'operations-center/page.tsx: missing data-mcim="{MCIM_AUTHORITY}" — '
            "page must declare MCIM authority"
        )

    return errors


def check_api_file() -> list[str]:
    """Check 3: API file exists."""
    if not API_FILE.is_file():
        return [f"missing API file: {API_FILE.relative_to(REPO_ROOT)}"]
    return []


def check_navigation_registration() -> list[str]:
    """Check 4: operations-center present in navigation console.ts."""
    errors: list[str] = []
    if not NAV_FILE.is_file():
        return [f"missing navigation file: {NAV_FILE.relative_to(REPO_ROOT)}"]
    try:
        text = NAV_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read navigation file: {exc}"]

    if "operations-center" not in text:
        errors.append(
            f"{NAV_FILE.relative_to(REPO_ROOT)}: missing 'operations-center' navigation registration"
        )
    return errors


def check_sidebar() -> list[str]:
    """Check 15: Sidebar.tsx references operations-center."""
    errors: list[str] = []
    if not SIDEBAR_FILE.is_file():
        return [f"missing Sidebar file: {SIDEBAR_FILE.relative_to(REPO_ROOT)}"]
    try:
        text = SIDEBAR_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read Sidebar file: {exc}"]

    if "operations-center" not in text:
        errors.append(
            "Sidebar.tsx: missing 'operations-center' reference — "
            "sidebar must include AGOC navigation entry"
        )
    return errors


def check_workspace_nav() -> list[str]:
    """Check 16: workspaceNav.ts references operations-center."""
    errors: list[str] = []
    if not WORKSPACE_NAV_FILE.is_file():
        return [
            f"missing workspaceNav file: {WORKSPACE_NAV_FILE.relative_to(REPO_ROOT)}"
        ]
    try:
        text = WORKSPACE_NAV_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read workspaceNav file: {exc}"]

    if "operations-center" not in text:
        errors.append(
            "workspaceNav.ts: missing 'operations-center' entry — "
            "workspace nav must register AGOC route"
        )
    return errors


def main() -> int:
    all_errors: list[str] = []
    passed = 0
    failed = 0

    def record(label: str, errors: list[str]) -> None:
        nonlocal passed, failed
        if errors:
            for e in errors:
                print(f"ERROR: {e}")
            all_errors.extend(errors)
            failed += 1
        else:
            print(f"PASS: {label}")
            passed += 1

    # Check 1 & 5: page file
    record("operations-center/page.tsx", check_page_file())

    # Check 3: API file
    record("operationsCenterApi.ts", check_api_file())

    # Check 4: navigation registration
    record(
        "navigation/console.ts — operations-center registration",
        check_navigation_registration(),
    )

    # Check 15: sidebar
    record("Sidebar.tsx — operations-center reference", check_sidebar())

    # Check 16: workspace nav
    record("workspaceNav.ts — operations-center reference", check_workspace_nav())

    # Check 2: all 10 component files exist + per-file quality checks
    if not COMPONENT_DIR.is_dir():
        print(
            f"ERROR: component directory not found: {COMPONENT_DIR.relative_to(REPO_ROOT)}"
        )
        all_errors.append("component directory missing")
        failed += 1
    else:
        for filename in EXPECTED_COMPONENTS:
            path = COMPONENT_DIR / filename
            if not path.is_file():
                err = f"missing component file: apps/console/components/operations-center/{filename}"
                print(f"ERROR: {err}")
                all_errors.append(err)
                failed += 1
                continue
            # Checks 6–8, 13–14 per component
            errs = check_component(path)
            record(filename, errs)

    # Check 9: automation safety
    record(
        "AutomationSafetyCenter.tsx — riskScore + killSwitch",
        check_automation_safety_center(),
    )

    # Check 10: evidence freshness
    record(
        "EvidenceFreshnessMonitor.tsx — trustScore", check_evidence_freshness_monitor()
    )

    # Check 11: briefing suppression
    record(
        "ExecutiveOperationalBriefing.tsx — sufficientEvidence",
        check_executive_operational_briefing(),
    )

    # Check 12: policy conflict
    record(
        "PolicyConflictCenter.tsx — anomalies/conflicts", check_policy_conflict_center()
    )

    print(f"\n{'=' * 60}")
    print(f"Total checks: {passed + failed}  passed: {passed}  failed: {failed}")
    print(f"Total errors: {len(all_errors)}")

    if all_errors:
        print("\nFAILED — operations-center CI check did not pass.")
        return 1

    print("\nPASS — Autonomous Governance Operations Center (AGOC) CI check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
