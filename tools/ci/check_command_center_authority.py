#!/usr/bin/env python3
"""
check_command_center_authority.py

CI validator for the Operations Workspace (PR 18.6.3).

Checks each command-center component file for:
  - MCIM_ID declaration matching MCIM-18.6-
  - AUTHORITY declaration
  - sourceOfTruth declaration
  - drillDown or href= reference
  - Does NOT contain Math.random
  - Does NOT contain dangerouslySetInnerHTML
  - Does NOT contain localStorage or sessionStorage
  - Does NOT contain 'destructive' as a Badge variant
  - Does NOT contain hardcoded fake metrics (= 97, = 98, = 99 percent patterns)

Also validates apps/console/app/dashboard/page.tsx for:
  - ops-matrix-heading
  - correlation-heading
  - future-heading
  - async function DashboardOverviewPage
  - Promise.allSettled

Returns exit 1 if any errors are found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


COMPONENT_DIR = (
    Path(__file__).resolve().parents[2]
    / "apps"
    / "console"
    / "components"
    / "command-center"
)
DASHBOARD_PAGE = (
    Path(__file__).resolve().parents[2]
    / "apps"
    / "console"
    / "app"
    / "dashboard"
    / "page.tsx"
)

# Files that are exempt from component-level checks (WidgetShell is the shared wrapper)
EXEMPT_FILES = {"WidgetShell.tsx"}

REQUIRED_DASHBOARD_ANCHORS = [
    "ops-matrix-heading",
    "correlation-heading",
    "future-heading",
    "async function DashboardOverviewPage",
    "Promise.allSettled",
]

PROHIBITED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"Math\.random"),
        "contains Math.random() — fabricated data not allowed",
    ),
    (
        re.compile(r"dangerouslySetInnerHTML"),
        "contains dangerouslySetInnerHTML — not allowed",
    ),
    (
        re.compile(r"localStorage"),
        "contains localStorage — not allowed for authoritative state",
    ),
    (
        re.compile(r"sessionStorage"),
        "contains sessionStorage — not allowed for authoritative state",
    ),
    (
        re.compile(r"""variant=['"]destructive['"]"""),
        "contains 'destructive' Badge variant — use 'danger' instead",
    ),
    (
        re.compile(r"=\s*(?:97|98|99)\b"),
        "possible hardcoded fake metric percentage (= 97, = 98, = 99)",
    ),
]


def check_file(path: Path) -> list[str]:
    """Return list of error strings for a single component file."""
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read file: {exc}"]

    name = path.name

    # MCIM_ID declaration matching MCIM-18.6-
    if not re.search(r"MCIM_ID\s*=.*MCIM-18\.6-", text) and "MCIM-18.6-" not in text:
        errors.append(f"{name}: missing MCIM_ID declaration matching MCIM-18.6-")

    # AUTHORITY declaration
    has_authority = (
        re.search(r"const\s+AUTHORITY\s*=", text) is not None
        or "AUTHORITY" in text
        or "authority:" in text.lower()
    )
    if not has_authority:
        errors.append(f"{name}: missing AUTHORITY declaration")

    # sourceOfTruth declaration
    if "sourceOfTruth" not in text:
        errors.append(f"{name}: missing sourceOfTruth reference")

    # drillDown or href= reference
    if "drillDown" not in text and "href=" not in text:
        errors.append(f"{name}: missing drillDown or href= reference")

    # Prohibited patterns
    for pattern, msg in PROHIBITED_PATTERNS:
        if pattern.search(text):
            errors.append(f"{name}: {msg}")

    return errors


def check_dashboard_page() -> list[str]:
    """Validate that the dashboard page contains all required anchor strings."""
    errors: list[str] = []
    if not DASHBOARD_PAGE.is_file():
        return [f"missing dashboard page: {DASHBOARD_PAGE}"]
    try:
        text = DASHBOARD_PAGE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read dashboard page: {exc}"]

    for anchor in REQUIRED_DASHBOARD_ANCHORS:
        if anchor not in text:
            errors.append(
                f"dashboard/page.tsx: missing required anchor string '{anchor}'"
            )

    return errors


def main() -> int:
    all_errors: list[str] = []

    # Check component files
    if not COMPONENT_DIR.is_dir():
        print(f"ERROR: command-center component directory not found: {COMPONENT_DIR}")
        return 1

    component_files = sorted(COMPONENT_DIR.glob("*.tsx"))
    if not component_files:
        print(f"ERROR: no .tsx files found in {COMPONENT_DIR}")
        return 1

    checked = 0
    passed = 0

    for path in component_files:
        if path.name in EXEMPT_FILES:
            continue
        errors = check_file(path)
        checked += 1
        if errors:
            for err in errors:
                print(f"ERROR: {err}")
                all_errors.append(err)
        else:
            passed += 1
            print(f"PASS: {path.name}")

    # Check dashboard page
    dashboard_errors = check_dashboard_page()
    if dashboard_errors:
        for err in dashboard_errors:
            print(f"ERROR: {err}")
        all_errors.extend(dashboard_errors)
    else:
        print("PASS: dashboard/page.tsx authority checks")

    total_errors = len(all_errors)

    print(f"\n{'=' * 50}")
    print(
        f"Components checked: {checked}, passed: {passed}, failed: {checked - passed}"
    )
    print(f"Dashboard checks: {'passed' if not dashboard_errors else 'FAILED'}")

    if total_errors > 0:
        print(f"\nFAILED: {total_errors} error(s) found.")
        return 1

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
