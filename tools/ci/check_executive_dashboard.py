#!/usr/bin/env python3
"""
check_executive_dashboard.py

CI validator for the Executive Command Center (PR 18.6.2).

Checks each command-center component file for:
  - authority string constant or comment (AUTHORITY = / # authority: / mcimId)
  - MCIM reference (MCIM-18.6-)
  - sourceOfTruth reference
  - drillDown reference (drillDown or href=)
  - No prohibited patterns (Math.random, hardcoded scores)

Also validates apps/console/app/dashboard/page.tsx for five required anchor strings.

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

REQUIRED_ANCHORS = [
    "billing-ready",
    "billing-not-ready",
    "billing-error",
    "events-loading",
    "Core unreachable",
]

PROHIBITED_PATTERNS = [
    (
        re.compile(r"Math\.random"),
        "contains Math.random() — fabricated data not allowed",
    ),
    # Hardcoded metric-looking numbers like = 87 or = 0.92 outside of test/comment context
    (
        re.compile(r"(?<!//\s)(?<!\*\s)=\s*(?:0\.9[0-9]|0\.[0-9]{2})\b(?!\s*//)"),
        "possible hardcoded confidence score",
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

    # MCIM reference
    if "MCIM-18.6-" not in text:
        errors.append(f"{name}: missing MCIM reference (MCIM-18.6-)")

    # authority reference
    has_authority = (
        "AUTHORITY" in text
        or "authority:" in text.lower()
        or "mcimId" in text
        or "Authority" in text
    )
    if not has_authority:
        errors.append(
            f"{name}: missing authority reference (AUTHORITY = / authority: / mcimId)"
        )

    # sourceOfTruth
    if "sourceOfTruth" not in text:
        errors.append(f"{name}: missing sourceOfTruth reference")

    # drillDown
    if "drillDown" not in text and "href=" not in text:
        errors.append(f"{name}: missing drillDown or href= reference")

    # Prohibited patterns
    for pattern, msg in PROHIBITED_PATTERNS:
        if pattern.search(text):
            errors.append(f"{name}: {msg}")

    return errors


def check_dashboard_anchors() -> list[str]:
    """Validate that the dashboard page contains all five required anchor strings."""
    errors: list[str] = []
    if not DASHBOARD_PAGE.is_file():
        return [f"missing dashboard page: {DASHBOARD_PAGE}"]
    try:
        text = DASHBOARD_PAGE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read dashboard page: {exc}"]

    for anchor in REQUIRED_ANCHORS:
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
        else:
            passed += 1
            print(f"PASS: {path.name}")

    # Check dashboard page anchors
    anchor_errors = check_dashboard_anchors()
    if anchor_errors:
        for err in anchor_errors:
            print(f"ERROR: {err}")
        all_errors.extend(anchor_errors)
    else:
        print("PASS: dashboard/page.tsx anchor strings")

    total_errors = (checked - passed) + len(anchor_errors)

    print(f"\n{'=' * 50}")
    print(
        f"Components checked: {checked}, passed: {passed}, failed: {checked - passed}"
    )
    print(f"Dashboard anchor checks: {'passed' if not anchor_errors else 'FAILED'}")

    if total_errors > 0:
        print(f"\nFAILED: {total_errors} error(s) found.")
        return 1

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
