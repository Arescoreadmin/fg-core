#!/usr/bin/env python3
"""
check_operations_workspace.py

CI validator for the Enterprise Operations Workspace (PR 18.6.4).

Checks each operations-workspace component file for:
  - MCIM_ID declaration matching MCIM-18.6-
  - AUTHORITY declaration
  - sourceOfTruth declaration
  - drillDown or href= reference
  - Does NOT contain Math.random
  - Does NOT contain dangerouslySetInnerHTML
  - Does NOT contain localStorage or sessionStorage
  - Does NOT contain 'destructive' as a Badge variant
  - Does NOT contain hardcoded fake metric percentages
  - Contains export default function
  - Does NOT contain aria-expanded on role="complementary" elements
  - Does NOT contain direct http fetch calls
  - Does NOT contain NEXT_PUBLIC env vars

Additional per-component checks:
  - ExportPanel must contain provenanceMetadata
  - DecisionLedger must NOT contain POST/write mutations
  - CommandPalette must contain role="dialog" and aria-modal

Also validates apps/console/app/workspace/page.tsx for required anchors.

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
    / "operations-workspace"
)
WORKSPACE_PAGE = (
    Path(__file__).resolve().parents[2]
    / "apps"
    / "console"
    / "app"
    / "workspace"
    / "page.tsx"
)

# WorkspaceShell is the shared wrapper — exempt from authority checks
EXEMPT_FILES = {"WorkspaceShell.tsx"}

REQUIRED_WORKSPACE_ANCHORS = [
    "workspace-page",
    "workspace-heading",
    "workspace-queue-heading",
    "workspace-case-heading",
    "workspace-ledger-heading",
    "workspace-workflow-heading",
    "workspace-timeline-heading",
    "workspace-health-heading",
    "async function WorkspaceOverviewPage",
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
        re.compile(r"value=\{9[789]\}|=\s*9[789]\s*%"),
        "possible hardcoded fake metric percentage (value={97}, = 98%, etc.)",
    ),
    (
        re.compile(r"fetch\(['\"]http"),
        "contains direct http fetch call — use internal API routes only",
    ),
    (
        re.compile(r"process\.env\.NEXT_PUBLIC_"),
        "contains NEXT_PUBLIC env var — not allowed in components",
    ),
]

# aria-expanded must not appear on a role="complementary" element in the same file
# (we flag co-occurrence as a proxy — exact DOM nesting would require a parser)
_ARIA_EXPANDED_RE = re.compile(r"aria-expanded")
_ROLE_COMPLEMENTARY_RE = re.compile(r'role="complementary"')

# export default function must be present in every non-exempt component
_EXPORT_DEFAULT_RE = re.compile(r"export default function")

# ExportPanel provenance check
_PROVENANCE_RE = re.compile(r"provenanceMetadata")

# DecisionLedger: no POST writes
_POST_RE = re.compile(r"fetch.*POST|method.*POST|\.post\(", re.IGNORECASE)

# CommandPalette: must have role="dialog" and aria-modal
_DIALOG_RE = re.compile(r'role="dialog"')
_ARIA_MODAL_RE = re.compile(r"aria-modal")


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

    # export default function
    if not _EXPORT_DEFAULT_RE.search(text):
        errors.append(f"{name}: missing 'export default function'")

    # aria-expanded must not co-occur with role="complementary"
    if _ARIA_EXPANDED_RE.search(text) and _ROLE_COMPLEMENTARY_RE.search(text):
        errors.append(
            f'{name}: aria-expanded found alongside role="complementary" — '
            "operations-workspace panels must not use aria-expanded on complementary regions"
        )

    # Prohibited patterns
    for pattern, msg in PROHIBITED_PATTERNS:
        if pattern.search(text):
            errors.append(f"{name}: {msg}")

    # Per-component specific checks
    if name == "ExportPanel.tsx":
        if not _PROVENANCE_RE.search(text):
            errors.append(
                f"{name}: missing provenanceMetadata — ExportPanel must include provenance"
            )

    if name == "DecisionLedger.tsx":
        if _POST_RE.search(text):
            errors.append(
                f"{name}: contains write/mutation operation (POST) — "
                "DecisionLedger is append-only display"
            )

    if name == "CommandPalette.tsx":
        if not _DIALOG_RE.search(text):
            errors.append(
                f'{name}: missing role="dialog" — CommandPalette must be a dialog'
            )
        if not _ARIA_MODAL_RE.search(text):
            errors.append(
                f"{name}: missing aria-modal — CommandPalette must declare aria-modal"
            )

    return errors


def check_workspace_page() -> list[str]:
    """Validate that the workspace page contains all required anchor strings."""
    errors: list[str] = []
    if not WORKSPACE_PAGE.is_file():
        return [f"missing workspace page: {WORKSPACE_PAGE}"]
    try:
        text = WORKSPACE_PAGE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read workspace page: {exc}"]

    for anchor in REQUIRED_WORKSPACE_ANCHORS:
        if anchor not in text:
            errors.append(
                f"workspace/page.tsx: missing required anchor string '{anchor}'"
            )

    # Workspace page must be a server component — no 'use client' at the top
    if re.match(r"\s*['\"]use client['\"]", text):
        errors.append(
            "workspace/page.tsx: must be a server component — "
            "remove 'use client' from the top level"
        )

    return errors


def main() -> int:
    all_errors: list[str] = []

    # Check component files
    if not COMPONENT_DIR.is_dir():
        print(
            f"ERROR: operations-workspace component directory not found: {COMPONENT_DIR}"
        )
        return 1

    component_files = sorted(COMPONENT_DIR.glob("*.tsx"))
    if not component_files:
        print(f"ERROR: no .tsx files found in {COMPONENT_DIR}")
        return 1

    checked = 0
    passed = 0

    for path in component_files:
        if path.name in EXEMPT_FILES:
            print(f"SKIP (exempt): {path.name}")
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

    # Check workspace page
    page_errors = check_workspace_page()
    if page_errors:
        for err in page_errors:
            print(f"ERROR: {err}")
        all_errors.extend(page_errors)
    else:
        print("PASS: workspace/page.tsx authority checks")

    total_errors = len(all_errors)

    print(f"\n{'=' * 50}")
    print(
        f"Components checked: {checked}, passed: {passed}, failed: {checked - passed}"
    )
    print(f"Workspace page checks: {'passed' if not page_errors else 'FAILED'}")

    if total_errors > 0:
        print(f"\nFAILED: {total_errors} error(s) found.")
        return 1

    print("\nOperations workspace check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
