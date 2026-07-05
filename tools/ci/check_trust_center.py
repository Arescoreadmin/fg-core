#!/usr/bin/env python3
"""
check_trust_center.py

CI validator for the Enterprise Trust Center (PR 18.6.5).

Checks each trust-center component file for:
  - MCIM_ID declaration matching MCIM-18.6-TRUST-
  - AUTHORITY declaration
  - sourceOfTruth declaration
  - drillDown declaration
  - Does NOT contain Math.random
  - Does NOT contain dangerouslySetInnerHTML
  - Does NOT contain localStorage or sessionStorage
  - Does NOT contain 'destructive' as a Badge variant
  - Does NOT contain hardcoded fake metric percentages (literal NN% as data values)
  - Contains export default function
  - Does NOT contain aria-expanded on role="complementary" elements
  - Does NOT contain direct fetch( calls
  - Does NOT contain NEXT_PUBLIC env vars

Additional per-component checks:
  - TrustCertificates.tsx must contain provenanceMetadata OR (signedHash and manifestHash)
  - TrustCertificates.tsx must contain disclaimer about not being legal certificates
  - TrustBenchmarks.tsx must contain text about authoritative data only
  - SLAForecasting.tsx must contain the hasHistoricalData guard
  - CaseRelationships.tsx must NOT contain "inferred" (no inferred relationships)
  - WorkspaceIntelligence.tsx must contain "deterministic"
  - OperationalMemory.tsx must contain "no browser storage" (case-insensitive) OR "server-authoritative"
  - CustomerTrustView.tsx must contain "operator preview" (case-insensitive)

Also validates apps/console/app/trust-center/page.tsx for required data-testid anchors.

Returns exit 1 if any errors are found, exit 0 if all pass.
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
    / "trust-center"
)
TRUST_CENTER_PAGE = (
    Path(__file__).resolve().parents[2]
    / "apps"
    / "console"
    / "app"
    / "trust-center"
    / "page.tsx"
)

# TrustCenterShell is the shared wrapper — exempt from authority checks
EXEMPT_FILES = {"TrustCenterShell.tsx"}

REQUIRED_PAGE_ANCHORS = [
    "trust-center-page",
    "trust-center-heading",
    "tc-scorecard-heading",
    "tc-assurance-heading",
    "tc-evidence-heading",
    "tc-provenance-heading",
    "tc-replay-heading",
    "tc-change-intel-heading",
    "tc-certs-heading",
    "tc-audit-ready-heading",
    "tc-customer-trust-heading",
    "tc-timeline-heading",
    "tc-memory-heading",
    "tc-effectiveness-heading",
    "tc-bottleneck-heading",
    "tc-benchmarks-heading",
    "tc-case-rel-heading",
    "tc-intel-heading",
    "tc-sla-heading",
    "tc-cmd-center-heading",
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
        re.compile(r"fetch\("),
        "contains direct fetch( call — use internal API routes only",
    ),
    (
        re.compile(r"process\.env\.NEXT_PUBLIC_"),
        "contains NEXT_PUBLIC env var — not allowed in components",
    ),
]

# Hardcoded fake metric percentages: digits followed by % appearing as JSX text
# values (not inside className or style attributes).
# We flag lines where \d{2}% appears outside of a className/style string.
_FAKE_PERCENT_RE = re.compile(r"(?<!className[=\s'\"{])(?<!style[=\s'\"{])\b\d{2}%")

# aria-expanded must not appear on a role="complementary" element in the same file
_ARIA_EXPANDED_RE = re.compile(r"aria-expanded")
_ROLE_COMPLEMENTARY_RE = re.compile(r'role="complementary"')

# export default function must be present in every non-exempt component
_EXPORT_DEFAULT_RE = re.compile(r"export default function")

# TrustCertificates checks
_PROVENANCE_META_RE = re.compile(r"provenanceMetadata")
_SIGNED_HASH_RE = re.compile(r"signedHash")
_MANIFEST_HASH_RE = re.compile(r"manifestHash")
_CERT_DISCLAIMER_RE = re.compile(r"not.*legal|legal.*certif", re.IGNORECASE)

# TrustBenchmarks: authoritative data only
_AUTHORITATIVE_RE = re.compile(r"authoritative", re.IGNORECASE)

# SLAForecasting: must have hasHistoricalData guard
_HISTORICAL_DATA_RE = re.compile(r"hasHistoricalData")

# CaseRelationships: must NOT contain "inferred"
_INFERRED_RE = re.compile(r"\binferred\b", re.IGNORECASE)

# WorkspaceIntelligence: must contain "deterministic"
_DETERMINISTIC_RE = re.compile(r"deterministic", re.IGNORECASE)

# OperationalMemory: no browser storage pattern
_NO_BROWSER_STORAGE_RE = re.compile(
    r"no browser storage|server-authoritative", re.IGNORECASE
)

# CustomerTrustView: must contain "operator preview"
_OPERATOR_PREVIEW_RE = re.compile(r"operator preview", re.IGNORECASE)


def _has_fake_percentage(text: str) -> bool:
    """
    Return True if the text contains a hardcoded NN% literal that is NOT
    inside a className or style attribute value.  We strip out all className=
    and style= attribute strings before searching.
    """
    # Remove className and style attribute strings so we don't flag them
    cleaned = re.sub(r'className\s*=\s*[{"\'][^}\'\"]*[}\'"]', "", text)
    cleaned = re.sub(r"style\s*=\s*\{[^}]*\}", "", cleaned)
    return bool(_FAKE_PERCENT_RE.search(cleaned))


def check_file(path: Path) -> list[str]:
    """Return list of error strings for a single component file."""
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read file: {exc}"]

    name = path.name

    # MCIM_ID declaration matching MCIM-18.6-TRUST-
    if (
        not re.search(r"MCIM_ID\s*=.*MCIM-18\.6-TRUST-", text)
        and "MCIM-18.6-TRUST-" not in text
    ):
        errors.append(f"{name}: missing MCIM_ID declaration matching MCIM-18.6-TRUST-")

    # AUTHORITY declaration
    if not re.search(r"const\s+AUTHORITY\s*=", text) and "AUTHORITY" not in text:
        errors.append(f"{name}: missing AUTHORITY declaration")

    # sourceOfTruth declaration
    if "sourceOfTruth" not in text:
        errors.append(f"{name}: missing sourceOfTruth declaration")

    # drillDown declaration
    if "drillDown" not in text:
        errors.append(f"{name}: missing drillDown declaration")

    # export default function
    if not _EXPORT_DEFAULT_RE.search(text):
        errors.append(f"{name}: missing 'export default function'")

    # aria-expanded must not co-occur with role="complementary"
    if _ARIA_EXPANDED_RE.search(text) and _ROLE_COMPLEMENTARY_RE.search(text):
        errors.append(
            f'{name}: aria-expanded found alongside role="complementary" — '
            "trust-center panels must not use aria-expanded on complementary regions"
        )

    # Hardcoded fake metric percentages
    if _has_fake_percentage(text):
        errors.append(
            f"{name}: contains hardcoded metric percentage literal (e.g. 85%) — "
            "use server-authoritative data only"
        )

    # Prohibited patterns
    for pattern, msg in PROHIBITED_PATTERNS:
        if pattern.search(text):
            errors.append(f"{name}: {msg}")

    # ── Per-component specific checks ──────────────────────────────────────────

    if name == "TrustCertificates.tsx":
        has_provenance = _PROVENANCE_META_RE.search(text)
        has_hashes = _SIGNED_HASH_RE.search(text) and _MANIFEST_HASH_RE.search(text)
        if not has_provenance and not has_hashes:
            errors.append(
                f"{name}: missing provenanceMetadata OR (signedHash + manifestHash) — "
                "TrustCertificates must declare cryptographic provenance"
            )
        if not _CERT_DISCLAIMER_RE.search(text):
            errors.append(
                f"{name}: missing legal disclaimer — "
                "TrustCertificates must state these are not legal certificates"
            )

    if name == "TrustBenchmarks.tsx":
        if not _AUTHORITATIVE_RE.search(text):
            errors.append(
                f"{name}: missing 'authoritative' text — "
                "TrustBenchmarks must state authoritative data only"
            )

    if name == "SLAForecasting.tsx":
        if not _HISTORICAL_DATA_RE.search(text):
            errors.append(
                f"{name}: missing hasHistoricalData guard — "
                "SLAForecasting must guard against missing historical data"
            )

    if name == "CaseRelationships.tsx":
        if _INFERRED_RE.search(text):
            errors.append(
                f"{name}: contains 'inferred' — "
                "CaseRelationships must not include inferred relationships"
            )

    if name == "WorkspaceIntelligence.tsx":
        if not _DETERMINISTIC_RE.search(text):
            errors.append(
                f"{name}: missing 'deterministic' — "
                "WorkspaceIntelligence must declare deterministic logic"
            )

    if name == "OperationalMemory.tsx":
        if not _NO_BROWSER_STORAGE_RE.search(text):
            errors.append(
                f"{name}: missing 'no browser storage' or 'server-authoritative' — "
                "OperationalMemory must declare it does not use browser storage"
            )

    if name == "CustomerTrustView.tsx":
        if not _OPERATOR_PREVIEW_RE.search(text):
            errors.append(
                f"{name}: missing 'operator preview' — "
                "CustomerTrustView must declare operator preview context"
            )

    return errors


def check_trust_center_page() -> list[str]:
    """Validate that the trust-center page contains all required data-testid anchors."""
    errors: list[str] = []
    if not TRUST_CENTER_PAGE.is_file():
        return [f"missing trust-center page: {TRUST_CENTER_PAGE}"]
    try:
        text = TRUST_CENTER_PAGE.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read trust-center page: {exc}"]

    for anchor in REQUIRED_PAGE_ANCHORS:
        if anchor not in text:
            errors.append(
                f"trust-center/page.tsx: missing required data-testid anchor '{anchor}'"
            )

    # Trust Center page must be a server component — no 'use client' at the top
    if re.match(r"\s*['\"]use client['\"]", text):
        errors.append(
            "trust-center/page.tsx: must be a server component — "
            "remove 'use client' from the top level"
        )

    return errors


def main() -> int:
    all_errors: list[str] = []

    # Check component files
    if not COMPONENT_DIR.is_dir():
        print(f"ERROR: trust-center component directory not found: {COMPONENT_DIR}")
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

    # Check trust-center page
    page_errors = check_trust_center_page()
    if page_errors:
        for err in page_errors:
            print(f"ERROR: {err}")
        all_errors.extend(page_errors)
    else:
        print("PASS: trust-center/page.tsx anchor checks")

    total_errors = len(all_errors)

    print(f"\n{'=' * 50}")
    print(
        f"Components checked: {checked}, passed: {passed}, failed: {checked - passed}"
    )
    print(f"Trust Center page checks: {'passed' if not page_errors else 'FAILED'}")

    if total_errors > 0:
        print(f"\nFAILED: {total_errors} error(s) found.")
        return 1

    print("\nTrust Center check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
