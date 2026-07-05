#!/usr/bin/env python3
"""CI validator for PR 18.6.6 — Enterprise Customer Portal Experience.
P2 hardening: localStorage safety, admin-route ban, engagementStore contract.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPONENTS_DIR = REPO_ROOT / "apps/portal/components/portal"
PAGES_DIR = REPO_ROOT / "apps/portal/app"
ENGAGEMENT_STORE = REPO_ROOT / "apps/portal/lib/engagementStore.ts"

EXPECTED_COMPONENTS = [
    "PortalShell.tsx",
    "CustomerDashboard.tsx",
    "EngagementOverview.tsx",
    "FindingsView.tsx",
    "EvidenceSummary.tsx",
    "ReportDelivery.tsx",
    "AttestationCenter.tsx",
    "RemediationCenter.tsx",
    "ChangeSummary.tsx",
    "TrustVerificationCenter.tsx",
    "CustomerTrustTimeline.tsx",
    "CustomerActionQueue.tsx",
    "CustomerExportCenter.tsx",
    "AssessmentDelivery.tsx",
    "NotificationCenter.tsx",
    "SupportCenter.tsx",
    "ObservationsPanel.tsx",
    "AuditEventsLog.tsx",
    "DocumentCenter.tsx",
    "ScanHistoryPanel.tsx",
    "QuestionnaireSummary.tsx",
    "ComplianceOverview.tsx",
]

EXPECTED_PAGES = [
    ("dashboard", "dashboard-page"),
    ("trust", "trust-page"),
    ("timeline", "timeline-page"),
    ("actions", "actions-page"),
    ("changes", "changes-page"),
    ("export", "export-page"),
    ("notifications", "notifications-page"),
    ("support", "support-page"),
]

MCIM_PREFIX = "MCIM-18.6-PORTAL-"

# Patterns forbidden in portal components (presentational — no localStorage, no admin routes)
COMPONENT_FORBIDDEN = [
    (r"Math\.random\(\)", "non-deterministic Math.random() usage"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML usage"),
    (r"sessionStorage", "sessionStorage usage"),
    (r'["\'](destructive)["\']', "destructive badge variant"),
    (r"tenant_id", "tenant_id exposure"),
    (r"@/components/ui/badge", "console badge import in portal"),
    (r"@/components/ui/button", "console button import in portal"),
    (r"@/components/ui/card", "console card import in portal"),
    (
        r"localStorage",
        "direct localStorage usage in portal component (use engagementStore)",
    ),
    (r"""["']/admin""", "reference to /admin route in portal component"),
    (r"""["']/console/""", "reference to /console/ route in portal component"),
]

# Patterns forbidden in portal pages
PAGE_FORBIDDEN = [
    (r"Math\.random\(\)", "non-deterministic Math.random() usage"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML usage"),
    (r"sessionStorage", "sessionStorage usage"),
    (r"tenant_id", "tenant_id exposure"),
    (r"""["']/admin""", "reference to /admin route in portal page"),
    (r"""["']/console/""", "reference to /console/ route in portal page"),
]

# Pages that are explicitly allowed to use localStorage directly (beyond engagementStore).
# Each entry maps page dir → approved key prefix.
PAGE_APPROVED_LOCALSTORAGE: dict[str, str] = {
    "notifications": "fg-portal-notifications-read",
    "changes": "fg-portal-change-baseline",
}

# localStorage keys that are banned regardless of file (must never appear in portal client)
BANNED_LOCALSTORAGE_KEYS = [
    "tenant",
    "auth",
    "role",
    "permission",
]


def check_component(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    name = path.name

    # MCIM ID declaration
    if f"const MCIM_ID = '{MCIM_PREFIX}" not in text:
        errors.append(f"{name}: missing MCIM_ID with prefix {MCIM_PREFIX!r}")

    # customerSafe = true
    if "const customerSafe = true" not in text:
        errors.append(f"{name}: missing 'const customerSafe = true'")

    # void declarations at bottom
    if "void MCIM_ID" not in text:
        errors.append(f"{name}: missing 'void MCIM_ID' declaration")
    if "void customerSafe" not in text:
        errors.append(f"{name}: missing 'void customerSafe' declaration")

    # PortalShell usage (all non-shell components should use it)
    if name != "PortalShell.tsx" and "PortalShell" not in text:
        errors.append(f"{name}: does not use PortalShell wrapper")

    # Forbidden patterns
    for pattern, msg in COMPONENT_FORBIDDEN:
        if re.search(pattern, text):
            errors.append(f"{name}: {msg}")

    # Section aria-label for non-shell components
    if name != "PortalShell.tsx":
        if "aria-label=" not in text:
            errors.append(f"{name}: missing aria-label on content section")

    # TrustVerificationCenter: must have trust disclaimer + manifestHash + signedHash
    if name == "TrustVerificationCenter.tsx":
        if "do not constitute legal certification" not in text:
            errors.append(f"{name}: missing required trust disclaimer")
        if "manifestHash" not in text:
            errors.append(f"{name}: missing manifestHash reference")
        if "signedHash" not in text:
            errors.append(f"{name}: missing signedHash reference")

    # CustomerExportCenter: must have export disclaimer
    if name == "CustomerExportCenter.tsx":
        if "do not constitute legal certification" not in text:
            errors.append(f"{name}: missing required export disclaimer")

    # ComplianceOverview: must have disclaimer
    if name == "ComplianceOverview.tsx":
        if "do not constitute legal certification" not in text:
            errors.append(f"{name}: missing required compliance disclaimer")

    # SupportCenter: must note operator-provided content
    if name == "SupportCenter.tsx":
        if "operator" not in text.lower():
            errors.append(f"{name}: missing operator notice")

    # AuditEventsLog: must note governance actions
    if name == "AuditEventsLog.tsx":
        if "governance" not in text.lower():
            errors.append(f"{name}: missing governance context notice")

    # ScanHistoryPanel: must note no raw payloads
    if name == "ScanHistoryPanel.tsx":
        if "raw scan" not in text.lower():
            errors.append(f"{name}: missing 'no raw scan payloads' notice")

    return errors


def check_page_localstorage(page_dir: str, text: str, name: str) -> list[str]:
    """Verify direct localStorage API calls in pages are constrained to approved UX state only.
    Note: mentions of 'localStorage' in comments (e.g. UX hint comments) are not API calls.
    """
    errors: list[str] = []
    # Only flag actual localStorage API calls, not comment mentions
    has_direct_call = bool(
        re.search(r"localStorage\.(getItem|setItem|removeItem)\(", text)
    )
    if not has_direct_call:
        return errors

    # Pages using localStorage must document it as non-authoritative UX state
    has_ux_comment = (
        "non-authoritative" in text.lower()
        or "ux hint" in text.lower()
        or "ux state" in text.lower()
        or "cosmetic" in text.lower()
    )
    if not has_ux_comment:
        errors.append(f"{name}: localStorage usage lacks non-authoritative/UX comment")

    # Pages not in the approved list must not use localStorage directly
    if page_dir not in PAGE_APPROVED_LOCALSTORAGE:
        errors.append(
            f"{name}: direct localStorage usage not permitted in this page "
            f"(approved pages: {list(PAGE_APPROVED_LOCALSTORAGE)})"
        )
        return errors

    # Approved pages must use only their assigned key prefix
    approved_key = PAGE_APPROVED_LOCALSTORAGE[page_dir]
    for match in re.finditer(r"localStorage\.\w+\(['\"]([^'\"]+)['\"]", text):
        key = match.group(1)
        if not key.startswith(approved_key) and key != "fg_portal_eid":
            errors.append(
                f"{name}: unexpected localStorage key {key!r} "
                f"(approved prefix: {approved_key!r})"
            )

    # Banned localStorage key patterns (must never appear anywhere in portal client)
    for banned in BANNED_LOCALSTORAGE_KEYS:
        for match in re.finditer(r"localStorage\.\w+\([^)]+\)", text):
            if banned in match.group(0).lower():
                errors.append(
                    f"{name}: localStorage used for banned category {banned!r}"
                )

    return errors


def check_page(page_dir: str, testid: str) -> list[str]:
    errors: list[str] = []
    page_path = PAGES_DIR / page_dir / "page.tsx"
    if not page_path.exists():
        return [f"missing page: apps/portal/app/{page_dir}/page.tsx"]
    text = page_path.read_text(encoding="utf-8")
    name = f"{page_dir}/page.tsx"

    if f'data-testid="{testid}"' not in text:
        errors.append(f'{name}: missing data-testid="{testid}"')

    if "use client" not in text:
        errors.append(f"{name}: missing 'use client' directive")

    if "getStoredEngagementId" not in text and "engagementId" not in text:
        errors.append(f"{name}: missing engagement ID handling")

    # Engagement ID must be treated as UX hint
    if "getStoredEngagementId" in text and "UX hint" not in text:
        errors.append(
            f"{name}: getStoredEngagementId() used without UX hint comment "
            f"— add '// UX hint' comment marking it as non-authoritative"
        )

    # Pages that call portalApi must guard against empty engagementId
    if "portalApi" in text and "if (!engagementId)" not in text:
        errors.append(
            f"{name}: calls portalApi but missing 'if (!engagementId)' guard — "
            f"invalid IDs must fail closed"
        )

    for pattern, msg in PAGE_FORBIDDEN:
        if re.search(pattern, text):
            errors.append(f"{name}: {msg}")

    errors.extend(check_page_localstorage(page_dir, text, name))

    return errors


def check_engagement_store() -> list[str]:
    """Verify engagementStore.ts documents the non-authoritative UX contract."""
    errors: list[str] = []
    if not ENGAGEMENT_STORE.is_file():
        return [f"missing engagementStore: {ENGAGEMENT_STORE.relative_to(REPO_ROOT)}"]
    text = ENGAGEMENT_STORE.read_text(encoding="utf-8")

    if "UX hint" not in text and "not authoritative" not in text:
        errors.append(
            "engagementStore.ts: missing security contract comment "
            "('UX hint only' or 'not authoritative')"
        )
    if "fail closed" not in text:
        errors.append("engagementStore.ts: missing 'fail closed' contract comment")
    if "tenant" in text.lower() and "tenant_id" in text:
        errors.append("engagementStore.ts: must not reference tenant_id")

    return errors


def run_checks() -> int:
    all_errors: list[str] = []
    passed = 0
    failed = 0

    # engagementStore contract
    errs = check_engagement_store()
    if errs:
        for e in errs:
            print(f"ERROR: {e}")
        all_errors.extend(errs)
        failed += 1
    else:
        print("PASS: engagementStore.ts")
        passed += 1

    # Component checks
    for filename in EXPECTED_COMPONENTS:
        path = COMPONENTS_DIR / filename
        if not path.exists():
            print(f"ERROR: missing component: apps/portal/components/portal/{filename}")
            failed += 1
            continue
        errs = check_component(path)
        if errs:
            for e in errs:
                print(f"ERROR: {e}")
            all_errors.extend(errs)
            failed += 1
        else:
            print(f"PASS: {filename}")
            passed += 1

    # Page checks
    for page_dir, testid in EXPECTED_PAGES:
        errs = check_page(page_dir, testid)
        if errs:
            for e in errs:
                print(f"ERROR: {e}")
            all_errors.extend(errs)
            failed += 1
        else:
            print(f"PASS: {page_dir}/page.tsx")
            passed += 1

    print(f"\n{passed} passed, {failed} failed, {len(all_errors)} errors total")
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(run_checks())
