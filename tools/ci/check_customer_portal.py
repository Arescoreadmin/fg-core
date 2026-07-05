#!/usr/bin/env python3
"""CI validator for PR 18.6.6 — Enterprise Customer Portal Experience."""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPONENTS_DIR = REPO_ROOT / "apps/portal/components/portal"
PAGES_DIR = REPO_ROOT / "apps/portal/app"

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
FORBIDDEN_PATTERNS = [
    (r"Math\.random\(\)", "non-deterministic Math.random() usage"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML usage"),
    (r'sessionStorage', "sessionStorage usage"),
    (r'["\'](destructive)["\']', "destructive badge variant"),
    (r'tenant_id', "tenant_id exposure"),
    (r'@/components/ui/badge', "console badge import in portal"),
    (r'@/components/ui/button', "console button import in portal"),
    (r'@/components/ui/card', "console card import in portal"),
]

CUSTOMER_SAFE_VOID = re.compile(
    r"void\s+MCIM_ID.*void\s+customerSafe|void\s+customerSafe.*void\s+MCIM_ID",
    re.DOTALL,
)


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
    for pattern, msg in FORBIDDEN_PATTERNS:
        # layout.tsx exception for dangerouslySetInnerHTML is handled separately
        if re.search(pattern, text):
            errors.append(f"{name}: {msg}")

    # Section aria-label for non-shell components
    if name != "PortalShell.tsx":
        if 'aria-label=' not in text:
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


def check_page(page_dir: str, testid: str) -> list[str]:
    errors: list[str] = []
    page_path = PAGES_DIR / page_dir / "page.tsx"
    if not page_path.exists():
        return [f"missing page: apps/portal/app/{page_dir}/page.tsx"]
    text = page_path.read_text(encoding="utf-8")
    name = f"{page_dir}/page.tsx"

    if f'data-testid="{testid}"' not in text:
        errors.append(f"{name}: missing data-testid=\"{testid}\"")

    if "use client" not in text:
        errors.append(f"{name}: missing 'use client' directive")

    if "getStoredEngagementId" not in text and "engagementId" not in text:
        errors.append(f"{name}: missing engagement ID handling")

    for pattern, msg in FORBIDDEN_PATTERNS:
        if re.search(pattern, text):
            errors.append(f"{name}: {msg}")

    return errors


def run_checks() -> int:
    all_errors: list[str] = []
    passed = 0
    failed = 0

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
