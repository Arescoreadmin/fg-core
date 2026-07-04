#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


REQUIRED_DOCS = (
    "docs/architecture/MCIM_18_6_MASTER_COMMAND_INFORMATION_MODEL.md",
    "docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md",
    "docs/architecture/MCIM_18_6_VALIDATION_CHECKLIST.md",
)

REQUIRED_SECTIONS = (
    "## Section 1 - Executive Summary",
    "## Section 2 - Canonical Capability Registry",
    "## Section 3 - Authority-to-Surface Matrix",
    "## Section 4 - Screen Registry",
    "## Section 5 - Widget Registry",
    "## Section 6 - Action Registry",
    "## Section 7 - State Ownership Map",
    "## Section 8 - Source-of-Truth Map",
    "## Section 9 - Workflow Map",
    "## Section 10 - Persona Model",
    "## Section 11 - Navigation Classification Model",
    "## Section 12 - Module Lifecycle Map",
    "## Section 13 - Technical Debt Ranking",
    "## Section 14 - Proposed 18.6 PR Breakdown",
    "## Section 15 - Validation Rules for Future UI PRs",
    "## Section 16 - Machine-Readable Appendix",
)

REQUIRED_JSON_BLOCKS = (
    "capability_registry",
    "screen_registry",
    "action_registry",
    "state_ownership",
    "navigation_classification",
    "module_lifecycle",
    "technical_debt",
)

ALLOWED_CHANGED_PATHS = {
    # MCIM phase 0 — architecture spec
    "docs/architecture/MCIM_18_6_MASTER_COMMAND_INFORMATION_MODEL.md",
    "docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md",
    "docs/architecture/MCIM_18_6_VALIDATION_CHECKLIST.md",
    "tools/ci/check_mcim_docs.py",
    "tests/tools/test_mcim_docs.py",
    "audits/2026-07-02_frostgate_console_portal_architecture_audit_phase1.md",
    "audits/2026-07-02_pr18-6_unified_governance_command_center_portal_ia_blueprint.md",
    # PR 18.6.1 — Unified Navigation Framework
    "packages/navigation/",
    "packages/navigation/package.json",
    "packages/navigation/tsconfig.json",
    "packages/navigation/navigation-registry.json",
    "packages/navigation/src/types.ts",
    "packages/navigation/src/registry.ts",
    "packages/navigation/src/resolver.ts",
    "packages/navigation/src/breadcrumbs.ts",
    "packages/navigation/src/search.ts",
    "packages/navigation/src/validator.ts",
    "packages/navigation/src/context.ts",
    "packages/navigation/src/index.ts",
    "packages/navigation/src/registrations/groups.ts",
    "packages/navigation/src/registrations/console.ts",
    "packages/navigation/src/registrations/portal.ts",
    "apps/console/components/layout/Sidebar.tsx",
    "apps/portal/app/layout.tsx",
    "apps/console/tsconfig.json",
    "apps/portal/tsconfig.json",
    "apps/console/package.json",
    "apps/portal/package.json",
    "apps/console/next.config.js",
    "apps/portal/next.config.js",
    "tools/ci/check_navigation_registry.py",
    "tests/tools/test_navigation_registry.py",
    "apps/console/tests/console-shell.test.js",
    "apps/console/tests/dashboard-mvp2.test.js",
    "apps/console/tests/field-assessment-workspace.test.js",
    "apps/console/tests/ai-workspace.test.js",
    "apps/console/tests/source-evidence-panel.test.js",
    "apps/console/tests/provenance-validation-panel.test.js",
    # PR 18.6.2 — Executive Command Center
    "apps/console/app/dashboard/page.tsx",
    "apps/console/components/command-center/",
    "apps/console/components/command-center/WidgetShell.tsx",
    "apps/console/components/command-center/ExecutiveKPIBar.tsx",
    "apps/console/components/command-center/ExecutiveHealthPanel.tsx",
    "apps/console/components/command-center/GovernanceOverview.tsx",
    "apps/console/components/command-center/TrustCenterSummary.tsx",
    "apps/console/components/command-center/ExecutiveRiskMap.tsx",
    "apps/console/components/command-center/ExecutiveActionQueue.tsx",
    "apps/console/components/command-center/FieldAssessmentStatus.tsx",
    "apps/console/components/command-center/GovernanceIntelligence.tsx",
    "apps/console/components/command-center/DecisionProvenancePanel.tsx",
    "apps/console/components/command-center/ExecutiveTimeline.tsx",
    "apps/console/components/command-center/ExecutiveNotifications.tsx",
    "apps/console/components/command-center/ReadinessSummary.tsx",
    "apps/console/components/command-center/ComplianceSummary.tsx",
    "apps/console/components/command-center/CustomerImpact.tsx",
    "apps/console/components/command-center/WorkloadDashboard.tsx",
    "apps/console/components/command-center/ExecutiveBriefing.tsx",
    "apps/console/components/command-center/GlobalSearch.tsx",
    "tools/ci/check_executive_dashboard.py",
    "tests/console/command-center.test.js",
    # Cross-PR shared artifacts (present on any 18.6.x branch)
    "docs/SOC_EXECUTION_GATES_2026-02-15.md",
    "docs/ai/PR_FIX_LOG.md",
    # PR 18.6.3 — Operations Workspace
    "apps/console/components/command-center/InvestigationDrawer.tsx",
    "apps/console/components/command-center/OperationalHealthMatrix.tsx",
    "apps/console/components/command-center/AuthorityMap.tsx",
    "apps/console/components/command-center/CorrelationGraph.tsx",
    "apps/console/components/command-center/ReplaySeam.tsx",
    "apps/console/components/command-center/FutureReservedPanels.tsx",
    "tools/ci/check_command_center_authority.py",
    "tests/console/command-center-actions.test.js",
    "docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md",
    "apps/console/tests/command-center.test.js",
    "apps/console/tests/dashboard-truth.test.js",
    "ROADMAP.md",
    # PR 18.6.4 — Enterprise Operations Workspace
    "apps/console/components/operations-workspace/",
    "apps/console/components/operations-workspace/WorkspaceShell.tsx",
    "apps/console/components/operations-workspace/UnifiedWorkQueue.tsx",
    "apps/console/components/operations-workspace/CaseWorkspace.tsx",
    "apps/console/components/operations-workspace/DecisionLedger.tsx",
    "apps/console/components/operations-workspace/WorkflowProgress.tsx",
    "apps/console/components/operations-workspace/InvestigationTimeline.tsx",
    "apps/console/components/operations-workspace/CrossAuthorityNav.tsx",
    "apps/console/components/operations-workspace/AuthorityHealthMap.tsx",
    "apps/console/components/operations-workspace/CorrelationGraph2.tsx",
    "apps/console/components/operations-workspace/CommandPalette.tsx",
    "apps/console/components/operations-workspace/PlaybookPanel.tsx",
    "apps/console/components/operations-workspace/DelegationPanel.tsx",
    "apps/console/components/operations-workspace/ExportPanel.tsx",
    "apps/console/app/workspace/",
    "apps/console/app/workspace/page.tsx",
    "tools/ci/check_operations_workspace.py",
    "tests/console/operations-workspace.test.js",
    "docs/architecture/OPERATIONS_WORKSPACE_18_6_4.md",
}

# The repo currently uses untracked audit notes as source material for MCIM.
# They are explicitly read-only evidence inputs, not part of the deliverable set.
# .venv is gitignored but git status --porcelain may still show it as untracked.
IGNORED_STATUS_PREFIXES = ("audits/", ".venv")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def validate_docs_exist(root: Path) -> list[str]:
    errors: list[str] = []
    for rel in REQUIRED_DOCS:
        if not (root / rel).is_file():
            errors.append(f"missing required doc: {rel}")
    return errors


def validate_required_sections(text: str) -> list[str]:
    return [
        f"missing required heading: {heading}"
        for heading in REQUIRED_SECTIONS
        if heading not in text
    ]


def extract_named_json_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for name in REQUIRED_JSON_BLOCKS:
        pattern = rf"### {re.escape(name)}\s+```json\s+(.*?)\s+```"
        match = re.search(pattern, text, flags=re.DOTALL)
        if match:
            blocks[name] = match.group(1)
    return blocks


def validate_json_blocks(text: str) -> list[str]:
    errors: list[str] = []
    blocks = extract_named_json_blocks(text)
    for name in REQUIRED_JSON_BLOCKS:
        if name not in blocks:
            errors.append(f"missing JSON appendix block: {name}")
            continue
        try:
            json.loads(blocks[name])
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON in block {name}: {exc}")
    return errors


def _git(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True
    )


def _pr_diff_files(root: Path) -> list[str] | None:
    """Return files changed in the PR diff, or None if not in CI / fetch fails."""
    base_ref = (os.environ.get("GITHUB_BASE_REF") or "").strip()
    if not base_ref:
        return None
    if _git(["fetch", "origin", base_ref, "--depth=1"], root).returncode != 0:
        return None
    result = _git(["diff", "--name-only", f"origin/{base_ref}...HEAD"], root)
    if result.returncode == 0:
        return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    fallback = _git(["diff", "--name-only", "HEAD~1..HEAD"], root)
    if fallback.returncode == 0:
        return [ln.strip() for ln in fallback.stdout.splitlines() if ln.strip()]
    return None


def _status_files(root: Path) -> list[tuple[str, str]]:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    entries: list[tuple[str, str]] = []
    for raw_line in proc.stdout.splitlines():
        if not raw_line:
            continue
        status = raw_line[:2]
        path = raw_line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        entries.append((status, path))
    return entries


def validate_changed_paths(root: Path) -> list[str]:
    errors: list[str] = []
    pr_files = _pr_diff_files(root)
    if pr_files is not None:
        entries: list[tuple[str, str]] = [("diff", p) for p in pr_files]
    else:
        entries = _status_files(root)
    for status, path in entries:
        if status == "??" and any(
            path.startswith(prefix) for prefix in IGNORED_STATUS_PREFIXES
        ):
            continue
        if path in ALLOWED_CHANGED_PATHS:
            continue
        errors.append(f"unexpected changed path {path!r} with status {status!r}")
    return errors


def run_checks(root: Path) -> list[str]:
    errors = validate_docs_exist(root)
    master_path = root / REQUIRED_DOCS[0]
    if master_path.is_file():
        text = read_text(master_path)
        errors.extend(validate_required_sections(text))
        errors.extend(validate_json_blocks(text))
    errors.extend(validate_changed_paths(root))
    return errors


def main() -> int:
    root = repo_root()
    errors = run_checks(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("MCIM docs check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
