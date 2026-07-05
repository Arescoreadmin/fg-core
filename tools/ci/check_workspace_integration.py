#!/usr/bin/env python3
"""CI validator for PR 18.6.8 — Workspace Integration & Demo Readiness.
Validates component presence, content contracts, forbidden patterns, lib files,
architecture doc, and navigation registry registration.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPONENTS_DIR = REPO_ROOT / "apps/console/components/workspace-integration"
LIB_DIR = REPO_ROOT / "apps/console/lib"
ARCH_DOC = REPO_ROOT / "docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md"
NAV_REGISTRY = REPO_ROOT / "packages/navigation/navigation-registry.json"

EXPECTED_COMPONENTS = [
    "WorkspaceMetadata.tsx",
    "CrossWorkspaceNav.tsx",
    "WorkspaceContextBridge.tsx",
    "WorkspaceEmptyState.tsx",
    "WorkspaceLoadingState.tsx",
    "DemoModeIndicator.tsx",
    "WorkspaceSearch.tsx",
    "index.ts",
]

EXPECTED_LIB_FILES = [
    "workspaceContext.ts",
    "demoFixtures.ts",
    "workspaceNav.ts",
]

# Required content tokens per component file
COMPONENT_REQUIRED: dict[str, list[str]] = {
    "WorkspaceMetadata.tsx": ["data-workspace-metadata", "aria-hidden", "mcimId"],
    "CrossWorkspaceNav.tsx": [
        "aria-label",
        "data-mcim-id",
        "buildWorkspaceUrl",
        "WorkspaceLink",
    ],
    "WorkspaceContextBridge.tsx": [
        "useWorkspaceContext",
        "buildWorkspaceUrl",
        "WorkspaceContext",
        "useSearchParams",
    ],
    "WorkspaceEmptyState.tsx": ["reason", "dataRequired", "nextAction", "mcimId"],
    "WorkspaceLoadingState.tsx": ["animate-pulse", "workspace", "mcimId"],
    "DemoModeIndicator.tsx": ["Demo Mode", "data-demo-mode", "active"],
    "WorkspaceSearch.tsx": [
        "combobox",
        "aria-expanded",
        "ArrowUp",
        "ArrowDown",
        "groupByWorkspace",
    ],
    "index.ts": [
        "WorkspaceMetadata",
        "CrossWorkspaceNav",
        "WorkspaceContextBridge",
        "WorkspaceEmptyState",
        "WorkspaceLoadingState",
        "DemoModeIndicator",
        "WorkspaceSearch",
        "WORKSPACE_INTEGRATION_VERSION",
    ],
}

# Required content tokens per lib file
LIB_REQUIRED: dict[str, list[str]] = {
    "workspaceContext.ts": [
        "parseWorkspaceContext",
        "buildWorkspaceUrl",
        "mergeWorkspaceContext",
        "WORKSPACE_CONTEXT_KEYS",
        "contextToParams",
    ],
    "demoFixtures.ts": [
        "DEMO_MODE_ACTIVE",
        "DEMO_TENANT_ID",
        "DEMO_ENGAGEMENTS",
        "DEMO_FINDINGS",
        "DEMO_REPORTS",
        "DEMO_REMEDIATIONS",
        "DEMO_EXECUTIVE_METRICS",
        "DEMO_TRUST_SCORE",
    ],
    "workspaceNav.ts": [
        "WORKSPACE_NAV_MAP",
        "WorkspaceNavLink",
    ],
}

# Patterns forbidden in workspace-integration component files
COMPONENT_FORBIDDEN = [
    (r"Math\.random\(\)", "non-deterministic Math.random() usage"),
    (r"sessionStorage", "browser-authoritative sessionStorage usage"),
    (r"localStorage", "browser-authoritative localStorage usage"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML usage (security)"),
    (r"tenant_id", "direct tenant_id exposure"),
    (r"No Data", "empty state without context — use WorkspaceEmptyState"),
]

# Patterns forbidden specifically in demoFixtures.ts
DEMO_FIXTURES_FORBIDDEN = [
    (r"Math\.random", "non-deterministic Math.random usage in demo fixtures"),
]


def check_component_file(path: Path) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for a component/index file."""
    errors: list[str] = []
    warnings: list[str] = []
    name = path.name
    text = path.read_text(encoding="utf-8")

    # Required content tokens
    for token in COMPONENT_REQUIRED.get(name, []):
        if token not in text:
            errors.append(f"{name}: missing required token {token!r}")

    # Forbidden patterns
    for pattern, msg in COMPONENT_FORBIDDEN:
        if re.search(pattern, text):
            errors.append(f"{name}: {msg}")

    # workspaceNav.ts: must define at least 4 workspace keys
    # (checked separately in lib check)

    return errors, warnings


def check_lib_file(filename: str) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for a lib file."""
    errors: list[str] = []
    warnings: list[str] = []
    path = LIB_DIR / filename

    if not path.exists():
        return [f"missing lib file: apps/console/lib/{filename}"], warnings

    text = path.read_text(encoding="utf-8")

    # Required tokens
    for token in LIB_REQUIRED.get(filename, []):
        if token not in text:
            errors.append(f"{filename}: missing required token {token!r}")

    # workspaceNav.ts: count workspace key definitions (expect at least 4)
    if filename == "workspaceNav.ts":
        # Count quoted workspace key strings in the nav map
        keys = re.findall(r"""['"]([\w-]+)['"]\s*:""", text)
        meaningful = [k for k in keys if len(k) > 2]
        if len(meaningful) < 4:
            errors.append(
                f"{filename}: WORKSPACE_NAV_MAP must define at least 4 workspace keys "
                f"(found {len(meaningful)})"
            )

    # demoFixtures.ts: forbidden patterns
    if filename == "demoFixtures.ts":
        for pattern, msg in DEMO_FIXTURES_FORBIDDEN:
            if re.search(pattern, text):
                errors.append(f"{filename}: {msg}")

    return errors, warnings


def check_navigation_registry() -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for the navigation registry."""
    errors: list[str] = []
    warnings: list[str] = []

    if not NAV_REGISTRY.exists():
        return [
            f"missing navigation registry: {NAV_REGISTRY.relative_to(REPO_ROOT)}"
        ], warnings

    text = NAV_REGISTRY.read_text(encoding="utf-8")
    has_version = '"18.6.8"' in text or "18.6.8" in text
    has_slug = "workspace-integration" in text

    if not has_version and not has_slug:
        errors.append(
            "navigation-registry.json: must contain version '18.6.8' "
            "or slug 'workspace-integration'"
        )
    elif not has_version:
        warnings.append(
            "navigation-registry.json: version not yet bumped to 18.6.8 "
            "(workspace-integration slug present)"
        )
    elif not has_slug:
        warnings.append(
            "navigation-registry.json: 'workspace-integration' slug not found "
            "(version 18.6.8 present)"
        )

    return errors, warnings


def run_checks() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    # ── 1. Component file existence + content ──────────────────────────────────
    for filename in EXPECTED_COMPONENTS:
        path = COMPONENTS_DIR / filename
        if not path.exists():
            msg = f"missing component: apps/console/components/workspace-integration/{filename}"
            print(f"❌ component exists — {filename}: file not found")
            errors.append(msg)
            continue

        file_errors, file_warnings = check_component_file(path)
        if file_errors:
            for e in file_errors:
                print(f"❌ {e}")
            errors.extend(file_errors)
        else:
            if file_warnings:
                for w in file_warnings:
                    print(f"⚠️  {w}")
                warnings.extend(file_warnings)
            print(f"✅ {filename}")

    # ── 2. Lib file existence + content ───────────────────────────────────────
    for filename in EXPECTED_LIB_FILES:
        lib_errors, lib_warnings = check_lib_file(filename)
        if lib_errors:
            for e in lib_errors:
                print(f"❌ {e}")
            errors.extend(lib_errors)
        else:
            if lib_warnings:
                for w in lib_warnings:
                    print(f"⚠️  {w}")
                warnings.extend(lib_warnings)
            print(f"✅ {filename}")

    # ── 3. Architecture doc ────────────────────────────────────────────────────
    if ARCH_DOC.exists():
        print(f"✅ docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md")
    else:
        msg = "missing architecture doc: docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md"
        print(f"❌ {msg}")
        errors.append(msg)

    # ── 4. Navigation registry ─────────────────────────────────────────────────
    nav_errors, nav_warnings = check_navigation_registry()
    if nav_errors:
        for e in nav_errors:
            print(f"❌ {e}")
        errors.extend(nav_errors)
    elif nav_warnings:
        for w in nav_warnings:
            print(f"⚠️  {w}")
        warnings.extend(nav_warnings)
        print("✅ navigation-registry.json (with warnings)")
    else:
        print("✅ navigation-registry.json")

    # ── Summary ────────────────────────────────────────────────────────────────
    total_checks = len(EXPECTED_COMPONENTS) + len(EXPECTED_LIB_FILES) + 2
    failed = len(errors)
    warn_count = len(warnings)
    passed = total_checks - failed

    print(
        f"\n{passed} passed, {failed} failed, {warn_count} warning(s), "
        f"{len(errors)} error(s) total"
    )

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(run_checks())
