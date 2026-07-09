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


EXEC_PAGE = REPO_ROOT / "apps/console/app/dashboard/executive/page.tsx"
NAV_SOURCE = REPO_ROOT / "packages/navigation/src/registrations/console.ts"
WORKSPACE_NAV = REPO_ROOT / "apps/console/lib/workspaceNav.ts"
APP_DIR = REPO_ROOT / "apps/console/app"
DEMO_FIXTURES = REPO_ROOT / "apps/console/lib/demoFixtures.ts"


def check_exec_page_hooks() -> tuple[list[str], list[str]]:
    """Verify executive page uses useRef pattern in all tab components."""
    errors: list[str] = []
    warnings: list[str] = []
    if not EXEC_PAGE.exists():
        return [
            "missing executive page: apps/console/app/dashboard/executive/page.tsx"
        ], warnings
    text = EXEC_PAGE.read_text(encoding="utf-8")
    if re.search(r"if\s*\(\s*initialData\s*\)\s*return", text):
        errors.append(
            "executive/page.tsx: bare 'if (initialData) return' inside useEffect — "
            "use useRef(Boolean(initialData)) to avoid stale closure warning"
        )
    if "hasInitialRef" not in text:
        errors.append(
            "executive/page.tsx: missing hasInitialRef pattern — "
            "apply useRef(Boolean(initialData)) to all tab components"
        )
    if "useRef" not in text:
        errors.append("executive/page.tsx: useRef not imported or used")
    return errors, warnings


def check_map_iterator_spread() -> tuple[list[str], list[str]]:
    """Verify WorkspaceSearch does not spread a MapIterator (ES target compat)."""
    errors: list[str] = []
    warnings: list[str] = []
    search_file = COMPONENTS_DIR / "WorkspaceSearch.tsx"
    if not search_file.exists():
        return errors, warnings
    text = search_file.read_text(encoding="utf-8")
    if re.search(r"\[\s*\.\.\.\s*\w+\s*\.\s*values\s*\(\s*\)\s*\]", text):
        errors.append(
            "WorkspaceSearch.tsx: [...map.values()] spread — use Array.from() for ES target safety"
        )
    return errors, warnings


def check_eval_route_absent() -> tuple[list[str], list[str]]:
    """Verify /dashboard/evaluation is not used for executive-intelligence links."""
    errors: list[str] = []
    warnings: list[str] = []
    if not WORKSPACE_NAV.exists():
        return errors, warnings
    text = WORKSPACE_NAV.read_text(encoding="utf-8")
    if "/dashboard/evaluation" in text:
        errors.append(
            "workspaceNav.ts: /dashboard/evaluation found — "
            "executive-intelligence must link to /dashboard/executive (Evaluation Lab is separate)"
        )
    if "/dashboard/executive" not in text:
        errors.append(
            "workspaceNav.ts: /dashboard/executive missing — "
            "Executive Intelligence workspace route must be present"
        )
    return errors, warnings


def check_nav_routes_implemented() -> tuple[list[str], list[str]]:
    """Verify every non-dynamic route in WORKSPACE_NAV_MAP has an implemented page."""
    errors: list[str] = []
    warnings: list[str] = []
    if not WORKSPACE_NAV.exists():
        return errors, warnings
    text = WORKSPACE_NAV.read_text(encoding="utf-8")
    routes = re.findall(r"""route:\s*['"]([^'"]+)['"]""", text)
    for route in sorted(set(routes)):
        if "[" in route:
            continue  # dynamic routes exempt
        page = APP_DIR / route.lstrip("/") / "page.tsx"
        if not page.exists():
            errors.append(
                f"workspaceNav.ts: route '{route}' has no page at "
                f"{page.relative_to(REPO_ROOT)}"
            )
    return errors, warnings


def check_context_filtering() -> tuple[list[str], list[str]]:
    """Verify CrossWorkspaceNav filters context to declared contextParams keys."""
    errors: list[str] = []
    warnings: list[str] = []
    nav_comp = COMPONENTS_DIR / "CrossWorkspaceNav.tsx"
    if not nav_comp.exists():
        return errors, warnings
    text = nav_comp.read_text(encoding="utf-8")
    if not re.search(
        r"for\s+\(.*of.*contextParams|contextParams\.forEach|contextParams.*filter",
        text,
    ):
        errors.append(
            "CrossWorkspaceNav.tsx: missing contextParams key filtering loop — "
            "stale context keys may propagate to unrelated workspaces"
        )
    if re.search(r"\.\.\.\s*context\b", text):
        errors.append(
            "CrossWorkspaceNav.tsx: full context spread detected — "
            "only keys declared in contextParams should be forwarded"
        )
    return errors, warnings


def check_demo_mode_safe() -> tuple[list[str], list[str]]:
    """Verify demo fixtures are deterministic and mode is off by default."""
    errors: list[str] = []
    warnings: list[str] = []
    if not DEMO_FIXTURES.exists():
        return errors, warnings
    text = DEMO_FIXTURES.read_text(encoding="utf-8")
    if re.search(r"DEMO_MODE_ACTIVE\s*=\s*true", text):
        errors.append("demoFixtures.ts: DEMO_MODE_ACTIVE must be false (is true)")
    if not re.search(r"DEMO_MODE_ACTIVE\s*=\s*false", text):
        errors.append("demoFixtures.ts: DEMO_MODE_ACTIVE must be explicitly false")
    if re.search(r"Date\.now\(\)", text):
        errors.append(
            "demoFixtures.ts: Date.now() forbidden — use fixed ISO date strings"
        )
    if re.search(r"Math\.random\(\)", text):
        errors.append(
            "demoFixtures.ts: Math.random() forbidden — fixtures must be deterministic"
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
        print("✅ docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md")
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

    # ── 5. Executive page hook warnings ───────────────────────────────────────
    hook_errors, hook_warnings = check_exec_page_hooks()
    if hook_errors:
        for e in hook_errors:
            print(f"❌ {e}")
        errors.extend(hook_errors)
    else:
        warnings.extend(hook_warnings)
        print("✅ executive/page.tsx (hook warning pattern)")

    # ── 6. MapIterator spread ──────────────────────────────────────────────────
    mi_errors, mi_warnings = check_map_iterator_spread()
    if mi_errors:
        for e in mi_errors:
            print(f"❌ {e}")
        errors.extend(mi_errors)
    else:
        warnings.extend(mi_warnings)
        print("✅ WorkspaceSearch.tsx (no MapIterator spread)")

    # ── 7. Evaluation Lab route absent from executive-intelligence ─────────────
    eval_errors, eval_warnings = check_eval_route_absent()
    if eval_errors:
        for e in eval_errors:
            print(f"❌ {e}")
        errors.extend(eval_errors)
    else:
        warnings.extend(eval_warnings)
        print("✅ workspaceNav.ts (executive route correct)")

    # ── 8. Nav routes implemented ──────────────────────────────────────────────
    route_errors, route_warnings = check_nav_routes_implemented()
    if route_errors:
        for e in route_errors:
            print(f"❌ {e}")
        errors.extend(route_errors)
    else:
        warnings.extend(route_warnings)
        print("✅ workspaceNav.ts (all routes implemented)")

    # ── 9. Context filtering in CrossWorkspaceNav ──────────────────────────────
    ctx_errors, ctx_warnings = check_context_filtering()
    if ctx_errors:
        for e in ctx_errors:
            print(f"❌ {e}")
        errors.extend(ctx_errors)
    else:
        warnings.extend(ctx_warnings)
        print("✅ CrossWorkspaceNav.tsx (context key filtering)")

    # ── 10. Demo mode safety ───────────────────────────────────────────────────
    demo_errors, demo_warnings = check_demo_mode_safe()
    if demo_errors:
        for e in demo_errors:
            print(f"❌ {e}")
        errors.extend(demo_errors)
    else:
        warnings.extend(demo_warnings)
        print("✅ demoFixtures.ts (demo mode safe)")

    # ── Summary ────────────────────────────────────────────────────────────────
    total_checks = len(EXPECTED_COMPONENTS) + len(EXPECTED_LIB_FILES) + 2 + 6
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
