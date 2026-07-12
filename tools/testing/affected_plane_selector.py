#!/usr/bin/env python3
"""Affected-plane selector for path-aware CI test selection.

Given a list of changed files (via git diff), determines which planes
in PLANE_REGISTRY are affected and returns the appropriate test markers
and CI gate recommendation.

Usage:
    python tools/testing/affected_plane_selector.py --files path/to/file1.py path/to/file2.py
    python tools/testing/affected_plane_selector.py --from-git HEAD~1

Output (JSON):
    {
      "affected_planes": ["identity"],
      "recommended_markers": "identity or security or smoke",
      "gate": "layer1",
      "high_risk": false,
      "fallback": false
    }

Failsafe: if classification is ambiguous (multiple non-overlapping planes,
CI infrastructure changes, shared modules), falls back to broader gate
with "fallback": true in the output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.plane_registry.registry import PLANE_REGISTRY  # noqa: E402

# Paths that always trigger high-risk validation regardless of plane.
HIGH_RISK_PATTERNS: tuple[str, ...] = (
    ".github/workflows/",
    "api/security/",
    "api/middleware/",
    "api/auth",
    "admin_gateway/",
    "migrations/",
    "contracts/",
    "services/plane_registry/",
    "tools/ci/check_security",
    "tests/security/",
    "api/db.py",
    "api/db_migrations.py",
    "api/main.py",
)

# Paths that affect ALL planes / core infrastructure — fall back to full gate.
CORE_INFRASTRUCTURE_PATTERNS: tuple[str, ...] = (
    "api/main.py",
    "api/db.py",
    "api/middleware/",
    "conftest.py",
    "requirements",
    "constraints.txt",
    "pyproject.toml",
    "pytest.ini",
    ".github/",
    "Makefile",
    "tools/testing/harness/",
    "tools/ci/",
    "services/plane_registry/",
)

# Map plane_id to route prefixes (extracted from PLANE_REGISTRY at import time)
_PLANE_PREFIX_MAP: dict[str, tuple[str, ...]] = {
    plane.plane_id: plane.route_prefixes for plane in PLANE_REGISTRY
}

# Map plane_id to API directory patterns (heuristic)
_PLANE_PATH_PATTERNS: dict[str, tuple[str, ...]] = {
    "control": ("api/control_plane/", "api/control_tower/", "api/compliance/"),
    "security": ("api/auth", "api/keys/", "api/security/"),
    "rbac": ("api/rbac/", "api/identity_administration/"),
    "data": (
        "api/ingest/",
        "api/feed/",
        "api/decisions/",
        "api/defend/",
        "api/stats/",
        "api/billing/",
    ),
    "agent": ("agent/", "api/agent/"),
    "ai": ("api/ai/", "api/ai_plane/"),
    "connector": ("api/modules/", "api/missions/", "api/roe/"),
    "evidence": (
        "api/audit/",
        "api/evidence/",
        "api/approvals/",
        "api/attestation/",
        "api/forensics/",
        "api/reports/",
    ),
    "workforce": ("api/workforce/",),
    "ui": ("api/ui/", "apps/console/"),
    "identity": (
        "api/identity_administration/",
        "api/identity_authority/",
        "api/identity_governance/",
        "services/identity/",
        "tests/identity_administration/",
        "tests/identity_authority/",
        "tests/identity_governance/",
    ),
}

# Test markers/paths per plane
_PLANE_TEST_MARKERS: dict[str, str] = {
    "control": "control or smoke or contract",
    "security": "security or smoke",
    "rbac": "security or smoke",
    "data": "smoke or contract",
    "agent": "smoke",
    "ai": "smoke or contract",
    "connector": "contract or smoke",
    "evidence": "smoke or contract",
    "workforce": "smoke",
    "ui": "smoke",
    "identity": "smoke or security",
}

_DEFAULT_MARKERS = "smoke or contract or security"


def _is_high_risk(changed_files: list[str]) -> bool:
    for f in changed_files:
        for pattern in HIGH_RISK_PATTERNS:
            if pattern in f or f.startswith(pattern):
                return True
    return False


def _is_core_infrastructure(changed_files: list[str]) -> bool:
    for f in changed_files:
        for pattern in CORE_INFRASTRUCTURE_PATTERNS:
            if pattern in f or f.startswith(pattern):
                return True
    return False


def _classify_files_to_planes(changed_files: list[str]) -> set[str]:
    """Map changed files to affected plane_ids using path heuristics."""
    affected: set[str] = set()
    for f in changed_files:
        matched = False
        for plane_id, patterns in _PLANE_PATH_PATTERNS.items():
            for pattern in patterns:
                if pattern in f or f.startswith(pattern):
                    affected.add(plane_id)
                    matched = True
                    break
        # Also check tests/ subdirectory names
        if not matched and f.startswith("tests/"):
            parts = f.split("/")
            if len(parts) >= 2:
                subdir = parts[1]
                if subdir in _PLANE_PREFIX_MAP:
                    affected.add(subdir)
    return affected


def _get_changed_files_from_git(base_ref: str = "HEAD~1") -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", base_ref],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [f.strip() for f in proc.stdout.splitlines() if f.strip()]


def select(changed_files: list[str]) -> dict[str, object]:
    """
    Classify changed files and return selection result.

    Returns dict with:
      - affected_planes: list of plane_ids
      - recommended_markers: pytest -m expression string
      - gate: "layer1" | "layer2" | "layer3"
      - high_risk: bool
      - fallback: bool (true = fell back to full fg-fast selection)
    """
    if not changed_files:
        return {
            "affected_planes": [],
            "recommended_markers": _DEFAULT_MARKERS,
            "gate": "layer1",
            "high_risk": False,
            "fallback": True,
            "reason": "no changed files — using full default selection",
        }

    high_risk = _is_high_risk(changed_files)

    # Core infrastructure changes require full gate
    if _is_core_infrastructure(changed_files):
        return {
            "affected_planes": ["all"],
            "recommended_markers": _DEFAULT_MARKERS,
            "gate": "layer1" if not high_risk else "layer2",
            "high_risk": high_risk,
            "fallback": True,
            "reason": "core infrastructure change — full selection required",
        }

    affected_planes = _classify_files_to_planes(changed_files)

    # If too many planes affected or classification ambiguous, use full selection
    if not affected_planes or len(affected_planes) > 3:
        return {
            "affected_planes": sorted(affected_planes) if affected_planes else [],
            "recommended_markers": _DEFAULT_MARKERS,
            "gate": "layer2" if high_risk else "layer1",
            "high_risk": high_risk,
            "fallback": True,
            "reason": f"ambiguous classification ({len(affected_planes)} planes) — full selection",
        }

    # Build combined marker expression for all affected planes
    marker_parts: set[str] = set()
    for plane_id in affected_planes:
        marker_expr = _PLANE_TEST_MARKERS.get(plane_id, "smoke")
        for part in marker_expr.split(" or "):
            marker_parts.add(part.strip())

    # Always include smoke tests (sanity baseline)
    marker_parts.add("smoke")

    # If high-risk plane affected, always include security
    if high_risk or any(p in affected_planes for p in ("security", "rbac", "identity")):
        marker_parts.add("security")

    recommended_markers = " or ".join(sorted(marker_parts))

    return {
        "affected_planes": sorted(affected_planes),
        "recommended_markers": recommended_markers,
        "gate": "layer2" if high_risk else "layer1",
        "high_risk": high_risk,
        "fallback": False,
        "reason": f"planes identified: {sorted(affected_planes)}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Determine affected planes and test selection from changed files"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--files",
        nargs="+",
        metavar="FILE",
        help="Explicit list of changed files (relative to repo root)",
    )
    group.add_argument(
        "--from-git",
        metavar="BASE_REF",
        help="Derive changed files from git diff BASE_REF (e.g. HEAD~1, origin/main)",
    )
    args = parser.parse_args()

    if args.from_git:
        changed_files = _get_changed_files_from_git(args.from_git)
    else:
        changed_files = args.files or []

    result = select(changed_files)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
