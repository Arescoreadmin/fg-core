#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

REGISTRY_PATH = REPO / "packages/navigation/navigation-registry.json"

REQUIRED_GROUPS = frozenset({
    "Operations", "Governance", "Intelligence", "Trust",
    "Compliance", "Enterprise", "Administration", "Portal",
})

# Enterprise is a reserved group and is explicitly allowed to be empty.
RESERVED_GROUPS = frozenset({"Enterprise"})

VALID_TIERS = frozenset({
    "primary", "secondary", "contextual", "administrative",
    "specialist", "hidden", "legacy", "deprecated", "future", "retired",
})

VALID_LIFECYCLES = frozenset({
    "core", "stable", "growing", "legacy", "future", "deprecated",
})

VALID_PLATFORMS = frozenset({"console", "portal", "both"})

VALID_ROLES = frozenset({
    "Executive", "Board", "CISO", "Compliance", "Auditor",
    "Operator", "AssessmentEngineer", "FieldAssessor",
    "Customer", "MSP", "Consultant", "Administrator", "Developer", "Support",
})

CONSOLE_REQUIRED_ROUTES = {
    "/dashboard",
    "/dashboard/control-tower",
    "/dashboard/readiness",
    "/field-assessment",
    "/dashboard/policies",
    "/dashboard/providers",
    "/dashboard/assistant",
    "/dashboard/corpus",
    "/dashboard/retrieval",
    "/dashboard/provenance",
    "/dashboard/decisions",
    "/dashboard/forensics",
    "/dashboard/evaluation",
    "/dashboard/workforce",
    "/admin/tenants",
    "/dashboard/settings",
    "/assessment",
}

PORTAL_REQUIRED_ROUTES = {
    "/",
    "/engagement",
    "/findings",
    "/reports",
    "/coverage",
    "/attestation",
    "/remediation",
    "/continuity",
    "/assistant",
}

# Routes that, if present in the registry, must carry tier='legacy'.
LEGACY_TIER_ROUTES = {"/assessment", "/onboarding"}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_registry(root: Path) -> dict:
    """Load navigation-registry.json from *root*, raising on missing or bad JSON."""
    path = root / "packages/navigation/navigation-registry.json"
    if not path.is_file():
        raise FileNotFoundError(f"navigation registry not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _console_items(registry: dict) -> list[dict]:
    return list(registry.get("console", []))


def _portal_items(registry: dict) -> list[dict]:
    return list(registry.get("portal", []))


def _all_items(registry: dict) -> list[dict]:
    return _console_items(registry) + _portal_items(registry)


# ---------------------------------------------------------------------------
# Individual checks — each returns a list of error strings
# ---------------------------------------------------------------------------


def check_required_groups(registry: dict) -> list[str]:
    """All 8 canonical MCIM groups must be present in registry.groups."""
    groups_raw = registry.get("groups") or []
    found = {str(g.get("id", "")) for g in groups_raw if isinstance(g, dict)}
    missing = REQUIRED_GROUPS - found
    return [f"missing required group: {g}" for g in sorted(missing)]


def check_no_duplicate_ids(registry: dict) -> list[str]:
    """No item id may appear more than once across console + portal."""
    errors: list[str] = []
    seen: dict[str, str] = {}  # id -> first-seen platform
    for platform, items in (("console", _console_items(registry)), ("portal", _portal_items(registry))):
        for item in items:
            item_id = str(item.get("id", ""))
            if not item_id:
                continue
            if item_id in seen:
                errors.append(
                    f"duplicate item id {item_id!r} in {platform} "
                    f"(first seen in {seen[item_id]})"
                )
            else:
                seen[item_id] = platform
    return errors


def check_no_duplicate_routes(registry: dict) -> list[str]:
    """No route may appear more than once within the same platform."""
    errors: list[str] = []
    for platform, items in (("console", _console_items(registry)), ("portal", _portal_items(registry))):
        seen: dict[str, str] = {}  # route -> first-seen item id
        for item in items:
            route = str(item.get("route", ""))
            item_id = str(item.get("id", ""))
            if not route:
                continue
            if route in seen:
                errors.append(
                    f"duplicate route {route!r} in {platform}: "
                    f"item {item_id!r} conflicts with {seen[route]!r}"
                )
            else:
                seen[route] = item_id
    return errors


def check_required_routes(registry: dict) -> list[str]:
    """All required console and portal routes must be present."""
    errors: list[str] = []
    console_routes = {str(item.get("route", "")) for item in _console_items(registry)}
    portal_routes = {str(item.get("route", "")) for item in _portal_items(registry)}
    for route in sorted(CONSOLE_REQUIRED_ROUTES - console_routes):
        errors.append(f"missing required console route: {route}")
    for route in sorted(PORTAL_REQUIRED_ROUTES - portal_routes):
        errors.append(f"missing required portal route: {route}")
    return errors


def check_valid_tiers(registry: dict) -> list[str]:
    """Every item's tier must be in VALID_TIERS."""
    errors: list[str] = []
    for item in _all_items(registry):
        tier = str(item.get("tier", ""))
        if tier not in VALID_TIERS:
            errors.append(
                f"item {item.get('id', '?')!r} has invalid tier {tier!r}"
            )
    return errors


def _get_lifecycle(item: dict) -> str:
    """Extract lifecycle from flat field or nested metadata, whichever is present."""
    flat = item.get("lifecycle")
    if flat is not None:
        return str(flat)
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        return str(metadata.get("lifecycle", ""))
    return ""


def check_valid_lifecycles(registry: dict) -> list[str]:
    """Every item's lifecycle must be in VALID_LIFECYCLES.

    Supports both flat ``lifecycle`` field and nested ``metadata.lifecycle``.
    """
    errors: list[str] = []
    for item in _all_items(registry):
        lifecycle = _get_lifecycle(item)
        if lifecycle not in VALID_LIFECYCLES:
            errors.append(
                f"item {item.get('id', '?')!r} has invalid lifecycle {lifecycle!r}"
            )
    return errors


def check_valid_platforms(registry: dict) -> list[str]:
    """Every item's platform must be in VALID_PLATFORMS."""
    errors: list[str] = []
    for item in _all_items(registry):
        platform = str(item.get("platform", ""))
        if platform not in VALID_PLATFORMS:
            errors.append(
                f"item {item.get('id', '?')!r} has invalid platform {platform!r}"
            )
    return errors


def check_valid_roles(registry: dict) -> list[str]:
    """Every item must have a non-empty roles list containing only valid role strings."""
    errors: list[str] = []
    for item in _all_items(registry):
        item_id = str(item.get("id", "?"))
        roles = item.get("roles", [])
        if not isinstance(roles, list) or len(roles) == 0:
            errors.append(f"item {item_id!r} has empty or missing roles")
            continue
        for role in roles:
            if str(role) not in VALID_ROLES:
                errors.append(
                    f"item {item_id!r} has invalid role {str(role)!r}"
                )
    return errors


def _get_mcim_id(item: dict) -> str | None:
    """Extract mcim_id from flat field or nested metadata, whichever is present."""
    flat = item.get("mcim_id")
    if flat is not None:
        return str(flat)
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        val = metadata.get("mcimId")
        return str(val) if val is not None else None
    return None


def _get_capability(item: dict) -> str | None:
    """Extract capability from flat field or nested metadata, whichever is present."""
    flat = item.get("capability")
    if flat is not None:
        return str(flat)
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        val = metadata.get("capability")
        return str(val) if val is not None else None
    return None


def check_mcim_ids(registry: dict) -> list[str]:
    """Every item's mcim_id (or metadata.mcimId) must be a non-empty string."""
    errors: list[str] = []
    for item in _all_items(registry):
        item_id = str(item.get("id", "?"))
        mcim_id = _get_mcim_id(item)
        if mcim_id is None:
            errors.append(f"item {item_id!r} missing mcim_id")
        elif not mcim_id.strip():
            errors.append(f"item {item_id!r} has empty mcim_id")
    return errors


def check_capabilities(registry: dict) -> list[str]:
    """Every item's capability (or metadata.capability) must be a non-empty string."""
    errors: list[str] = []
    for item in _all_items(registry):
        item_id = str(item.get("id", "?"))
        capability = _get_capability(item)
        if capability is None:
            errors.append(f"item {item_id!r} missing capability")
        elif not capability.strip():
            errors.append(f"item {item_id!r} has empty capability")
    return errors


def check_portal_groups(registry: dict) -> list[str]:
    """All items in the portal list must belong to the 'Portal' group."""
    errors: list[str] = []
    for item in _portal_items(registry):
        item_id = str(item.get("id", "?"))
        group = str(item.get("group", ""))
        if group != "Portal":
            errors.append(
                f"portal item {item_id!r} must be in group 'Portal', got {group!r}"
            )
    return errors


def check_legacy_routes_present(registry: dict) -> list[str]:
    """Routes in LEGACY_TIER_ROUTES, when present, must have tier='legacy'."""
    errors: list[str] = []
    for item in _all_items(registry):
        route = str(item.get("route", ""))
        if route in LEGACY_TIER_ROUTES:
            tier = str(item.get("tier", ""))
            if tier != "legacy":
                errors.append(
                    f"route {route!r} (item {item.get('id', '?')!r}) must have "
                    f"tier='legacy', got {tier!r}"
                )
    return errors


def check_no_orphaned_groups(registry: dict) -> list[str]:
    """Every item's group must be one of the eight canonical MCIM groups."""
    errors: list[str] = []
    for item in _all_items(registry):
        item_id = str(item.get("id", "?"))
        group = str(item.get("group", ""))
        if group not in REQUIRED_GROUPS:
            errors.append(
                f"item {item_id!r} belongs to unknown group {group!r}"
            )
    return errors


def check_group_coverage(registry: dict) -> list[str]:
    """Every non-reserved group must contain at least one item."""
    errors: list[str] = []
    groups_with_items: set[str] = {
        str(item.get("group", "")) for item in _all_items(registry)
    }
    for group in sorted(REQUIRED_GROUPS - RESERVED_GROUPS):
        if group not in groups_with_items:
            errors.append(f"group {group!r} has no items (non-reserved groups must not be empty)")
    return errors


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_all_checks(registry: dict) -> list[str]:
    """Run every validation check and return the combined list of errors."""
    errors: list[str] = []
    checks = [
        check_required_groups,
        check_no_duplicate_ids,
        check_no_duplicate_routes,
        check_required_routes,
        check_valid_tiers,
        check_valid_lifecycles,
        check_valid_platforms,
        check_valid_roles,
        check_mcim_ids,
        check_capabilities,
        check_portal_groups,
        check_legacy_routes_present,
        check_no_orphaned_groups,
        check_group_coverage,
    ]
    for check in checks:
        errors.extend(check(registry))
    return errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    try:
        registry = load_registry(REPO)
    except FileNotFoundError as exc:
        print(f"navigation registry check: FAILED — {exc}")
        return 1
    except json.JSONDecodeError as exc:
        print(f"navigation registry check: FAILED — invalid JSON: {exc}")
        return 1

    errors = run_all_checks(registry)
    if errors:
        print("navigation registry check: FAILED")
        for error in errors:
            print(f" - {error}")
        return 1

    print("navigation registry check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
