#!/usr/bin/env python3
"""Tests for tools/ci/check_navigation_registry.py — 300+ deterministic tests."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from tools.ci.check_navigation_registry import (
    CONSOLE_REQUIRED_ROUTES,
    LEGACY_TIER_ROUTES,
    PORTAL_REQUIRED_ROUTES,
    REPO,
    REQUIRED_GROUPS,
    RESERVED_GROUPS,
    VALID_LIFECYCLES,
    VALID_PLATFORMS,
    VALID_ROLES,
    VALID_TIERS,
    check_capabilities,
    check_group_coverage,
    check_legacy_routes_present,
    check_mcim_ids,
    check_no_duplicate_ids,
    check_no_duplicate_routes,
    check_no_orphaned_groups,
    check_portal_groups,
    check_required_groups,
    check_required_routes,
    check_valid_lifecycles,
    check_valid_platforms,
    check_valid_roles,
    check_valid_tiers,
    load_registry,
    run_all_checks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Kept for tests that explicitly pass `metadata=` to _item(); the CI tool
# supports both the flat-field schema (actual registry) and nested metadata.
_VALID_METADATA: dict = {
    "mcimId": "MCIM-001",
    "capability": "Dashboard",
    "family": "operator-execution",
    "authority": "ops",
    "sourceOfTruth": "ops",
    "maturity": "functional",
    "lifecycle": "core",
    "businessValue": "core ops",
}

_ALL_VALID_ROLES: list[str] = sorted(VALID_ROLES)


def _item(
    *,
    item_id: str = "item-1",
    title: str = "Item One",
    route: str = "/dashboard",
    group: str = "Operations",
    tier: str = "primary",
    platform: str = "console",
    roles: list[str] | None = None,
    lifecycle: str = "core",
    mcim_id: str = "MCIM-001",
    capability: str = "Dashboard",
    metadata: dict | None = None,
) -> dict:
    """Build a navigation item using the flat-field schema (matching actual registry).

    When ``metadata`` is explicitly supplied the item will carry a ``metadata``
    key instead of flat fields, which exercises the nested-metadata code paths in
    the CI validator.
    """
    base: dict = {
        "id": item_id,
        "title": title,
        "route": route,
        "group": group,
        "tier": tier,
        "platform": platform,
        "roles": roles if roles is not None else ["Operator"],
        "aliases": [],
        "keywords": [],
    }
    if metadata is not None:
        base["metadata"] = metadata
    else:
        # Flat-field schema — matches the actual navigation-registry.json format.
        base["mcim_id"] = mcim_id
        base["capability"] = capability
        base["lifecycle"] = lifecycle
    return base


def _portal_item(
    *,
    item_id: str = "portal-home",
    route: str = "/",
    tier: str = "primary",
    lifecycle: str = "core",
    mcim_id: str = "MCIM-P001",
    capability: str = "Portal Home",
    roles: list[str] | None = None,
    group: str = "Portal",
    platform: str = "portal",
    metadata: dict | None = None,
) -> dict:
    return _item(
        item_id=item_id,
        route=route,
        group=group,
        tier=tier,
        platform=platform,
        lifecycle=lifecycle,
        mcim_id=mcim_id,
        capability=capability,
        roles=roles if roles is not None else ["Customer"],
        metadata=metadata,
    )


def _group_def(
    group_id: str = "Operations",
    *,
    platform: str = "console",
    reserved: bool = False,
) -> dict:
    return {
        "id": group_id,
        "label": group_id,
        "description": f"{group_id} group",
        "platform": platform,
        "reserved": reserved,
    }


def _all_group_defs() -> list[dict]:
    platform_map = {
        "Operations": "console",
        "Governance": "console",
        "Intelligence": "console",
        "Trust": "console",
        "Compliance": "console",
        "Enterprise": "console",
        "Administration": "both",
        "Portal": "portal",
    }
    reserved = {"Enterprise"}
    return [
        _group_def(g, platform=p, reserved=(g in reserved))
        for g, p in platform_map.items()
    ]


def _minimal_console_items() -> list[dict]:
    """One item per required console route, all valid.

    Routes are spread across the canonical groups so that every non-reserved
    group has at least one item and check_group_coverage passes.  Routes in
    LEGACY_TIER_ROUTES receive tier='legacy' as required by check_legacy_routes_present.
    """
    # Map each required route to a group that satisfies group-coverage.
    _ROUTE_GROUP: dict[str, str] = {
        "/dashboard": "Operations",
        "/dashboard/control-tower": "Operations",
        "/dashboard/readiness": "Governance",
        "/field-assessment": "Governance",
        "/dashboard/policies": "Governance",
        "/dashboard/providers": "Governance",
        "/dashboard/assistant": "Intelligence",
        "/dashboard/corpus": "Intelligence",
        "/dashboard/retrieval": "Intelligence",
        "/dashboard/provenance": "Trust",
        "/dashboard/decisions": "Trust",
        "/dashboard/forensics": "Trust",
        "/dashboard/evaluation": "Compliance",
        "/dashboard/workforce": "Compliance",
        "/dashboard/settings": "Administration",
        "/admin/tenants": "Administration",
        "/assessment": "Operations",
    }
    items = []
    for idx, route in enumerate(sorted(CONSOLE_REQUIRED_ROUTES)):
        group = _ROUTE_GROUP.get(route, "Operations")
        tier = "legacy" if route in LEGACY_TIER_ROUTES else "primary"
        items.append(
            _item(
                item_id=f"console-{idx}",
                route=route,
                group=group,
                tier=tier,
            )
        )
    return items


def _minimal_portal_items() -> list[dict]:
    """One item per required portal route, all valid."""
    items = []
    for idx, route in enumerate(sorted(PORTAL_REQUIRED_ROUTES)):
        items.append(
            _portal_item(
                item_id=f"portal-{idx}",
                route=route,
            )
        )
    return items


def _make_registry(
    console: list[dict] | None = None,
    portal: list[dict] | None = None,
    groups: list[dict] | None = None,
    stats: dict | None = None,
) -> dict:
    """Build a minimal structurally valid registry dict."""
    c = console if console is not None else _minimal_console_items()
    p = portal if portal is not None else _minimal_portal_items()
    g = groups if groups is not None else _all_group_defs()
    reg: dict = {"console": c, "portal": p, "groups": g}
    if stats is not None:
        reg["stats"] = stats
    return reg


def _valid_registry() -> dict:
    """Return a fully valid registry that passes run_all_checks."""
    return _make_registry()


# ---------------------------------------------------------------------------
# 1. load_registry
# ---------------------------------------------------------------------------


class TestLoadRegistry:
    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_registry(tmp_path)

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        nav = tmp_path / "packages" / "navigation"
        nav.mkdir(parents=True)
        (nav / "navigation-registry.json").write_text("{bad json}", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            load_registry(tmp_path)

    def test_valid_json_returns_dict(self, tmp_path: Path) -> None:
        nav = tmp_path / "packages" / "navigation"
        nav.mkdir(parents=True)
        payload = {"console": [], "portal": [], "groups": []}
        (nav / "navigation-registry.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        result = load_registry(tmp_path)
        assert result == payload

    def test_returns_dict_type(self, tmp_path: Path) -> None:
        nav = tmp_path / "packages" / "navigation"
        nav.mkdir(parents=True)
        (nav / "navigation-registry.json").write_text(
            json.dumps({"a": 1}), encoding="utf-8"
        )
        result = load_registry(tmp_path)
        assert isinstance(result, dict)

    def test_nested_content_preserved(self, tmp_path: Path) -> None:
        nav = tmp_path / "packages" / "navigation"
        nav.mkdir(parents=True)
        payload = {"console": [{"id": "x"}], "portal": [], "groups": []}
        (nav / "navigation-registry.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        result = load_registry(tmp_path)
        assert result["console"][0]["id"] == "x"

    def test_empty_json_object_loads(self, tmp_path: Path) -> None:
        nav = tmp_path / "packages" / "navigation"
        nav.mkdir(parents=True)
        (nav / "navigation-registry.json").write_text("{}", encoding="utf-8")
        result = load_registry(tmp_path)
        assert result == {}

    def test_completely_missing_parent_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_registry(tmp_path / "nonexistent")


# ---------------------------------------------------------------------------
# 2. check_required_groups
# ---------------------------------------------------------------------------


class TestCheckRequiredGroups:
    def test_all_groups_present_passes(self) -> None:
        reg = _make_registry(groups=_all_group_defs())
        assert check_required_groups(reg) == []

    def test_empty_groups_fails_all(self) -> None:
        reg = _make_registry(groups=[])
        errors = check_required_groups(reg)
        assert len(errors) == len(REQUIRED_GROUPS)

    @pytest.mark.parametrize("missing_group", sorted(REQUIRED_GROUPS))
    def test_each_missing_group_fails(self, missing_group: str) -> None:
        groups = [g for g in _all_group_defs() if g["id"] != missing_group]
        reg = _make_registry(groups=groups)
        errors = check_required_groups(reg)
        assert any(missing_group in e for e in errors)

    def test_extra_group_does_not_fail(self) -> None:
        groups = _all_group_defs() + [_group_def("ExtraGroup")]
        reg = _make_registry(groups=groups)
        assert check_required_groups(reg) == []

    def test_groups_missing_id_field_treated_as_absent(self) -> None:
        groups = [{"label": "Operations"}]  # no "id"
        reg = _make_registry(groups=groups)
        errors = check_required_groups(reg)
        assert any("Operations" in e for e in errors)

    def test_groups_not_list_treated_as_empty(self) -> None:
        reg = {"console": [], "portal": [], "groups": None}
        errors = check_required_groups(reg)
        assert len(errors) == len(REQUIRED_GROUPS)

    def test_error_count_matches_missing_groups(self) -> None:
        groups = [g for g in _all_group_defs() if g["id"] in {"Operations", "Portal"}]
        reg = _make_registry(groups=groups)
        errors = check_required_groups(reg)
        missing = REQUIRED_GROUPS - {"Operations", "Portal"}
        assert len(errors) == len(missing)

    def test_returns_list_type(self) -> None:
        reg = _make_registry(groups=_all_group_defs())
        assert isinstance(check_required_groups(reg), list)


# ---------------------------------------------------------------------------
# 3. check_no_duplicate_ids
# ---------------------------------------------------------------------------


class TestCheckNoDuplicateIds:
    def test_no_dupes_passes(self) -> None:
        reg = _valid_registry()
        assert check_no_duplicate_ids(reg) == []

    def test_dupe_in_console_fails(self) -> None:
        items = [
            _item(item_id="dup", route="/dashboard"),
            _item(item_id="dup", route="/dashboard/readiness"),
        ]
        reg = _make_registry(console=items)
        errors = check_no_duplicate_ids(reg)
        assert any("dup" in e for e in errors)

    def test_dupe_in_portal_fails(self) -> None:
        items = [
            _portal_item(item_id="dup", route="/"),
            _portal_item(item_id="dup", route="/engagement"),
        ]
        reg = _make_registry(portal=items)
        errors = check_no_duplicate_ids(reg)
        assert any("dup" in e for e in errors)

    def test_dupe_across_console_and_portal_fails(self) -> None:
        console = [_item(item_id="shared-id", route="/dashboard")]
        portal = [_portal_item(item_id="shared-id", route="/")]
        reg = _make_registry(console=console, portal=portal)
        errors = check_no_duplicate_ids(reg)
        assert any("shared-id" in e for e in errors)

    def test_unique_ids_across_platforms_pass(self) -> None:
        console = [_item(item_id="c-1", route="/dashboard")]
        portal = [_portal_item(item_id="p-1", route="/")]
        reg = _make_registry(console=console, portal=portal)
        assert check_no_duplicate_ids(reg) == []

    def test_empty_console_and_portal_passes(self) -> None:
        reg = _make_registry(console=[], portal=[])
        assert check_no_duplicate_ids(reg) == []

    def test_single_item_no_error(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="only-one", route="/dashboard")], portal=[]
        )
        assert check_no_duplicate_ids(reg) == []

    def test_items_missing_id_skipped(self) -> None:
        items = [{"route": "/dashboard", "group": "Operations"}]
        reg = _make_registry(console=items, portal=[])
        errors = check_no_duplicate_ids(reg)
        assert errors == []

    def test_multiple_dupes_all_reported(self) -> None:
        items = [
            _item(item_id="dup-a", route="/dashboard"),
            _item(item_id="dup-a", route="/dashboard/readiness"),
            _item(item_id="dup-b", route="/field-assessment"),
            _item(item_id="dup-b", route="/dashboard/policies"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_no_duplicate_ids(reg)
        assert len([e for e in errors if "dup-a" in e]) >= 1
        assert len([e for e in errors if "dup-b" in e]) >= 1


# ---------------------------------------------------------------------------
# 4. check_no_duplicate_routes
# ---------------------------------------------------------------------------


class TestCheckNoDuplicateRoutes:
    def test_no_dupes_passes(self) -> None:
        reg = _valid_registry()
        assert check_no_duplicate_routes(reg) == []

    def test_dupe_route_in_console_fails(self) -> None:
        items = [
            _item(item_id="a", route="/dashboard"),
            _item(item_id="b", route="/dashboard"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_no_duplicate_routes(reg)
        assert any("/dashboard" in e for e in errors)

    def test_dupe_route_in_portal_fails(self) -> None:
        items = [
            _portal_item(item_id="a", route="/engagement"),
            _portal_item(item_id="b", route="/engagement"),
        ]
        reg = _make_registry(portal=items, console=[])
        errors = check_no_duplicate_routes(reg)
        assert any("/engagement" in e for e in errors)

    def test_same_route_in_console_and_portal_allowed(self) -> None:
        # Routes are checked per-platform only
        console = [_item(item_id="c-assist", route="/dashboard/assistant")]
        portal = [_portal_item(item_id="p-assist", route="/assistant")]
        reg = _make_registry(console=console, portal=portal)
        assert check_no_duplicate_routes(reg) == []

    def test_empty_lists_passes(self) -> None:
        reg = _make_registry(console=[], portal=[])
        assert check_no_duplicate_routes(reg) == []

    def test_three_identical_routes_reports_two_errors(self) -> None:
        items = [
            _item(item_id="a", route="/dashboard"),
            _item(item_id="b", route="/dashboard"),
            _item(item_id="c", route="/dashboard"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_no_duplicate_routes(reg)
        # b and c both conflict with a
        assert len(errors) >= 2

    def test_items_missing_route_skipped(self) -> None:
        items = [{"id": "no-route", "group": "Operations"}]
        reg = _make_registry(console=items, portal=[])
        assert check_no_duplicate_routes(reg) == []


# ---------------------------------------------------------------------------
# 5. check_required_routes
# ---------------------------------------------------------------------------


class TestCheckRequiredRoutes:
    def test_all_present_passes(self) -> None:
        reg = _valid_registry()
        assert check_required_routes(reg) == []

    @pytest.mark.parametrize("missing_route", sorted(CONSOLE_REQUIRED_ROUTES))
    def test_each_missing_console_route_fails(self, missing_route: str) -> None:
        items = [i for i in _minimal_console_items() if i["route"] != missing_route]
        reg = _make_registry(console=items)
        errors = check_required_routes(reg)
        assert any(missing_route in e for e in errors)

    @pytest.mark.parametrize("missing_route", sorted(PORTAL_REQUIRED_ROUTES))
    def test_each_missing_portal_route_fails(self, missing_route: str) -> None:
        items = [i for i in _minimal_portal_items() if i["route"] != missing_route]
        reg = _make_registry(portal=items)
        errors = check_required_routes(reg)
        assert any(missing_route in e for e in errors)

    def test_missing_console_route_mentions_console(self) -> None:
        items = [i for i in _minimal_console_items() if i["route"] != "/dashboard"]
        reg = _make_registry(console=items)
        errors = check_required_routes(reg)
        assert any("console" in e for e in errors)

    def test_missing_portal_route_mentions_portal(self) -> None:
        items = [i for i in _minimal_portal_items() if i["route"] != "/"]
        reg = _make_registry(portal=items)
        errors = check_required_routes(reg)
        assert any("portal" in e for e in errors)

    def test_empty_console_list_reports_all_missing(self) -> None:
        reg = _make_registry(console=[], portal=_minimal_portal_items())
        errors = check_required_routes(reg)
        assert len(errors) == len(CONSOLE_REQUIRED_ROUTES)

    def test_empty_portal_list_reports_all_missing(self) -> None:
        reg = _make_registry(console=_minimal_console_items(), portal=[])
        errors = check_required_routes(reg)
        assert len(errors) == len(PORTAL_REQUIRED_ROUTES)

    def test_extra_routes_do_not_cause_errors(self) -> None:
        extra = _item(item_id="extra", route="/extra/feature", group="Operations")
        items = _minimal_console_items() + [extra]
        reg = _make_registry(console=items)
        assert check_required_routes(reg) == []


# ---------------------------------------------------------------------------
# 6. check_valid_tiers
# ---------------------------------------------------------------------------


class TestCheckValidTiers:
    def test_all_valid_tiers_pass(self) -> None:
        items = [
            _item(item_id=f"tier-{idx}", route=f"/route-{idx}", tier=tier)
            for idx, tier in enumerate(sorted(VALID_TIERS))
        ]
        reg = _make_registry(console=items, portal=[])
        assert check_valid_tiers(reg) == []

    @pytest.mark.parametrize("valid_tier", sorted(VALID_TIERS))
    def test_each_valid_tier_passes(self, valid_tier: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="t", route="/dashboard", tier=valid_tier)],
            portal=[],
        )
        assert check_valid_tiers(reg) == []

    @pytest.mark.parametrize(
        "bad_tier",
        ["invalid", "PRIMARY", "Primary", "tier-x", "", "none", "unknown"],
    )
    def test_invalid_tiers_fail(self, bad_tier: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="t", route="/dashboard", tier=bad_tier)],
            portal=[],
        )
        errors = check_valid_tiers(reg)
        assert len(errors) >= 1

    def test_invalid_tier_mentions_item_id(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="my-item", route="/dashboard", tier="bad-tier")],
            portal=[],
        )
        errors = check_valid_tiers(reg)
        assert any("my-item" in e for e in errors)

    def test_invalid_tier_in_portal_also_fails(self) -> None:
        reg = _make_registry(
            console=[],
            portal=[_portal_item(item_id="portal-t", route="/", tier="wrong")],
        )
        errors = check_valid_tiers(reg)
        assert len(errors) >= 1

    def test_multiple_invalid_tiers_all_reported(self) -> None:
        items = [
            _item(item_id="a", route="/dashboard", tier="bad1"),
            _item(item_id="b", route="/dashboard/readiness", tier="bad2"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_valid_tiers(reg)
        assert len(errors) >= 2

    def test_empty_tier_string_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="t", route="/dashboard", tier="")],
            portal=[],
        )
        errors = check_valid_tiers(reg)
        assert len(errors) >= 1

    def test_empty_lists_returns_empty(self) -> None:
        assert check_valid_tiers({"console": [], "portal": [], "groups": []}) == []


# ---------------------------------------------------------------------------
# 7. check_valid_lifecycles
# ---------------------------------------------------------------------------


class TestCheckValidLifecycles:
    @pytest.mark.parametrize("valid_lc", sorted(VALID_LIFECYCLES))
    def test_each_valid_lifecycle_passes(self, valid_lc: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="lc", route="/dashboard", lifecycle=valid_lc)],
            portal=[],
        )
        assert check_valid_lifecycles(reg) == []

    @pytest.mark.parametrize(
        "bad_lc",
        ["invalid", "CORE", "Core", "lifecycle-x", "", "unknown", "none"],
    )
    def test_invalid_lifecycles_fail(self, bad_lc: str) -> None:
        meta = dict(_VALID_METADATA)
        meta["lifecycle"] = bad_lc
        reg = _make_registry(
            console=[_item(item_id="lc", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_valid_lifecycles(reg)
        assert len(errors) >= 1

    def test_invalid_lifecycle_mentions_item_id(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["lifecycle"] = "bad-lifecycle"
        reg = _make_registry(
            console=[_item(item_id="my-lc-item", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_valid_lifecycles(reg)
        assert any("my-lc-item" in e for e in errors)

    def test_missing_metadata_fails(self) -> None:
        # Build item with nested metadata schema, empty lifecycle — no flat field.
        item = _item(item_id="no-meta", route="/dashboard", metadata={})
        reg = _make_registry(console=[item], portal=[])
        errors = check_valid_lifecycles(reg)
        assert len(errors) >= 1

    def test_metadata_not_dict_fails(self) -> None:
        # Flat lifecycle field removed; metadata is not a dict → lifecycle falls back to "".
        item = _item(item_id="bad-meta", route="/dashboard")
        del item["lifecycle"]  # remove flat field
        item["metadata"] = "not-a-dict"
        reg = _make_registry(console=[item], portal=[])
        errors = check_valid_lifecycles(reg)
        assert len(errors) >= 1

    def test_portal_invalid_lifecycle_also_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["lifecycle"] = "bad"
        reg = _make_registry(
            portal=[_portal_item(item_id="portal-lc", route="/", metadata=meta)],
            console=[],
        )
        errors = check_valid_lifecycles(reg)
        assert len(errors) >= 1

    def test_all_valid_lifecycles_together_pass(self) -> None:
        items = [
            _item(item_id=f"lc-{idx}", route=f"/route-{idx}", lifecycle=lc)
            for idx, lc in enumerate(sorted(VALID_LIFECYCLES))
        ]
        reg = _make_registry(console=items, portal=[])
        assert check_valid_lifecycles(reg) == []


# ---------------------------------------------------------------------------
# 8. check_valid_platforms
# ---------------------------------------------------------------------------


class TestCheckValidPlatforms:
    @pytest.mark.parametrize("valid_platform", sorted(VALID_PLATFORMS))
    def test_each_valid_platform_passes(self, valid_platform: str) -> None:
        group = "Portal" if valid_platform == "portal" else "Operations"
        reg = _make_registry(
            console=[
                _item(
                    item_id="plat",
                    route="/dashboard",
                    platform=valid_platform,
                    group=group,
                )
            ],
            portal=[],
        )
        assert check_valid_platforms(reg) == []

    @pytest.mark.parametrize(
        "bad_platform",
        ["invalid", "CONSOLE", "Console", "both+portal", "", "web", "all"],
    )
    def test_invalid_platforms_fail(self, bad_platform: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="plat", route="/dashboard", platform=bad_platform)],
            portal=[],
        )
        errors = check_valid_platforms(reg)
        assert len(errors) >= 1

    def test_invalid_platform_mentions_item_id(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="plat-item", route="/dashboard", platform="wrong")],
            portal=[],
        )
        errors = check_valid_platforms(reg)
        assert any("plat-item" in e for e in errors)

    def test_portal_item_with_invalid_platform_fails(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", platform="wrong")],
            console=[],
        )
        errors = check_valid_platforms(reg)
        assert len(errors) >= 1

    def test_empty_registry_passes(self) -> None:
        assert check_valid_platforms({"console": [], "portal": [], "groups": []}) == []

    def test_multiple_invalid_platforms_all_reported(self) -> None:
        items = [
            _item(item_id="a", route="/dashboard", platform="web"),
            _item(item_id="b", route="/dashboard/readiness", platform="mobile"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_valid_platforms(reg)
        assert len(errors) >= 2


# ---------------------------------------------------------------------------
# 9. check_valid_roles
# ---------------------------------------------------------------------------


class TestCheckValidRoles:
    @pytest.mark.parametrize("valid_role", sorted(VALID_ROLES))
    def test_each_valid_role_passes(self, valid_role: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=[valid_role])],
            portal=[],
        )
        assert check_valid_roles(reg) == []

    def test_multiple_valid_roles_pass(self) -> None:
        reg = _make_registry(
            console=[
                _item(
                    item_id="r",
                    route="/dashboard",
                    roles=["Operator", "CISO", "Auditor"],
                )
            ],
            portal=[],
        )
        assert check_valid_roles(reg) == []

    def test_all_valid_roles_together_pass(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=list(VALID_ROLES))],
            portal=[],
        )
        assert check_valid_roles(reg) == []

    def test_empty_roles_list_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=[])],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    def test_missing_roles_key_fails(self) -> None:
        item = _item(item_id="r", route="/dashboard")
        del item["roles"]
        reg = _make_registry(console=[item], portal=[])
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    def test_roles_not_list_fails(self) -> None:
        item = _item(item_id="r", route="/dashboard")
        item["roles"] = "Operator"
        reg = _make_registry(console=[item], portal=[])
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    @pytest.mark.parametrize(
        "bad_role",
        ["invalid", "operator", "OPERATOR", "Admin", "user", "", "superuser"],
    )
    def test_invalid_role_fails(self, bad_role: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=[bad_role])],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    def test_invalid_role_mentions_item_id(self) -> None:
        reg = _make_registry(
            console=[
                _item(item_id="bad-role-item", route="/dashboard", roles=["BadRole"])
            ],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert any("bad-role-item" in e for e in errors)

    def test_one_invalid_role_in_otherwise_valid_list_fails(self) -> None:
        reg = _make_registry(
            console=[
                _item(item_id="r", route="/dashboard", roles=["Operator", "BadRole"])
            ],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert any("BadRole" in e for e in errors)

    def test_portal_empty_roles_fails(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", roles=[])],
            console=[],
        )
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    def test_portal_valid_roles_pass(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", roles=["Customer", "MSP"])],
            console=[],
        )
        assert check_valid_roles(reg) == []

    def test_null_roles_fails(self) -> None:
        item = _item(item_id="r", route="/dashboard")
        item["roles"] = None
        reg = _make_registry(console=[item], portal=[])
        errors = check_valid_roles(reg)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# 10. check_mcim_ids
# ---------------------------------------------------------------------------


class TestCheckMcimIds:
    def test_non_empty_mcim_id_passes(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="m", route="/dashboard", mcim_id="MCIM-001")],
            portal=[],
        )
        assert check_mcim_ids(reg) == []

    def test_empty_mcim_id_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["mcimId"] = ""
        reg = _make_registry(
            console=[_item(item_id="m", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_whitespace_only_mcim_id_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["mcimId"] = "   "
        reg = _make_registry(
            console=[_item(item_id="m", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_missing_mcim_id_key_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        del meta["mcimId"]
        reg = _make_registry(
            console=[_item(item_id="m", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_missing_metadata_fails(self) -> None:
        # Nested metadata schema with empty dict — no mcimId key, no flat mcim_id.
        item = _item(item_id="m", route="/dashboard", metadata={})
        reg = _make_registry(console=[item], portal=[])
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_metadata_not_dict_fails(self) -> None:
        # Remove flat mcim_id and set metadata to non-dict → _get_mcim_id returns None.
        item = _item(item_id="m", route="/dashboard")
        del item["mcim_id"]
        item["metadata"] = None
        reg = _make_registry(console=[item], portal=[])
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_error_mentions_item_id(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["mcimId"] = ""
        reg = _make_registry(
            console=[_item(item_id="mcim-item", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_mcim_ids(reg)
        assert any("mcim-item" in e for e in errors)

    def test_portal_item_missing_mcim_id_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["mcimId"] = ""
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", metadata=meta)],
            console=[],
        )
        errors = check_mcim_ids(reg)
        assert len(errors) >= 1

    def test_multiple_items_without_mcim_id_all_reported(self) -> None:
        meta_a = dict(_VALID_METADATA)
        meta_a["mcimId"] = ""
        meta_b = dict(_VALID_METADATA)
        meta_b["mcimId"] = ""
        items = [
            _item(item_id="a", route="/dashboard", metadata=meta_a),
            _item(item_id="b", route="/dashboard/readiness", metadata=meta_b),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_mcim_ids(reg)
        assert len(errors) >= 2

    def test_numeric_mcim_id_passes(self) -> None:
        # mcimId can be any non-empty string (even numeric string values)
        meta = dict(_VALID_METADATA)
        meta["mcimId"] = "12345"
        reg = _make_registry(
            console=[_item(item_id="m", route="/dashboard", metadata=meta)],
            portal=[],
        )
        assert check_mcim_ids(reg) == []


# ---------------------------------------------------------------------------
# 11. check_capabilities
# ---------------------------------------------------------------------------


class TestCheckCapabilities:
    def test_non_empty_capability_passes(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="c", route="/dashboard", capability="Dashboard")],
            portal=[],
        )
        assert check_capabilities(reg) == []

    def test_empty_capability_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["capability"] = ""
        reg = _make_registry(
            console=[_item(item_id="c", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_whitespace_only_capability_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["capability"] = "   "
        reg = _make_registry(
            console=[_item(item_id="c", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_missing_capability_key_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        del meta["capability"]
        reg = _make_registry(
            console=[_item(item_id="c", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_error_mentions_item_id(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["capability"] = ""
        reg = _make_registry(
            console=[_item(item_id="cap-item", route="/dashboard", metadata=meta)],
            portal=[],
        )
        errors = check_capabilities(reg)
        assert any("cap-item" in e for e in errors)

    def test_missing_metadata_fails(self) -> None:
        # Nested metadata schema, empty dict — no capability key, no flat field.
        item = _item(item_id="c", route="/dashboard", metadata={})
        reg = _make_registry(console=[item], portal=[])
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_metadata_not_dict_fails(self) -> None:
        # Remove flat capability and set metadata to non-dict → _get_capability returns None.
        item = _item(item_id="c", route="/dashboard")
        del item["capability"]
        item["metadata"] = "bad"
        reg = _make_registry(console=[item], portal=[])
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_portal_empty_capability_fails(self) -> None:
        meta = dict(_VALID_METADATA)
        meta["capability"] = ""
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", metadata=meta)],
            console=[],
        )
        errors = check_capabilities(reg)
        assert len(errors) >= 1

    def test_multiple_missing_capabilities_all_reported(self) -> None:
        meta_a = dict(_VALID_METADATA)
        meta_a["capability"] = ""
        meta_b = dict(_VALID_METADATA)
        meta_b["capability"] = ""
        items = [
            _item(item_id="a", route="/dashboard", metadata=meta_a),
            _item(item_id="b", route="/dashboard/readiness", metadata=meta_b),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_capabilities(reg)
        assert len(errors) >= 2

    def test_valid_capability_with_spaces_passes(self) -> None:
        reg = _make_registry(
            console=[
                _item(item_id="c", route="/dashboard", capability="AI Governance")
            ],
            portal=[],
        )
        assert check_capabilities(reg) == []


# ---------------------------------------------------------------------------
# 12. check_portal_groups
# ---------------------------------------------------------------------------


class TestCheckPortalGroups:
    def test_portal_item_in_portal_group_passes(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", group="Portal")],
            console=[],
        )
        assert check_portal_groups(reg) == []

    @pytest.mark.parametrize(
        "wrong_group",
        [
            "Operations",
            "Governance",
            "Intelligence",
            "Trust",
            "Compliance",
            "Enterprise",
            "Administration",
        ],
    )
    def test_portal_item_in_wrong_group_fails(self, wrong_group: str) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", group=wrong_group)],
            console=[],
        )
        errors = check_portal_groups(reg)
        assert len(errors) >= 1

    def test_error_mentions_item_id(self) -> None:
        reg = _make_registry(
            portal=[
                _portal_item(item_id="my-portal-item", route="/", group="Operations")
            ],
            console=[],
        )
        errors = check_portal_groups(reg)
        assert any("my-portal-item" in e for e in errors)

    def test_empty_portal_list_passes(self) -> None:
        assert check_portal_groups({"console": [], "portal": [], "groups": []}) == []

    def test_console_items_in_any_group_not_checked(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="c", route="/dashboard", group="Operations")],
            portal=[],
        )
        assert check_portal_groups(reg) == []

    def test_multiple_portal_items_wrong_group_all_reported(self) -> None:
        items = [
            _portal_item(item_id="a", route="/", group="Operations"),
            _portal_item(item_id="b", route="/engagement", group="Governance"),
        ]
        reg = _make_registry(portal=items, console=[])
        errors = check_portal_groups(reg)
        assert len(errors) >= 2

    def test_mixed_portal_items_only_wrong_group_reported(self) -> None:
        items = [
            _portal_item(item_id="ok", route="/", group="Portal"),
            _portal_item(item_id="bad", route="/engagement", group="Operations"),
        ]
        reg = _make_registry(portal=items, console=[])
        errors = check_portal_groups(reg)
        assert len(errors) == 1
        assert "bad" in errors[0]

    def test_wrong_group_mentions_wrong_group_in_error(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", group="Operations")],
            console=[],
        )
        errors = check_portal_groups(reg)
        assert any("Operations" in e for e in errors)


# ---------------------------------------------------------------------------
# 13. check_legacy_routes_present
# ---------------------------------------------------------------------------


class TestCheckLegacyRoutesPresent:
    def test_assessment_with_legacy_tier_passes(self) -> None:
        item = _item(
            item_id="assess", route="/assessment", group="Operations", tier="legacy"
        )
        reg = _make_registry(console=[item], portal=[])
        assert check_legacy_routes_present(reg) == []

    def test_assessment_with_primary_tier_fails(self) -> None:
        item = _item(
            item_id="assess", route="/assessment", group="Operations", tier="primary"
        )
        reg = _make_registry(console=[item], portal=[])
        errors = check_legacy_routes_present(reg)
        assert len(errors) >= 1

    @pytest.mark.parametrize(
        "bad_tier",
        [
            "primary",
            "secondary",
            "contextual",
            "administrative",
            "specialist",
            "hidden",
            "deprecated",
            "future",
            "retired",
        ],
    )
    def test_assessment_with_non_legacy_tier_fails(self, bad_tier: str) -> None:
        item = _item(
            item_id="assess", route="/assessment", group="Operations", tier=bad_tier
        )
        reg = _make_registry(console=[item], portal=[])
        errors = check_legacy_routes_present(reg)
        assert len(errors) >= 1

    def test_onboarding_with_legacy_tier_passes(self) -> None:
        item = _item(
            item_id="onboard", route="/onboarding", group="Operations", tier="legacy"
        )
        reg = _make_registry(console=[item], portal=[])
        assert check_legacy_routes_present(reg) == []

    def test_onboarding_with_primary_tier_fails(self) -> None:
        item = _item(
            item_id="onboard", route="/onboarding", group="Operations", tier="primary"
        )
        reg = _make_registry(console=[item], portal=[])
        errors = check_legacy_routes_present(reg)
        assert len(errors) >= 1

    def test_absent_legacy_routes_not_required(self) -> None:
        # If /assessment and /onboarding are absent, no error from this check
        reg = _make_registry(console=[], portal=[])
        assert check_legacy_routes_present(reg) == []

    def test_error_mentions_route(self) -> None:
        item = _item(
            item_id="assess", route="/assessment", group="Operations", tier="primary"
        )
        reg = _make_registry(console=[item], portal=[])
        errors = check_legacy_routes_present(reg)
        assert any("/assessment" in e for e in errors)

    def test_error_mentions_item_id(self) -> None:
        item = _item(
            item_id="my-assess", route="/assessment", group="Operations", tier="primary"
        )
        reg = _make_registry(console=[item], portal=[])
        errors = check_legacy_routes_present(reg)
        assert any("my-assess" in e for e in errors)

    def test_other_routes_not_subject_to_legacy_check(self) -> None:
        item = _item(
            item_id="dash", route="/dashboard", group="Operations", tier="primary"
        )
        reg = _make_registry(console=[item], portal=[])
        assert check_legacy_routes_present(reg) == []

    def test_both_legacy_routes_present_correct_tier_passes(self) -> None:
        items = [
            _item(
                item_id="assess", route="/assessment", group="Operations", tier="legacy"
            ),
            _item(
                item_id="onboard",
                route="/onboarding",
                group="Operations",
                tier="legacy",
            ),
        ]
        reg = _make_registry(console=items, portal=[])
        assert check_legacy_routes_present(reg) == []

    def test_both_legacy_routes_wrong_tier_reports_two_errors(self) -> None:
        items = [
            _item(
                item_id="assess",
                route="/assessment",
                group="Operations",
                tier="primary",
            ),
            _item(
                item_id="onboard",
                route="/onboarding",
                group="Operations",
                tier="primary",
            ),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_legacy_routes_present(reg)
        assert len(errors) >= 2


# ---------------------------------------------------------------------------
# 14. check_no_orphaned_groups
# ---------------------------------------------------------------------------


class TestCheckNoOrphanedGroups:
    @pytest.mark.parametrize("valid_group", sorted(REQUIRED_GROUPS))
    def test_each_valid_group_passes(self, valid_group: str) -> None:
        platform = "portal" if valid_group == "Portal" else "console"
        item = _item(
            item_id="g", route="/dashboard", group=valid_group, platform=platform
        )
        reg = _make_registry(
            console=[item] if platform == "console" else [],
            portal=[item] if platform == "portal" else [],
        )
        assert check_no_orphaned_groups(reg) == []

    @pytest.mark.parametrize(
        "bad_group",
        ["Unknown", "Reporting", "Analytics", "Security", "Finance", "HR", "Dev", ""],
    )
    def test_unknown_group_fails(self, bad_group: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="g", route="/dashboard", group=bad_group)],
            portal=[],
        )
        errors = check_no_orphaned_groups(reg)
        assert len(errors) >= 1

    def test_error_mentions_item_id(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="orphan-item", route="/dashboard", group="Unknown")],
            portal=[],
        )
        errors = check_no_orphaned_groups(reg)
        assert any("orphan-item" in e for e in errors)

    def test_error_mentions_bad_group(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="g", route="/dashboard", group="UnknownGroup")],
            portal=[],
        )
        errors = check_no_orphaned_groups(reg)
        assert any("UnknownGroup" in e for e in errors)

    def test_empty_lists_passes(self) -> None:
        assert (
            check_no_orphaned_groups({"console": [], "portal": [], "groups": []}) == []
        )

    def test_valid_registry_passes(self) -> None:
        assert check_no_orphaned_groups(_valid_registry()) == []

    def test_portal_item_in_unknown_group_fails(self) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", group="Reporting")],
            console=[],
        )
        errors = check_no_orphaned_groups(reg)
        assert len(errors) >= 1

    def test_multiple_orphaned_groups_all_reported(self) -> None:
        items = [
            _item(item_id="a", route="/dashboard", group="Bad1"),
            _item(item_id="b", route="/dashboard/readiness", group="Bad2"),
        ]
        reg = _make_registry(console=items, portal=[])
        errors = check_no_orphaned_groups(reg)
        assert len(errors) >= 2


# ---------------------------------------------------------------------------
# 15. check_group_coverage
# ---------------------------------------------------------------------------


class TestCheckGroupCoverage:
    def test_all_groups_with_items_passes(self) -> None:
        reg = _valid_registry()
        assert check_group_coverage(reg) == []

    def test_empty_enterprise_group_is_allowed(self) -> None:
        # Enterprise is reserved — no item required
        assert "Enterprise" in RESERVED_GROUPS
        items = [i for i in _minimal_console_items() if i.get("group") != "Enterprise"]
        reg = _make_registry(console=items, portal=_minimal_portal_items())
        # No error for Enterprise being empty
        errors = check_group_coverage(reg)
        assert not any("Enterprise" in e for e in errors)

    @pytest.mark.parametrize(
        "empty_group",
        sorted(group for group in REQUIRED_GROUPS if group not in RESERVED_GROUPS),
    )
    def test_empty_non_reserved_group_fails(self, empty_group: str) -> None:
        # Build registry with all groups represented except the one we're testing
        console_items = [
            i for i in _minimal_console_items() if i.get("group") != empty_group
        ]
        portal_items = [
            i for i in _minimal_portal_items() if i.get("group") != empty_group
        ]
        reg = _make_registry(console=console_items, portal=portal_items)
        errors = check_group_coverage(reg)
        assert any(empty_group in e for e in errors), (
            f"expected error for empty group {empty_group!r}, got: {errors}"
        )

    def test_empty_all_lists_fails_for_non_reserved_groups(self) -> None:
        reg = _make_registry(console=[], portal=[])
        errors = check_group_coverage(reg)
        non_reserved = REQUIRED_GROUPS - RESERVED_GROUPS
        for group in non_reserved:
            assert any(group in e for e in errors), f"expected error for {group}"

    def test_reserved_groups_never_fail(self) -> None:
        reg = _make_registry(console=[], portal=[])
        errors = check_group_coverage(reg)
        for group in RESERVED_GROUPS:
            assert not any(group in e for e in errors), (
                f"reserved group {group} should not fail coverage check"
            )


# ---------------------------------------------------------------------------
# 16. run_all_checks
# ---------------------------------------------------------------------------


class TestRunAllChecks:
    def test_valid_registry_returns_empty(self) -> None:
        reg = _valid_registry()
        assert run_all_checks(reg) == []

    def test_returns_list_type(self) -> None:
        reg = _valid_registry()
        assert isinstance(run_all_checks(reg), list)

    def test_empty_registry_collects_multiple_errors(self) -> None:
        reg: dict = {"console": [], "portal": [], "groups": []}
        errors = run_all_checks(reg)
        assert len(errors) > 1

    def test_missing_group_produces_error(self) -> None:
        groups = [g for g in _all_group_defs() if g["id"] != "Trust"]
        reg = _make_registry(groups=groups)
        errors = run_all_checks(reg)
        assert any("Trust" in e for e in errors)

    def test_duplicate_id_produces_error(self) -> None:
        console = _minimal_console_items()
        # Inject a duplicate
        dup = dict(console[0])
        dup["route"] = "/extra-dup-route"
        console.append(dup)
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("duplicate" in e.lower() for e in errors)

    def test_invalid_tier_produces_error(self) -> None:
        console = _minimal_console_items()
        console[0] = dict(console[0])
        console[0]["tier"] = "bad-tier"
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("tier" in e for e in errors)

    def test_invalid_lifecycle_produces_error(self) -> None:
        console = _minimal_console_items()
        item = dict(console[0])
        item["lifecycle"] = (
            "bad-lifecycle"  # flat field (matches actual registry schema)
        )
        console[0] = item
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("lifecycle" in e for e in errors)

    def test_empty_roles_produces_error(self) -> None:
        console = _minimal_console_items()
        item = dict(console[0])
        item["roles"] = []
        console[0] = item
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("roles" in e for e in errors)

    def test_missing_mcim_id_produces_error(self) -> None:
        console = _minimal_console_items()
        item = dict(console[0])
        item["mcim_id"] = ""  # flat field set to empty (matches actual registry schema)
        console[0] = item
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("mcim" in e.lower() for e in errors)

    def test_multiple_errors_all_collected(self) -> None:
        # Force several different check failures at once
        groups = [g for g in _all_group_defs() if g["id"] != "Trust"]
        console = [_item(item_id="bad", route="/dashboard", tier="INVALID", roles=[])]
        reg = _make_registry(console=console, portal=[], groups=groups)
        errors = run_all_checks(reg)
        assert len(errors) >= 3

    def test_portal_wrong_group_produces_error(self) -> None:
        portal = [_portal_item(item_id="p", route="/", group="Operations")]
        reg = _make_registry(portal=portal)
        errors = run_all_checks(reg)
        assert any("portal" in e.lower() or "Portal" in e for e in errors)

    def test_missing_required_console_route_produces_error(self) -> None:
        console = [i for i in _minimal_console_items() if i["route"] != "/dashboard"]
        reg = _make_registry(console=console)
        errors = run_all_checks(reg)
        assert any("/dashboard" in e for e in errors)

    def test_missing_required_portal_route_produces_error(self) -> None:
        portal = [i for i in _minimal_portal_items() if i["route"] != "/"]
        reg = _make_registry(portal=portal)
        errors = run_all_checks(reg)
        assert any("/" in e for e in errors)


# ---------------------------------------------------------------------------
# 17. Integration — actual registry file
# ---------------------------------------------------------------------------


class TestIntegration:
    @pytest.mark.slow
    def test_actual_registry_passes_all_checks(self) -> None:
        reg_path = REPO / "packages/navigation/navigation-registry.json"
        if not reg_path.is_file():
            pytest.skip("navigation-registry.json not yet created")
        registry = load_registry(REPO)
        errors = run_all_checks(registry)
        assert errors == [], "\n".join(errors)

    @pytest.mark.slow
    def test_actual_registry_is_valid_json(self) -> None:
        reg_path = REPO / "packages/navigation/navigation-registry.json"
        if not reg_path.is_file():
            pytest.skip("navigation-registry.json not yet created")
        content = reg_path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, dict)

    @pytest.mark.slow
    def test_actual_registry_has_console_and_portal_keys(self) -> None:
        reg_path = REPO / "packages/navigation/navigation-registry.json"
        if not reg_path.is_file():
            pytest.skip("navigation-registry.json not yet created")
        data = json.loads(reg_path.read_text(encoding="utf-8"))
        assert "console" in data
        assert "portal" in data

    @pytest.mark.slow
    def test_actual_registry_has_groups_key(self) -> None:
        reg_path = REPO / "packages/navigation/navigation-registry.json"
        if not reg_path.is_file():
            pytest.skip("navigation-registry.json not yet created")
        data = json.loads(reg_path.read_text(encoding="utf-8"))
        assert "groups" in data


# ---------------------------------------------------------------------------
# 18. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_console_list_no_crash(self) -> None:
        reg = _make_registry(console=[], portal=_minimal_portal_items())
        # check_no_duplicate_ids and routes should not crash on empty lists
        assert isinstance(check_no_duplicate_ids(reg), list)
        assert isinstance(check_no_duplicate_routes(reg), list)

    def test_empty_portal_list_no_crash(self) -> None:
        reg = _make_registry(console=_minimal_console_items(), portal=[])
        assert isinstance(check_no_duplicate_ids(reg), list)
        assert isinstance(check_no_duplicate_routes(reg), list)

    def test_single_console_item_no_crash(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="only", route="/dashboard")], portal=[]
        )
        assert isinstance(run_all_checks(reg), list)

    def test_single_portal_item_no_crash(self) -> None:
        reg = _make_registry(
            console=[], portal=[_portal_item(item_id="only", route="/")]
        )
        assert isinstance(run_all_checks(reg), list)

    def test_console_key_missing_treated_as_empty(self) -> None:
        reg: dict = {"portal": [], "groups": _all_group_defs()}
        # Should not KeyError, should not crash
        errors = run_all_checks(reg)
        assert isinstance(errors, list)

    def test_portal_key_missing_treated_as_empty(self) -> None:
        reg: dict = {"console": [], "groups": _all_group_defs()}
        errors = run_all_checks(reg)
        assert isinstance(errors, list)

    def test_item_with_all_optional_fields_passes(self) -> None:
        item = dict(_item(item_id="full", route="/dashboard"))
        item["icon"] = "dashboard-icon"
        item["breadcrumbParent"] = "root"
        item["featureFlag"] = "FEATURE_X"
        item["visibility"] = "visible"
        item["classification"] = "primary"
        item["aliases"] = ["/dash"]
        item["keywords"] = ["dash", "home"]
        reg = _make_registry(console=[item], portal=[])
        # Should not crash
        errors = check_valid_tiers(reg)
        assert isinstance(errors, list)

    def test_item_with_non_string_id_does_not_crash(self) -> None:
        item = _item(item_id="ok", route="/dashboard")
        item["id"] = 12345  # int id, unusual
        reg = _make_registry(console=[item], portal=[])
        assert isinstance(check_no_duplicate_ids(reg), list)

    def test_registry_with_none_groups_does_not_crash(self) -> None:
        reg: dict = {"console": [], "portal": [], "groups": None}
        assert isinstance(check_required_groups(reg), list)

    def test_very_large_roles_list_does_not_crash(self) -> None:
        roles = list(VALID_ROLES)
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=roles)],
            portal=[],
        )
        assert check_valid_roles(reg) == []

    def test_item_with_platform_both_passes_platform_check(self) -> None:
        item = _item(
            item_id="b", route="/dashboard", platform="both", group="Administration"
        )
        reg = _make_registry(console=[item], portal=[])
        assert check_valid_platforms(reg) == []


# ---------------------------------------------------------------------------
# 19. Stats validation
# ---------------------------------------------------------------------------


class TestStatsValidation:
    def test_stats_console_total_matching_length_passes_run_all(self) -> None:
        console = _minimal_console_items()
        portal = _minimal_portal_items()
        stats = {
            "console_total": len(console),
            "portal_total": len(portal),
            "total": len(console) + len(portal),
        }
        reg = _make_registry(console=console, portal=portal, stats=stats)
        assert run_all_checks(reg) == []

    def test_registry_without_stats_still_passes(self) -> None:
        reg = _valid_registry()
        assert "stats" not in reg or reg.get("stats") is None
        assert run_all_checks(reg) == []

    def test_stats_field_ignored_by_checks(self) -> None:
        # Even if stats are wrong, the validation checks don't fail on stats alone
        reg = _valid_registry()
        reg["stats"] = {"console_total": 9999, "portal_total": 9999}
        errors = run_all_checks(reg)
        assert errors == []


# ---------------------------------------------------------------------------
# 20. Groups array validation
# ---------------------------------------------------------------------------


class TestGroupsArrayValidation:
    def test_exactly_eight_groups_in_all_group_defs(self) -> None:
        groups = _all_group_defs()
        assert len(groups) == 8

    def test_required_groups_set_has_exactly_eight(self) -> None:
        assert len(REQUIRED_GROUPS) == 8

    def test_all_eight_groups_present_no_check_error(self) -> None:
        reg = _make_registry(groups=_all_group_defs())
        assert check_required_groups(reg) == []

    def test_seven_groups_fails_once(self) -> None:
        groups = _all_group_defs()[:-1]
        assert len(groups) == 7
        reg = _make_registry(groups=groups)
        errors = check_required_groups(reg)
        assert len(errors) == 1

    def test_zero_groups_fails_eight_times(self) -> None:
        reg = _make_registry(groups=[])
        errors = check_required_groups(reg)
        assert len(errors) == 8

    def test_duplicate_groups_not_double_counted_in_found(self) -> None:
        # Duplicate group entries — each unique id should still be found
        groups = _all_group_defs() + [_group_def("Operations")]
        reg = _make_registry(groups=groups)
        assert check_required_groups(reg) == []

    def test_group_ids_match_required_groups_exactly(self) -> None:
        group_ids = {g["id"] for g in _all_group_defs()}
        assert group_ids == REQUIRED_GROUPS

    def test_portal_group_in_required_groups(self) -> None:
        assert "Portal" in REQUIRED_GROUPS

    def test_enterprise_group_in_required_groups(self) -> None:
        assert "Enterprise" in REQUIRED_GROUPS

    def test_enterprise_in_reserved_groups(self) -> None:
        assert "Enterprise" in RESERVED_GROUPS

    def test_portal_not_in_reserved_groups(self) -> None:
        assert "Portal" not in RESERVED_GROUPS


# ---------------------------------------------------------------------------
# 21. Constants consistency tests
# ---------------------------------------------------------------------------


class TestConstants:
    def test_console_required_routes_non_empty(self) -> None:
        assert len(CONSOLE_REQUIRED_ROUTES) > 0

    def test_portal_required_routes_non_empty(self) -> None:
        assert len(PORTAL_REQUIRED_ROUTES) > 0

    def test_valid_tiers_non_empty(self) -> None:
        assert len(VALID_TIERS) > 0

    def test_valid_lifecycles_non_empty(self) -> None:
        assert len(VALID_LIFECYCLES) > 0

    def test_valid_platforms_exactly_three(self) -> None:
        assert VALID_PLATFORMS == {"console", "portal", "both"}

    def test_valid_roles_non_empty(self) -> None:
        assert len(VALID_ROLES) > 0

    def test_legacy_tier_routes_contains_assessment(self) -> None:
        assert "/assessment" in LEGACY_TIER_ROUTES

    def test_legacy_tier_routes_contains_onboarding(self) -> None:
        assert "/onboarding" in LEGACY_TIER_ROUTES

    @pytest.mark.parametrize("route", sorted(CONSOLE_REQUIRED_ROUTES))
    def test_each_console_required_route_starts_with_slash(self, route: str) -> None:
        assert route.startswith("/")

    @pytest.mark.parametrize("route", sorted(PORTAL_REQUIRED_ROUTES))
    def test_each_portal_required_route_starts_with_slash(self, route: str) -> None:
        assert route.startswith("/")

    @pytest.mark.parametrize("tier", sorted(VALID_TIERS))
    def test_each_valid_tier_is_lowercase_string(self, tier: str) -> None:
        assert tier == tier.lower()
        assert isinstance(tier, str)

    @pytest.mark.parametrize("lc", sorted(VALID_LIFECYCLES))
    def test_each_valid_lifecycle_is_lowercase_string(self, lc: str) -> None:
        assert lc == lc.lower()
        assert isinstance(lc, str)

    @pytest.mark.parametrize("role", sorted(VALID_ROLES))
    def test_each_valid_role_is_non_empty_string(self, role: str) -> None:
        assert isinstance(role, str)
        assert role.strip() != ""

    def test_dashboard_in_console_required_routes(self) -> None:
        assert "/dashboard" in CONSOLE_REQUIRED_ROUTES

    def test_portal_home_in_portal_required_routes(self) -> None:
        assert "/" in PORTAL_REQUIRED_ROUTES

    def test_assessment_in_console_required_routes(self) -> None:
        assert "/assessment" in CONSOLE_REQUIRED_ROUTES

    def test_admin_tenants_in_console_required_routes(self) -> None:
        assert "/admin/tenants" in CONSOLE_REQUIRED_ROUTES

    def test_console_required_routes_count(self) -> None:
        # 17 required console routes as spec'd
        assert len(CONSOLE_REQUIRED_ROUTES) == 17

    def test_portal_required_routes_count(self) -> None:
        # 9 required portal routes as spec'd
        assert len(PORTAL_REQUIRED_ROUTES) == 9


# ---------------------------------------------------------------------------
# 22. check_valid_roles — parametrized boundary coverage
# ---------------------------------------------------------------------------


class TestRolesBoundary:
    @pytest.mark.parametrize("role", sorted(VALID_ROLES))
    def test_single_valid_role_passes(self, role: str) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=[role])],
            portal=[],
        )
        assert check_valid_roles(reg) == []

    @pytest.mark.parametrize("role", sorted(VALID_ROLES))
    def test_valid_role_in_portal_passes(self, role: str) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="p", route="/", roles=[role])],
            console=[],
        )
        assert check_valid_roles(reg) == []

    def test_roles_with_whitespace_variant_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=[" Operator"])],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert len(errors) >= 1

    def test_lowercase_role_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="r", route="/dashboard", roles=["operator"])],
            portal=[],
        )
        errors = check_valid_roles(reg)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# 23. check_valid_tiers — parametrized boundary coverage
# ---------------------------------------------------------------------------


class TestTiersBoundary:
    @pytest.mark.parametrize("tier", sorted(VALID_TIERS))
    def test_each_valid_tier_in_portal_also_passes(self, tier: str) -> None:
        reg = _make_registry(
            portal=[_portal_item(item_id="t", route="/", tier=tier)],
            console=[],
        )
        assert check_valid_tiers(reg) == []

    def test_tier_with_capital_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="t", route="/dashboard", tier="Primary")],
            portal=[],
        )
        errors = check_valid_tiers(reg)
        assert len(errors) >= 1

    def test_tier_with_trailing_space_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="t", route="/dashboard", tier="primary ")],
            portal=[],
        )
        errors = check_valid_tiers(reg)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# 24. check_valid_platforms — boundary
# ---------------------------------------------------------------------------


class TestPlatformsBoundary:
    def test_platform_uppercase_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="p", route="/dashboard", platform="Console")],
            portal=[],
        )
        errors = check_valid_platforms(reg)
        assert len(errors) >= 1

    def test_platform_mixed_case_fails(self) -> None:
        reg = _make_registry(
            console=[_item(item_id="p", route="/dashboard", platform="Both")],
            portal=[],
        )
        errors = check_valid_platforms(reg)
        assert len(errors) >= 1

    def test_all_three_platforms_valid_in_single_registry(self) -> None:
        items = [
            _item(
                item_id="c", route="/dashboard", platform="console", group="Operations"
            ),
            _item(
                item_id="b",
                route="/dashboard/readiness",
                platform="both",
                group="Operations",
            ),
        ]
        portal = [_portal_item(item_id="p", route="/", platform="portal")]
        reg = _make_registry(console=items, portal=portal)
        assert check_valid_platforms(reg) == []
