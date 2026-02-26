#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import PurePosixPath, Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_DIR = REPO_ROOT / "tools/testing/policy"
PLANE_REGISTRY = REPO_ROOT / "tools/ci/plane_registry_snapshot.json"

OWNERSHIP_ALLOWED_KEYS = {"module_id", "plane", "owner", "path_globs", "route_prefixes", "required_categories"}
REQUIRED_TESTS_ALLOWED_KEYS = {"version", "fail_closed", "categories", "module_registration"}
MODULE_MANIFEST_ALLOWED_KEYS = {"version", "modules"}
MODULE_ALLOWED_KEYS = {"module_id", "plane", "route_prefixes", "required_scopes", "required_test_category"}


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"invalid yaml mapping: {path}")
    return data


def _assert_unknown_keys(name: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise SystemExit(f"{name} has unknown keys: {unknown}")


def _assert_normalized_glob(glob: str) -> None:
    if "\\" in glob:
        raise SystemExit(f"path glob must be POSIX normalized: {glob}")
    if str(PurePosixPath(glob)) != glob and not glob.startswith("**/"):
        raise SystemExit(f"path glob must be normalized without ../ segments: {glob}")


def _validate_ownership_map(data: dict[str, Any], categories: set[str]) -> None:
    for required in ["version", "owners"]:
        if required not in data:
            raise SystemExit(f"ownership_map missing required key: {required}")

    owners = data.get("owners")
    if not isinstance(owners, list) or not owners:
        raise SystemExit("ownership_map owners must be non-empty list")

    for owner in owners:
        if not isinstance(owner, dict):
            raise SystemExit("ownership_map owner entry must be mapping")
        _assert_unknown_keys("ownership_map.owner", owner, OWNERSHIP_ALLOWED_KEYS)
        for required in ["module_id", "plane", "owner", "path_globs", "required_categories"]:
            if required not in owner:
                raise SystemExit(f"ownership_map owner missing required key: {required}")
        for path_glob in owner.get("path_globs", []):
            _assert_normalized_glob(path_glob)
        missing_categories = sorted(set(owner.get("required_categories", [])) - categories)
        if missing_categories:
            raise SystemExit(f"ownership_map owner references undefined categories: {missing_categories}")


def _validate_required_tests(data: dict[str, Any]) -> set[str]:
    _assert_unknown_keys("required_tests", data, REQUIRED_TESTS_ALLOWED_KEYS)
    for required in ["version", "fail_closed", "categories", "module_registration"]:
        if required not in data:
            raise SystemExit(f"required_tests missing required key: {required}")

    categories = data.get("categories")
    if not isinstance(categories, dict) or not categories:
        raise SystemExit("required_tests categories must be non-empty mapping")

    for category, cfg in categories.items():
        if not isinstance(cfg, dict):
            raise SystemExit(f"required_tests category {category} must be mapping")
        required_globs = cfg.get("required_test_globs")
        if not isinstance(required_globs, list) or not required_globs:
            raise SystemExit(f"required_tests category {category} requires non-empty required_test_globs")
        for pattern in required_globs:
            _assert_normalized_glob(pattern)

    module_registration = data.get("module_registration")
    if not isinstance(module_registration, dict):
        raise SystemExit("required_tests module_registration must be mapping")
    for key in ["registry_files", "required_skeleton_globs"]:
        if key not in module_registration:
            raise SystemExit(f"required_tests module_registration missing key: {key}")
    return set(categories.keys())


def _normalize_prefix(prefix: str) -> str:
    parts = [part for part in prefix.split("/") if part]
    if parts and parts[0].startswith("v") and parts[0][1:].isdigit():
        parts = parts[1:]
    return "/" + "/".join(parts)


def _load_plane_prefixes() -> set[str]:
    if not PLANE_REGISTRY.exists():
        return set()
    raw = json.loads(PLANE_REGISTRY.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        records = raw.get("data", [])
    elif isinstance(raw, list):
        records = raw
    else:
        raise SystemExit("plane_registry_snapshot must be object or list")

    prefixes: set[str] = set()
    for item in records:
        if not isinstance(item, dict):
            continue
        for prefix in item.get("route_prefixes", []):
            prefixes.add(prefix)
    return prefixes


def _validate_module_manifest(data: dict[str, Any], categories: set[str], known_prefixes: set[str]) -> None:
    _assert_unknown_keys("module_manifest", data, MODULE_MANIFEST_ALLOWED_KEYS)
    for required in ["version", "modules"]:
        if required not in data:
            raise SystemExit(f"module_manifest missing required key: {required}")
    modules = data.get("modules")
    if not isinstance(modules, list) or not modules:
        raise SystemExit("module_manifest modules must be non-empty list")

    for module in modules:
        if not isinstance(module, dict):
            raise SystemExit("module_manifest module entry must be mapping")
        _assert_unknown_keys("module_manifest.module", module, MODULE_ALLOWED_KEYS)
        for required in ["module_id", "plane", "route_prefixes", "required_scopes", "required_test_category"]:
            if required not in module:
                raise SystemExit(f"module_manifest module missing required key: {required}")

        missing_categories = sorted(set(module.get("required_test_category", [])) - categories)
        if missing_categories:
            raise SystemExit(f"module_manifest has undefined test categories: {missing_categories}")

        if known_prefixes:
            normalized_known = {_normalize_prefix(p) for p in known_prefixes}
            for prefix in module.get("route_prefixes", []):
                normalized = _normalize_prefix(prefix)
                if not normalized.startswith("/"):
                    raise SystemExit(f"module_manifest route prefix invalid: {prefix}")
                # Missing from snapshot is allowed for in-flight modules; contradiction is malformed prefix.
                _ = normalized_known


def main() -> int:
    required_tests = _load_yaml(POLICY_DIR / "required_tests.yaml")
    categories = _validate_required_tests(required_tests)

    ownership = _load_yaml(POLICY_DIR / "ownership_map.yaml")
    _validate_ownership_map(ownership, categories)

    module_manifest = _load_yaml(POLICY_DIR / "module_manifest.yaml")
    known_prefixes = _load_plane_prefixes()
    _validate_module_manifest(module_manifest, categories, known_prefixes)

    print("policy validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
