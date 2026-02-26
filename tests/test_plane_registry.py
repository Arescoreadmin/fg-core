from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from services.plane_registry import PLANE_REGISTRY


EXPECTED_PLANES = {
    "control",
    "data",
    "agent",
    "ai",
    "connector",
    "evidence",
    "ui",
    "security",
}

FORBIDDEN_LEGACY_DISABLED = (
    "/_legacy/ui_legacy/_disabled",
    "/_legacy/ui_feed/_disabled",
)


def test_plane_registry_has_required_fields() -> None:
    assert {p.plane_id for p in PLANE_REGISTRY} == EXPECTED_PLANES
    for plane in PLANE_REGISTRY:
        assert plane.route_prefixes
        assert plane.allowed_dependency_categories
        assert plane.required_make_targets
        assert plane.required_ci_gates


def test_plane_registry_checker_passes() -> None:
    proc = subprocess.run(
        [sys.executable, "tools/ci/check_plane_registry.py"],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": "."},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_route_inventory_excludes_legacy_disabled_ui_routes() -> None:
    inventory_doc = json.loads(Path("tools/ci/route_inventory.json").read_text())
    inventory = (
        inventory_doc.get("routes", []) if isinstance(inventory_doc, dict) else []
    )
    inventory_paths = {route["path"] for route in inventory}
    assert set(FORBIDDEN_LEGACY_DISABLED).isdisjoint(inventory_paths)

    offenders: list[str] = []
    for api_file in Path("api").rglob("*.py"):
        source = api_file.read_text()
        for forbidden_path in FORBIDDEN_LEGACY_DISABLED:
            if forbidden_path in source:
                offenders.append(f"{api_file}:{forbidden_path}")

    assert not offenders, (
        f"found forbidden legacy disabled route strings in source: {offenders}"
    )
