from __future__ import annotations

import os
import subprocess
import sys

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
