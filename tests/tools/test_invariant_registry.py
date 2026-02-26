from __future__ import annotations

from pathlib import Path

import pytest

from tools.testing.security.check_invariant_coverage import (
    validate_critical_coverage,
    validate_path_mapping,
    validate_route_prefix_registrations,
)


def test_critical_invariant_without_enforcement_fails() -> None:
    with pytest.raises(SystemExit):
        validate_critical_coverage([{"id": "INV-X", "severity": "critical", "enforced_by": []}])


def test_new_protected_path_requires_mapping() -> None:
    with pytest.raises(SystemExit):
        validate_path_mapping(["migrations/new.sql"], {"security/": ["INV-1"]})


def test_new_api_route_module_requires_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    api_dir = tmp_path / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / "x.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/x')\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        validate_route_prefix_registrations(["api/x.py"], {})
