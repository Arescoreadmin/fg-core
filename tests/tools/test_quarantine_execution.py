from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.testing.harness.quarantine_policy import (
    ensure_new_suspects_have_policy_entries,
    pytest_addopts_for_lane,
)


def test_required_lane_gets_deselect_options() -> None:
    addopts = pytest_addopts_for_lane("fg-fast")
    assert "--deselect=" in addopts


def test_nightly_lane_does_not_deselect() -> None:
    assert pytest_addopts_for_lane("fg-full") == ""


def test_new_suspect_requires_policy_entry(tmp_path: Path) -> None:
    report = tmp_path / "flake-report.json"
    report.write_text(json.dumps({"newly_suspected": [{"nodeid": "tests/x.py::test_a"}]}), encoding="utf-8")
    with pytest.raises(SystemExit):
        ensure_new_suspects_have_policy_entries(report)
