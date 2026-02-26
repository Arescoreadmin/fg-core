from __future__ import annotations

from pathlib import Path

import pytest

from tools.testing.harness.runtime_baseline import update_baseline


def test_baseline_update_blocked_off_main(tmp_path: Path) -> None:
    p = tmp_path / "runtime_baselines.yaml"
    p.write_text("lanes: {}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        update_baseline(p, "fg-fast", 123, branch="feature", event="workflow_dispatch")


def test_baseline_update_allowed_on_main_schedule(tmp_path: Path) -> None:
    p = tmp_path / "runtime_baselines.yaml"
    p.write_text("lanes: {}\n", encoding="utf-8")
    update_baseline(p, "fg-fast", 123, branch="main", event="schedule")
    assert "fg-fast: 123" in p.read_text(encoding="utf-8")
