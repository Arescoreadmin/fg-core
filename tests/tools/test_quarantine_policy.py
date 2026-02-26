from __future__ import annotations

from pathlib import Path

from tools.testing.harness.flake_detect import _load_quarantine


def test_quarantine_policy_schema_loads() -> None:
    entries = _load_quarantine(Path("tools/testing/policy/flaky_tests.yaml"))
    assert entries
    nodeid, payload = next(iter(entries.items()))
    assert nodeid.startswith("tests/")
    assert payload["sla_days"] > 0
