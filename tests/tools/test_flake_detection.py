from __future__ import annotations

from tools.testing.harness.flake_detect import detect_flakes


def test_detect_flakes_identifies_oscillation() -> None:
    findings = detect_flakes(
        ["tests/a.py::test_x"],
        {"tests/a.py::test_x": ["fail", "pass", "fail"]},
    )
    assert findings and findings[0]["classification"] == "flake-suspected"


def test_detect_flakes_ignores_consistent_failures() -> None:
    findings = detect_flakes(
        ["tests/a.py::test_x"], {"tests/a.py::test_x": ["fail", "fail", "fail"]}
    )
    assert findings == []
