from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.testing.policy.check_policy_drift import enforce_policy_drift


def test_policy_change_requires_justification_and_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tools/testing/policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tools/testing/policy/runtime_baselines.yaml").write_text(
        "lanes: {}\n", encoding="utf-8"
    )

    import subprocess

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="tools/testing/policy/runtime_baselines.yaml\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"pull_request": {"body": "nope", "labels": []}}), encoding="utf-8"
    )
    with pytest.raises(SystemExit):
        enforce_policy_drift("main", event, allow_flag=False)


def test_policy_change_allowed_with_justification_and_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    import subprocess

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="tools/testing/policy/runtime_baselines.yaml\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "pull_request": {
                    "body": "## Policy Change Justification\nApproved.",
                    "labels": [{"name": "policy-change-approved"}],
                }
            }
        ),
        encoding="utf-8",
    )
    changed, files = enforce_policy_drift("main", event, allow_flag=False)
    assert changed is True
    assert "tools/testing/policy/runtime_baselines.yaml" in files
