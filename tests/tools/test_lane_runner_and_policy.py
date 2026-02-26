from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.testing.harness import lane_runner, triage_report
from tools.testing.policy import validate_policy


def test_lane_runner_allowlist_rejects_unknown_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.argv", ["lane_runner.py", "--lane", "unknown"])
    with pytest.raises(SystemExit):
        lane_runner.main()


def test_lane_runner_shell_false_and_list_args_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        captured["args"] = args
        captured["shell"] = kwargs.get("shell")
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="ok", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc = lane_runner._run_command(
        lane_runner.CommandSpec(("python", "-V")),
        cwd=tmp_path,
        log_file=tmp_path / "run.log",
    )
    assert rc == 0
    assert captured["shell"] is False
    assert isinstance(captured["args"], list)


def test_triage_bucketing_contract_drift() -> None:
    report = triage_report._classify(["error: openapi contract mismatch"])
    assert report["bucket"] == "contract drift"


def test_triage_bucketing_rls_missing() -> None:
    report = triage_report._classify(["RLS policy missing for table x"])
    assert report["bucket"] == "RLS missing"


def test_policy_validation_unknown_key_fails(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nunknown: true\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        validate_policy._assert_unknown_keys(
            "policy", {"version": 1, "unknown": True}, {"version"}
        )
