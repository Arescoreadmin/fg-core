from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.ci import check_timeout_hierarchy
from tools.testing import affected_plane_selector
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
    assert report["category"] == "CONTRACT_DRIFT"


def test_triage_bucketing_rls_missing() -> None:
    report = triage_report._classify(["RLS policy missing for table x"])
    assert report["category"] == "RLS_MISSING_OR_WEAK"


def test_policy_validation_unknown_key_fails(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nunknown: true\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        validate_policy._assert_unknown_keys(
            "policy", {"version": 1, "unknown": True}, {"version"}
        )


def test_fg_security_lane_has_explicit_timeout() -> None:
    # make fg-security takes ~21 min; the default COMMAND_TIMEOUT_SECONDS=300
    # would silently kill it after 5 min. Assert an explicit timeout is set.
    fg_sec = lane_runner.ALLOWED_LANES["fg-security"]
    make_cmd = next(
        (c for c in fg_sec if c.argv == ("make", "fg-security")),
        None,
    )
    assert make_cmd is not None, "fg-security lane missing make fg-security command"
    assert make_cmd.timeout_seconds > lane_runner.COMMAND_TIMEOUT_SECONDS, (
        f"make fg-security uses default timeout {lane_runner.COMMAND_TIMEOUT_SECONDS}s "
        f"which is too short for a ~21-min command; set an explicit timeout_seconds"
    )


def test_timeout_hierarchy_validator_passes() -> None:
    # Smoke-test the hierarchy validator end-to-end against the live repo.
    rc = check_timeout_hierarchy.main()
    assert rc == 0, (
        "CI timeout hierarchy has a violation — run check_timeout_hierarchy.py for details"
    )


def test_affected_plane_selector_identity_plane_files() -> None:
    result = affected_plane_selector.select(
        ["api/identity_administration/routes/admin.py"]
    )
    assert result["fallback"] is False
    affected_planes = result["affected_planes"]
    assert isinstance(affected_planes, list)
    assert "identity" in affected_planes


def test_affected_plane_selector_high_risk_falls_back() -> None:
    result = affected_plane_selector.select([".github/workflows/ci.yml"])
    assert result["fallback"] is True
    assert result["high_risk"] is True


def test_affected_plane_selector_empty_files_falls_back() -> None:
    result = affected_plane_selector.select([])
    assert result["fallback"] is True
