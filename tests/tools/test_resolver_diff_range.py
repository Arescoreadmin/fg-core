from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tools.testing.harness.required_tests_gate import (
    ChangedFile,
    _changed_files,
    _parse_name_status,
    _resolve_diff_range,
)


def _mock_git(rules: list[tuple[str, int, str, str]]):
    """Returns a fake _run_git where first matching rule (by substring) wins."""

    def _fake(args):
        cmd = " ".join(str(a) for a in args)
        for substr, rc, out, err in rules:
            if substr in cmd:
                return mock.Mock(returncode=rc, stdout=out, stderr=err)
        return mock.Mock(returncode=0, stdout="", stderr="")

    return _fake


# ---------------------------------------------------------------------------
# Strategy A tests
# ---------------------------------------------------------------------------


def test_event_shas_both_present() -> None:
    base_sha = "aabbccdd1122" * 3  # 36 chars (long enough for slicing)
    head_sha = "11223344aabb" * 3
    rules = [
        ("cat-file", 0, "", ""),
        # merge-base verification required by Strategy A
        ("merge-base", 0, "mergebase0000\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, base_sha, head_sha)

    assert base == base_sha
    assert head == head_sha
    assert any("A" in d for d in diags)


def test_event_base_sha_missing_fetch_succeeds() -> None:
    base_sha = "deadbeef1234" * 3
    head_sha = "cafecafe5678" * 3

    # Stateful: first cat-file for base returns 1, second returns 0
    cat_file_calls: list[int] = []

    def stateful_run(args):
        cmd = " ".join(str(a) for a in args)
        if "cat-file" in cmd and base_sha[:12] in cmd:
            cat_file_calls.append(1)
            rc = 1 if len(cat_file_calls) == 1 else 0
            return mock.Mock(returncode=rc, stdout="", stderr="")
        if "cat-file" in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")
        if "fetch" in cmd and base_sha[:12] in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")
        if "merge-base" in cmd:
            return mock.Mock(returncode=0, stdout="verifiedbase\n", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=stateful_run,
    ):
        base, head, diags = _resolve_diff_range(None, base_sha, head_sha)

    assert base == base_sha
    assert head == head_sha


def test_event_head_sha_missing_fetch_succeeds() -> None:
    base_sha = "feedface1234" * 3
    head_sha = "babe00001234" * 3

    cat_file_calls: list[int] = []

    def stateful_run(args):
        cmd = " ".join(str(a) for a in args)
        if "cat-file" in cmd and head_sha[:12] in cmd:
            cat_file_calls.append(1)
            rc = 1 if len(cat_file_calls) == 1 else 0
            return mock.Mock(returncode=rc, stdout="", stderr="")
        if "cat-file" in cmd and base_sha[:12] in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")
        if "fetch" in cmd and head_sha[:12] in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")
        if "merge-base" in cmd:
            return mock.Mock(returncode=0, stdout="verifiedbase\n", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=stateful_run,
    ):
        base, head, diags = _resolve_diff_range(None, base_sha, head_sha)

    assert base == base_sha
    assert head == head_sha


def test_event_shas_present_but_no_merge_base_falls_back() -> None:
    """Objects both locally present but no common ancestor → fall through to C/D."""
    base_sha = "abcdef001234" * 3
    head_sha = "fedcba005678" * 3
    rules = [
        ("cat-file", 0, "", ""),
        # Strategy A merge-base check: no common ancestor (shallow PR head)
        (f"merge-base {base_sha[:12]}", 128, "", "fatal: no merge base"),
        # Strategy C: origin/main present, merge-base via HEAD succeeds
        ("merge-base origin/main HEAD", 0, "realmergebase\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, base_sha, head_sha)

    assert base == "realmergebase"
    assert head == "HEAD"
    assert any("no common ancestor" in d for d in diags)
    assert any("C" in d for d in diags)


def test_event_shas_fetch_fails_falls_back() -> None:
    base_sha = "baad00001234" * 3
    head_sha = "good11112345" * 3

    rules = [
        # cat-file for base_sha → always missing
        (base_sha[:12], 1, "", ""),
        # fetch for base_sha → fails
        (f"fetch --no-tags --depth=1 origin {base_sha}", 1, "", ""),
        # head_sha is always present
        (head_sha[:12], 0, "", ""),
        # Strategy C: origin/main present, merge-base fails
        ("cat-file -e origin/main", 0, "", ""),
        ("merge-base origin/main HEAD", 1, "", ""),
        # Strategy D: local main succeeds
        ("merge-base main HEAD", 0, "deadbeef\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, base_sha, head_sha)

    assert base == "deadbeef"
    assert head == "HEAD"


# ---------------------------------------------------------------------------
# Strategy B test
# ---------------------------------------------------------------------------


def test_explicit_base_ref() -> None:
    rules = [
        # Strategy B: fetch and merge-base succeed
        ("fetch --no-tags --depth=200 origin main", 0, "", ""),
        ("merge-base origin/main HEAD", 0, "cafebabe\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range("main", None, None)

    assert base == "cafebabe"
    assert head == "HEAD"
    assert any("B" in d for d in diags)


# ---------------------------------------------------------------------------
# Strategy C test
# ---------------------------------------------------------------------------


def test_origin_main_fallback() -> None:
    rules = [
        # origin/main is present
        ("cat-file -e origin/main", 0, "", ""),
        # merge-base origin/main succeeds
        ("merge-base origin/main HEAD", 0, "aabbcc00\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, None, None)

    assert base == "aabbcc00"
    assert head == "HEAD"
    assert any("C" in d for d in diags)


# ---------------------------------------------------------------------------
# Strategy D test
# ---------------------------------------------------------------------------


def test_local_main_fallback() -> None:
    rules = [
        # origin/main present but merge-base fails
        ("cat-file -e origin/main", 0, "", ""),
        ("merge-base origin/main HEAD", 1, "", ""),
        # local main merge-base succeeds
        ("merge-base main HEAD", 0, "11223344\n", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, None, None)

    assert base == "11223344"
    assert head == "HEAD"
    assert any("D" in d for d in diags)


# ---------------------------------------------------------------------------
# Strategy E test
# ---------------------------------------------------------------------------


def test_head_parent_fallback() -> None:
    rules = [
        # origin/main present, merge-base fails
        ("cat-file -e origin/main", 0, "", ""),
        ("merge-base origin/main HEAD", 1, "", ""),
        # local main merge-base fails
        ("merge-base main HEAD", 1, "", ""),
        # HEAD~1 exists
        ("cat-file -e HEAD~1", 0, "", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        base, head, diags = _resolve_diff_range(None, None, None)

    assert base == "HEAD~1"
    assert head == "HEAD"
    assert any("E" in d for d in diags)


# ---------------------------------------------------------------------------
# Strategy F test
# ---------------------------------------------------------------------------


def test_all_strategies_exhausted_raises() -> None:
    rules = [
        # origin/main present, merge-base fails
        ("cat-file -e origin/main", 0, "", ""),
        ("merge-base origin/main HEAD", 1, "", ""),
        # local main merge-base fails
        ("merge-base main HEAD", 1, "", ""),
        # HEAD~1 not present
        ("cat-file -e HEAD~1", 1, "", ""),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        with pytest.raises(SystemExit) as exc_info:
            _resolve_diff_range(None, None, None)

    msg = str(exc_info.value)
    assert "fail-closed" in msg
    assert "next:" in msg


# ---------------------------------------------------------------------------
# git diff failure test
# ---------------------------------------------------------------------------


def test_git_diff_failure_includes_diagnostics() -> None:
    rules = [
        # Strategy C: origin/main present, merge-base returns a sha
        ("cat-file -e origin/main", 0, "", ""),
        ("merge-base origin/main HEAD", 0, "aabbccdd\n", ""),
        # git diff fails
        ("diff --name-status", 128, "", "fatal: bad object"),
    ]
    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=_mock_git(rules),
    ):
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": ""}, clear=False):
            with pytest.raises(SystemExit) as exc_info:
                _changed_files(None)

    msg = str(exc_info.value)
    assert "aabbccdd" in msg
    assert "HEAD" in msg
    assert "fatal: bad object" in msg
    assert "resolution" in msg


# ---------------------------------------------------------------------------
# Regression: nested invocation event-path fallback
# ---------------------------------------------------------------------------


def test_nested_invocation_event_path_fallback(tmp_path: Path) -> None:
    fake_base_sha = "badfeed000000000000000000000000000000000"
    fake_head_sha = "cafecafe000000000000000000000000000000000"

    event = {
        "pull_request": {
            "base": {"sha": fake_base_sha},
            "head": {"sha": fake_head_sha},
        }
    }
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event))

    def stateful_run(args):
        cmd = " ".join(str(a) for a in args)

        # cat-file for base_sha: always fails (not in local checkout)
        if "cat-file" in cmd and fake_base_sha[:12] in cmd:
            return mock.Mock(returncode=1, stdout="", stderr="")

        # fetch for base_sha: fails (can't fetch arbitrary SHA)
        if "fetch" in cmd and fake_base_sha[:12] in cmd:
            return mock.Mock(returncode=128, stdout="", stderr="")

        # cat-file for head_sha: present
        if "cat-file" in cmd and fake_head_sha[:12] in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")

        # Strategy C: origin/main present
        if "cat-file" in cmd and "origin/main" in cmd:
            return mock.Mock(returncode=0, stdout="", stderr="")

        # Strategy C: merge-base succeeds
        if "merge-base origin/main HEAD" in cmd:
            return mock.Mock(returncode=0, stdout="feedcafe\n", stderr="")

        # git diff: success with some content
        if "diff --name-status" in cmd:
            return mock.Mock(returncode=0, stdout="M\tsome/file.py\n", stderr="")

        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch(
        "tools.testing.harness.required_tests_gate._run_git",
        side_effect=stateful_run,
    ):
        with mock.patch.dict(
            os.environ,
            {"GITHUB_EVENT_PATH": str(event_file)},
            clear=False,
        ):
            files, diags = _changed_files(None)

    assert files  # non-empty, not SystemExit
    # Strategy A was attempted but rejected
    assert any("A" in d and "rejected" in d for d in diags)
    # Strategy C resolved it
    assert any("C" in d and "resolved" in d for d in diags)


# ---------------------------------------------------------------------------
# Rename parsing unit test
# ---------------------------------------------------------------------------


def test_rename_parsing_unchanged() -> None:
    diff_output = "R100\told.py\tnew.py\n"
    result = _parse_name_status(diff_output)
    assert result == [ChangedFile("R100", "new.py", "old.py")]
