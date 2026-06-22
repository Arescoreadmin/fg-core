"""Tests for tools/ci/check_soc_review_sync.py (SOC-HIGH-002).

Covers:
- shallow repository (fetch succeeds, three-dot diff succeeds)
- missing merge base (falls back to HEAD~1..HEAD)
- missing base branch (fetch fails → fail open → exit 0)
- fallback diff path (three-dot fails, HEAD~1 succeeds)
- critical file detection
- SOC docs present alongside critical files → OK
- SOC docs absent alongside critical files → FAIL
- no GITHUB_BASE_REF → local diff path
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.ci.check_soc_review_sync import (
    SOC_DOCS,
    _changed_files_ci,
    _changed_files_local,
    _is_critical,
    main,
)


# ── helpers ────────────────────────────────────────────────────────────────────


def _cp(returncode: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    """Build a fake CompletedProcess."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ── _is_critical ──────────────────────────────────────────────────────────────


def test_is_critical_workflow():
    assert _is_critical(".github/workflows/ci.yml") is True


def test_is_critical_tools_ci():
    assert _is_critical("tools/ci/check_soc_review_sync.py") is True


def test_is_critical_regular_file():
    assert _is_critical("api/routes.py") is False


def test_is_critical_docs():
    assert _is_critical("docs/SOC_ARCH_REVIEW_2026-02-15.md") is False


# ── _changed_files_ci ─────────────────────────────────────────────────────────


def test_ci_shallow_repo_three_dot_succeeds():
    """Shallow repo: fetch ok, three-dot diff ok → no warning."""
    fetch_ok = _cp(0)
    diff_ok = _cp(0, stdout="api/admin_identity.py\nREADME.md\n")

    with patch(
        "tools.ci.check_soc_review_sync._run_git", side_effect=[fetch_ok, diff_ok]
    ):
        files, warn = _changed_files_ci("main")

    assert warn is None
    assert "api/admin_identity.py" in files
    assert "README.md" in files


def test_ci_fetch_fails_fail_open():
    """fetch fails → warn, empty file list (fail open)."""
    fetch_fail = _cp(1, stderr="could not read from remote")

    with patch("tools.ci.check_soc_review_sync._run_git", return_value=fetch_fail):
        files, warn = _changed_files_ci("main")

    assert files == []
    assert warn is not None
    assert "unable to fetch" in warn


def test_ci_missing_merge_base_falls_back_to_head_tilde():
    """Three-dot diff fails (no merge base) → falls back to HEAD~1..HEAD."""
    fetch_ok = _cp(0)
    diff_fail = _cp(128, stderr="no merge base")
    fallback_ok = _cp(0, stdout="tools/ci/check_soc_review_sync.py\n")

    with patch(
        "tools.ci.check_soc_review_sync._run_git",
        side_effect=[fetch_ok, diff_fail, fallback_ok],
    ):
        files, warn = _changed_files_ci("main")

    assert "tools/ci/check_soc_review_sync.py" in files
    assert warn is not None
    assert "HEAD~1..HEAD fallback" in warn


def test_ci_both_diffs_fail_fail_open():
    """Both three-dot and HEAD~1 fail → fail open with warning, no files."""
    fetch_ok = _cp(0)
    diff_fail = _cp(128, stderr="no merge base")
    fallback_fail = _cp(128, stderr="HEAD~1 unavailable")

    with patch(
        "tools.ci.check_soc_review_sync._run_git",
        side_effect=[fetch_ok, diff_fail, fallback_fail],
    ):
        files, warn = _changed_files_ci("main")

    assert files == []
    assert warn is not None
    assert "warning mode" in warn


def test_ci_missing_base_branch_fail_open():
    """Base branch does not exist remotely → fail open."""
    fetch_fail = _cp(1, stderr="couldn't find remote ref nonexistent-branch")

    with patch("tools.ci.check_soc_review_sync._run_git", return_value=fetch_fail):
        files, warn = _changed_files_ci("nonexistent-branch")

    assert files == []
    assert warn is not None


# ── _changed_files_local ──────────────────────────────────────────────────────


def test_local_parses_modified_files():
    porcelain = " M api/admin_identity.py\n M tools/ci/route_inventory.json\n"
    status_ok = _cp(0, stdout=porcelain)

    with patch("tools.ci.check_soc_review_sync._run_git", return_value=status_ok):
        files = _changed_files_local()

    assert "api/admin_identity.py" in files
    assert "tools/ci/route_inventory.json" in files


def test_local_parses_rename():
    porcelain = "R  old_name.py -> new_name.py\n"
    status_ok = _cp(0, stdout=porcelain)

    with patch("tools.ci.check_soc_review_sync._run_git", return_value=status_ok):
        files = _changed_files_local()

    assert "new_name.py" in files
    assert "old_name.py" not in files


def test_local_git_fail_returns_empty():
    with patch("tools.ci.check_soc_review_sync._run_git", return_value=_cp(1)):
        assert _changed_files_local() == []


# ── main() integration ────────────────────────────────────────────────────────


def test_main_critical_changed_no_soc_docs_fails(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_ci",
        return_value=(["tools/ci/check_soc_review_sync.py"], None),
    ):
        assert main() == 1


def test_main_critical_changed_with_soc_docs_passes(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    soc_doc = next(iter(SOC_DOCS))
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_ci",
        return_value=(["tools/ci/check_soc_review_sync.py", soc_doc], None),
    ):
        assert main() == 0


def test_main_no_critical_files_passes(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_ci",
        return_value=(["README.md", "api/routes.py"], None),
    ):
        assert main() == 0


def test_main_fail_open_on_empty_diff_with_warning(monkeypatch):
    """Fail-open path: warn returned, empty files → exit 0."""
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_ci",
        return_value=(
            [],
            "soc-review-sync: unable to determine CI diff — defaulting to warning mode",
        ),
    ):
        assert main() == 0


def test_main_no_base_ref_uses_local_diff(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_local",
        return_value=["README.md"],
    ):
        assert main() == 0


def test_main_no_changed_files_passes(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    with patch(
        "tools.ci.check_soc_review_sync._changed_files_ci",
        return_value=([], None),
    ):
        assert main() == 0


def test_main_shallow_repo_race_does_not_fail(monkeypatch):
    """The original failure scenario: shallow file race → must not exit 1."""
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    # Simulate: fetch ok, three-dot fails with shallow race error,
    # HEAD~1 succeeds with non-critical files only.
    fetch_ok = _cp(0)
    diff_fail = _cp(128, stderr="fatal: shallow file has changed since we read it")
    fallback_ok = _cp(0, stdout="README.md\n")

    with patch(
        "tools.ci.check_soc_review_sync._run_git",
        side_effect=[fetch_ok, diff_fail, fallback_ok],
    ):
        rc = main()

    assert rc == 0
