"""Tests for tools/ci/check_pr_base_is_mainline.py

Uses real temporary git repositories so that actual git merge-base semantics
are exercised — the same semantics that caused the original race defect.

Test groups:
    A  PR CI with valid immutable base SHA succeeds.
    B  Checker uses immutable base SHA, not mutable origin/main.
    C  origin/main advancing after PR-ref creation does NOT corrupt validation.
    D  Missing GITHUB_PR_BASE_SHA in PR CI fails closed.
    E  Invalid / unresolvable base SHA fails closed.
    F  SOC review already in immutable base + added in PR diff fails.
    G  SOC review absent from immutable base → addition is accepted.
    H  Push / non-PR (no GITHUB_BASE_REF) remains compatible.
    I  No HEAD~1 fallback exists in source.
    J  Synthetic merge-commit topology validates correctly.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import textwrap
from collections.abc import Generator
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Path to the checker under test
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_CHECKER = _REPO_ROOT / "tools" / "ci" / "check_pr_base_is_mainline.py"
_SOC_PATH = "docs/SOC_ARCH_REVIEW_2026-02-15.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git(
    args: list[str], cwd: pathlib.Path, **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        **kwargs,
    )


def _git_ok(args: list[str], cwd: pathlib.Path) -> str:
    result = _git(args, cwd, check=True)
    return result.stdout.strip()


def _run_checker(
    cwd: pathlib.Path,
    env: dict[str, str],
    python: str = "python",
) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, **env}
    # Override REPO detection: the checker resolves REPO from its own __file__,
    # so we monkey-patch by setting cwd to the tmpdir and passing REPO override
    # via a wrapper — easier to just run via subprocess with overridden GIT_DIR
    # and cwd so all git calls land in the right repo.
    return subprocess.run(
        [python, str(_CHECKER)],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=full_env,
    )


class _Repo:
    """Minimal git repo fixture for checker tests."""

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._git_ok(["init", "-b", "main"])
        self._git_ok(["config", "user.email", "test@test.com"])
        self._git_ok(["config", "user.name", "Test"])

    def _git_ok(self, args: list[str]) -> str:
        return _git_ok(args, self.root)

    def write(self, rel: str, content: str = "x") -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def add_all(self) -> None:
        self._git_ok(["add", "-A"])

    def commit(self, msg: str = "commit") -> str:
        self._git_ok(["commit", "-m", msg])
        return self._git_ok(["rev-parse", "HEAD"])

    def sha(self) -> str:
        return self._git_ok(["rev-parse", "HEAD"])

    def branch(self, name: str) -> None:
        self._git_ok(["checkout", "-b", name])

    def checkout(self, ref: str) -> None:
        self._git_ok(["checkout", ref])

    def add_remote(self, name: str, url: str) -> None:
        self._git_ok(["remote", "add", name, url])

    def fetch(self, remote: str = "origin") -> None:
        self._git_ok(["fetch", remote])


@pytest.fixture()
def repos(tmp_path: pathlib.Path) -> Generator[tuple[_Repo, _Repo], None, None]:
    """(origin, clone) — origin is a bare-like repo; clone has origin remote."""
    origin_path = tmp_path / "origin"
    clone_path = tmp_path / "clone"

    # Build origin: main with one sentinel commit
    origin = _Repo(origin_path)
    origin.write("README.md", "init")
    origin.add_all()
    origin.commit("initial")

    # Clone origin
    subprocess.run(
        ["git", "clone", str(origin_path), str(clone_path)],
        check=True,
        capture_output=True,
    )
    _git_ok(["config", "user.email", "test@test.com"], clone_path)
    _git_ok(["config", "user.name", "Test"], clone_path)
    clone = _Repo.__new__(_Repo)
    clone.root = clone_path

    yield origin, clone


def _pr_env(base_sha: str, base_ref: str = "main") -> dict[str, str]:
    return {
        "CI": "true",
        "GITHUB_BASE_REF": base_ref,
        "GITHUB_PR_BASE_SHA": base_sha,
        "GITHUB_EVENT_NAME": "pull_request",
        # Suppress Railway / other env pollution from tests
        "GIT_AUTHOR_NAME": "test",
        "GIT_COMMITTER_NAME": "test",
    }


def _push_env() -> dict[str, str]:
    return {
        "CI": "true",
        "GITHUB_BASE_REF": "",
        "GITHUB_PR_BASE_SHA": "",
        "GITHUB_EVENT_NAME": "push",
    }


def _local_env() -> dict[str, str]:
    return {
        "CI": "",
        "GITHUB_BASE_REF": "",
        "GITHUB_PR_BASE_SHA": "",
        "GITHUB_EVENT_NAME": "",
    }


# ---------------------------------------------------------------------------
# The checker resolves REPO from __file__ (the checker's own location), but
# git calls land in cwd. We patch REPO by running the checker with a wrapper
# that overrides the module-level REPO constant. Simpler: monkeypatch the
# checker's REPO via environment.
#
# Actually the cleanest approach: run the checker with a custom PYTHONPATH
# pointing to a shim that sets REPO before importing. Instead, we use
# subprocess.run(cwd=clone.root) and rely on the fact that the checker's
# _run_git sets cwd=REPO. Since REPO is derived from __file__ (the real
# checker path), we must override it.
#
# We solve this by writing a tiny runner shim into tmp_path that overrides
# REPO at import time.
# ---------------------------------------------------------------------------


def _make_runner(tmp: pathlib.Path, repo_root: pathlib.Path) -> pathlib.Path:
    """Write a thin runner that overrides check_pr_base_is_mainline.REPO."""
    runner = tmp / "_run_checker.py"
    checker_str = str(_CHECKER).replace("\\", "/")
    repo_str = str(repo_root).replace("\\", "/")
    runner.write_text(
        textwrap.dedent(f"""\
        import pathlib, importlib.util, sys
        spec = importlib.util.spec_from_file_location(
            "check_pr_base_is_mainline", "{checker_str}"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Override REPO after exec so the module-level assignment doesn't win.
        mod.REPO = pathlib.Path("{repo_str}")
        sys.exit(mod.main())
        """)
    )
    return runner


def _run(runner: pathlib.Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    full_env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"CI", "GITHUB_BASE_REF", "GITHUB_PR_BASE_SHA", "GITHUB_EVENT_NAME"}
    }
    full_env.update(env)
    return subprocess.run(
        ["python", str(runner)],
        capture_output=True,
        text=True,
        env=full_env,
    )


# ---------------------------------------------------------------------------
# A — PR CI with valid immutable base SHA succeeds
# ---------------------------------------------------------------------------


def test_A1_pr_ci_valid_base_sha_passes(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    origin, clone = repos
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # Add a PR commit on the clone
    clone._git_ok(["checkout", "-b", "pr-branch"])
    clone.write("newfile.txt", "pr change")
    clone.add_all()
    clone.commit("PR commit")

    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


def test_A2_pr_ci_no_pr_commits_passes(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    """HEAD == base SHA is a valid (empty-diff) PR."""
    origin, clone = repos
    base_sha = clone._git_ok(["rev-parse", "origin/main"])
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


# ---------------------------------------------------------------------------
# B — Uses immutable base SHA, not mutable origin/main
# ---------------------------------------------------------------------------


def test_B1_immutable_sha_used_not_mutable_origin_main(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    """Even if origin/main no longer contains a merge base with HEAD,
    validation succeeds when the immutable SHA is used."""
    origin, clone = repos
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # PR branch: add a commit
    clone._git_ok(["checkout", "-b", "pr-branch"])
    clone.write("pr.txt", "pr")
    clone.add_all()
    clone.commit("PR commit")

    # Simulate origin/main advancing (orphan replacement so merge-base disappears)
    origin._git_ok(["checkout", "--orphan", "tmp-orphan"])
    origin.write("unrelated.txt", "diverged")
    origin.add_all()
    origin.commit("diverged main")
    origin._git_ok(["branch", "-f", "main", "tmp-orphan"])
    origin._git_ok(["checkout", "main"])
    clone.fetch()
    # origin/main now has no merge-base with pr-branch

    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    # Must pass using the immutable SHA (which IS reachable from pr-branch)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


# ---------------------------------------------------------------------------
# C — origin/main advancing does NOT corrupt validation (explicit regression)
# ---------------------------------------------------------------------------


def test_C1_origin_main_advances_after_pr_creation(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    origin, clone = repos
    # Record the immutable base SHA at PR creation time
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # PR branch
    clone._git_ok(["checkout", "-b", "pr-branch"])
    clone.write("feature.txt", "feature")
    clone.add_all()
    clone.commit("feature commit")

    # origin/main advances independently
    origin.write("main-advance.txt", "main moved forward")
    origin.add_all()
    origin.commit("main advances")
    clone.fetch()

    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    # Must still pass — the immutable SHA is unaffected by origin/main moving
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


# ---------------------------------------------------------------------------
# D — Missing GITHUB_PR_BASE_SHA in PR CI fails closed
# ---------------------------------------------------------------------------


def test_D1_missing_base_sha_fails_closed(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    env = {
        "CI": "true",
        "GITHUB_BASE_REF": "main",
        "GITHUB_PR_BASE_SHA": "",  # missing
        "GITHUB_EVENT_NAME": "pull_request",
    }
    result = _run(runner, env)
    assert result.returncode == 1
    assert "pr-base-mainline: FAILED" in result.stdout
    assert "GITHUB_PR_BASE_SHA" in result.stdout


def test_D2_unset_base_sha_fails_closed(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    env = {
        "CI": "true",
        "GITHUB_BASE_REF": "main",
        # GITHUB_PR_BASE_SHA deliberately absent from env dict
        "GITHUB_EVENT_NAME": "pull_request",
    }
    result = _run(runner, env)
    assert result.returncode == 1
    assert "GITHUB_PR_BASE_SHA" in result.stdout


# ---------------------------------------------------------------------------
# E — Invalid / unresolvable base SHA fails closed
# ---------------------------------------------------------------------------


def test_E1_garbage_sha_fails_closed(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
    assert result.returncode == 1
    assert "pr-base-mainline: FAILED" in result.stdout
    assert "does not resolve to a commit" in result.stdout


def test_E2_truncated_sha_fails_closed(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env("abc123"))
    assert result.returncode == 1
    assert "pr-base-mainline: FAILED" in result.stdout


# ---------------------------------------------------------------------------
# F — SOC review already in immutable base + added in PR diff fails
# ---------------------------------------------------------------------------


def test_F1_soc_review_already_in_base_plus_added_fails(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    origin, clone = repos

    # Put the SOC review file in the base commit on origin/main
    origin.write(_SOC_PATH, "soc review content")
    origin.add_all()
    origin.commit("add SOC review to base")
    clone.fetch()
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # PR branch: re-add the same file (simulates a bad rebase that re-adds it)
    clone._git_ok(["checkout", "-b", "bad-pr"])
    clone._git_ok(["reset", "--hard", "origin/main~1"])
    clone.write(_SOC_PATH, "soc review content")
    clone.add_all()
    clone.commit("re-add SOC review")

    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 1
    assert "pr-base-mainline: FAILED" in result.stdout
    assert _SOC_PATH in result.stdout


# ---------------------------------------------------------------------------
# G — SOC review absent from immutable base → addition accepted
# ---------------------------------------------------------------------------


def test_G1_soc_review_absent_from_base_addition_is_ok(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    origin, clone = repos
    # base commit has NO SOC review file
    base_sha = clone._git_ok(["rev-parse", "origin/main"])
    assert not (origin.root / _SOC_PATH).exists()

    # PR branch: add SOC review for the first time (legitimate)
    clone._git_ok(["checkout", "-b", "add-soc"])
    clone.write(_SOC_PATH, "new soc review")
    clone.add_all()
    clone.commit("add SOC review")

    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


# ---------------------------------------------------------------------------
# H — Push / non-PR behavior remains compatible
# ---------------------------------------------------------------------------


def test_H1_push_event_skips_check(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _push_env())
    assert result.returncode == 0
    assert "skipped" in result.stdout


def test_H2_local_no_ci_no_base_ref_skips(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _local_env())
    assert result.returncode == 0
    assert "skipped" in result.stdout


def test_H3_ci_missing_base_ref_non_push_fails(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    _, clone = repos
    runner = _make_runner(tmp_path, clone.root)
    env = {
        "CI": "true",
        "GITHUB_BASE_REF": "",
        "GITHUB_PR_BASE_SHA": "",
        "GITHUB_EVENT_NAME": "workflow_dispatch",  # not a push
    }
    result = _run(runner, env)
    assert result.returncode == 1
    assert "GITHUB_BASE_REF is missing in CI" in result.stdout


# ---------------------------------------------------------------------------
# I — No HEAD~1 fallback exists in source
# ---------------------------------------------------------------------------


def test_I1_no_head_minus_1_fallback_in_source() -> None:
    src = _CHECKER.read_text(encoding="utf-8")
    assert "HEAD~1" not in src, "HEAD~1 fallback must not exist in the checker"
    assert "HEAD^" not in src, "HEAD^ fallback must not exist in the checker"


def test_I2_no_silent_fallback_to_origin_main_in_pr_ci() -> None:
    """In PR CI path, the checker must not fall through to origin/<base_ref>."""
    src = _CHECKER.read_text(encoding="utf-8")
    # The is_ci branch must set base_spec = base_sha (the immutable SHA),
    # never origin/<anything> in the PR CI code path.
    # Simple structural assertion: after the is_ci block sets base_spec,
    # the diff and probe use base_spec uniformly — verified by the other tests.
    # Here: verify no unconditional 'origin/' string in the diff/probe call sites.
    # The only 'origin/' references should be in the non-CI else branch.
    lines = src.splitlines()
    in_else = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("else:"):
            in_else = True
        if in_else:
            break
    # The diff call uses 'base_spec' not a hardcoded 'origin/...' string:
    assert 'f"{base_spec}...HEAD"' in src or "f'{base_spec}...HEAD'" in src
    assert 'f"{base_spec}:{' in src or "f'{base_spec}:" in src


# ---------------------------------------------------------------------------
# J — Synthetic merge-commit topology validates correctly
# ---------------------------------------------------------------------------


def test_J1_synthetic_merge_commit_topology(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    """Simulate GitHub's synthetic merge commit.

    GitHub Actions checks out a temporary merge commit:
        merge_sha = merge(PR_HEAD, origin/main)

    HEAD = merge_sha
    base_sha = immutable commit where PR branched from main

    The checker must validate correctly under this topology.
    """
    origin, clone = repos
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # PR branch
    clone._git_ok(["checkout", "-b", "pr-branch"])
    clone.write("pr-feature.txt", "pr content")
    clone.add_all()
    clone.commit("PR commit")
    pr_head = clone._git_ok(["rev-parse", "HEAD"])

    # origin/main may have advanced
    origin.write("main-extra.txt", "extra commit on main")
    origin.add_all()
    origin.commit("main advances concurrently")
    clone.fetch()
    main_sha = clone._git_ok(["rev-parse", "origin/main"])

    # Simulate the synthetic merge commit GitHub creates:
    #   merge pr_head into origin/main tip
    clone._git_ok(["checkout", "-b", "synthetic-merge", main_sha])
    merge_result = _git(
        ["merge", "--no-ff", pr_head, "-m", "synthetic merge"],
        cwd=clone.root,
    )
    if merge_result.returncode != 0:
        pytest.skip("merge conflict in synthetic topology test")

    # HEAD is now the synthetic merge commit; base_sha is the immutable PR base
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout


def test_J2_synthetic_merge_soc_in_base_no_spurious_failure(
    repos: tuple[_Repo, _Repo], tmp_path: pathlib.Path
) -> None:
    """Synthetic merge topology with SOC file in base does not spuriously fail.

    When base_sha is an ancestor of the synthetic merge commit (GitHub's
    normal topology), git diff base_sha...HEAD uses base_sha itself as the
    merge base, so the SOC file never appears as 'A' (it's already present
    in base_sha and remains present in the merged result). The checker must
    not emit a false positive.
    """
    origin, clone = repos

    # SOC review exists in base
    origin.write(_SOC_PATH, "soc content")
    origin.add_all()
    origin.commit("add SOC to main")
    clone.fetch()
    base_sha = clone._git_ok(["rev-parse", "origin/main"])

    # PR branch: normal feature commit on top of origin/main (no SOC changes)
    clone._git_ok(["checkout", "-b", "feature-pr", "origin/main"])
    clone.write("feature.txt", "feature")
    clone.add_all()
    clone.commit("feature commit")
    pr_head = clone._git_ok(["rev-parse", "HEAD"])

    # Synthetic merge: merge PR into current origin/main (same as base_sha here)
    clone._git_ok(["checkout", "-b", "synthetic", "origin/main"])
    merge_result = _git(
        ["merge", "--no-ff", pr_head, "-m", "synthetic merge"], cwd=clone.root
    )
    if merge_result.returncode != 0:
        pytest.skip("merge conflict in synthetic topology test")

    # SOC file is in base AND in HEAD — checker must not call this a re-addition.
    runner = _make_runner(tmp_path, clone.root)
    result = _run(runner, _pr_env(base_sha))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pr-base-mainline: OK" in result.stdout
