"""FG-855-REPAIR-001 — regression guard for required-CI test coverage.

Each case copies the real Makefile and ci.yml into a throwaway repo, applies
one regression (a dropped directory, a selector, a removed CI step ...) and
proves tools/ci/check_required_ci_coverage.py fails closed on it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tools.ci import check_required_ci_coverage as cov

pytestmark = pytest.mark.contract

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    shutil.copy(REPO / "Makefile", tmp_path / "Makefile")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    shutil.copy(REPO / ".github" / "workflows" / "ci.yml", wf / "ci.yml")
    (tmp_path / "agent" / "tests").mkdir(parents=True)
    for i in range(cov.AGENT_TESTS_MIN_FILES):
        (tmp_path / "agent" / "tests" / f"test_agent_{i}.py").write_text("")
    (tmp_path / "tests" / "security").mkdir(parents=True)
    (tmp_path / "tests" / "security" / "test_security_lane.py").write_text("")
    for i in range(cov.REGRESSION_MIN_FILES):
        (tmp_path / "tests" / f"test_field_assessment_{i}.py").write_text("")
    for rel in cov.REGRESSION_EXCLUDED_FILES:
        (tmp_path / rel).write_text("")
    (tmp_path / "tests" / "test_unrelated.py").write_text("")
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, f"fixture drift: {old!r} not in {path.name}"
    path.write_text(text.replace(old, new, 1))


def test_real_repository_passes():
    assert cov.check(REPO) == []


def test_real_selection_covers_all_measured_files():
    selected = set(cov.regression_paths(REPO))
    # The 85-test file named by the original #855 audit and the CI-Required
    # membership tests must stay selected.
    assert "tests/test_field_assessment.py" in selected
    assert "tests/tools/test_github_repo_security.py" in selected
    assert not any(p.startswith("tests/security/") for p in selected)
    assert len(selected) >= cov.REGRESSION_MIN_FILES


def test_fake_repo_baseline_passes(fake_repo: Path):
    assert cov.check(fake_repo) == []


def test_selection_is_sorted_and_picks_up_new_files(fake_repo: Path):
    (fake_repo / "tests" / "test_new_security_case.py").write_text("")
    paths = cov.regression_paths(fake_repo)
    assert paths == sorted(paths)
    assert "tests/test_new_security_case.py" in paths
    assert "tests/test_unrelated.py" not in paths
    assert "tests/security/test_security_lane.py" not in paths
    assert not set(cov.REGRESSION_EXCLUDED_FILES) & set(paths)


@pytest.mark.parametrize(
    ("old", "new", "expect"),
    [
        ("tests/agent agent/tests", "tests/agent", "agent/tests"),
        ("tests/agent agent/tests", "agent/tests", "tests/agent"),
        (
            "tests/agent agent/tests",
            "-k 'not queue' tests/agent agent/tests",
            "selector",
        ),
        (
            "--fg-per-test-timeout=$(AGENT_TEST_TIMEOUT_SECONDS) \\\n\t\ttests/agent",
            "tests/agent",
            "per-test timeout",
        ),
        (
            "check_required_ci_coverage.py --print-paths regression",
            "check_required_ci_coverage.py",
            "must take its paths",
        ),
        (
            "--junitxml $(JUNIT_DIR)/ci-assessment-security.xml",
            "-m 'not slow' --junitxml $(JUNIT_DIR)/ci-assessment-security.xml",
            "selector",
        ),
        (
            "-q tests/test_security_hardening.py tests/test_security_middleware.py",
            "-q tests/test_security_middleware.py",
            "no longer runs it",
        ),
    ],
)
def test_makefile_regressions_fail(fake_repo: Path, old: str, new: str, expect: str):
    _edit(fake_repo / "Makefile", old, new)
    failures = cov.check(fake_repo)
    assert any(expect in f for f in failures), failures


@pytest.mark.parametrize(
    ("old", "new", "expect"),
    [
        ("run: make ci-assessment-security", "run: make ci-pt", "no job runs"),
        (
            "run: make ci-assessment-security",
            "run: make ci-assessment-security\n        continue-on-error: true",
            "continue-on-error",
        ),
        (
            "- name: Assessment + security regression (ci-assessment-security)",
            "- name: Assessment + security regression (ci-assessment-security)\n"
            "        if: ${{ false }}",
            "if condition",
        ),
        (
            "run: make agent-unit",
            "run: make agent-smoke",
            "no job runs 'make agent-unit'",
        ),
        ("      - pt\n", "", "not in CI Required"),
    ],
)
def test_workflow_regressions_fail(fake_repo: Path, old: str, new: str, expect: str):
    _edit(fake_repo / ".github" / "workflows" / "ci.yml", old, new)
    failures = cov.check(fake_repo)
    assert any(expect in f for f in failures), failures


def test_agent_tests_below_floor_fail(fake_repo: Path):
    (fake_repo / "agent" / "tests" / "test_agent_0.py").unlink()
    assert any("below the recorded floor" in f for f in cov.check(fake_repo))


def test_regression_selection_below_floor_fails(fake_repo: Path):
    (fake_repo / "tests" / "test_field_assessment_0.py").unlink()
    assert any("regression selection holds" in f for f in cov.check(fake_repo))


def test_print_paths_fails_closed_on_empty_selection(tmp_path: Path, capsys):
    (tmp_path / "tests").mkdir()
    assert cov.main(["--print-paths", "regression", "--repo", str(tmp_path)]) == 1
    assert "empty regression selection" in capsys.readouterr().err
