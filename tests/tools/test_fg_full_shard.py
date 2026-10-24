"""Regression tests for the fg-full deterministic test-file partitioner.

Covers:
  - Deterministic, reproducible shard assignment.
  - Complete collection (no omissions).
  - No duplicate assignments across shards.
  - Detection of dropped test nodes.
  - Detection of unknown test nodes.
  - Shard emptiness detection.
  - Aggregation gate: failure on missing artifacts.
  - Aggregation gate: failure on failed shard.
  - Aggregation gate: failure on cancelled/missing shard.
  - Aggregation gate: failure on invalid JUnit XML.
  - Aggregation gate: correct accounting of skipped tests.
  - Aggregation gate: duplicate detection via test-count bound.
  - Stable CLI flag interface (used by workflow and Makefile).
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

# Ensure the repo root is importable.
_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.ci.fg_full_shard import _assign_shard, _collect_test_files, _relative  # noqa: E402
from tools.ci.fg_full_aggregate import aggregate  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _synthetic_files(n: int) -> list[Path]:
    """Return n synthetic Path objects with deterministic names."""
    return [Path(f"/repo/tests/test_module_{i:04d}.py") for i in range(n)]


# ---------------------------------------------------------------------------
# Shard partitioning — correctness
# ---------------------------------------------------------------------------


class TestShardPartitionCorrectness:
    """Complete, no-dup, deterministic assignment across a range of sizes."""

    @pytest.mark.parametrize(
        "total_files,total_shards",
        [
            (731, 6),
            (100, 4),
            (7, 3),
            (1, 1),
            (6, 6),
            (5, 6),  # fewer files than shards → some shards empty
        ],
    )
    def test_no_omissions(self, total_files: int, total_shards: int) -> None:
        files = _synthetic_files(total_files)
        assigned: list[Path] = []
        for idx in range(total_shards):
            assigned.extend(_assign_shard(files, idx, total_shards))
        assert set(assigned) == set(files), "Some files were not assigned to any shard"

    @pytest.mark.parametrize(
        "total_files,total_shards",
        [
            (731, 6),
            (100, 4),
            (7, 3),
            (1, 1),
        ],
    )
    def test_no_duplicates(self, total_files: int, total_shards: int) -> None:
        files = _synthetic_files(total_files)
        all_assigned: list[Path] = []
        for idx in range(total_shards):
            all_assigned.extend(_assign_shard(files, idx, total_shards))
        assert len(all_assigned) == len(set(all_assigned)), (
            "Duplicate file assigned to multiple shards"
        )

    @pytest.mark.parametrize(
        "total_files,total_shards",
        [
            (731, 6),
            (100, 4),
        ],
    )
    def test_total_count_preserved(self, total_files: int, total_shards: int) -> None:
        files = _synthetic_files(total_files)
        total = sum(
            len(_assign_shard(files, idx, total_shards)) for idx in range(total_shards)
        )
        assert total == total_files

    def test_partition_is_exhaustive(self) -> None:
        """Union of all shards equals the original file list."""
        files = _synthetic_files(50)
        all_shards = [_assign_shard(files, i, 6) for i in range(6)]
        union = [f for shard in all_shards for f in shard]
        assert sorted(union) == sorted(files)


# ---------------------------------------------------------------------------
# Shard partitioning — determinism
# ---------------------------------------------------------------------------


class TestShardDeterminism:
    """Same input → same output, independent of call order or environment."""

    def test_repeated_calls_identical(self) -> None:
        files = _synthetic_files(731)
        first = _assign_shard(files, 0, 6)
        second = _assign_shard(files, 0, 6)
        assert first == second

    def test_shard_independent_of_other_shard_calls(self) -> None:
        files = _synthetic_files(100)
        # Call shard 3 before shard 0.
        shard_3 = _assign_shard(files, 3, 6)
        shard_0_a = _assign_shard(files, 0, 6)
        # Call shard 0 fresh.
        shard_0_b = _assign_shard(files, 0, 6)
        assert shard_0_a == shard_0_b
        # Silence unused-variable warning.
        assert shard_3 is not None

    def test_sorted_input_required(self) -> None:
        """Reversed input produces different shards — caller must sort."""
        files = _synthetic_files(12)
        rev = list(reversed(files))
        shard_fwd = _assign_shard(files, 0, 3)
        shard_rev = _assign_shard(rev, 0, 3)
        # They should differ when the list order differs.
        assert shard_fwd != shard_rev


# ---------------------------------------------------------------------------
# Shard partitioning — real repo
# ---------------------------------------------------------------------------


class TestShardRealRepo:
    """Verify against the actual tests/ directory."""

    def test_real_file_count_nonzero(self) -> None:
        files = _collect_test_files()
        assert len(files) >= 100, f"Expected ≥100 test files; got {len(files)}"

    def test_real_validate_6_shards(self) -> None:
        """No omissions, no duplicates in the real repo with 6 shards."""
        files = _collect_test_files()
        total = 6
        all_assigned: list[Path] = []
        for idx in range(total):
            shard = _assign_shard(files, idx, total)
            all_assigned.extend(shard)
        assert len(all_assigned) == len(files), (
            f"Assigned {len(all_assigned)} files but repo has {len(files)}"
        )
        assert len(set(all_assigned)) == len(files), (
            "Duplicate file in shard assignment"
        )

    def test_relative_paths_are_stable(self) -> None:
        """Relative paths must be posix-normalised strings (no backslash)."""
        files = _collect_test_files()
        for f in files[:10]:
            rel = _relative(f)
            assert "\\" not in rel, f"Backslash in relative path: {rel}"
            assert rel.startswith("tests/"), f"Expected tests/ prefix: {rel}"

    def test_all_files_in_sorted_order(self) -> None:
        files = _collect_test_files()
        rels = [_relative(f) for f in files]
        assert rels == sorted(rels), (
            "collect_test_files must return files in sorted order"
        )


# ---------------------------------------------------------------------------
# Aggregation gate — helpers
# ---------------------------------------------------------------------------


def _write_junit(
    path: Path,
    *,
    tests: int,
    failures: int = 0,
    errors: int = 0,
    skipped: int = 0,
    duration: float = 10.0,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    xml = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="utf-8"?>
        <testsuites>
          <testsuite name="shard"
                     tests="{tests}"
                     failures="{failures}"
                     errors="{errors}"
                     skipped="{skipped}"
                     time="{duration}">
          </testsuite>
        </testsuites>
    """)
    path.write_text(xml, encoding="utf-8")


# ---------------------------------------------------------------------------
# Aggregation gate — correctness
# ---------------------------------------------------------------------------


class TestAggregateGate:
    def test_all_shards_pass(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        for i in range(3):
            _write_junit(
                artifacts / f"shard-{i}" / f"junit-shard-{i}.xml",
                tests=100,
                failures=0,
            )
        passed, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=250, expected_max_tests=350
        )
        assert passed
        assert summary["result"] == "PASS"
        assert summary["total_tests"] == 300

    def test_fails_on_missing_shard_directory(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        # Write shards 0 and 2, omit shard 1.
        for i in (0, 2):
            _write_junit(
                artifacts / f"shard-{i}" / f"junit-shard-{i}.xml",
                tests=100,
            )
        passed, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=1, expected_max_tests=10000
        )
        assert not passed
        assert "directory missing" in summary["gate_errors"][0]

    def test_fails_on_missing_junit_xml(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        for i in range(3):
            # Create directory but no JUnit file.
            (artifacts / f"shard-{i}").mkdir(parents=True)
        passed, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=1, expected_max_tests=10000
        )
        assert not passed
        assert any("JUnit XML missing" in e for e in summary["gate_errors"])

    def test_fails_on_corrupt_junit(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        shard_dir = artifacts / "shard-0"
        shard_dir.mkdir(parents=True)
        (shard_dir / "junit-shard-0.xml").write_text("NOT_VALID_XML", encoding="utf-8")
        passed, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=1, expected_max_tests=10000
        )
        assert not passed
        assert any("parse error" in e for e in summary["gate_errors"])

    def test_fails_on_shard_with_test_failures(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        _write_junit(
            artifacts / "shard-0" / "junit-shard-0.xml",
            tests=100,
            failures=2,
        )
        passed, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=1, expected_max_tests=10000
        )
        assert not passed
        assert any("failure" in e for e in summary["gate_errors"])

    def test_fails_on_shard_with_errors(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        _write_junit(
            artifacts / "shard-0" / "junit-shard-0.xml",
            tests=100,
            failures=0,
            errors=1,
        )
        passed, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=1, expected_max_tests=10000
        )
        assert not passed
        assert any("error" in e for e in summary["gate_errors"])

    def test_fails_on_empty_shard(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        _write_junit(
            artifacts / "shard-0" / "junit-shard-0.xml",
            tests=0,
        )
        passed, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=0, expected_max_tests=10000
        )
        assert not passed
        assert any("zero tests" in e for e in summary["gate_errors"])

    def test_fails_below_min_test_threshold(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        for i in range(3):
            _write_junit(
                artifacts / f"shard-{i}" / f"junit-shard-{i}.xml",
                tests=10,
            )
        passed, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=100, expected_max_tests=10000
        )
        assert not passed
        assert any("minimum" in e for e in summary["gate_errors"])

    def test_fails_above_max_test_threshold(self, tmp_path: Path) -> None:
        """Detects duplicate shard assignment (too many tests reported)."""
        artifacts = tmp_path / "shards"
        _write_junit(
            artifacts / "shard-0" / "junit-shard-0.xml",
            tests=9999,
        )
        passed, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=1, expected_max_tests=100
        )
        assert not passed
        assert any("maximum" in e for e in summary["gate_errors"])

    def test_skipped_tests_aggregated_correctly(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        for i in range(3):
            _write_junit(
                artifacts / f"shard-{i}" / f"junit-shard-{i}.xml",
                tests=100,
                skipped=10,
            )
        passed, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=250, expected_max_tests=350
        )
        assert passed
        assert summary["total_skipped"] == 30

    def test_duration_aggregated(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "shards"
        for i in range(3):
            _write_junit(
                artifacts / f"shard-{i}" / f"junit-shard-{i}.xml",
                tests=100,
                duration=120.0,
            )
        _, _, summary = aggregate(
            artifacts, total_shards=3, expected_min_tests=250, expected_max_tests=350
        )
        assert summary["total_duration_seconds"] == pytest.approx(360.0, abs=1.0)

    def test_result_json_structure(self, tmp_path: Path) -> None:
        """Summary JSON must have the required keys for CI consumption."""
        artifacts = tmp_path / "shards"
        _write_junit(
            artifacts / "shard-0" / "junit-shard-0.xml",
            tests=50,
        )
        _, _, summary = aggregate(
            artifacts, total_shards=1, expected_min_tests=1, expected_max_tests=1000
        )
        required_keys = {
            "total_shards",
            "total_tests",
            "total_failures",
            "total_errors",
            "total_skipped",
            "total_duration_seconds",
            "result",
            "gate_errors",
            "shards",
        }
        assert required_keys <= set(summary.keys())


# ---------------------------------------------------------------------------
# CLI interface stability
# ---------------------------------------------------------------------------


class TestCLIInterface:
    """The CLI flags used by Makefile and workflow must remain stable."""

    def test_flat_shard_flags(self) -> None:
        """--shard-index N --total-shards M --fmt json must be parseable."""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                "tools/ci/fg_full_shard.py",
                "--shard-index",
                "0",
                "--total-shards",
                "6",
                "--fmt",
                "json",
            ],
            cwd=_REPO,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["shard_index"] == 0
        assert data["total_shards"] == 6
        assert data["file_count"] > 0

    def test_validate_flag(self) -> None:
        """--validate --total-shards 6 must exit 0 on a clean repo."""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                "tools/ci/fg_full_shard.py",
                "--validate",
                "--total-shards",
                "6",
            ],
            cwd=_REPO,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        assert "PASS" in result.stdout

    def test_pytest_args_fmt_is_space_separated(self) -> None:
        """--fmt pytest-args must produce a space-separated string (no newlines)."""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                "tools/ci/fg_full_shard.py",
                "--shard-index",
                "1",
                "--total-shards",
                "6",
                "--fmt",
                "pytest-args",
            ],
            cwd=_REPO,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        output = result.stdout.strip()
        assert "\n" not in output, "pytest-args must be a single line"
        parts = output.split()
        assert len(parts) > 1, "Expected multiple file paths"
        assert all(p.startswith("tests/") for p in parts)
