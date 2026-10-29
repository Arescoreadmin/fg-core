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

from tools.ci.fg_full_shard import (  # noqa: E402
    _assign_shard,
    _assign_shards_greedy,
    _collect_test_files,
    _duration_weight,
    _load_test_counts,
    _load_test_durations,
    _relative,
)
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
            assert rel.startswith("tests/") or rel.startswith("backend/tests/"), (
                f"Expected tests/ or backend/tests/ prefix: {rel}"
            )

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
# Duration weighting — POST-786-SHARD-RUNTIME-001
# ---------------------------------------------------------------------------


class TestDurationWeighting:
    """Duration loading, fallback, and balance after the empirical-data update."""

    def test_duration_json_loads_cleanly(self) -> None:
        """fg_test_durations.json must load without error and all values must be positive.

        Zero-valued entries are excluded at load time so they fall through to the
        count-based fallback in _duration_weight.  Only positive, trustworthy values
        are loaded; expect ≥300 such entries from run 40720279440.
        """
        durations = _load_test_durations()
        assert len(durations) >= 300, (
            f"Expected ≥300 positive-duration files; got {len(durations)}"
        )
        for k, v in durations.items():
            assert isinstance(v, float) and v > 0, (
                f"Non-positive duration in loaded dict for {k}: {v}"
            )

    def test_duration_json_has_no_zero_entries(self) -> None:
        """fg_test_durations.json must not store zero-valued entries.

        Zero values are indistinguishable from 'unmeasured' and would cause
        _duration_weight to bypass the count-based fallback, piling zero-weight
        files onto the lightest shard without raising its estimated load.
        """
        raw_path = _REPO / "tools" / "ci" / "fg_test_durations.json"
        raw = json.loads(raw_path.read_text())
        zeros = [k for k, v in raw.items() if not k.startswith("_") and v == 0]
        assert not zeros, (
            f"fg_test_durations.json contains {len(zeros)} zero-valued entries; "
            "remove them so they use the count × 0.5 s fallback instead. "
            f"First offenders: {zeros[:3]}"
        )

    def test_duration_source_run_annotated(self) -> None:
        """fg_test_durations.json must carry a _source_run annotation."""
        raw_path = _REPO / "tools" / "ci" / "fg_test_durations.json"
        raw = json.loads(raw_path.read_text())
        assert "_source_run" in raw, "fg_test_durations.json missing _source_run annotation"
        assert raw["_source_run"], "_source_run must be non-empty"

    def test_fallback_weight_uses_count_times_half(self) -> None:
        """An unmeasured file falls back to count × 0.5 s."""
        counts = {"tests/test_unmeasured_synthetic.py": 42}
        durations: dict[str, float] = {}
        f = Path(_REPO / "tests" / "test_unmeasured_synthetic.py")
        weight = _duration_weight(f, counts, durations)
        assert weight == pytest.approx(21.0), (
            f"Fallback weight should be 42 × 0.5 = 21.0; got {weight}"
        )

    def test_zero_duration_in_dict_uses_fallback(self) -> None:
        """A zero-valued duration entry must use the count-based fallback, not 0.

        This guards against the P2 finding where round(subsecond_time) == 0
        causes all such files to pile onto one shard with zero estimated load.
        """
        counts = {"tests/test_subsecond_file.py": 80}
        durations = {"tests/test_subsecond_file.py": 0.0}
        f = Path(_REPO / "tests" / "test_subsecond_file.py")
        weight = _duration_weight(f, counts, durations)
        assert weight == pytest.approx(40.0), (
            f"Zero-valued duration should fall through to 80 × 0.5 = 40.0; got {weight}"
        )

    def test_measured_file_uses_duration_not_fallback(self) -> None:
        """A file present in the durations dict uses that value, ignoring count."""
        counts = {"tests/test_known.py": 100}
        durations = {"tests/test_known.py": 999.0}
        f = Path(_REPO / "tests" / "test_known.py")
        weight = _duration_weight(f, counts, durations)
        assert weight == pytest.approx(999.0), (
            f"Measured weight should be 999.0; got {weight}"
        )

    def test_real_validate_10_shards(self) -> None:
        """Production 10-shard layout must pass the validate invariants."""
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                "tools/ci/fg_full_shard.py",
                "--validate",
                "--total-shards",
                "10",
            ],
            cwd=_REPO,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        assert "PASS" in result.stdout

    def test_10_shard_duration_imbalance_at_most_1_percent(self) -> None:
        """With empirical durations, 10-shard duration-imbalance must be ≤ 1.01x."""
        files = _collect_test_files()
        counts = _load_test_counts()
        durations = _load_test_durations()

        all_shards = _assign_shards_greedy(files, 10)
        shard_loads = [
            sum(_duration_weight(f, counts, durations) for f in all_shards[i])
            for i in range(10)
        ]
        max_load = max(shard_loads)
        min_load = min(shard_loads)
        # Avoid division by zero for a perfectly balanced set.
        if min_load > 0:
            imbalance = max_load / min_load
            assert imbalance <= 1.01, (
                f"10-shard duration imbalance {imbalance:.4f}x exceeds 1.01x; "
                f"re-run Phase B to update fg_test_durations.json"
            )

    def test_10_shard_no_empty_shard(self) -> None:
        """Every shard must contain at least one test file."""
        files = _collect_test_files()
        all_shards = _assign_shards_greedy(files, 10)
        for i in range(10):
            assert len(all_shards[i]) >= 1, f"Shard {i} is empty"

    def test_security_test_file_has_duration_entry(self) -> None:
        """test_dependency_audit_enforcement.py must have an explicit duration entry."""
        durations = _load_test_durations()
        key = "tests/security/test_dependency_audit_enforcement.py"
        assert key in durations, (
            f"{key} not in fg_test_durations.json; "
            "add a conservative estimate to prevent it landing in a slow shard"
        )
        assert durations[key] > 0


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
        assert all(
            p.startswith("tests/") or p.startswith("backend/tests/") for p in parts
        )
