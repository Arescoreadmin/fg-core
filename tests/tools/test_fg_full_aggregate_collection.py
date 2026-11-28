"""FG-CI-NIGHTLY-REPAIR-001 — no collected test can silently drop out of a shard.

`make fg-full-shard` writes shard-collection.json (pytest --collect-only count)
before running; `fg_full_aggregate.py --require-collection` reconciles it with
the shard's JUnit exactly, replacing the static-count 90% tolerance as the
truncation guard for the scheduled run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.ci.fg_full_aggregate import aggregate, main

pytestmark = pytest.mark.contract


def _shard(
    root: Path,
    idx: int,
    *,
    tests: int,
    collected: int | None,
    errors: int = 0,
    collection_skipped: int = 0,
) -> None:
    d = root / f"shard-{idx}"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"junit-shard-{idx}.xml").write_text(
        f'<testsuites><testsuite name="pytest" tests="{tests}" failures="0" '
        f'errors="{errors}" skipped="0" time="1.0"/></testsuites>'
    )
    if collected is not None:
        (d / "shard-collection.json").write_text(
            json.dumps(
                {
                    "shard_index": idx,
                    "collected_tests": collected,
                    "collection_skipped": collection_skipped,
                }
            )
        )


def _run(root: Path, require: bool = True):
    return aggregate(root, 2, 1, 10_000, require_collection=require)


def test_exact_match_passes(tmp_path: Path) -> None:
    _shard(tmp_path, 0, tests=100, collected=100)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert passed, summary["gate_errors"]
    assert [s["collected_tests"] for s in summary["shards"]] == [100, 120]
    assert summary["require_collection"] is True


def test_fewer_executed_than_collected_fails(tmp_path: Path) -> None:
    # Within the old 90% tolerance, but 5 tests never ran.
    _shard(tmp_path, 0, tests=95, collected=100)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert not passed
    assert any("5 test(s) did not execute" in e for e in summary["gate_errors"])


def test_more_executed_than_collected_without_errors_fails(tmp_path: Path) -> None:
    _shard(tmp_path, 0, tests=101, collected=100)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert not passed
    assert any("possible duplicate execution" in e for e in summary["gate_errors"])


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "not json",
        '{"collected_tests": -1, "collection_skipped": 0}',
        '{"collected_tests": true, "collection_skipped": 0}',
        '{"collected_tests": 100}',
        '{"collected_tests": 100, "collection_skipped": -1}',
        "{}",
    ],
)
def test_missing_or_invalid_collection_record_fails(tmp_path: Path, payload) -> None:
    _shard(tmp_path, 0, tests=100, collected=None)
    if payload is not None:
        (tmp_path / "shard-0" / "shard-collection.json").write_text(payload)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert not passed
    assert any(
        "shard-collection.json missing or invalid" in e for e in summary["gate_errors"]
    )


def test_without_flag_behaviour_is_unchanged(tmp_path: Path) -> None:
    _shard(tmp_path, 0, tests=95, collected=None)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, _ = _run(tmp_path, require=False)
    assert passed


def test_cli_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _shard(tmp_path, 0, tests=95, collected=100)
    _shard(tmp_path, 1, tests=120, collected=120)
    base = ["prog", "--artifacts-dir", str(tmp_path), "--total-shards", "2",
            "--expected-min-tests", "1", "--expected-max-tests", "10000"]  # fmt: skip
    monkeypatch.setattr("sys.argv", base)
    assert main() == 0
    monkeypatch.setattr("sys.argv", [*base, "--require-collection"])
    assert main() == 1


def test_module_level_collection_skip_is_reconciled(tmp_path: Path) -> None:
    # Run 45890327767: backend/tests/test_intel.py skips at module level; JUnit
    # records it as one skipped testcase that --collect-only does not count.
    _shard(tmp_path, 0, tests=2656, collected=2655, collection_skipped=1)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert passed, summary["gate_errors"]
    assert summary["shards"][0]["collection_skipped"] == 1


def test_collection_skip_does_not_hide_a_missing_test(tmp_path: Path) -> None:
    _shard(tmp_path, 0, tests=2655, collected=2655, collection_skipped=1)
    _shard(tmp_path, 1, tests=120, collected=120)
    passed, _, summary = _run(tmp_path)
    assert not passed
    assert any("1 test(s) did not execute" in e for e in summary["gate_errors"])
