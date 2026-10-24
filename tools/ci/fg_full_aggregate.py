#!/usr/bin/env python3
"""Aggregation gate for fg-full sharded execution.

Consumes one JUnit XML per shard, verifies completeness, and emits a
consolidated pass/fail decision with an aggregated summary.

Failure modes (all fail closed):
  - Missing shard artifact directory or JUnit XML.
  - Corrupt or unparseable JUnit XML.
  - Any shard reported test failures.
  - Any shard reported zero tests collected (empty shard guard).
  - Total collected tests falls outside tolerance of expected inventory.
  - Expected shards do not match the shard directories found.

Usage
-----
    python tools/ci/fg_full_aggregate.py \
        --artifacts-dir artifacts/fg-full-shards \
        --total-shards 6 \
        --expected-min-tests 23000

    # Each shard N writes its JUnit to:
    #   artifacts/fg-full-shards/shard-<N>/junit-shard-<N>.xml

Exit codes:
  0 — all shards passed, inventory within tolerance
  1 — one or more failures, missing shards, or empty shards
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ShardResult:
    shard_index: int
    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    present: bool = False
    parse_ok: bool = False
    error_detail: str = ""


def _parse_junit(path: Path) -> tuple[int, int, int, int, float]:
    """Return (tests, failures, errors, skipped, duration) from a JUnit XML."""
    tree = ET.parse(path)
    root = tree.getroot()

    # JUnit XML may have either a single <testsuite> or a <testsuites> wrapper.
    if root.tag == "testsuites":
        suites = list(root.iter("testsuite"))
    elif root.tag == "testsuite":
        suites = [root]
    else:
        raise ValueError(f"unexpected root tag: {root.tag!r}")

    tests = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) for s in suites)
    errors = sum(int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    duration = sum(float(s.get("time", 0)) for s in suites)
    return tests, failures, errors, skipped, duration


def aggregate(
    artifacts_dir: Path,
    total_shards: int,
    expected_min_tests: int,
    expected_max_tests: int,
) -> tuple[bool, list[ShardResult], dict[str, Any]]:
    results: list[ShardResult] = []

    for idx in range(total_shards):
        shard_dir = artifacts_dir / f"shard-{idx}"
        junit_path = shard_dir / f"junit-shard-{idx}.xml"
        r = ShardResult(shard_index=idx)

        if not shard_dir.exists():
            r.error_detail = f"shard directory missing: {shard_dir}"
            results.append(r)
            continue
        r.present = True

        if not junit_path.exists():
            r.error_detail = f"JUnit XML missing: {junit_path}"
            results.append(r)
            continue

        try:
            tests, failures, errors, skipped, duration = _parse_junit(junit_path)
            r.tests = tests
            r.failures = failures
            r.errors = errors
            r.skipped = skipped
            r.duration_seconds = duration
            r.parse_ok = True
        except Exception as exc:
            r.error_detail = f"JUnit parse error: {exc}"
            results.append(r)
            continue

        if r.tests == 0:
            r.error_detail = (
                "shard collected zero tests (empty shard or collection failure)"
            )

        results.append(r)

    # Aggregate totals
    total_tests = sum(r.tests for r in results)
    total_failures = sum(r.failures for r in results)
    total_errors = sum(r.errors for r in results)
    total_skipped = sum(r.skipped for r in results)
    total_duration = sum(r.duration_seconds for r in results)

    summary: dict[str, Any] = {
        "total_shards": total_shards,
        "total_tests": total_tests,
        "total_failures": total_failures,
        "total_errors": total_errors,
        "total_skipped": total_skipped,
        "total_duration_seconds": round(total_duration, 1),
        "expected_min_tests": expected_min_tests,
        "expected_max_tests": expected_max_tests,
        "shards": [
            {
                "shard_index": r.shard_index,
                "present": r.present,
                "parse_ok": r.parse_ok,
                "tests": r.tests,
                "failures": r.failures,
                "errors": r.errors,
                "skipped": r.skipped,
                "duration_seconds": round(r.duration_seconds, 1),
                "error_detail": r.error_detail,
            }
            for r in results
        ],
    }

    # Determine overall pass/fail
    gate_errors: list[str] = []
    for r in results:
        if not r.present:
            gate_errors.append(f"shard {r.shard_index}: directory missing")
        elif not r.parse_ok:
            gate_errors.append(f"shard {r.shard_index}: {r.error_detail}")
        elif r.error_detail:
            gate_errors.append(f"shard {r.shard_index}: {r.error_detail}")
        elif r.failures > 0 or r.errors > 0:
            gate_errors.append(
                f"shard {r.shard_index}: {r.failures} failure(s), {r.errors} error(s)"
            )

    if total_tests < expected_min_tests:
        gate_errors.append(
            f"total tests {total_tests} < expected minimum {expected_min_tests} "
            "(possible collection failure or omitted shard)"
        )
    if total_tests > expected_max_tests:
        gate_errors.append(
            f"total tests {total_tests} > expected maximum {expected_max_tests} "
            "(possible duplicate shard assignment)"
        )

    passed = len(gate_errors) == 0
    summary["gate_errors"] = gate_errors
    summary["result"] = "PASS" if passed else "FAIL"
    return passed, results, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate fg-full shard results.")
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--total-shards", type=int, required=True)
    parser.add_argument("--expected-min-tests", type=int, default=22000)
    parser.add_argument("--expected-max-tests", type=int, default=26000)
    parser.add_argument(
        "--out-json", type=Path, default=None, help="Write summary JSON to this path."
    )
    args = parser.parse_args()

    passed, results, summary = aggregate(
        args.artifacts_dir,
        args.total_shards,
        args.expected_min_tests,
        args.expected_max_tests,
    )

    # Always print the summary
    print(json.dumps(summary, indent=2))

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(summary, indent=2))

    if passed:
        print(
            f"\nfg-full-aggregate: PASS — "
            f"{summary['total_tests']} tests across {args.total_shards} shards"
        )
        return 0
    else:
        print("\nfg-full-aggregate: FAILED", file=sys.stderr)
        for err in summary["gate_errors"]:
            print(f"  ERROR: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
