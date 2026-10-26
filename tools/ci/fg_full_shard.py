#!/usr/bin/env python3
"""Deterministic test-file partitioner for fg-full sharded execution.

Collects all test files under tests/ (same environment as fg-full-pytest),
sorts them deterministically (lexicographic path, PYTHONHASHSEED=0), and
assigns files to shards using greedy bin-packing by estimated duration.

Load weighting
--------------
Bin-packing uses fg_test_durations.json (per-file estimated CI seconds) when
present, falling back to count × 0.5 s for unmeasured files.  The manifest
and expected_tests fields always report actual test counts (from
fg_test_counts.json) for aggregation accuracy — duration weights are used
only for scheduling, not for result verification.

Duration weights were derived from workflow run 40366143888 (2026-10-26),
which showed that count-only balancing placed multi-second-per-test files
(test_ea_canonical_14_6_1.py ≈ 4.6 s/test, test_governance_orchestration.py
≈ 2.1 s/test) into the same shards, causing consistent 45-min timeouts.

Invariants
----------
* Every test file belongs to exactly one shard (completeness + no duplicates).
* Assignment depends only on the sorted file list and shard parameters —
  it does not depend on filesystem ordering, mtime, or unstable hashing.
* Collection failures are fatal (fail closed).

Usage
-----
    # List files for shard 2 of 10 (one line per file):
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 10

    # Print as space-separated pytest args:
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 10 --fmt pytest-args

    # Print JSON shard manifest (includes expected_tests):
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 10 --fmt json

    # Print inventory of ALL shards (for reconciliation):
    python tools/ci/fg_full_shard.py --inventory --total-shards 10

    # Validate no omissions/duplicates across all shards:
    python tools/ci/fg_full_shard.py --validate --total-shards 10
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# All pytest testpaths (matches pytest.ini / pyproject.toml testpaths).
TEST_ROOTS = [REPO_ROOT / "tests", REPO_ROOT / "backend" / "tests"]
# Pre-computed per-file test counts for manifest / expected-test reporting.
TEST_COUNTS_PATH = Path(__file__).parent / "fg_test_counts.json"
# Per-file estimated CI durations in seconds for bin-packing only.
DURATIONS_PATH = Path(__file__).parent / "fg_test_durations.json"


def _load_test_counts() -> dict[str, int]:
    """Load per-file test counts from fg_test_counts.json, or empty dict."""
    if TEST_COUNTS_PATH.exists():
        try:
            return json.loads(TEST_COUNTS_PATH.read_text())
        except Exception:
            return {}
    return {}


def _load_test_durations() -> dict[str, float]:
    """Load per-file estimated CI durations (seconds) from fg_test_durations.json."""
    if DURATIONS_PATH.exists():
        try:
            raw = json.loads(DURATIONS_PATH.read_text())
            return {k: float(v) for k, v in raw.items() if not k.startswith("_")}
        except Exception:
            return {}
    return {}


def _collect_test_files() -> list[Path]:
    """Return all test files under all pytest testpaths, sorted lexicographically.

    Uses pathlib glob, not pytest collection, so this is fast and has no side
    effects. The sort is stable across platforms because it is based on
    POSIX-normalised relative path strings, not inode order.
    """
    files = sorted(
        (
            p
            for root in TEST_ROOTS
            if root.exists()
            for p in root.rglob("test_*.py")
            if p.is_file()
        ),
        key=lambda p: str(p.relative_to(REPO_ROOT)),
    )
    if not files:
        print(
            "ERROR: fg_full_shard: no test files found under test roots — "
            "check that REPO_ROOT is correct or that tests/ has not been deleted",
            file=sys.stderr,
        )
        sys.exit(1)
    return files


def _duration_weight(f: Path, counts: dict[str, int], durations: dict[str, float]) -> float:
    """Estimated CI duration for a file in seconds.

    Uses fg_test_durations.json when present; falls back to count × 0.5 s for
    unmeasured files.  The 0.5 s/test baseline is calibrated from run
    40366143888 where fast shards ran at ~0.31 s/test and medium shards at
    ~0.9–1.0 s/test (average ≈ 0.5 s/test across all unmeasured files).
    """
    rel = _relative(f)
    if rel in durations:
        return durations[rel]
    return counts.get(rel, 1) * 0.5


def _assign_shards_greedy(
    files: list[Path], total_shards: int
) -> dict[int, list[Path]]:
    """Greedy bin-packing: always assign next file (heaviest first) to least-loaded shard.

    Load is measured in estimated CI seconds (fg_test_durations.json) to
    balance wall-clock runtime rather than raw test count.  Files without a
    duration entry fall back to count × 0.5 s (fg_test_counts.json).

    Returns a mapping of shard_index → list[Path].
    """
    counts = _load_test_counts()
    durations = _load_test_durations()

    sorted_files = sorted(
        files,
        key=lambda f: _duration_weight(f, counts, durations),
        reverse=True,
    )
    shard_loads: list[float] = [0.0] * total_shards
    shard_files: dict[int, list[Path]] = {i: [] for i in range(total_shards)}

    for f in sorted_files:
        lightest = min(range(total_shards), key=lambda i: shard_loads[i])
        shard_files[lightest].append(f)
        shard_loads[lightest] += _duration_weight(f, counts, durations)

    # Sort each shard's files lexicographically for determinism.
    for idx in shard_files:
        shard_files[idx].sort(key=_relative)

    return shard_files


def _assign_shard(files: list[Path], shard_index: int, total_shards: int) -> list[Path]:
    """Return files belonging to shard_index using greedy bin-packing."""
    return _assign_shards_greedy(files, total_shards)[shard_index]


def _relative(f: Path) -> str:
    try:
        return str(f.relative_to(REPO_ROOT))
    except ValueError:
        return str(f)


def _expected_tests(files: list[Path]) -> int:
    """Sum expected test counts for a list of files."""
    counts = _load_test_counts()
    return sum(counts.get(_relative(f), 1) for f in files)


def _cmd_shard(args: argparse.Namespace) -> int:
    files = _collect_test_files()
    shard_files = _assign_shard(files, args.shard_index, args.total_shards)

    if not shard_files:
        print(
            f"ERROR: shard {args.shard_index}/{args.total_shards} is empty — "
            "total_shards exceeds total file count",
            file=sys.stderr,
        )
        return 1

    fmt = getattr(args, "fmt", "lines")
    if fmt == "pytest-args":
        # Space-separated relative paths suitable for pytest command line.
        print(" ".join(_relative(f) for f in shard_files))
    elif fmt == "json":
        manifest = {
            "shard_index": args.shard_index,
            "total_shards": args.total_shards,
            "file_count": len(shard_files),
            "total_files": len(files),
            "expected_tests": _expected_tests(shard_files),
            "files": [_relative(f) for f in shard_files],
        }
        print(json.dumps(manifest, indent=2))
    else:
        for f in shard_files:
            print(_relative(f))
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    files = _collect_test_files()
    all_shards = _assign_shards_greedy(files, args.total_shards)
    counts = _load_test_counts()
    inventory: dict[str, object] = {}
    for idx in range(args.total_shards):
        shard_f = all_shards[idx]
        inventory[str(idx)] = {
            "files": [_relative(f) for f in shard_f],
            "expected_tests": sum(counts.get(_relative(f), 1) for f in shard_f),
        }

    print(
        json.dumps({"total_shards": args.total_shards, "shards": inventory}, indent=2)
    )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    """Fail-closed validation: all files covered, no duplicates, no empties."""
    files = _collect_test_files()
    all_assigned: list[str] = []
    errors: list[str] = []
    counts = _load_test_counts()
    durations = _load_test_durations()

    all_shards = _assign_shards_greedy(files, args.total_shards)
    shard_tests: list[int] = []
    shard_weights: list[float] = []
    for idx in range(args.total_shards):
        shard = all_shards[idx]
        if not shard:
            errors.append(f"shard {idx} is empty")
        all_assigned.extend(_relative(f) for f in shard)
        shard_tests.append(sum(counts.get(_relative(f), 1) for f in shard))
        shard_weights.append(sum(_duration_weight(f, counts, durations) for f in shard))

    # Duplicate check
    seen: set[str] = set()
    for path in all_assigned:
        if path in seen:
            errors.append(f"duplicate assignment: {path}")
        seen.add(path)

    # Omission check
    full_set = {_relative(f) for f in files}
    assigned_set = set(all_assigned)
    missing = full_set - assigned_set
    extra = assigned_set - full_set
    for m in sorted(missing):
        errors.append(f"not assigned to any shard: {m}")
    for e in sorted(extra):
        errors.append(f"assigned but not in file list: {e}")

    if errors:
        print("fg_full_shard validate: FAILED", file=sys.stderr)
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        return 1

    total_tests = sum(shard_tests)
    max_tests = max(shard_tests)
    min_tests = min(shard_tests)
    avg_tests = total_tests / args.total_shards
    count_imbalance = max_tests / avg_tests if avg_tests > 0 else 0

    total_weight = sum(shard_weights)
    max_weight = max(shard_weights)
    min_weight = min(shard_weights)
    avg_weight = total_weight / args.total_shards
    dur_imbalance = max_weight / avg_weight if avg_weight > 0 else 0

    print(
        f"fg_full_shard validate: PASS "
        f"({len(files)} files, {args.total_shards} shards, no omissions, no duplicates)\n"
        f"  tests:    total={total_tests} min={min_tests} max={max_tests} "
        f"avg={avg_tests:.0f} count-imbalance={count_imbalance:.2f}x\n"
        f"  duration: total={total_weight:.0f}s min={min_weight:.0f}s max={max_weight:.0f}s "
        f"avg={avg_weight:.0f}s duration-imbalance={dur_imbalance:.2f}x"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic test-file partitioner for fg-full sharded execution."
    )
    sub = parser.add_subparsers(dest="command")

    # Default mode: print shard assignment
    p_shard = sub.add_parser("shard", help="Print files for a given shard.")
    p_shard.add_argument("--shard-index", type=int, required=True)
    p_shard.add_argument("--total-shards", type=int, required=True)
    p_shard.add_argument(
        "--fmt",
        choices=["lines", "pytest-args", "json"],
        default="lines",
        help="Output format.",
    )

    p_inv = sub.add_parser("inventory", help="Print full inventory of all shards.")
    p_inv.add_argument("--total-shards", type=int, required=True)

    p_val = sub.add_parser("validate", help="Validate shard coverage (fail closed).")
    p_val.add_argument("--total-shards", type=int, required=True)

    # Also support flat flags for backward compat / workflow convenience
    parser.add_argument("--shard-index", type=int, default=None)
    parser.add_argument("--total-shards", type=int, default=None)
    parser.add_argument(
        "--fmt",
        choices=["lines", "pytest-args", "json"],
        default="lines",
    )
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--validate", action="store_true")

    args = parser.parse_args()

    # Flat-flag mode (used by Makefile / workflow)
    if args.command is None:
        if args.validate:
            if args.total_shards is None:
                parser.error("--validate requires --total-shards")
            return _cmd_validate(args)
        if args.inventory:
            if args.total_shards is None:
                parser.error("--inventory requires --total-shards")
            return _cmd_inventory(args)
        if args.shard_index is None or args.total_shards is None:
            parser.error("Requires --shard-index and --total-shards (or a subcommand)")
        return _cmd_shard(args)

    if args.command == "shard":
        return _cmd_shard(args)
    if args.command == "inventory":
        return _cmd_inventory(args)
    if args.command == "validate":
        return _cmd_validate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
