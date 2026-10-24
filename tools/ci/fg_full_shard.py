#!/usr/bin/env python3
"""Deterministic test-file partitioner for fg-full sharded execution.

Collects all test files under tests/ (same environment as fg-full-pytest),
sorts them deterministically (lexicographic path, PYTHONHASHSEED=0), and
assigns files to shards using round-robin modulo.

Invariants
----------
* Every test file belongs to exactly one shard (completeness + no duplicates).
* Assignment depends only on the sorted file list and shard parameters —
  it does not depend on filesystem ordering, mtime, or unstable hashing.
* Collection failures are fatal (fail closed).

Usage
-----
    # List files for shard 2 of 6 (one line per file):
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 6

    # Print as space-separated pytest args:
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 6 --fmt pytest-args

    # Print JSON shard manifest:
    python tools/ci/fg_full_shard.py --shard-index 2 --total-shards 6 --fmt json

    # Print inventory of ALL shards (for reconciliation):
    python tools/ci/fg_full_shard.py --inventory --total-shards 6

    # Validate no omissions/duplicates across all shards:
    python tools/ci/fg_full_shard.py --validate --total-shards 6
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# All pytest testpaths (matches pytest.ini / pyproject.toml testpaths).
TEST_ROOTS = [REPO_ROOT / "tests", REPO_ROOT / "backend" / "tests"]


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


def _assign_shard(files: list[Path], shard_index: int, total_shards: int) -> list[Path]:
    """Return files belonging to shard_index (0-based, modulo round-robin)."""
    return [f for i, f in enumerate(files) if i % total_shards == shard_index]


def _relative(f: Path) -> str:
    return str(f.relative_to(REPO_ROOT))


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
            "files": [_relative(f) for f in shard_files],
        }
        print(json.dumps(manifest, indent=2))
    else:
        for f in shard_files:
            print(_relative(f))
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    files = _collect_test_files()
    inventory: dict[int, list[str]] = {}
    for idx in range(args.total_shards):
        inventory[idx] = [
            _relative(f) for f in _assign_shard(files, idx, args.total_shards)
        ]

    print(
        json.dumps({"total_shards": args.total_shards, "shards": inventory}, indent=2)
    )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    """Fail-closed validation: all files covered, no duplicates, no empties."""
    files = _collect_test_files()
    all_assigned: list[str] = []
    errors: list[str] = []

    for idx in range(args.total_shards):
        shard = _assign_shard(files, idx, args.total_shards)
        if not shard:
            errors.append(f"shard {idx} is empty")
        all_assigned.extend(_relative(f) for f in shard)

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

    print(
        f"fg_full_shard validate: PASS "
        f"({len(files)} files, {args.total_shards} shards, no omissions, no duplicates)"
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
