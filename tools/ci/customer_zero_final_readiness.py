#!/usr/bin/env python3
"""CUSTOMER-ZERO-FINAL-READINESS-001 — Offline readiness operator command.

Evaluates all known offline engineering blockers before the third paid
Customer-Zero trust ceremony. This command is:

  - OFFLINE only (no network calls, no cloud mutation)
  - READ-ONLY (no database or filesystem mutations)
  - ZERO COST (no paid infrastructure contact)
  - FAIL-CLOSED (exit 1 on any FAIL or NOT_PROVEN in required dimensions)

EXIT CODES
----------
  0 — All required dimensions PASS or NOT_APPLICABLE → READY
  1 — One or more required dimensions FAIL or NOT_PROVEN → BLOCKED
  2 — Internal error (authority file missing, etc.)

SAFETY WARNING
--------------
READY does NOT authorize:
  - CUSTOMER-ZERO-TRUST-003 (third paid ceremony)
  - CUSTOMER-ZERO-ACCEPT-001
  - Paid HCP infrastructure provisioning
  - Customer-Zero acceptance execution

Fresh explicit human cost authorization is required before Run 3.

Usage:
    python tools/ci/customer_zero_final_readiness.py
    python tools/ci/customer_zero_final_readiness.py --json
    python tools/ci/customer_zero_final_readiness.py --json --output result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")

try:
    from services.governance.customer_zero_readiness import (
        FinalResult,
        evaluate,
        render_human_readable,
    )
except ImportError as exc:
    print(
        f"ERROR: Could not import customer_zero_readiness module: {exc}",
        file=sys.stderr,
    )
    print(
        "Ensure you are running from the fg-core root with .venv activated.",
        file=sys.stderr,
    )
    sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON result to stdout",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write machine-readable JSON result to FILE",
    )
    parser.add_argument(
        "--repo",
        metavar="PATH",
        help="Path to fg-core repository root (default: auto-detected)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable output (machine-readable still emitted if --json)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve() if args.repo else _ROOT

    # Safety: never run if production environment is detected
    fg_env = os.getenv("FG_ENV", "test").lower()
    if fg_env in {"production", "staging", "prod"}:
        print(
            f"ERROR: customer_zero_final_readiness.py MUST NOT run in environment '{fg_env}'.",
            file=sys.stderr,
        )
        print(
            "This tool is offline-only and must not be used in live environments.",
            file=sys.stderr,
        )
        return 2

    try:
        result = evaluate(repo)
    except Exception as exc:
        print(f"ERROR: Evaluation failed: {exc}", file=sys.stderr)
        return 2

    result_dict = result.to_dict()

    # Human-readable output
    if not args.quiet:
        print(render_human_readable(result))

    # Machine-readable JSON
    json_str = json.dumps(result_dict, indent=2, sort_keys=True)
    if args.as_json:
        print(json_str)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json_str + "\n", encoding="utf-8")
        if not args.quiet:
            print(
                f"\nMachine-readable result written to: {output_path}", file=sys.stderr
            )

    return 0 if result.final_result == FinalResult.READY else 1


if __name__ == "__main__":
    sys.exit(main())
