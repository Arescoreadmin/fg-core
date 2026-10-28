#!/usr/bin/env python3
"""Verify offline ceremony simulation evidence is fresh and valid.

Read-only. Never modifies the evidence file. Exits 1 on any validation
failure; exits 0 only when evidence is fresh, GREEN, and complete.

Assurance boundary:
  source_tree_hash covers every git-tracked file except:
    - customer_one/offline_simulation_evidence.json  (circular: records its own hash)
    - ROADMAP.md  (tracking ledger; updating it would invalidate the hash it describes)
  These exclusions match _TREE_HASH_EXCLUDED in run_offline_ceremony_simulation.py and
  the exclusion set used by services/governance/customer_zero_readiness.py.

If evidence is stale, run:
    python tools/ci/run_offline_ceremony_simulation.py --repo .

EXIT CODES:
  0 — Evidence is valid and fresh
  1 — Evidence is stale, missing, malformed, or failed
  2 — Internal error (import failure or unexpected exception)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")

EVIDENCE_RELPATH = "customer_one/offline_simulation_evidence.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--repo",
        default=str(_ROOT),
        help="Root of the FrostGate repository (default: auto-detected)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    evidence_path = repo / EVIDENCE_RELPATH

    try:
        from services.governance.customer_zero_readiness import (
            ReadinessStatus,
            _validate_offline_simulation_evidence,
        )
    except ImportError as exc:
        print(f"ERROR: failed to import validator: {exc}", file=sys.stderr)
        return 2

    try:
        status, ev, reason, remediation = _validate_offline_simulation_evidence(
            evidence_path, repo
        )
    except Exception as exc:
        print(f"ERROR: validator raised unexpected error: {exc}", file=sys.stderr)
        return 2

    if status == ReadinessStatus.PASS:
        print("offline-simulation-evidence: OK")
        print(f"  {ev}")
        return 0

    print("offline-simulation-evidence: FAILED")
    print(f"  {ev}")
    if reason:
        print(f"  reason: {reason}")
    if remediation:
        print(f"  remediation: {remediation}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
