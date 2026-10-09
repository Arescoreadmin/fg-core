#!/usr/bin/env python3
"""CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 — Operator preflight authority gate CLI.

Answers the single operational question:
  "Has the operator completed all known offline preparation, and are the 16
  deferred live checks correctly catalogued for human review before any human
  cost authorization decision?"

This command is:
  - OFFLINE by default (no network calls, no cloud mutation, no credentials)
  - READ-ONLY (no database or filesystem mutations)
  - DETERMINISTIC (same inputs → same preflight fingerprint)
  - FAIL-CLOSED (exit nonzero for BLOCKED)
  - SECRET-SAFE (no credentials, tokens, or private keys)
  - MACHINE-READABLE (--json flag)

EXIT CODES
----------
  0 — All offline preparation checks pass → PREPARED_FOR_HUMAN_REVIEW
  1 — One or more checks fail → BLOCKED
  2 — Internal error

CANONICAL TRUTH (IMMUTABLE — NOT CHANGED BY THIS COMMAND)
-----------------------------------------------------------
  CUSTOMER_ZERO_TRUST: NOT_PROVEN
  CUSTOMER_ZERO_TRUST_003: BLOCKED
  CUSTOMER_ZERO_ACCEPT_001: BLOCKED
  THIRD_PAID_CEREMONY: NOT_AUTHORIZED
  PAID_HCP_INFRASTRUCTURE: ABSENT
  COST_AUTHORIZATION: NOT_AUTHORIZED

SAFETY WARNINGS
---------------
PREPARED_FOR_HUMAN_REVIEW does NOT authorize spending.
PREPARED_FOR_HUMAN_REVIEW does NOT prove trust.
PREPARED_FOR_HUMAN_REVIEW does NOT unblock TRUST-003 or ACCEPT-001.
CI success does NOT authorize spending or trust.
This command MUST NOT write to any tracked evidence files during evaluation.
Repeated evaluation → same preflight fingerprint.

Usage:
    python tools/ci/customer_zero_run3_operator_preflight.py --repo .
    python tools/ci/customer_zero_run3_operator_preflight.py --repo . --json
    python tools/ci/customer_zero_run3_operator_preflight.py --repo . --json --output result.json
    python tools/ci/customer_zero_run3_operator_preflight.py --repo . --quiet
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")

SCHEMA_VERSION = "1.0"
WORK_ITEM = "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001"

# Canonical truth — never changed by this evaluator
CANONICAL_TRUTH = {
    "customer_zero_trust": "NOT_PROVEN",
    "customer_zero_trust_003": "BLOCKED",
    "customer_zero_accept_001": "BLOCKED",
    "third_paid_ceremony": "NOT_AUTHORIZED",
    "paid_hcp_infrastructure": "ABSENT",
    "cost_authorization": "NOT_AUTHORIZED",
}


def _render_human_readable(
    manifest_dict: dict[str, Any],
    blockers: list[str],
    offline_checks: list[dict[str, Any]],
) -> str:
    """Render a human-readable summary of the preflight manifest."""
    lines = [
        "=" * 70,
        "CUSTOMER-ZERO RUN-3 OPERATOR PREFLIGHT AUTHORITY",
        f"Work Item: {WORK_ITEM}",
        f"Source SHA: {manifest_dict.get('source_sha', 'UNKNOWN')[:16]}...",
        "=" * 70,
        "",
        "CANONICAL TRUTH (IMMUTABLE — NOT CHANGED BY THIS RESULT)",
        f"  {'CUSTOMER_ZERO_TRUST':<52} {CANONICAL_TRUTH['customer_zero_trust']}",
        f"  {'CUSTOMER_ZERO_TRUST_003':<52} {CANONICAL_TRUTH['customer_zero_trust_003']}",
        f"  {'CUSTOMER_ZERO_ACCEPT_001':<52} {CANONICAL_TRUTH['customer_zero_accept_001']}",
        f"  {'THIRD_PAID_CEREMONY':<52} {CANONICAL_TRUTH['third_paid_ceremony']}",
        f"  {'PAID_HCP_INFRASTRUCTURE':<52} {CANONICAL_TRUTH['paid_hcp_infrastructure']}",
        f"  {'COST_AUTHORIZATION':<52} {CANONICAL_TRUTH['cost_authorization']}",
        "",
        "── OFFLINE MANDATORY CHECKS ────────────────────────────────────────",
    ]

    for check in sorted(offline_checks, key=lambda x: x.get("check_id", "")):
        result = check.get("result", "?")
        check_id = check.get("check_id", "?")
        marker = " " if result == "PASS" else "*"
        lines.append(f"  {marker} {check_id:<47} {result}")

    lines.append("")

    # Deferred live checks summary
    required_checks = manifest_dict.get("required_checks", [])
    lines.append(
        f"── DEFERRED LIVE CHECKS ({len(required_checks)}) ─────────────────────────────────────"
    )
    for check in required_checks[:5]:  # Show first 5
        cid = check.get("check_id", "?")
        stage = check.get("execution_stage", "?")
        lines.append(f"    {cid:<45} [{stage}]")
    if len(required_checks) > 5:
        lines.append(
            f"    ... and {len(required_checks) - 5} more (see --json for full list)"
        )
    lines.append("")

    if blockers:
        lines.append(f"BLOCKERS ({len(blockers)}):")
        for b in blockers:
            lines.append(f"  - {b}")
    else:
        lines.append("BLOCKERS: None")

    lines.append("")

    # Fingerprints
    pfp = manifest_dict.get("preflight_fingerprint", "N/A")
    cfp = manifest_dict.get("candidate_fingerprint", "N/A")
    ifp = manifest_dict.get("infrastructure_fingerprint", "N/A")
    rfp = manifest_dict.get("resource_inventory_fingerprint", "N/A")

    lines.append(f"PREFLIGHT FINGERPRINT:           {pfp[:32]}...")
    lines.append(f"CANDIDATE FINGERPRINT:           {cfp[:32]}...")
    lines.append(f"INFRASTRUCTURE FINGERPRINT:      {ifp[:32]}...")
    lines.append(f"RESOURCE INVENTORY FINGERPRINT:  {rfp[:32]}...")

    lines.append("")
    status = manifest_dict.get("preflight_status", "BLOCKED")
    lines.append(f"PREFLIGHT STATUS: {status}")

    if status == "PREPARED_FOR_HUMAN_REVIEW":
        lines.extend(
            [
                "",
                "NEXT STEP: Submit this manifest for human operator review.",
                "",
                "WARNING: PREPARED_FOR_HUMAN_REVIEW means offline preparation is complete.",
                "         It does NOT authorize spending.",
                "         It does NOT prove trust.",
                "         It does NOT unblock TRUST-003 or ACCEPT-001.",
                "         A human operator must review this manifest and create a",
                "         separate explicit cost authorization before any paid",
                "         HCP infrastructure is provisioned.",
            ]
        )
    elif status == "BLOCKED":
        lines.extend(
            [
                "",
                "NEXT STEP: Resolve all blockers listed above before requesting human review.",
            ]
        )

    lines.append("=" * 70)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repo",
        default=".",
        metavar="PATH",
        help="Path to the fg-core repository root (default: .)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON manifest to stdout",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write machine-readable JSON manifest to FILE (does not track evidence files)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable output (use with --json for machine-readable only)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not repo.exists():
        print(f"ERROR: Repository path not found: {repo}", file=sys.stderr)
        return 2

    # Import and run the manifest builder
    try:
        from services.governance.run3_operator_preflight import build_preflight_manifest
    except ImportError as exc:
        print(
            f"ERROR: Could not import run3_operator_preflight module: {exc}",
            file=sys.stderr,
        )
        print(
            "Ensure you are running from the fg-core root with .venv activated.",
            file=sys.stderr,
        )
        return 2

    try:
        manifest = build_preflight_manifest(repo)
    except Exception as exc:
        print(f"ERROR: Manifest builder failed: {exc}", file=sys.stderr)
        return 2

    manifest_dict = manifest.to_dict()
    blockers = manifest.blockers
    offline_checks = manifest.offline_checks

    # Human-readable output — suppressed by --json (machine consumers) or --quiet
    if not args.quiet and not args.as_json:
        print(_render_human_readable(manifest_dict, blockers, offline_checks))

    # JSON output
    if args.as_json:
        print(json.dumps(manifest_dict, indent=2, default=str))

    # File output (never writes to tracked evidence files)
    if args.output:
        output_path = Path(args.output)
        # Safety: refuse to write to tracked evidence files
        tracked_evidence_files = {
            "customer_one/offline_simulation_evidence.json",
            "customer_one/ceremony_state.yaml",
            "customer_one/roadmap_authority.yaml",
        }
        try:
            rel = output_path.resolve().relative_to(repo)
            if str(rel) in tracked_evidence_files:
                print(
                    f"ERROR: Cannot write to tracked evidence file: {rel}",
                    file=sys.stderr,
                )
                return 2
        except ValueError:
            pass  # Output path is outside repo — allowed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(manifest_dict, indent=2, default=str),
            encoding="utf-8",
        )
        if not args.quiet:
            print(f"JSON manifest written to: {output_path}", file=sys.stderr)

    # Exit code
    status = manifest.preflight_status
    if status == "PREPARED_FOR_HUMAN_REVIEW":
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
