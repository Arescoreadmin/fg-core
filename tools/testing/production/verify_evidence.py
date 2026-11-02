#!/usr/bin/env python3
"""tools/testing/production/verify_evidence.py — MODE-B-PROOF-HARDENING-001 evidence verifier.

Standalone verifier that independently recomputes the fingerprint and acceptance
decision from a stored evidence JSON file. Used as the distinct acceptance step
in CI — separate from evidence generation.

Usage:
  python tools/testing/production/verify_evidence.py <evidence-file>
  python tools/testing/production/verify_evidence.py <evidence-file> --require-accepted

Exit codes:
  0 — Evidence fingerprint valid; acceptance_decision is ACCEPTED
  1 — Acceptance decision is REJECTED_FAIL
  2 — Evidence file missing or unreadable
  3 — Acceptance decision is REJECTED_INCOMPLETE or REJECTED_EMPTY
  4 — Fingerprint mismatch (evidence may be tampered or truncated)
  5 — Schema or parse error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.testing.production.evidence import (  # noqa: E402
    AcceptanceDecision,
    CANONICAL_CHECK_MANIFESTS,
    EvidenceResult,
    fingerprint,
    load_evidence,
    verify_acceptance,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MODE-B-PROOF-HARDENING-001 — independent evidence verifier"
    )
    parser.add_argument("evidence_file", help="Path to the evidence JSON file")
    parser.add_argument(
        "--require-accepted",
        action="store_true",
        help="Exit nonzero unless acceptance_decision is ACCEPTED",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print verification result as JSON",
    )
    args = parser.parse_args(argv)

    path = Path(args.evidence_file)
    if not path.exists():
        print(f"ERROR: Evidence file not found: {path}", file=sys.stderr)
        return 2

    try:
        record = load_evidence(path)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"ERROR: Failed to parse evidence file: {exc}", file=sys.stderr)
        return 5

    # Independently recompute fingerprint
    stored_fp = record.evidence_fingerprint
    computed_fp = fingerprint(record)

    fp_valid = stored_fp == computed_fp

    # Semantic 15: Check manifest completeness against the canonical actor profile.
    canonical = CANONICAL_CHECK_MANIFESTS.get(record.verification_profile)
    stored_manifest_set = set(record.required_check_manifest)
    missing_canonical = (
        [cid for cid in canonical if cid not in stored_manifest_set]
        if canonical
        else []
    )

    # Independently recompute acceptance decision (includes semantic 15 internally).
    computed_decision = verify_acceptance(record)
    stored_decision = record.acceptance_decision

    result = {
        "evidence_file": str(path),
        "schema_version": record.schema_version,
        "run_id": record.run_id,
        "verification_profile": record.verification_profile,
        "environment": record.environment,
        "console_origin": record.console_origin,
        "repo_sha": record.repo_sha,
        "timestamp": record.timestamp,
        "workflow_run_id": record.workflow_run_id,
        "test_execution_mode": record.test_execution_mode,
        "overall_result": record.overall_result.value,
        "stored_acceptance_decision": stored_decision,
        "computed_acceptance_decision": computed_decision.value,
        "stored_fingerprint": stored_fp,
        "computed_fingerprint": computed_fp,
        "fingerprint_valid": fp_valid,
        "acceptance_agrees": stored_decision == computed_decision.value,
        "verification_ok": fp_valid and stored_decision == computed_decision.value,
        "checks": [{"id": c.id, "result": c.result.value} for c in record.checks],
        "required_check_manifest": record.required_check_manifest,
        "canonical_manifest": list(canonical) if canonical else None,
        "missing_canonical_checks": missing_canonical,
        "manifest_complete": len(missing_canonical) == 0,
    }

    if args.output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print("MODE-B-PROOF-HARDENING-001 — Evidence Verifier")
        print("=" * 64)
        print(f"File:         {path}")
        print(f"Profile:      {record.verification_profile}")
        print(f"Run ID:       {record.run_id}")
        print(f"Timestamp:    {record.timestamp}")
        print(f"Repo SHA:     {record.repo_sha}")
        print(f"Mode:         {record.test_execution_mode}")
        print()
        print(f"Fingerprint:  {'VALID' if fp_valid else 'MISMATCH'}")
        if not fp_valid:
            print(f"  Stored:   {stored_fp}")
            print(f"  Computed: {computed_fp}")
        if canonical:
            manifest_ok = len(missing_canonical) == 0
            print(f"Manifest:     {'COMPLETE' if manifest_ok else 'INCOMPLETE'}")
            if missing_canonical:
                print(
                    f"  Missing canonical checks for profile "
                    f"'{record.verification_profile}': {missing_canonical}"
                )
        print(f"Stored decision:   {stored_decision}")
        print(f"Computed decision: {computed_decision.value}")
        if stored_decision != computed_decision.value:
            print("  WARNING: Stored and computed acceptance decisions disagree!")
        print()
        print("Checks:")
        for c in record.checks:
            marker = (
                "  [PASS]"
                if c.result == EvidenceResult.PASS
                else f"  [{c.result.value[:4]}]"
            )
            req = " *" if c.id in record.required_check_manifest else ""
            print(f"{marker} {c.id}{req}")
        if record.required_check_manifest:
            print(
                f"\n  * = required for acceptance ({len(record.required_check_manifest)} required)"
            )
        print()
        print(f"Verification: {'OK' if result['verification_ok'] else 'FAILED'}")
        print(f"Acceptance:   {computed_decision.value}")
        print("=" * 64)

    # Fingerprint mismatch is the most severe error
    if not fp_valid:
        print(
            "ERROR: Fingerprint mismatch — evidence may be tampered or truncated.",
            file=sys.stderr,
        )
        return 4

    if stored_decision != computed_decision.value:
        print(
            "WARNING: Stored acceptance decision disagrees with recomputed decision. "
            "Using recomputed value.",
            file=sys.stderr,
        )

    # Exit code based on computed (authoritative) decision
    decision = computed_decision
    if decision == AcceptanceDecision.ACCEPTED:
        return 0
    if decision == AcceptanceDecision.REJECTED_FAIL:
        return 1
    # REJECTED_INCOMPLETE or REJECTED_EMPTY
    return 3


if __name__ == "__main__":
    sys.exit(main())
