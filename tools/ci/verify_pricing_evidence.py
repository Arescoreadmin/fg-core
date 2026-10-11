#!/usr/bin/env python3
"""CUSTOMER-ZERO-RUN3-PRICING-EVIDENCE-001 — Independent pricing evidence verifier CLI.

This standalone CLI loads the pricing evidence instance, cost authorization request,
and ceremony state, runs the pricing evidence verifier and cost authorization verifier,
and produces a machine-readable JSON report.

SAFETY INVARIANTS (NON-NEGOTIABLE)
------------------------------------
1. The 'approved' field in the output report is ALWAYS false.
2. APPROVED state is unreachable from this tool.
3. No cloud queries, no network calls, no credentials.
4. No authorization is granted, advanced, or implied.

USAGE
-----
  python tools/ci/verify_pricing_evidence.py [--repo .] [--json] [--output FILE]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def _load_module(name: str, path: Path):
    """Load a Python module from a file path."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module {name!r} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def run_verification(
    repo: Path,
    evidence_file: Path | None = None,
    request_file: Path | None = None,
    ceremony_state_file: Path | None = None,
) -> dict:
    """Run the full pricing evidence verification pipeline.

    Returns a dict with the verification report. 'approved' is always False.
    """
    evidence_path = evidence_file or (
        repo / "customer_one" / "run3_pricing_evidence_instance.json"
    )
    request_path = request_file or (
        repo / "customer_one" / "run3_cost_authorization_request.json"
    )
    # ceremony_state_file is accepted for future use but not currently consumed
    _ = ceremony_state_file
    pricing_schema_path = repo / "customer_one" / "run3_pricing_evidence_schema.json"

    # Load modules
    verifier_mod = _load_module(
        "run3_pricing_evidence_verifier",
        repo / "services" / "governance" / "run3_pricing_evidence_verifier.py",
    )
    cost_review_mod = _load_module(
        "customer_zero_cost_review",
        repo / "services" / "governance" / "customer_zero_cost_review.py",
    )

    # Run pricing evidence verification
    pricing_result = verifier_mod.verify_pricing_evidence_file(str(evidence_path))

    # Build a pricing override dict when evidence is validated, so the 22-condition
    # cost verifier sees validated values rather than the legacy null schema.
    # Without this, a fully validated evidence instance still fails the cost review
    # because pricing_schema_path has fp_001_status=OPEN and all evidence fields null.
    pricing_override: dict | None = None
    if pricing_result.is_valid and pricing_result.pricing_snapshot is not None:
        try:
            instance_data = json.loads(evidence_path.read_text())
            snap = pricing_result.pricing_snapshot
            bum = snap.get("billing_unit_minutes")
            billing_unit_str = (
                "hourly" if bum == 60 else f"{bum}_minutes" if bum else "unknown"
            )
            prov = instance_data.get("provenance", {}) or {}
            src = instance_data.get("source", {}) or {}
            intg = instance_data.get("integrity", {}) or {}
            ep = instance_data.get("expiry_policy", {}) or {}
            pricing_override = {
                "fp_001_status": "CLOSED",
                "evidence": {
                    "source": src.get("classification"),
                    "product_tier_confirmed": snap.get("tier"),
                    "region_confirmed": snap.get("region"),
                    "currency": snap.get("currency"),
                    "hourly_rate_usd": snap.get("hourly_rate_usd"),
                    "billing_unit": billing_unit_str,
                    "rate_confirmed_at": instance_data.get("collection_timestamp_utc"),
                    "rate_valid_until": ep.get("expires_at_utc"),
                    "verifier_identity": prov.get("independent_reviewer_identity"),
                    "fingerprint": intg.get("evidence_fingerprint_sha256"),
                },
            }
        except Exception:
            pricing_override = None  # fall back to legacy schema on any load error

    # Run cost authorization verification
    cost_result = cost_review_mod.verify_cost_review(
        request_path,
        pricing_schema_path,
        pricing_override_dict=pricing_override,
    )

    # Determine overall status from pricing evidence result
    pe_status = pricing_result.validation_status
    if pe_status == "REJECTED_NOT_POPULATED":
        overall_status = "BLOCKED_PRICING_UNVERIFIED"
        next_action = (
            "All core pricing evidence fields are null — the template has not been "
            "populated. Human operator must observe current HCP Vault Dedicated "
            "(standard_small, us-east-1) pricing from the HCP portal and populate "
            "customer_one/run3_pricing_evidence_instance.json. "
            "Follow docs/operations/customer_zero_run3_pricing_evidence_capture.md."
        )
    elif pe_status in (
        "REJECTED_SCHEMA",
        "REJECTED_CONTENT",
        "REJECTED_PROVENANCE",
        "REJECTED_FRESHNESS",
        "REJECTED_SOURCE",
        "REJECTED_TAMPERED",
    ):
        overall_status = "BLOCKED_PRICING_EVIDENCE_INVALID"
        next_action = (
            "Pricing evidence instance validation failed. "
            f"Fix: {'; '.join(pricing_result.findings[:3])}. "
            "See docs/operations/customer_zero_run3_pricing_evidence_capture.md."
        )
    elif pe_status == "UNVALIDATED":
        overall_status = "BLOCKED_PRICING_UNVERIFIED"
        next_action = (
            "All pricing evidence fields are null or the evidence fingerprint is not set. "
            "Human operator must populate customer_one/run3_pricing_evidence_instance.json "
            "from the live HCP portal. "
            "Follow docs/operations/customer_zero_run3_pricing_evidence_capture.md."
        )
    elif pe_status == "VALIDATED":
        # Check cost authorization status for further blocking
        ca_state = cost_result.overall_state
        if ca_state == "READY_FOR_HUMAN_DECISION":
            overall_status = "READY_FOR_HUMAN_DECISION"
            next_action = (
                "All automated checks pass. Package is ready for human approver review. "
                "Human approver must make an explicit authorization decision — "
                "APPROVED state is NOT reachable through automation."
            )
        else:
            # Determine specific blocking reason
            blocker_ids = {b.split(":")[0] for b in cost_result.blockers}
            identity_blockers = {
                "C14_OPERATOR_IDENTITY_SET",
                "C15_APPROVER_IDENTITY_SET",
            }
            exposure_blockers = {
                "C10_MAX_COST_SET",
                "C11_MAX_RUNTIME_SET",
                "C12_TEARDOWN_RESERVE_SET",
            }
            if blocker_ids & identity_blockers:
                overall_status = "BLOCKED_HUMAN_INPUTS"
                next_action = (
                    "Pricing is validated. Human operator and approver identities must be set "
                    "in run3_cost_authorization_request.json before the review package is complete."
                )
            elif blocker_ids & exposure_blockers:
                overall_status = "BLOCKED_FINANCIAL_EXPOSURE"
                next_action = (
                    "Pricing is validated but maximum cost/runtime not set. "
                    "Human operator must set requested_max_cost_usd, "
                    "requested_max_runtime_minutes, and teardown_reserve_minutes."
                )
            else:
                overall_status = "BLOCKED_PRICING_UNVERIFIED"
                next_action = (
                    "Cost authorization has unresolved blockers. "
                    f"Blockers: {cost_result.blockers[:3]}. "
                    "Resolve all blockers before presenting for human decision."
                )
    else:
        overall_status = "BLOCKED_PRICING_UNVERIFIED"
        next_action = (
            f"Unexpected pricing evidence status: {pe_status!r}. "
            "Investigate and resolve before proceeding."
        )

    # SAFETY: approved is ALWAYS false
    approved = False

    report = {
        "report_timestamp_utc": datetime.now(UTC).isoformat(),
        "evidence_file": str(evidence_path),
        "pricing_evidence_result": pricing_result.to_dict(),
        "cost_authorization_result": cost_result.to_dict(),
        "overall_status": overall_status,
        "next_action": next_action,
        "approved": approved,
    }

    # Safety guard — must never be True
    if report["approved"] is not False:
        raise RuntimeError(
            "BUG: verify_pricing_evidence.py produced approved=True. "
            "This tool MUST NEVER set approved=True. "
            "This is a critical defect — do not proceed."
        )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Independent pricing evidence verifier for Customer-Zero Run-3."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="Path to repository root (default: .)",
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        default=None,
        help="Path to pricing evidence instance JSON",
    )
    parser.add_argument(
        "--request",
        type=Path,
        default=None,
        help="Path to cost authorization request JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON report to this file (default: stdout)",
    )
    args = parser.parse_args(argv)

    repo = args.repo.resolve()

    report = run_verification(
        repo=repo,
        evidence_file=args.evidence,
        request_file=args.request,
    )

    output = json.dumps(report, indent=2)

    if args.output:
        args.output.write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit 0 only when READY_FOR_HUMAN_DECISION; non-zero for all blocked states
    overall = report.get("overall_status", "")
    return 0 if overall == "READY_FOR_HUMAN_DECISION" else 1


if __name__ == "__main__":
    sys.exit(main())
