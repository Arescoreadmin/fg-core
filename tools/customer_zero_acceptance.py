#!/usr/bin/env python3
"""Run the bounded Customer-Zero acceptance contract.

The runner validates the independently-authored corpus and expected outcomes,
then aggregates evidence supplied by canonical authorities.  It never invents
runtime evidence or human approval: omitted dimensions remain NOT_PROVEN.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.testing.runtime_intelligence.signing import Ed25519KeyProvider  # noqa: E402

from customer_one.acceptance import (  # noqa: E402
    ACCEPTANCE_SCHEMA_VERSION,
    AcceptanceContractError,
    AcceptanceDimension,
    build_acceptance_bundle,
    canonical_fingerprint,
    validate_actor_assertion,
    validate_corpus,
    validate_expected_outcomes,
)

DEFAULT_CORPUS = Path("customer_one/customer_zero_corpus.json")
DEFAULT_OUTCOMES = Path("customer_one/customer_zero_expected_outcomes.json")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
DIMENSIONS = (
    "SOURCE_IDENTITY",
    "EVIDENCE_COMPLETENESS",
    "EXPECTED_OUTCOMES",
    "DETERMINISTIC_FINDINGS",
    "EPISTEMIC_DETERMINATION",
    "RESULT_TRUTH",
    "REPORT",
    "REPORT_QA",
    "SIGNED_PROOF",
    "DETERMINISTIC_REPLAY",
    "TENANT_ISOLATION",
    "RECOVERY",
    "DEPENDENCY_SECURITY",
    "SCHEMA_RLS",
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceContractError(f"ARTIFACT_READ_FAILED:{path}") from exc
    if not isinstance(value, dict):
        raise AcceptanceContractError(f"ARTIFACT_OBJECT_REQUIRED:{path}")
    return value


def _write_json(path: Path, value: dict[str, Any], *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if exclusive:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        path.write_text(rendered, encoding="utf-8")


def _approval(args: argparse.Namespace) -> int:
    corpus = _read_json(args.corpus)
    outcomes = _read_json(args.expected_outcomes)
    assertion = _read_json(args.identity_assertion)
    grant = _read_json(args.authority_grant)
    validate_corpus(corpus)
    validate_expected_outcomes(outcomes, corpus)
    validate_actor_assertion(assertion, grant)
    try:
        provenance_bytes = args.provenance.read_bytes()
    except OSError as exc:
        raise AcceptanceContractError("APPROVAL_PROVENANCE_READ_FAILED") from exc
    provenance = {
        "reference": str(args.provenance),
        "fingerprint": hashlib.sha256(provenance_bytes).hexdigest(),
    }
    approver = {
        "subject": assertion["subject"],
        "principal_id": assertion["principal_id"],
        "actor_kind": assertion["actor_kind"],
        "capability": grant["capability"],
        "authority": grant["authority"],
    }
    approval = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "approval_id": str(uuid.uuid4()),
        "status": "APPROVED",
        "work_item": "CUSTOMER-ZERO-ACCEPT-001",
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus["corpus_version"],
        "corpus_fingerprint": corpus["fingerprint"],
        "expected_outcome_id": outcomes["expected_outcome_id"],
        "expected_outcome_version": outcomes["expected_outcome_version"],
        "expected_outcome_fingerprint": outcomes["fingerprint"],
        "approver": approver,
        "identity_assertion": assertion,
        "authority_grant": grant,
        "approved_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "provenance": provenance,
    }
    approval["record_fingerprint"] = canonical_fingerprint(approval)
    private_key = os.getenv("FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX", "").strip()
    if not private_key:
        raise AcceptanceContractError("APPROVAL_SIGNING_KEY_UNAVAILABLE")
    approval["record_signature"] = (
        Ed25519KeyProvider(private_key_hex=private_key)
        .sign(approval["record_fingerprint"].encode("ascii"))
        .hex()
    )
    _write_json(args.output, approval, exclusive=True)
    print(json.dumps(approval, indent=2, sort_keys=True))
    return 0


def _review(args: argparse.Namespace) -> int:
    corpus = _read_json(args.corpus)
    outcomes = _read_json(args.expected_outcomes)
    validate_corpus(corpus)
    validate_expected_outcomes(outcomes, corpus)
    assertions = {item["scenario_id"]: item for item in outcomes["assertions"]}
    print(f"Customer-Zero corpus: {corpus['corpus_id']} v{corpus['corpus_version']}")
    print(f"Corpus fingerprint: {corpus['fingerprint']}")
    print(
        f"Expected outcomes: {outcomes['expected_outcome_id']} v{outcomes['expected_outcome_version']}"
    )
    print(f"Expected-outcome fingerprint: {outcomes['fingerprint']}")
    print("Approval authority: customer_zero.acceptance.approve")
    print("Allowed actor kinds: human, operator")
    print("Scenarios:")
    for scenario in corpus["scenarios"]:
        expected = assertions.get(scenario["scenario_id"], {})
        print(
            f"- {scenario['scenario_id']}: {scenario.get('description', '')} "
            f"=> {expected.get('epistemic_state', 'MISSING')} / "
            f"{expected.get('truth_release', 'MISSING')}"
        )
    return 0


def _run(args: argparse.Namespace) -> int:
    corpus = _read_json(args.corpus)
    outcomes = _read_json(args.expected_outcomes)
    validate_corpus(corpus)
    validate_expected_outcomes(outcomes, corpus)
    dimensions = {
        name: AcceptanceDimension("NOT_PROVEN", "RUNTIME_EVIDENCE_NOT_COLLECTED")
        for name in DIMENSIONS
    }
    if not SHA_RE.fullmatch(args.source_sha):
        dimensions["SOURCE_IDENTITY"] = AcceptanceDimension(
            "FAIL", "SOURCE_SHA_INVALID"
        )
    else:
        dimensions["SOURCE_IDENTITY"] = AcceptanceDimension(
            "PASS", "SOURCE_SHA_RECORDED", (args.source_sha,)
        )
    approval = _read_json(args.approval) if args.approval else None
    bundle = build_acceptance_bundle(
        corpus=corpus,
        expected_outcomes=outcomes,
        approval=approval,
        source_sha=args.source_sha,
        dimensions=dimensions,
        acceptance_run_id=args.run_id or str(uuid.uuid4()),
        environment=args.environment,
    )
    rendered = json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    approve = subparsers.add_parser(
        "approve", help="write an explicit human approval record"
    )
    approve.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    approve.add_argument("--expected-outcomes", type=Path, default=DEFAULT_OUTCOMES)
    approve.add_argument("--output", type=Path, required=True)
    approve.add_argument("--identity-assertion", type=Path, required=True)
    approve.add_argument("--authority-grant", type=Path, required=True)
    approve.add_argument("--provenance", type=Path, required=True)
    approve.set_defaults(handler=_approval)
    review = subparsers.add_parser("review", help="print the human review packet")
    review.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    review.add_argument("--expected-outcomes", type=Path, default=DEFAULT_OUTCOMES)
    review.set_defaults(handler=_review)
    run = subparsers.add_parser("run", help="evaluate the acceptance contract")
    run.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    run.add_argument("--expected-outcomes", type=Path, default=DEFAULT_OUTCOMES)
    run.add_argument("--approval", type=Path)
    run.add_argument("--output", type=Path)
    run.add_argument("--source-sha", required=True)
    run.add_argument("--environment", required=True)
    run.add_argument("--run-id")
    run.set_defaults(handler=_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return args.handler(args)
    except AcceptanceContractError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
