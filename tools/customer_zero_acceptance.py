#!/usr/bin/env python3
"""Run the bounded Customer-Zero acceptance contract.

The runner validates the independently-authored corpus and expected outcomes,
then aggregates evidence supplied by canonical authorities.  It never invents
runtime evidence or human approval: omitted dimensions remain NOT_PROVEN.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from customer_one.acceptance import (  # noqa: E402
    ACCEPTANCE_SCHEMA_VERSION,
    AcceptanceContractError,
    AcceptanceDimension,
    build_acceptance_bundle,
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


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _approval(args: argparse.Namespace) -> int:
    corpus = _read_json(args.corpus)
    outcomes = _read_json(args.expected_outcomes)
    validate_corpus(corpus)
    validate_expected_outcomes(outcomes, corpus)
    approval = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "status": "APPROVED",
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus["corpus_version"],
        "corpus_fingerprint": corpus["fingerprint"],
        "expected_outcome_id": outcomes["expected_outcome_id"],
        "expected_outcome_version": outcomes["expected_outcome_version"],
        "expected_outcome_fingerprint": outcomes["fingerprint"],
        "approver": args.approver,
        "approver_authority": args.authority,
        "approved_at": args.approved_at,
        "provenance": args.provenance,
    }
    _write_json(args.output, approval)
    print(json.dumps(approval, indent=2, sort_keys=True))
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
    approve.add_argument("--approver", required=True)
    approve.add_argument("--authority", required=True)
    approve.add_argument("--approved-at", required=True)
    approve.add_argument("--provenance", required=True)
    approve.set_defaults(handler=_approval)
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
