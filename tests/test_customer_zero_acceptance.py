"""CUSTOMER-ZERO-ACCEPT-001 contract and fail-closed runner proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from customer_one.acceptance import (
    AcceptanceContractError,
    AcceptanceDimension,
    aggregate_dimensions,
    build_acceptance_bundle,
    validate_corpus,
    validate_expected_outcomes,
)


ROOT = Path(__file__).parents[1]


def _contracts() -> tuple[dict, dict]:
    corpus = json.loads((ROOT / "customer_one/customer_zero_corpus.json").read_text())
    outcomes = json.loads(
        (ROOT / "customer_one/customer_zero_expected_outcomes.json").read_text()
    )
    return corpus, outcomes


def test_corpus_and_expected_outcomes_are_immutable_contracts() -> None:
    corpus, outcomes = _contracts()
    assert validate_corpus(corpus) == corpus["fingerprint"]
    assert validate_expected_outcomes(outcomes, corpus) == outcomes["fingerprint"]
    assert corpus["synthetic"] is True
    assert len(corpus["scenarios"]) == len(outcomes["assertions"])


def test_mutated_corpus_cannot_reuse_approval() -> None:
    corpus, outcomes = _contracts()
    corpus["scenarios"][0]["description"] = "tampered"
    with pytest.raises(AcceptanceContractError, match="CORPUS_FINGERPRINT_MISMATCH"):
        validate_corpus(corpus)
    # The expected-outcome artifact remains independently valid, but its
    # approved binding cannot be reused until the corpus is restored.
    assert (
        validate_expected_outcomes(outcomes, _contracts()[0]) == outcomes["fingerprint"]
    )


def test_mutated_expected_outcomes_fail_closed() -> None:
    corpus, outcomes = _contracts()
    outcomes["assertions"][0]["truth_release"] = "blocked"
    with pytest.raises(
        AcceptanceContractError, match="EXPECTED_OUTCOME_FINGERPRINT_MISMATCH"
    ):
        validate_expected_outcomes(outcomes, corpus)


def test_aggregation_is_fail_closed_and_deterministic() -> None:
    passed = {"REPORT": AcceptanceDimension("PASS", "ok")}
    assert aggregate_dimensions(passed) == "PASS"
    assert (
        aggregate_dimensions(
            {**passed, "RECOVERY": AcceptanceDimension("NOT_PROVEN", "missing")}
        )
        == "NOT_PROVEN"
    )
    assert (
        aggregate_dimensions(
            {
                **passed,
                "TRUTH": AcceptanceDimension("FAIL", "mismatch"),
                "RECOVERY": AcceptanceDimension("NOT_PROVEN", "missing"),
            }
        )
        == "FAIL"
    )


def test_bundle_without_human_approval_is_not_proven() -> None:
    corpus, outcomes = _contracts()
    bundle = build_acceptance_bundle(
        corpus=corpus,
        expected_outcomes=outcomes,
        approval=None,
        source_sha="cb26171707eee41f9778e57ecc6c0c40cf5eb30f",
        acceptance_run_id="run-test-001",
        environment="CI",
        dimensions={
            "SOURCE_IDENTITY": AcceptanceDimension("PASS", "source SHA recorded"),
            "EXPECTED_OUTCOMES": AcceptanceDimension("PASS", "contract validated"),
            "RECOVERY": AcceptanceDimension(
                "NOT_PROVEN", "recovery evidence unavailable"
            ),
        },
    )
    assert bundle["final_state"] == "NOT_PROVEN"
    assert bundle["approval"] is None
    assert bundle["synthetic"] is True
    assert bundle["release"]["source_sha"] == "cb26171707eee41f9778e57ecc6c0c40cf5eb30f"


def test_missing_mandatory_dimension_cannot_pass() -> None:
    corpus, outcomes = _contracts()
    bundle = build_acceptance_bundle(
        corpus=corpus,
        expected_outcomes=outcomes,
        approval=None,
        source_sha="cb26171707eee41f9778e57ecc6c0c40cf5eb30f",
        acceptance_run_id="run-test-002",
        environment="local_acceptance",
        dimensions={},
    )
    assert bundle["final_state"] == "NOT_PROVEN"
