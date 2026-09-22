"""CUSTOMER-ZERO-ACCEPT-001 contract and fail-closed runner proof."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pytest

from customer_one.acceptance import (
    ACCEPTANCE_APPROVAL_AUTHORITY,
    ACCEPTANCE_APPROVAL_CAPABILITY,
    AcceptanceContractError,
    AcceptanceDimension,
    aggregate_dimensions,
    build_acceptance_bundle,
    canonical_fingerprint,
    validate_actor_assertion,
    validate_approval,
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


def _signed_assertion(monkeypatch: pytest.MonkeyPatch) -> dict:
    private = Ed25519PrivateKey.generate()
    public = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    monkeypatch.setenv("FG_CUSTOMER_ZERO_APPROVAL_PUBLIC_KEY_HEX", public)
    monkeypatch.setenv(
        "FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX",
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex(),
    )
    issued = datetime.now(UTC).replace(microsecond=0)
    assertion = {
        "subject": "auth0|customer-zero-approver",
        "principal_id": "principal-customer-zero-approver",
        "actor_kind": "operator",
        "capability": ACCEPTANCE_APPROVAL_CAPABILITY,
        "authority": ACCEPTANCE_APPROVAL_AUTHORITY,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    assertion["assertion_fingerprint"] = canonical_fingerprint(assertion)
    assertion["signature"] = private.sign(
        assertion["assertion_fingerprint"].encode("ascii")
    ).hex()
    return assertion


def private_sign_for_test(payload: str, assertion: dict) -> str:
    del assertion
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import os

    return (
        Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(os.environ["FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX"])
        )
        .sign(payload.encode("ascii"))
        .hex()
    )


def test_arbitrary_identity_and_authority_cannot_validate() -> None:
    corpus, outcomes = _contracts()
    with pytest.raises(AcceptanceContractError, match="APPROVAL_SCHEMA_INVALID"):
        validate_approval(
            {"status": "APPROVED", "approver": "Jason", "authority": "Founder"},
            corpus,
            outcomes,
        )


def test_signed_canonical_assertion_binds_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, outcomes = _contracts()
    assertion = _signed_assertion(monkeypatch)
    validate_actor_assertion(assertion)
    approval = {
        "approval_id": "approval-test-001",
        "status": "APPROVED",
        "work_item": "CUSTOMER-ZERO-ACCEPT-001",
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus["corpus_version"],
        "corpus_fingerprint": corpus["fingerprint"],
        "expected_outcome_id": outcomes["expected_outcome_id"],
        "expected_outcome_version": outcomes["expected_outcome_version"],
        "expected_outcome_fingerprint": outcomes["fingerprint"],
        "approver": {
            field: assertion[field]
            for field in (
                "subject",
                "principal_id",
                "actor_kind",
                "capability",
                "authority",
            )
        },
        "actor_assertion": assertion,
        "approved_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "provenance": {"reference": "review-packet.md", "fingerprint": "a" * 64},
    }
    approval["record_fingerprint"] = canonical_fingerprint(approval)
    approval["record_signature"] = private_sign_for_test(
        approval["record_fingerprint"], assertion
    )
    validate_approval(approval, corpus, outcomes)
    approval["record_fingerprint"] = "0" * 64
    with pytest.raises(
        AcceptanceContractError, match="APPROVAL_RECORD_FINGERPRINT_MISMATCH"
    ):
        validate_approval(approval, corpus, outcomes)


def test_service_assertion_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    assertion = _signed_assertion(monkeypatch)
    assertion["actor_kind"] = "service"
    with pytest.raises(AcceptanceContractError, match="ACTOR_KIND_NOT_ALLOWED"):
        validate_actor_assertion(assertion)
