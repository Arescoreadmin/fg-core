"""
tests/security/test_retrieval_policy_center_security.py

Security regression tests for PR 49 — Retrieval Policy Center.

Covers:
- Tenant isolation: tenant A cannot view/edit tenant B policy corpora
- Denied corpora are not leaked into retrieval
- Invalid policy configurations fail closed via existing engine
- Semantic retrieval cannot bypass denied corpora
- Fallback cannot bypass denied corpora
- Retrieval policy engine remains functional after PR 49
- Provenance enforcement remains functional after PR 49
- Audit safety: policy decision logs do not contain raw chunk text or secrets
- Cross-tenant corpus access denied
"""

from __future__ import annotations

import logging
from typing import Any, cast

import pytest

from services.ai.policy import AiRagRules
from services.ai.retrieval_policy import (
    RETRIEVAL_POLICY_ALLOWED,
    RETRIEVAL_POLICY_DISABLED,
    RETRIEVAL_POLICY_LEXICAL_FALLBACK,
    RETRIEVAL_POLICY_STRATEGY_DENIED,
    evaluate_retrieval_policy,
)

_TENANT_A = "tenant-rpc-sec-a"
_TENANT_B = "tenant-rpc-sec-b"

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def db_session(tmp_path: Any, monkeypatch: pytest.MonkeyPatch):
    db_path = str(tmp_path / "rpc-security-test.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    SessionLocal = get_sessionmaker(sqlite_path=db_path)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


def _rules(**overrides: Any) -> AiRagRules:
    values: dict[str, Any] = {
        "enabled": True,
        "require_grounded_response": True,
        "no_answer_on_ungrounded": True,
        "allowed_corpus_ids": (),
        "denied_corpus_ids": (),
        "max_top_k": 4,
        "allowed_retrieval_strategies": ("lexical",),
        "require_grounded_context": True,
        "allow_lexical_fallback": False,
        "allow_semantic": False,
        "allow_no_context_answer": False,
    }
    values.update(overrides)
    return AiRagRules(
        enabled=cast(bool, values["enabled"]),
        require_grounded_response=cast(bool, values["require_grounded_response"]),
        no_answer_on_ungrounded=cast(bool, values["no_answer_on_ungrounded"]),
        allowed_corpus_ids=cast(tuple[str, ...], values["allowed_corpus_ids"]),
        denied_corpus_ids=cast(tuple[str, ...], values["denied_corpus_ids"]),
        max_top_k=cast(int, values["max_top_k"]),
        allowed_retrieval_strategies=cast(
            tuple[str, ...], values["allowed_retrieval_strategies"]
        ),
        require_grounded_context=cast(bool, values["require_grounded_context"]),
        allow_lexical_fallback=cast(bool, values["allow_lexical_fallback"]),
        allow_semantic=cast(bool, values["allow_semantic"]),
        allow_no_context_answer=cast(bool, values["allow_no_context_answer"]),
    )


def _seed_corpus(db_session: Any, *, tenant_id: str, corpus_name: str) -> str:
    from api.rag_corpus_store import create_corpus

    corpus = create_corpus(db_session, tenant_id=tenant_id, name=corpus_name)
    return str(corpus["corpus_id"])


# ─── Tenant isolation ─────────────────────────────────────────────────────────


def test_tenant_a_corpus_not_accessible_to_tenant_b(db_session: Any) -> None:
    """
    Tenant A corpora must never appear in Tenant B policy decisions.
    Corpus scope must be tenant-scoped before any retrieval can occur.
    """
    corpus_a = _seed_corpus(db_session, tenant_id=_TENANT_A, corpus_name="corpus-a")

    # Tenant B requests Tenant A's corpus explicitly — must not be effective
    rules_b = _rules(
        allowed_corpus_ids=(),
        denied_corpus_ids=(),
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_B,
        corpus_ids=[corpus_a],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules_b,
    )
    # Corpus from Tenant A must not appear in Tenant B's effective scope
    assert corpus_a not in decision.effective_corpus_ids, (
        f"Cross-tenant corpus {corpus_a} appeared in tenant {_TENANT_B} effective scope"
    )


def test_tenant_b_cannot_access_tenant_a_denied_corpus(db_session: Any) -> None:
    """
    Even if Tenant A explicitly allows a corpus, Tenant B cannot access it.
    Tenant binding is enforced at the corpus store level.
    """
    corpus_a = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="cross-tenant-target"
    )

    # Tenant A's rules explicitly allow their own corpus
    rules_b = _rules(allowed_corpus_ids=(corpus_a,))
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_B,
        corpus_ids=[corpus_a],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules_b,
    )
    assert corpus_a not in decision.effective_corpus_ids


def test_retrieval_policy_tenant_id_required(db_session: Any) -> None:
    """
    Blank tenant_id must raise a hard error — never silently allow all-tenant scope.
    """
    rules = _rules()
    with pytest.raises(ValueError, match="tenant_id"):
        evaluate_retrieval_policy(
            db_session,
            tenant_id="",
            corpus_ids=[],
            top_k=4,
            requested_strategy="lexical",
            rag_rules=rules,
        )


def test_whitespace_only_tenant_id_rejected(db_session: Any) -> None:
    rules = _rules()
    with pytest.raises(ValueError, match="tenant_id"):
        evaluate_retrieval_policy(
            db_session,
            tenant_id="   ",
            corpus_ids=[],
            top_k=4,
            requested_strategy="lexical",
            rag_rules=rules,
        )


# ─── Denied corpora enforcement ───────────────────────────────────────────────


def test_denied_corpus_is_excluded_from_effective_scope(db_session: Any) -> None:
    """
    Denied corpora must not appear in effective retrieval scope.
    This is enforced by the retrieval policy engine before any SQL query.
    """
    corpus_id = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="denied-corpus"
    )
    rules = _rules(
        denied_corpus_ids=(corpus_id,),
        allowed_corpus_ids=(corpus_id,),
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[corpus_id],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert corpus_id not in decision.effective_corpus_ids
    assert corpus_id in decision.denied_corpus_ids


def test_denied_corpus_overrides_allowed_corpus(db_session: Any) -> None:
    """Denied takes precedence over allowed — same corpus ID in both lists."""
    corpus_id = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="conflict-corpus"
    )
    rules = _rules(
        allowed_corpus_ids=(corpus_id,),
        denied_corpus_ids=(corpus_id,),
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[corpus_id],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert corpus_id not in decision.effective_corpus_ids
    # Effective scope is empty since the only candidate is denied
    assert len(decision.effective_corpus_ids) == 0


def test_denied_corpus_not_in_semantic_scope(db_session: Any) -> None:
    """
    Semantic retrieval must not access denied corpora.
    Corpus deny-list is evaluated before strategy execution.
    """
    denied_corpus = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="denied-for-semantic"
    )
    rules = _rules(
        denied_corpus_ids=(denied_corpus,),
        allowed_corpus_ids=(),
        allow_semantic=True,
        allowed_retrieval_strategies=("semantic",),
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[denied_corpus],
        top_k=4,
        requested_strategy="semantic",
        rag_rules=rules,
    )
    assert denied_corpus not in decision.effective_corpus_ids


def test_lexical_fallback_does_not_bypass_denied_corpora(db_session: Any) -> None:
    """
    Lexical fallback must not bypass denied corpus restrictions.
    The fallback path re-uses the same effective corpus list.
    """
    denied_corpus = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="denied-for-fallback"
    )
    rules = _rules(
        denied_corpus_ids=(denied_corpus,),
        allow_lexical_fallback=True,
        allow_semantic=True,
        allowed_retrieval_strategies=("lexical", "semantic"),
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[denied_corpus],
        top_k=4,
        requested_strategy="semantic",
        rag_rules=rules,
    )
    # Regardless of fallback, the denied corpus must not be in scope
    assert denied_corpus not in decision.effective_corpus_ids


# ─── Top-K clamping ───────────────────────────────────────────────────────────


def test_top_k_clamped_to_max_top_k(db_session: Any) -> None:
    """
    Requested top_k exceeding policy max_top_k must be clamped, not silently passed.
    """
    rules = _rules(max_top_k=4)
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=100,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert decision.effective_top_k == 4
    assert decision.requested_top_k == 100


def test_top_k_zero_rejected(db_session: Any) -> None:
    rules = _rules()
    with pytest.raises(ValueError, match="top_k"):
        evaluate_retrieval_policy(
            db_session,
            tenant_id=_TENANT_A,
            corpus_ids=[],
            top_k=0,
            requested_strategy="lexical",
            rag_rules=rules,
        )


def test_top_k_negative_rejected(db_session: Any) -> None:
    rules = _rules()
    with pytest.raises(ValueError, match="top_k"):
        evaluate_retrieval_policy(
            db_session,
            tenant_id=_TENANT_A,
            corpus_ids=[],
            top_k=-1,
            requested_strategy="lexical",
            rag_rules=rules,
        )


# ─── Strategy enforcement ─────────────────────────────────────────────────────


def test_unsupported_strategy_falls_back_to_lexical(db_session: Any) -> None:
    """
    Unrecognized strategy values are normalized to lexical (safe default),
    not passed through to the backend retriever.
    """
    rules = _rules(allowed_retrieval_strategies=("lexical",))
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="UNKNOWN_STRATEGY",
        rag_rules=rules,
    )
    # Normalized to lexical
    assert decision.requested_strategy == "lexical"


def test_semantic_strategy_denied_when_semantic_disabled(db_session: Any) -> None:
    """
    Semantic strategy must be denied when allow_semantic=False.
    Strategy denial must not silently coerce to allowed.
    """
    rules = _rules(
        allow_semantic=False,
        allowed_retrieval_strategies=("semantic",),
        allow_lexical_fallback=False,
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="semantic",
        rag_rules=rules,
    )
    assert not decision.allowed
    assert decision.reason_code == RETRIEVAL_POLICY_STRATEGY_DENIED


def test_lexical_fallback_used_when_semantic_denied(db_session: Any) -> None:
    """
    Lexical fallback activates when semantic is denied and fallback is enabled.
    Fallback must not restore the denied strategy.
    """
    rules = _rules(
        allow_semantic=False,
        allowed_retrieval_strategies=("lexical", "semantic"),
        allow_lexical_fallback=True,
    )
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="semantic",
        rag_rules=rules,
    )
    assert decision.allowed
    assert decision.reason_code == RETRIEVAL_POLICY_LEXICAL_FALLBACK
    assert decision.effective_strategy == "lexical"
    assert decision.lexical_fallback_used is True


def test_rag_disabled_policy_blocks_all_retrieval(db_session: Any) -> None:
    """
    When RAG is disabled, the policy decision must block all retrieval.
    """
    rules = _rules(enabled=False)
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert not decision.allowed
    assert decision.reason_code == RETRIEVAL_POLICY_DISABLED
    assert len(decision.effective_corpus_ids) == 0


# ─── Audit log safety ─────────────────────────────────────────────────────────


def test_policy_audit_metadata_excludes_raw_chunk_text(
    db_session: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Audit log entries for retrieval policy decisions must not contain
    raw chunk text, raw prompts, sensitive corpus content, or secret tokens.
    """
    corpus_id = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="audit-safety-corpus"
    )
    rules = _rules(allowed_corpus_ids=(corpus_id,))

    with caplog.at_level(logging.INFO, logger="frostgate.ai.retrieval_policy"):
        decision = evaluate_retrieval_policy(
            db_session,
            tenant_id=_TENANT_A,
            corpus_ids=[corpus_id],
            top_k=4,
            requested_strategy="lexical",
            rag_rules=rules,
        )

    log_text = " ".join(caplog.messages)

    # Audit log must not contain raw chunk or corpus content
    assert "chunk_text" not in log_text
    assert "raw_text" not in log_text
    assert "document_body" not in log_text

    # Decision metadata must be ID/count/boolean only
    metadata = decision.audit_metadata()
    for key, value in metadata.items():
        if key.endswith("_corpus_ids") or key.endswith("_corpus_count"):
            continue
        assert isinstance(value, (bool, int, str, type(None))), (
            f"Audit metadata field {key!r} has unsafe type {type(value)}"
        )


def test_policy_audit_metadata_contains_expected_safe_fields(
    db_session: Any,
) -> None:
    """
    Audit metadata must include all required safe fields for forensic reconstruction.
    """
    rules = _rules()
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    metadata = decision.audit_metadata()
    required_fields = {
        "reason_code",
        "allowed",
        "requested_corpus_count",
        "effective_corpus_count",
        "requested_top_k",
        "effective_top_k",
        "requested_strategy",
        "effective_strategy",
        "denied_corpus_count",
        "allowed_corpus_count",
        "require_grounded_context",
        "allow_no_context_answer",
        "semantic_allowed",
        "lexical_fallback_used",
    }
    missing = required_fields - set(metadata.keys())
    assert not missing, f"Audit metadata missing fields: {missing}"


# ─── Retrieval policy engine regression ───────────────────────────────────────


def test_allowed_corpus_in_effective_scope(db_session: Any) -> None:
    """Regression: allowed corpus for tenant appears in effective scope."""
    corpus_id = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="allowed-corpus"
    )
    rules = _rules(allowed_corpus_ids=(corpus_id,))
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[corpus_id],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert decision.allowed
    assert corpus_id in decision.effective_corpus_ids
    assert decision.reason_code == RETRIEVAL_POLICY_ALLOWED


def test_empty_corpus_list_gives_empty_scope(db_session: Any) -> None:
    """Regression: requesting no corpora with no allowlist gives empty scope."""
    rules = _rules(allowed_corpus_ids=(), denied_corpus_ids=())
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert len(decision.effective_corpus_ids) == 0


def test_nonexistent_corpus_excluded_from_scope(db_session: Any) -> None:
    """Regression: non-existent corpus IDs must not appear in effective scope."""
    fake_corpus_id = "corpus-does-not-exist-xyz"
    rules = _rules()
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[fake_corpus_id],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    assert fake_corpus_id not in decision.effective_corpus_ids


def test_duplicate_corpus_ids_deduplicated(db_session: Any) -> None:
    """Regression: duplicate corpus IDs in request must not result in duplicates in scope."""
    corpus_id = _seed_corpus(
        db_session, tenant_id=_TENANT_A, corpus_name="dedup-corpus"
    )
    rules = _rules(allowed_corpus_ids=(corpus_id,))
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id=_TENANT_A,
        corpus_ids=[corpus_id, corpus_id, corpus_id],
        top_k=4,
        requested_strategy="lexical",
        rag_rules=rules,
    )
    count = sum(1 for c in decision.effective_corpus_ids if c == corpus_id)
    assert count == 1, f"Corpus {corpus_id!r} appeared {count} times in effective scope"


# ─── Provenance enforcement regression ────────────────────────────────────────


def test_provenance_module_still_importable() -> None:
    """
    Regression: provenance enforcement module must remain importable after PR 49.
    PR 49 does not touch provenance enforcement.
    """
    from services.ai import provenance  # noqa: F401

    assert hasattr(provenance, "validate_answer_provenance")


def test_retrieval_policy_engine_still_importable() -> None:
    """
    Regression: retrieval policy engine module must remain importable after PR 49.
    """
    from services.ai import retrieval_policy  # noqa: F401

    assert hasattr(retrieval_policy, "evaluate_retrieval_policy")
    assert hasattr(retrieval_policy, "RetrievalPolicyDecision")
