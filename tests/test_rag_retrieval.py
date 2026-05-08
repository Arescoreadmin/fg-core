from __future__ import annotations

import importlib
import os
from typing import cast

import pytest

os.environ.setdefault("FG_ENV", "test")

_CORPUS_IDS_OMITTED = object()


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "retrieval-test.db")
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


def _seed_document(
    db_session,
    *,
    tenant_id: str,
    corpus_name: str = "Corpus",
    title: str = "Policy Guide",
    source: str = "https://example.test/policy",
    document_metadata: dict | None = None,
    chunks: list[dict],
) -> tuple[dict, dict, list[dict]]:
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db_session,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=title,
        source=source,
        metadata=document_metadata,
    )
    stored_chunks = store_chunks(
        db_session,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=chunks,
    )
    return corpus, document, stored_chunks


def _request(
    query: str,
    tenant_id: str = "tenant-a",
    corpus_ids: list[str] | None | object = _CORPUS_IDS_OMITTED,
    top_k: int = 5,
):
    from api.rag_context import RagContextRequest

    if corpus_ids is None:
        return RagContextRequest.model_construct(
            query=query,
            tenant_id=tenant_id,
            corpus_ids=None,
            top_k=top_k,
        )

    return RagContextRequest(
        query=query,
        tenant_id=tenant_id,
        corpus_ids=[]
        if corpus_ids is _CORPUS_IDS_OMITTED
        else cast(list[str], corpus_ids),
        top_k=top_k,
    )


def test_retrieval_returns_relevant_chunks(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[
            {"text": "Authentication policy requires MFA.", "ordinal": 0},
            {"text": "Quarterly billing export schedule.", "ordinal": 1},
        ],
    )

    response = retrieve_rag_context(db_session, _request("authentication mfa"))

    assert response.context_count == 1
    assert response.used_retrieval is True
    assert response.chunks[0].text == "Authentication policy requires MFA."


def test_retrieval_ranks_chunks_by_lexical_score(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[
            {"text": "Authentication policy.", "ordinal": 0},
            {
                "text": "Authentication policy requires authentication MFA.",
                "ordinal": 1,
            },
        ],
    )

    response = retrieve_rag_context(db_session, _request("authentication mfa policy"))

    assert [chunk.text for chunk in response.chunks] == [
        "Authentication policy requires authentication MFA.",
        "Authentication policy.",
    ]
    assert response.chunks[0].score > response.chunks[1].score


def test_retrieval_stable_ordering_for_ties(db_session):
    from api.rag_retrieval import retrieve_rag_context

    corpus_b, _, chunks_b = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="B Corpus",
        title="B",
        chunks=[{"text": "shared term", "ordinal": 0}],
    )
    corpus_a, _, chunks_a = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="A Corpus",
        title="A",
        chunks=[
            {"text": "shared term", "ordinal": 2},
            {"text": "shared term", "ordinal": 1},
        ],
    )

    response = retrieve_rag_context(db_session, _request("shared term"))

    expected = sorted(
        [
            (
                corpus_a["corpus_id"],
                chunks_a[0]["document_id"],
                2,
                chunks_a[0]["chunk_id"],
            ),
            (
                corpus_a["corpus_id"],
                chunks_a[1]["document_id"],
                1,
                chunks_a[1]["chunk_id"],
            ),
            (
                corpus_b["corpus_id"],
                chunks_b[0]["document_id"],
                0,
                chunks_b[0]["chunk_id"],
            ),
        ],
        key=lambda item: (item[0], item[1], item[2], item[3]),
    )
    actual = [
        (
            chunk.provenance.corpus_id,
            chunk.provenance.document_id,
            next(
                stored["ordinal"]
                for stored in [*chunks_a, *chunks_b]
                if stored["chunk_id"] == chunk.provenance.chunk_id
            ),
            chunk.provenance.chunk_id,
        )
        for chunk in response.chunks
    ]
    assert actual == expected


def test_retrieval_filters_by_tenant(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-owner",
        chunks=[{"text": "private acquisition strategy", "ordinal": 0}],
    )

    response = retrieve_rag_context(
        db_session,
        _request("private acquisition", tenant_id="tenant-attacker"),
    )

    assert response.chunks == []
    assert response.context_count == 0
    assert response.used_retrieval is False


def test_retrieval_same_query_is_tenant_isolated(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        title="Tenant A Policy",
        chunks=[{"text": "shared query tenant alpha controls", "ordinal": 0}],
    )
    _seed_document(
        db_session,
        tenant_id="tenant-b",
        title="Tenant B Policy",
        chunks=[{"text": "shared query tenant beta controls", "ordinal": 0}],
    )

    response_a = retrieve_rag_context(db_session, _request("shared query", "tenant-a"))
    response_b = retrieve_rag_context(db_session, _request("shared query", "tenant-b"))

    assert [chunk.provenance.title for chunk in response_a.chunks] == [
        "Tenant A Policy"
    ]
    assert [chunk.provenance.title for chunk in response_b.chunks] == [
        "Tenant B Policy"
    ]


def test_retrieval_empty_corpus_returns_empty_context(db_session):
    from api.rag_corpus_store import create_corpus
    from api.rag_retrieval import retrieve_rag_context

    create_corpus(db_session, tenant_id="tenant-a", name="Empty")

    response = retrieve_rag_context(db_session, _request("anything"))

    assert response.chunks == []
    assert response.context_count == 0
    assert response.used_retrieval is False


def test_retrieval_filters_by_corpus_ids(db_session):
    from api.rag_retrieval import retrieve_rag_context

    allowed, _, _ = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Allowed",
        chunks=[{"text": "retention policy allowed corpus", "ordinal": 0}],
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Blocked",
        chunks=[{"text": "retention policy blocked corpus", "ordinal": 0}],
    )

    response = retrieve_rag_context(
        db_session,
        _request("retention policy", corpus_ids=[allowed["corpus_id"]]),
    )

    assert len(response.chunks) == 1
    assert response.chunks[0].provenance.corpus_id == allowed["corpus_id"]
    assert "allowed corpus" in response.chunks[0].text


def test_retrieval_corpus_ids_none_searches_normally(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[{"text": "normal unrestricted policy result", "ordinal": 0}],
    )

    response = retrieve_rag_context(
        db_session,
        _request("unrestricted policy", corpus_ids=None),
    )

    assert len(response.chunks) == 1
    assert response.chunks[0].text == "normal unrestricted policy result"


def test_retrieval_blank_corpus_ids_return_empty_context(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[{"text": "policy that must not broaden", "ordinal": 0}],
    )

    response = retrieve_rag_context(
        db_session,
        _request("policy", corpus_ids=[" ", "\t"]),
    )

    assert response.chunks == []
    assert response.context_count == 0
    assert response.used_retrieval is False


def test_retrieval_mixed_blank_corpus_ids_preserve_valid_filter(db_session):
    from api.rag_retrieval import retrieve_rag_context

    allowed, _, _ = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Allowed",
        chunks=[{"text": "mixed filter policy allowed", "ordinal": 0}],
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Blocked",
        chunks=[{"text": "mixed filter policy blocked", "ordinal": 0}],
    )

    response = retrieve_rag_context(
        db_session,
        _request("mixed filter policy", corpus_ids=[" ", allowed["corpus_id"], "\t"]),
    )

    assert len(response.chunks) == 1
    assert response.chunks[0].provenance.corpus_id == allowed["corpus_id"]
    assert response.chunks[0].text == "mixed filter policy allowed"


def test_retrieval_blank_corpus_filter_never_broadens_to_all_corpora(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="A",
        chunks=[{"text": "broadening regression policy alpha", "ordinal": 0}],
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="B",
        chunks=[{"text": "broadening regression policy beta", "ordinal": 0}],
    )

    unfiltered = retrieve_rag_context(db_session, _request("broadening policy"))
    blank_filtered = retrieve_rag_context(
        db_session,
        _request("broadening policy", corpus_ids=[" ", "\t"]),
    )

    assert len(unfiltered.chunks) == 2
    assert blank_filtered.chunks == []


def test_retrieval_respects_top_k(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[
            {"text": "policy one", "ordinal": 0},
            {"text": "policy two", "ordinal": 1},
            {"text": "policy three", "ordinal": 2},
        ],
    )

    response = retrieve_rag_context(db_session, _request("policy", top_k=2))

    assert len(response.chunks) == 2
    assert response.context_count == 2


def test_retrieval_streams_candidates_without_fetchall():
    spec = importlib.util.find_spec("api.rag_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    assert ".fetchall(" not in source


def test_retrieval_preserves_top_k_under_many_prefiltered_candidates(db_session):
    from api.rag_retrieval import retrieve_rag_context

    chunks = [
        {"text": f"policy low relevance {index}", "ordinal": index}
        for index in range(30)
    ]
    chunks.append(
        {
            "text": "policy policy policy policy exact highest relevance",
            "ordinal": 30,
        }
    )
    _seed_document(db_session, tenant_id="tenant-a", chunks=chunks)

    response = retrieve_rag_context(db_session, _request("policy exact", top_k=1))

    assert len(response.chunks) == 1
    assert (
        response.chunks[0].text == "policy policy policy policy exact highest relevance"
    )


def test_retrieval_deterministic_ordering_preserved_with_prefilter(db_session):
    from api.rag_retrieval import retrieve_rag_context

    _seed_document(
        db_session,
        tenant_id="tenant-a",
        chunks=[
            {"text": "unmatched noise one", "ordinal": 0},
            {"text": "stable bounded term", "ordinal": 2},
            {"text": "stable bounded term", "ordinal": 1},
            {"text": "unmatched noise two", "ordinal": 3},
        ],
    )

    response_1 = retrieve_rag_context(db_session, _request("stable bounded"))
    response_2 = retrieve_rag_context(db_session, _request("stable bounded"))

    assert [chunk.provenance.chunk_id for chunk in response_1.chunks] == [
        chunk.provenance.chunk_id for chunk in response_2.chunks
    ]
    assert [chunk.text for chunk in response_1.chunks] == [
        "stable bounded term",
        "stable bounded term",
    ]


def test_retrieval_returns_chunk_provenance(db_session):
    from api.rag_retrieval import retrieve_rag_context

    corpus, document, chunks = _seed_document(
        db_session,
        tenant_id="tenant-a",
        title="Evidence Runbook",
        source="https://example.test/runbook",
        chunks=[
            {
                "text": "evidence retention policy",
                "ordinal": 0,
                "metadata": {"uri": "https://example.test/runbook#p7", "page": 7},
            }
        ],
    )

    response = retrieve_rag_context(db_session, _request("evidence retention"))
    provenance = response.chunks[0].provenance

    assert provenance.corpus_id == corpus["corpus_id"]
    assert provenance.document_id == document["document_id"]
    assert provenance.chunk_id == chunks[0]["chunk_id"]
    assert provenance.source == "https://example.test/runbook"
    assert provenance.title == "Evidence Runbook"
    assert provenance.uri == "https://example.test/runbook#p7"
    assert provenance.page == 7
    assert response.chunks[0].score > 0.0


def test_retrieval_rejects_missing_tenant(db_session):
    from api.rag_context import RagContextRequest
    from api.rag_retrieval import retrieve_rag_context

    request = RagContextRequest(query="policy", tenant_id="tenant-a").model_copy(
        update={"tenant_id": ""}
    )

    with pytest.raises(ValueError, match="tenant_id"):
        retrieve_rag_context(db_session, request)


def test_retrieval_does_not_import_legacy_placeholder_retrieval():
    spec = importlib.util.find_spec("api.rag_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        lines = fh.readlines()

    import_lines = [
        line for line in lines if line.strip().startswith(("import ", "from "))
    ]
    assert all("legacy_placeholder_retrieval" not in line for line in import_lines)


def test_retrieval_does_not_call_embeddings_or_provider():
    spec = importlib.util.find_spec("api.rag_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        lines = fh.readlines()

    executable_lines = [
        line.strip().lower()
        for line in lines
        if line.strip().startswith(("import ", "from ", "return ", "raise "))
        or "(" in line
    ]
    forbidden = ("embedding", "pgvector", "provider", "openai", "anthropic", "dispatch")
    for line in executable_lines:
        assert all(token not in line for token in forbidden)
