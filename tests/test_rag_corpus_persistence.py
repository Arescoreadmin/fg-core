"""
tests/test_rag_corpus_persistence.py — Corpus persistence tests for PR 14.

Covers:
- Corpus CRUD with tenant isolation
- Document CRUD with tenant isolation
- Chunk storage, ordering, and metadata round-trip
- Blank-value rejection
- No import of retrieval or rag_stub modules
"""

from __future__ import annotations

import importlib
import os

import pytest

os.environ.setdefault("FG_ENV", "test")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    """
    Provide a fresh SQLAlchemy Session backed by a per-test SQLite DB.
    The session is closed after each test.
    """
    db_path = str(tmp_path / "corpus-test.db")
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


# ---------------------------------------------------------------------------
# rag_corpora tests
# ---------------------------------------------------------------------------


def test_create_corpus_for_tenant(db_session):
    from api.rag_corpus_store import create_corpus

    corpus = create_corpus(db_session, tenant_id="tenant-alpha", name="My Corpus")

    assert corpus["corpus_id"].startswith("corp-")
    assert corpus["tenant_id"] == "tenant-alpha"
    assert corpus["name"] == "My Corpus"
    assert corpus["description"] is None
    assert corpus["metadata"] is None
    assert "created_at" in corpus
    assert "updated_at" in corpus


def test_list_corpora_filters_by_tenant(db_session):
    from api.rag_corpus_store import create_corpus, list_corpora

    create_corpus(db_session, tenant_id="tenant-a", name="Corpus A1")
    create_corpus(db_session, tenant_id="tenant-a", name="Corpus A2")
    create_corpus(db_session, tenant_id="tenant-b", name="Corpus B1")

    a_corpora = list_corpora(db_session, tenant_id="tenant-a")
    b_corpora = list_corpora(db_session, tenant_id="tenant-b")

    assert len(a_corpora) == 2
    assert all(c["tenant_id"] == "tenant-a" for c in a_corpora)
    assert len(b_corpora) == 1
    assert b_corpora[0]["tenant_id"] == "tenant-b"


def test_wrong_tenant_cannot_read_corpus(db_session):
    from api.rag_corpus_store import create_corpus, get_corpus

    corpus = create_corpus(db_session, tenant_id="tenant-owner", name="Private")
    corpus_id = corpus["corpus_id"]

    result = get_corpus(db_session, tenant_id="tenant-attacker", corpus_id=corpus_id)

    assert result is None, "Cross-tenant corpus read must return None"


def test_missing_tenant_rejected_for_corpus(db_session):
    from api.rag_corpus_store import create_corpus, list_corpora

    with pytest.raises(ValueError, match="tenant_id"):
        create_corpus(db_session, tenant_id="", name="X")

    with pytest.raises(ValueError, match="tenant_id"):
        create_corpus(db_session, tenant_id="   ", name="X")

    with pytest.raises(ValueError, match="tenant_id"):
        list_corpora(db_session, tenant_id="")  # type: ignore[arg-type]


def test_blank_corpus_name_rejected(db_session):
    from api.rag_corpus_store import create_corpus

    with pytest.raises(ValueError, match="name"):
        create_corpus(db_session, tenant_id="tenant-x", name="")

    with pytest.raises(ValueError, match="name"):
        create_corpus(db_session, tenant_id="tenant-x", name="   ")


def test_get_corpus_returns_none_for_missing(db_session):
    from api.rag_corpus_store import get_corpus

    result = get_corpus(db_session, tenant_id="tenant-x", corpus_id="corp-nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# rag_documents tests
# ---------------------------------------------------------------------------


def test_create_document_metadata_for_tenant_corpus(db_session):
    from api.rag_corpus_store import create_corpus, create_document

    corpus = create_corpus(db_session, tenant_id="tenant-doc", name="DocCorpus")
    doc = create_document(
        db_session,
        tenant_id="tenant-doc",
        corpus_id=corpus["corpus_id"],
        title="Guide to Testing",
        source="https://example.com/guide",
        metadata={"version": 2, "lang": "en"},
    )

    assert doc["document_id"].startswith("doc-")
    assert doc["tenant_id"] == "tenant-doc"
    assert doc["corpus_id"] == corpus["corpus_id"]
    assert doc["title"] == "Guide to Testing"
    assert doc["source"] == "https://example.com/guide"
    assert doc["metadata"] == {"version": 2, "lang": "en"}


def test_wrong_tenant_cannot_read_document(db_session):
    from api.rag_corpus_store import create_corpus, create_document, get_document

    corpus = create_corpus(db_session, tenant_id="tenant-owner", name="C")
    doc = create_document(
        db_session,
        tenant_id="tenant-owner",
        corpus_id=corpus["corpus_id"],
        title="Secret Doc",
    )

    result = get_document(
        db_session, tenant_id="tenant-attacker", document_id=doc["document_id"]
    )
    assert result is None, "Cross-tenant document read must return None"


def test_document_requires_corpus_owned_by_same_tenant(db_session):
    from api.rag_corpus_store import create_corpus, create_document

    corpus = create_corpus(db_session, tenant_id="tenant-owner", name="Owned")

    with pytest.raises(ValueError, match="corpus_id"):
        create_document(
            db_session,
            tenant_id="tenant-attacker",
            corpus_id=corpus["corpus_id"],
            title="Sneaky Doc",
        )


def test_list_documents_filters_by_tenant_corpus(db_session):
    from api.rag_corpus_store import create_corpus, create_document, list_documents

    ca = create_corpus(db_session, tenant_id="tenant-a", name="CA")
    cb = create_corpus(db_session, tenant_id="tenant-b", name="CB")

    create_document(
        db_session, tenant_id="tenant-a", corpus_id=ca["corpus_id"], title="D-A1"
    )
    create_document(
        db_session, tenant_id="tenant-a", corpus_id=ca["corpus_id"], title="D-A2"
    )
    create_document(
        db_session, tenant_id="tenant-b", corpus_id=cb["corpus_id"], title="D-B1"
    )

    docs_a = list_documents(db_session, tenant_id="tenant-a", corpus_id=ca["corpus_id"])
    docs_b = list_documents(db_session, tenant_id="tenant-b", corpus_id=cb["corpus_id"])

    assert len(docs_a) == 2
    assert all(d["tenant_id"] == "tenant-a" for d in docs_a)
    assert len(docs_b) == 1


# ---------------------------------------------------------------------------
# rag_chunks tests
# ---------------------------------------------------------------------------


def test_wrong_tenant_cannot_store_chunks(db_session):
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id="tenant-owner", name="C")
    doc = create_document(
        db_session,
        tenant_id="tenant-owner",
        corpus_id=corpus["corpus_id"],
        title="Doc",
    )

    with pytest.raises(ValueError, match="document_id"):
        store_chunks(
            db_session,
            tenant_id="tenant-attacker",
            document_id=doc["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[{"text": "hello", "ordinal": 0}],
        )


def test_store_chunks_for_tenant_document(db_session):
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id="tenant-x", name="CX")
    doc = create_document(
        db_session,
        tenant_id="tenant-x",
        corpus_id=corpus["corpus_id"],
        title="Doc X",
    )

    chunks = store_chunks(
        db_session,
        tenant_id="tenant-x",
        document_id=doc["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[
            {"text": "Chunk zero", "ordinal": 0},
            {"text": "Chunk one", "ordinal": 1},
        ],
    )

    assert len(chunks) == 2
    assert all(c["tenant_id"] == "tenant-x" for c in chunks)
    assert all(c["chunk_id"].startswith("ck-") for c in chunks)
    assert chunks[0]["ordinal"] == 0
    assert chunks[1]["ordinal"] == 1


def test_list_chunks_filters_by_tenant(db_session):
    from api.rag_corpus_store import (
        create_corpus,
        create_document,
        list_chunks,
        store_chunks,
    )

    ca = create_corpus(db_session, tenant_id="tenant-a", name="CA")
    cb = create_corpus(db_session, tenant_id="tenant-b", name="CB")
    da = create_document(
        db_session, tenant_id="tenant-a", corpus_id=ca["corpus_id"], title="DA"
    )
    db_ = create_document(
        db_session, tenant_id="tenant-b", corpus_id=cb["corpus_id"], title="DB"
    )

    store_chunks(
        db_session,
        tenant_id="tenant-a",
        document_id=da["document_id"],
        corpus_id=ca["corpus_id"],
        chunks=[{"text": "A chunk", "ordinal": 0}],
    )
    store_chunks(
        db_session,
        tenant_id="tenant-b",
        document_id=db_["document_id"],
        corpus_id=cb["corpus_id"],
        chunks=[
            {"text": "B chunk 1", "ordinal": 0},
            {"text": "B chunk 2", "ordinal": 1},
        ],
    )

    chunks_a = list_chunks(
        db_session, tenant_id="tenant-a", document_id=da["document_id"]
    )
    chunks_b = list_chunks(
        db_session, tenant_id="tenant-b", document_id=db_["document_id"]
    )

    assert len(chunks_a) == 1
    assert chunks_a[0]["tenant_id"] == "tenant-a"
    assert len(chunks_b) == 2
    assert all(c["tenant_id"] == "tenant-b" for c in chunks_b)


def test_chunk_ordering_is_stable(db_session):
    from api.rag_corpus_store import (
        create_corpus,
        create_document,
        list_chunks,
        store_chunks,
    )

    corpus = create_corpus(db_session, tenant_id="tenant-ord", name="Ord")
    doc = create_document(
        db_session,
        tenant_id="tenant-ord",
        corpus_id=corpus["corpus_id"],
        title="Ordering Test",
    )

    # Insert deliberately out of ordinal order to verify DB sort.
    store_chunks(
        db_session,
        tenant_id="tenant-ord",
        document_id=doc["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[
            {"text": "Third chunk", "ordinal": 2},
            {"text": "First chunk", "ordinal": 0},
            {"text": "Second chunk", "ordinal": 1},
        ],
    )

    chunks = list_chunks(
        db_session, tenant_id="tenant-ord", document_id=doc["document_id"]
    )
    assert [c["ordinal"] for c in chunks] == [0, 1, 2]
    assert chunks[0]["text"] == "First chunk"
    assert chunks[1]["text"] == "Second chunk"
    assert chunks[2]["text"] == "Third chunk"


def test_chunk_metadata_round_trips(db_session):
    from api.rag_corpus_store import (
        create_corpus,
        create_document,
        list_chunks,
        store_chunks,
    )

    corpus = create_corpus(db_session, tenant_id="tenant-meta", name="MetaTest")
    doc = create_document(
        db_session,
        tenant_id="tenant-meta",
        corpus_id=corpus["corpus_id"],
        title="Meta Doc",
    )

    meta_in = {"source_page": 3, "confidence": 0.95, "tags": ["alpha", "beta"]}
    store_chunks(
        db_session,
        tenant_id="tenant-meta",
        document_id=doc["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": "Meta chunk", "ordinal": 0, "metadata": meta_in}],
    )

    chunks = list_chunks(
        db_session, tenant_id="tenant-meta", document_id=doc["document_id"]
    )
    assert len(chunks) == 1
    assert chunks[0]["metadata"] == meta_in


def test_blank_chunk_text_rejected(db_session):
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id="tenant-blank", name="B")
    doc = create_document(
        db_session,
        tenant_id="tenant-blank",
        corpus_id=corpus["corpus_id"],
        title="Blank Test",
    )

    with pytest.raises(ValueError, match="blank"):
        store_chunks(
            db_session,
            tenant_id="tenant-blank",
            document_id=doc["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[{"text": "", "ordinal": 0}],
        )

    with pytest.raises(ValueError, match="blank"):
        store_chunks(
            db_session,
            tenant_id="tenant-blank",
            document_id=doc["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[{"text": "   ", "ordinal": 0}],
        )


def test_store_chunks_rejects_corpus_document_mismatch(db_session):
    """Chunks must not be stored when corpus_id disagrees with the document's actual corpus."""
    from api.rag_corpus_store import (
        create_corpus,
        create_document,
        list_chunks,
        store_chunks,
    )

    corpus_a = create_corpus(db_session, tenant_id="tenant-mismatch", name="Corpus A")
    corpus_b = create_corpus(db_session, tenant_id="tenant-mismatch", name="Corpus B")
    doc_a = create_document(
        db_session,
        tenant_id="tenant-mismatch",
        corpus_id=corpus_a["corpus_id"],
        title="Doc in Corpus A",
    )

    # Pass corpus_b's id but doc_a belongs to corpus_a — must be rejected.
    with pytest.raises(ValueError):
        store_chunks(
            db_session,
            tenant_id="tenant-mismatch",
            document_id=doc_a["document_id"],
            corpus_id=corpus_b["corpus_id"],
            chunks=[{"text": "misattributed chunk", "ordinal": 0}],
        )

    # Confirm zero chunks were inserted for either corpus.
    assert (
        list_chunks(
            db_session, tenant_id="tenant-mismatch", document_id=doc_a["document_id"]
        )
        == []
    )


def test_invalid_chunk_in_batch_inserts_zero_chunks(db_session):
    """If any chunk in a batch is invalid, no chunk from that batch is persisted."""
    from api.rag_corpus_store import (
        create_corpus,
        create_document,
        list_chunks,
        store_chunks,
    )

    corpus = create_corpus(db_session, tenant_id="tenant-partial", name="Partial")
    doc = create_document(
        db_session,
        tenant_id="tenant-partial",
        corpus_id=corpus["corpus_id"],
        title="Partial Batch Doc",
    )

    # First chunk is valid; second chunk has blank text — whole batch must be rejected.
    with pytest.raises(ValueError, match="blank"):
        store_chunks(
            db_session,
            tenant_id="tenant-partial",
            document_id=doc["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[
                {"text": "valid chunk", "ordinal": 0},
                {"text": "   ", "ordinal": 1},
            ],
        )

    # No chunks should have been persisted.
    assert (
        list_chunks(
            db_session, tenant_id="tenant-partial", document_id=doc["document_id"]
        )
        == []
    )


def test_corpus_persistence_does_not_call_retrieval(db_session):
    """
    api.rag_corpus_store must not import any retrieval module.
    (Docstring comments mentioning "retrieval" for context are permitted;
    import statements referencing a retrieval module are not.)
    """
    import api.rag_corpus_store as store_mod

    for attr_val in vars(store_mod).values():
        mod_name = getattr(attr_val, "__module__", "") or ""
        assert "retrieval" not in mod_name, (
            f"api.rag_corpus_store unexpectedly exposes retrieval module: {mod_name}"
        )

    spec = importlib.util.find_spec("api.rag_corpus_store")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        lines = fh.readlines()
    import_lines = [ln for ln in lines if ln.strip().startswith(("import ", "from "))]
    for line in import_lines:
        assert "retrieval" not in line, (
            f"api/rag_corpus_store.py must not import any retrieval module; found: {line.strip()}"
        )


def test_corpus_persistence_does_not_import_rag_stub(db_session):
    """
    api.rag_corpus_store must never import rag_stub.
    """
    spec = importlib.util.find_spec("api.rag_corpus_store")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()
    assert "rag_stub" not in source, (
        "api/rag_corpus_store.py must not import or reference rag_stub"
    )
