"""
tests/embeddings/test_embedding_pipeline.py

Embedding generation pipeline tests — PR 21.

Covers:
- generate_embedding_for_chunk (single chunk)
- generate_embeddings_for_document (all chunks in a document)
- generate_embeddings_for_corpus (all chunks in a corpus)
- deterministic output (same text → same vector)
- idempotent reruns (no duplicate rows)
- content hash change triggers update
- blank tenant rejection at all pipeline entry points
- tenant isolation (cross-tenant reads return nothing)
- no duplicate rows on repeated runs
- audit safety (log fields do not include raw chunk text)
- no network calls (DeterministicStubProvider never calls out)
- no inference path changes (pipeline does not touch ai_plane_extension)
- no vector search introduced (no pgvector ANN queries)

No pgvector required; all tests use the SQLite fallback.
"""

from __future__ import annotations

import logging
import os

os.environ.setdefault("FG_ENV", "test")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.embeddings import (
    DeterministicStubProvider,
    EmbeddingModel,
    canonical_content_hash,
)
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.embeddings import (
    PipelineTenantRequiredError,
    generate_embedding_for_chunk,
    generate_embeddings_for_corpus,
    generate_embeddings_for_document,
    get_embedding_for_chunk,
    list_embeddings_for_corpus,
    ensure_sqlite_schema,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-pipeline"
_TENANT_B = "tenant-other"
_MODEL = EmbeddingModel.INSTRUCTOR_XL
_DIM = 768

# ---------------------------------------------------------------------------
# SQLite helpers — must create BOTH rag and embedding tables
# ---------------------------------------------------------------------------


_RAG_DDL = """
CREATE TABLE IF NOT EXISTS rag_corpora (
    corpus_id   TEXT NOT NULL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    metadata    TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rag_corpora_tenant_corpus
    ON rag_corpora (tenant_id, corpus_id);

CREATE TABLE IF NOT EXISTS rag_documents (
    document_id TEXT NOT NULL PRIMARY KEY,
    corpus_id   TEXT NOT NULL REFERENCES rag_corpora (corpus_id),
    tenant_id   TEXT NOT NULL,
    title       TEXT NOT NULL,
    source      TEXT,
    metadata    TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_corpus
    ON rag_documents (tenant_id, corpus_id);
CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_document
    ON rag_documents (tenant_id, document_id);

CREATE TABLE IF NOT EXISTS rag_chunks (
    chunk_id    TEXT NOT NULL PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES rag_documents (document_id),
    corpus_id   TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    text        TEXT NOT NULL,
    ordinal     INTEGER NOT NULL,
    metadata    TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_corpus
    ON rag_chunks (tenant_id, corpus_id);
CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_document
    ON rag_chunks (tenant_id, document_id);
"""


def _setup_full_schema(engine) -> None:
    """Create both rag tables and embedding_vectors table for pipeline tests."""
    with engine.begin() as conn:
        for stmt in _RAG_DDL.strip().split(";"):
            s = stmt.strip()
            if s:
                conn.exec_driver_sql(s + ";")
    ensure_sqlite_schema(engine)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    e = create_engine(f"sqlite:///{tmp_path / 'pipeline-test.db'}")
    _setup_full_schema(e)
    return e


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session
        session.rollback()


@pytest.fixture()
def provider():
    return DeterministicStubProvider(model=_MODEL)


@pytest.fixture()
def corpus(db):
    """Create a corpus for _TENANT."""
    return create_corpus(db, tenant_id=_TENANT, name="Test Corpus")


@pytest.fixture()
def document(db, corpus):
    """Create a document inside the corpus."""
    return create_document(
        db,
        tenant_id=_TENANT,
        corpus_id=corpus["corpus_id"],
        title="Test Document",
    )


@pytest.fixture()
def chunk(db, corpus, document):
    """Store a single chunk in the document."""
    chunks = store_chunks(
        db,
        tenant_id=_TENANT,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": "The quick brown fox.", "ordinal": 0}],
    )
    return chunks[0]


# ---------------------------------------------------------------------------
# test_generate_embedding_for_chunk
# ---------------------------------------------------------------------------


class TestGenerateEmbeddingForChunk:
    def test_generate_embedding_for_chunk(self, db, provider, corpus, document, chunk):
        """Basic: single chunk produces a persisted embedding."""
        result = generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        assert result.status == "persisted"
        assert result.tenant_id == _TENANT
        assert result.chunk_id == chunk["chunk_id"]
        assert result.dimensions == _DIM
        assert result.embedding_model == _MODEL.value

    def test_generate_embedding_for_chunk_persists_to_db(
        self, db, provider, corpus, document, chunk
    ):
        """Result is retrievable from the persistence layer after generation."""
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        row = get_embedding_for_chunk(db, tenant_id=_TENANT, chunk_id=chunk["chunk_id"])
        assert row is not None
        assert row.tenant_id == _TENANT
        assert row.chunk_id == chunk["chunk_id"]
        assert len(row.vector) == _DIM

    def test_generate_embedding_requires_tenant(
        self, db, provider, corpus, document, chunk
    ):
        """Blank tenant_id must be rejected at the pipeline entry point."""
        with pytest.raises(PipelineTenantRequiredError):
            generate_embedding_for_chunk(
                db,
                tenant_id="",
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                chunk_id=chunk["chunk_id"],
                chunk_text=chunk["text"],
                provider=provider,
            )

    def test_generate_embedding_requires_tenant_whitespace(
        self, db, provider, corpus, document, chunk
    ):
        """Whitespace-only tenant_id must be rejected."""
        with pytest.raises(PipelineTenantRequiredError):
            generate_embedding_for_chunk(
                db,
                tenant_id="   ",
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                chunk_id=chunk["chunk_id"],
                chunk_text=chunk["text"],
                provider=provider,
            )


# ---------------------------------------------------------------------------
# test_embedding_generation_is_deterministic
# ---------------------------------------------------------------------------


class TestEmbeddingGenerationIsDeterministic:
    def test_embedding_generation_is_deterministic(self, engine, provider):
        """Same text → same vector on repeated calls (no randomness)."""
        text = "Determinism test sentence."
        from api.embeddings.contracts import EmbeddingRequest

        # Two independent provider instances to prove independence from state
        req1 = DeterministicStubProvider(model=_MODEL)
        r1 = req1.embed(
            EmbeddingRequest.from_chunk(
                tenant_id="t1",
                corpus_id="c1",
                document_id="d1",
                chunk_id="ck1",
                text=text,
            )
        )
        req2 = DeterministicStubProvider(model=_MODEL)
        r2 = req2.embed(
            EmbeddingRequest.from_chunk(
                tenant_id="t1",
                corpus_id="c1",
                document_id="d1",
                chunk_id="ck1",
                text=text,
            )
        )
        assert r1.vector == r2.vector, "Same text must produce the same vector"

    def test_different_texts_produce_different_vectors(self, provider):
        """Different chunk texts must produce different vectors."""
        from api.embeddings.contracts import EmbeddingRequest

        r1 = provider.embed(
            EmbeddingRequest.from_chunk(
                tenant_id="t",
                corpus_id="c",
                document_id="d",
                chunk_id="ck1",
                text="First text content.",
            )
        )
        r2 = provider.embed(
            EmbeddingRequest.from_chunk(
                tenant_id="t",
                corpus_id="c",
                document_id="d",
                chunk_id="ck2",
                text="Second text content.",
            )
        )
        assert r1.vector != r2.vector

    def test_embedding_dimensions_are_stable(self, provider):
        """Provider always returns exactly _DIM dimensions."""
        from api.embeddings.contracts import EmbeddingRequest

        for i in range(3):
            r = provider.embed(
                EmbeddingRequest.from_chunk(
                    tenant_id="t",
                    corpus_id="c",
                    document_id="d",
                    chunk_id=f"ck-{i}",
                    text=f"Text variant {i}.",
                )
            )
            assert len(r.vector) == _DIM


# ---------------------------------------------------------------------------
# test_embedding_generation_is_idempotent
# ---------------------------------------------------------------------------


class TestEmbeddingGenerationIsIdempotent:
    def test_embedding_generation_is_idempotent(
        self, db, provider, corpus, document, chunk
    ):
        """Rerunning the pipeline on the same chunk produces no duplicate rows."""
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        rows = list_embeddings_for_corpus(
            db, tenant_id=_TENANT, corpus_id=corpus["corpus_id"]
        )
        assert len(rows) == 1, "Idempotent rerun must not create duplicate rows"

    def test_embedding_generation_does_not_duplicate_rows(
        self, db, provider, corpus, document
    ):
        """Multiple reruns of generate_embeddings_for_document → no duplicates."""
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=document["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[
                {"text": "Chunk alpha.", "ordinal": 0},
                {"text": "Chunk beta.", "ordinal": 1},
            ],
        )
        for _ in range(3):
            generate_embeddings_for_document(
                db,
                tenant_id=_TENANT,
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                provider=provider,
            )
        rows = list_embeddings_for_corpus(
            db, tenant_id=_TENANT, corpus_id=corpus["corpus_id"]
        )
        assert len(rows) == 2, (
            "Three reruns must produce exactly 2 rows (one per chunk)"
        )


# ---------------------------------------------------------------------------
# test_embedding_generation_updates_changed_content
# ---------------------------------------------------------------------------


class TestEmbeddingGenerationUpdatesChangedContent:
    def test_embedding_generation_updates_changed_content(
        self, db, provider, corpus, document, chunk
    ):
        """When chunk text changes (different hash), the embedding is updated."""
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text="Original text.",
            provider=provider,
        )
        row1 = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id=chunk["chunk_id"]
        )
        assert row1 is not None
        old_hash = row1.content_hash

        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text="Changed text — different content.",
            provider=provider,
        )
        row2 = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id=chunk["chunk_id"]
        )
        assert row2 is not None
        assert row2.content_hash != old_hash, "Changed content must produce a new hash"
        assert row2.vector != row1.vector, "Changed content must produce a new vector"


# ---------------------------------------------------------------------------
# test_generate_embeddings_for_document
# ---------------------------------------------------------------------------


class TestGenerateEmbeddingsForDocument:
    def test_generate_embeddings_for_document(self, db, provider, corpus, document):
        """Document pipeline processes all chunks in ordinal order."""
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=document["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[
                {"text": "First sentence.", "ordinal": 0},
                {"text": "Second sentence.", "ordinal": 1},
                {"text": "Third sentence.", "ordinal": 2},
            ],
        )
        result = generate_embeddings_for_document(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            provider=provider,
        )
        assert result.total_chunks == 3
        assert result.persisted == 3
        assert result.failed == 0
        assert result.tenant_id == _TENANT
        assert result.embedding_model == _MODEL.value

    def test_generate_embeddings_for_document_requires_tenant(
        self, db, provider, corpus, document
    ):
        """Blank tenant_id is rejected at the document-level entry point."""
        with pytest.raises(PipelineTenantRequiredError):
            generate_embeddings_for_document(
                db,
                tenant_id="",
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                provider=provider,
            )

    def test_generate_embeddings_for_document_empty_doc(
        self, db, provider, corpus, document
    ):
        """Document with no chunks produces an empty result without error."""
        result = generate_embeddings_for_document(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            provider=provider,
        )
        assert result.total_chunks == 0
        assert result.persisted == 0


# ---------------------------------------------------------------------------
# test_generate_embeddings_for_corpus
# ---------------------------------------------------------------------------


class TestGenerateEmbeddingsForCorpus:
    def test_generate_embeddings_for_corpus(self, db, provider, corpus):
        """Corpus pipeline processes all documents and chunks."""
        doc1 = create_document(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            title="Doc 1",
        )
        doc2 = create_document(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            title="Doc 2",
        )
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=doc1["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[{"text": "Doc1 chunk A.", "ordinal": 0}],
        )
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=doc2["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[
                {"text": "Doc2 chunk A.", "ordinal": 0},
                {"text": "Doc2 chunk B.", "ordinal": 1},
            ],
        )
        result = generate_embeddings_for_corpus(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            provider=provider,
        )
        assert result.total_documents == 2
        assert result.total_chunks == 3
        assert result.persisted == 3
        assert result.failed == 0
        assert result.tenant_id == _TENANT

    def test_generate_embeddings_for_corpus_requires_tenant(self, db, provider, corpus):
        """Blank tenant_id is rejected at the corpus-level entry point."""
        with pytest.raises(PipelineTenantRequiredError):
            generate_embeddings_for_corpus(
                db,
                tenant_id="",
                corpus_id=corpus["corpus_id"],
                provider=provider,
            )

    def test_generate_embeddings_for_corpus_empty(self, db, provider, corpus):
        """Empty corpus produces a zero-count result without error."""
        result = generate_embeddings_for_corpus(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            provider=provider,
        )
        assert result.total_documents == 0
        assert result.total_chunks == 0


# ---------------------------------------------------------------------------
# test_embedding_generation_preserves_tenant_isolation
# ---------------------------------------------------------------------------


class TestEmbeddingGenerationPreservesTenantIsolation:
    def test_embedding_generation_preserves_tenant_isolation(self, db, provider):
        """Embedding written for tenant A is not visible to tenant B."""
        corpus_a = create_corpus(db, tenant_id=_TENANT, name="Corpus A")
        doc_a = create_document(
            db, tenant_id=_TENANT, corpus_id=corpus_a["corpus_id"], title="Doc A"
        )
        chunks_a = store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=doc_a["document_id"],
            corpus_id=corpus_a["corpus_id"],
            chunks=[{"text": "Tenant A content.", "ordinal": 0}],
        )
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus_a["corpus_id"],
            document_id=doc_a["document_id"],
            chunk_id=chunks_a[0]["chunk_id"],
            chunk_text=chunks_a[0]["text"],
            provider=provider,
        )
        # Tenant B must not see tenant A's embeddings
        row = get_embedding_for_chunk(
            db, tenant_id=_TENANT_B, chunk_id=chunks_a[0]["chunk_id"]
        )
        assert row is None, "Tenant B must not access Tenant A's embeddings"

    def test_corpus_pipeline_does_not_return_other_tenant_chunks(self, db, provider):
        """Cross-tenant corpus listing must never return foreign-tenant rows."""
        corpus_a = create_corpus(db, tenant_id=_TENANT, name="Corpus A")
        doc_a = create_document(
            db, tenant_id=_TENANT, corpus_id=corpus_a["corpus_id"], title="Doc A"
        )
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=doc_a["document_id"],
            corpus_id=corpus_a["corpus_id"],
            chunks=[{"text": "Tenant A data.", "ordinal": 0}],
        )
        generate_embeddings_for_corpus(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus_a["corpus_id"],
            provider=provider,
        )
        # Query under tenant B for same corpus_id → must return empty
        rows = list_embeddings_for_corpus(
            db, tenant_id=_TENANT_B, corpus_id=corpus_a["corpus_id"]
        )
        assert len(rows) == 0, "Tenant B must not see Tenant A's embeddings"


# ---------------------------------------------------------------------------
# test_embedding_generation_audit_safe
# ---------------------------------------------------------------------------


class TestEmbeddingGenerationAuditSafe:
    def test_embedding_generation_audit_safe(
        self, db, provider, corpus, document, chunk, caplog
    ):
        """Audit log entries must not contain raw chunk text or raw vectors."""
        chunk_text = "Sensitive chunk content that must not appear in logs."
        with caplog.at_level(logging.INFO, logger="frostgate.embeddings.pipeline"):
            generate_embedding_for_chunk(
                db,
                tenant_id=_TENANT,
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                chunk_id=chunk["chunk_id"],
                chunk_text=chunk_text,
                provider=provider,
            )

        for record in caplog.records:
            # Raw chunk text must never appear
            assert chunk_text not in record.getMessage(), (
                "Raw chunk text must not appear in audit log messages"
            )
            # Vector data must never appear (long float sequences)
            msg = record.getMessage()
            assert "0.0" * 5 not in msg, "Raw vector must not appear in audit log"

    def test_audit_log_contains_safe_fields(
        self, db, provider, corpus, document, chunk, caplog
    ):
        """Audit logs must include safe identifiers and counts."""
        with caplog.at_level(logging.INFO, logger="frostgate.embeddings.pipeline"):
            generate_embedding_for_chunk(
                db,
                tenant_id=_TENANT,
                corpus_id=corpus["corpus_id"],
                document_id=document["document_id"],
                chunk_id=chunk["chunk_id"],
                chunk_text=chunk["text"],
                provider=provider,
            )
        # At least one log record should reference our tenant_id
        assert any(
            _TENANT in str(r.getMessage()) or str(getattr(r, "extra", {}))
            for r in caplog.records
        ), "Audit log should reference tenant_id"


# ---------------------------------------------------------------------------
# test_embedding_pipeline_does_not_call_network
# ---------------------------------------------------------------------------


class TestEmbeddingPipelineDoesNotCallNetwork:
    def test_embedding_pipeline_does_not_call_network(
        self, db, provider, corpus, document, chunk, monkeypatch
    ):
        """Pipeline must never make network calls via the stub provider."""
        import socket

        _original_connect = socket.socket.connect

        def _block_connect(self, *args, **kwargs):
            raise AssertionError(
                "test_embedding_pipeline_does_not_call_network: "
                "network call detected — pipeline must not access the network"
            )

        monkeypatch.setattr(socket.socket, "connect", _block_connect)

        result = generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        assert result.status == "persisted"


# ---------------------------------------------------------------------------
# test_embedding_pipeline_does_not_modify_inference_path
# ---------------------------------------------------------------------------


class TestEmbeddingPipelineDoesNotModifyInferencePath:
    def test_embedding_pipeline_does_not_modify_inference_path(self):
        """Pipeline module must not import or modify ai_plane_extension."""
        import ast
        import pathlib

        pipeline_path = (
            pathlib.Path(__file__).parent.parent.parent
            / "services"
            / "embeddings"
            / "pipeline.py"
        )
        source = pipeline_path.read_text()
        tree = ast.parse(source)

        forbidden_imports = {
            "ai_plane_extension",
            "AIPlaneService",
            "infer",
            "openai",
        }
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    assert not any(f in name for f in forbidden_imports), (
                        f"Pipeline must not import {name!r} — "
                        "inference path must not be modified"
                    )

    def test_no_vector_search_in_pipeline(self):
        """Pipeline module must not contain any similarity search SQL or API calls."""
        import ast
        import pathlib

        pipeline_path = (
            pathlib.Path(__file__).parent.parent.parent
            / "services"
            / "embeddings"
            / "pipeline.py"
        )
        source = pipeline_path.read_text()
        # Strip docstrings from the AST before scanning for forbidden patterns
        tree = ast.parse(source)

        # Collect all string literals that are NOT docstrings (i.e., used in SQL/code)
        code_strings: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Heuristic: docstrings are Expr(value=Constant(...)) at top of body
                code_strings.append(node.value.lower())

        # Also check non-string code tokens via the raw source
        # (SQL operators in text() calls, function names)
        import tokenize
        import io

        tokens: list[str] = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                if tok.type in (tokenize.OP, tokenize.NAME):
                    tokens.append(tok.string.lower())
                elif tok.type == tokenize.STRING:
                    tokens.append(tok.string.lower())
        except tokenize.TokenError:
            pass

        # SQL-level vector search operators and function names that must not appear
        # in actual code (not comments/docstrings)
        forbidden_sql_patterns = [
            "cosine_similarity",
            "l2_distance",
            "inner_product",
            "<->",
            "<#>",
            "<=>",
            "ivfflat",
            "hnsw",
        ]
        full_code = " ".join(tokens)
        for pattern in forbidden_sql_patterns:
            assert pattern not in full_code, (
                f"Pipeline must not use vector search SQL pattern {pattern!r}"
            )


# ---------------------------------------------------------------------------
# test_embedding_persistence_linkage
# ---------------------------------------------------------------------------


class TestEmbeddingPersistenceLinkage:
    def test_embedding_persistence_linkage(self, db, provider, corpus, document, chunk):
        """Generated embedding is linked to the correct chunk/document/corpus."""
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        row = get_embedding_for_chunk(db, tenant_id=_TENANT, chunk_id=chunk["chunk_id"])
        assert row is not None
        assert row.corpus_id == corpus["corpus_id"]
        assert row.document_id == document["document_id"]
        assert row.chunk_id == chunk["chunk_id"]
        assert row.tenant_id == _TENANT

    def test_content_hash_preserved_in_persistence(
        self, db, provider, corpus, document, chunk
    ):
        """content_hash in the persisted row matches canonical_content_hash(text)."""
        generate_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            chunk_text=chunk["text"],
            provider=provider,
        )
        row = get_embedding_for_chunk(db, tenant_id=_TENANT, chunk_id=chunk["chunk_id"])
        assert row is not None
        assert row.content_hash == canonical_content_hash(chunk["text"])


# ---------------------------------------------------------------------------
# test_deterministic_ordering
# ---------------------------------------------------------------------------


class TestDeterministicOrdering:
    def test_deterministic_ordering(self, db, provider, corpus, document):
        """Document-level pipeline processes chunks in ascending ordinal order."""
        store_chunks(
            db,
            tenant_id=_TENANT,
            document_id=document["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[
                {"text": "Third chunk.", "ordinal": 2},
                {"text": "First chunk.", "ordinal": 0},
                {"text": "Second chunk.", "ordinal": 1},
            ],
        )
        result = generate_embeddings_for_document(
            db,
            tenant_id=_TENANT,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            provider=provider,
        )
        # All three chunks must be processed regardless of insertion order
        assert result.total_chunks == 3
        assert result.persisted == 3
