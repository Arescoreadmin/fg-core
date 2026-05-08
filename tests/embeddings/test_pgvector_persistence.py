"""
tests/embeddings/test_pgvector_persistence.py

Persistence layer tests — SQLite backend (dev/test fallback).

Covers: insert, read, upsert, duplicate prevention, delete, list,
        embedding_exists, contract compatibility with PR 19 schemas.

No pgvector required; all tests use the SQLite fallback.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.embeddings import (
    ChunkEmbeddingRecord,
    EmbeddingModel,
    canonical_content_hash,
)
from services.embeddings import (
    DuplicateEmbeddingError,
    EmbeddingRow,
    TenantRequiredError,
    delete_embedding,
    embedding_exists,
    ensure_sqlite_schema,
    get_embedding_for_chunk,
    list_embeddings_for_corpus,
    save_embedding,
    upsert_embedding,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-alpha"
_CORPUS = "corpus-001"
_DOCUMENT = "doc-001"
_CHUNK = "chunk-001"
_TEXT = "The quick brown fox."
_HASH = canonical_content_hash(_TEXT)
_MODEL = EmbeddingModel.INSTRUCTOR_XL  # dim=768 — smallest for fast tests
_DIM = 768
_VECTOR = tuple(0.01 * i for i in range(_DIM))
_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    e = create_engine(f"sqlite:///{tmp_path / 'embed-test.db'}")
    ensure_sqlite_schema(e)
    return e


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session
        session.rollback()


def _record(**overrides: object) -> ChunkEmbeddingRecord:
    kwargs: dict[str, object] = dict(
        tenant_id=_TENANT,
        corpus_id=_CORPUS,
        document_id=_DOCUMENT,
        chunk_id=_CHUNK,
        content_hash=_HASH,
        embedding_model=_MODEL,
        dimensions=_DIM,
        vector=_VECTOR,
        created_at=_NOW,
    )
    kwargs.update(overrides)
    return ChunkEmbeddingRecord(**kwargs)


# ---------------------------------------------------------------------------
# Schema / DDL
# ---------------------------------------------------------------------------


class TestSqliteSchema:
    def test_schema_creates_table(self, engine):
        from sqlalchemy import inspect as sa_inspect

        inspector = sa_inspect(engine)
        assert "embedding_vectors" in inspector.get_table_names()

    def test_schema_idempotent(self, engine):
        # calling twice must not raise
        ensure_sqlite_schema(engine)
        from sqlalchemy import inspect as sa_inspect

        inspector = sa_inspect(engine)
        assert "embedding_vectors" in inspector.get_table_names()

    def test_schema_rejects_postgres_engine(self):
        # ensure_sqlite_schema must refuse to run against postgres engines
        from unittest.mock import MagicMock

        fake_engine = MagicMock()
        fake_engine.dialect.name = "postgresql"
        with pytest.raises(RuntimeError, match="postgres"):
            ensure_sqlite_schema(fake_engine)


# ---------------------------------------------------------------------------
# Insert / read
# ---------------------------------------------------------------------------


class TestSaveAndRead:
    def test_save_returns_embedding_row(self, db):
        row = save_embedding(db, _record())
        assert isinstance(row, EmbeddingRow)
        assert row.tenant_id == _TENANT
        assert row.chunk_id == _CHUNK
        assert row.model == _MODEL.value
        assert row.dimensions == _DIM
        assert len(row.vector) == _DIM

    def test_save_persists_to_db(self, db):
        saved = save_embedding(db, _record())
        fetched = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id=_CHUNK, model=_MODEL.value
        )
        assert fetched is not None
        assert fetched.id == saved.id
        assert fetched.content_hash == _HASH

    def test_get_returns_none_when_missing(self, db):
        result = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id="nonexistent-chunk"
        )
        assert result is None

    def test_get_scopes_to_tenant(self, db):
        save_embedding(db, _record(tenant_id="tenant-a"))
        result = get_embedding_for_chunk(db, tenant_id="tenant-b", chunk_id=_CHUNK)
        assert result is None

    def test_get_with_model_filter(self, db):
        # Save one embedding; lookup with wrong model returns None
        save_embedding(db, _record())
        result = get_embedding_for_chunk(
            db,
            tenant_id=_TENANT,
            chunk_id=_CHUNK,
            model=EmbeddingModel.BGE_LARGE_EN.value,
        )
        assert result is None

    def test_vector_round_trips_correctly(self, db):
        save_embedding(db, _record())
        fetched = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id=_CHUNK, model=_MODEL.value
        )
        assert fetched is not None
        assert len(fetched.vector) == _DIM
        assert abs(fetched.vector[0] - _VECTOR[0]) < 1e-6


# ---------------------------------------------------------------------------
# Duplicate prevention
# ---------------------------------------------------------------------------


class TestDuplicatePrevention:
    def test_save_twice_raises_duplicate(self, db):
        save_embedding(db, _record())
        with pytest.raises(DuplicateEmbeddingError):
            save_embedding(db, _record())

    def test_different_hash_is_allowed(self, db):
        save_embedding(db, _record())
        other_text = "Different content."
        row2 = save_embedding(
            db,
            _record(
                content_hash=canonical_content_hash(other_text),
                chunk_id="chunk-002",
            ),
        )
        assert row2.chunk_id == "chunk-002"

    def test_different_model_is_allowed(self, db):
        save_embedding(db, _record())
        # BGE_LARGE_EN dim=1024, use that
        row2 = save_embedding(
            db,
            _record(
                chunk_id="chunk-002",
                embedding_model=EmbeddingModel.BGE_LARGE_EN,
                dimensions=1024,
                vector=tuple(0.1 for _ in range(1024)),
            ),
        )
        assert row2.model == EmbeddingModel.BGE_LARGE_EN.value


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


class TestUpsert:
    def test_upsert_inserts_when_missing(self, db):
        row = upsert_embedding(db, _record())
        assert row.id is not None

    def test_upsert_is_idempotent_same_hash(self, db):
        row1 = upsert_embedding(db, _record())
        row2 = upsert_embedding(db, _record())
        # Same identity — should be the same row (updated, not duplicated)
        assert row1.content_hash == row2.content_hash
        all_rows = list_embeddings_for_corpus(db, tenant_id=_TENANT, corpus_id=_CORPUS)
        assert len(all_rows) == 1

    def test_upsert_updates_existing_row(self, db):
        upsert_embedding(db, _record())
        new_vector = tuple(0.99 for _ in range(_DIM))
        # same hash → same "identity"; update the vector
        upsert_embedding(db, _record(vector=new_vector))
        fetched = get_embedding_for_chunk(
            db, tenant_id=_TENANT, chunk_id=_CHUNK, model=_MODEL.value
        )
        assert fetched is not None
        assert abs(fetched.vector[0] - 0.99) < 1e-6


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_returns_true_when_found(self, db):
        row = save_embedding(db, _record())
        result = delete_embedding(db, tenant_id=_TENANT, embedding_id=row.id)
        assert result is True

    def test_delete_removes_row(self, db):
        row = save_embedding(db, _record())
        delete_embedding(db, tenant_id=_TENANT, embedding_id=row.id)
        fetched = get_embedding_for_chunk(db, tenant_id=_TENANT, chunk_id=_CHUNK)
        assert fetched is None

    def test_delete_returns_false_when_not_found(self, db):
        result = delete_embedding(db, tenant_id=_TENANT, embedding_id="nonexistent-id")
        assert result is False

    def test_delete_cannot_cross_tenant(self, db):
        row = save_embedding(db, _record(tenant_id="tenant-x"))
        # Delete with wrong tenant → returns False, row still exists
        result = delete_embedding(db, tenant_id="tenant-y", embedding_id=row.id)
        assert result is False
        still_there = get_embedding_for_chunk(db, tenant_id="tenant-x", chunk_id=_CHUNK)
        assert still_there is not None


# ---------------------------------------------------------------------------
# embedding_exists
# ---------------------------------------------------------------------------


class TestEmbeddingExists:
    def test_returns_false_when_missing(self, db):
        assert not embedding_exists(
            db,
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            chunk_id=_CHUNK,
            model=_MODEL.value,
            content_hash=_HASH,
        )

    def test_returns_true_after_insert(self, db):
        save_embedding(db, _record())
        assert embedding_exists(
            db,
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            chunk_id=_CHUNK,
            model=_MODEL.value,
            content_hash=_HASH,
        )

    def test_different_tenant_returns_false(self, db):
        save_embedding(db, _record())
        assert not embedding_exists(
            db,
            tenant_id="other-tenant",
            corpus_id=_CORPUS,
            chunk_id=_CHUNK,
            model=_MODEL.value,
            content_hash=_HASH,
        )


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class TestList:
    def test_list_empty_corpus(self, db):
        rows = list_embeddings_for_corpus(db, tenant_id=_TENANT, corpus_id=_CORPUS)
        assert rows == []

    def test_list_returns_saved_rows(self, db):
        save_embedding(db, _record(chunk_id="chunk-001"))
        save_embedding(db, _record(chunk_id="chunk-002"))
        rows = list_embeddings_for_corpus(db, tenant_id=_TENANT, corpus_id=_CORPUS)
        assert len(rows) == 2

    def test_list_scoped_to_corpus(self, db):
        save_embedding(db, _record(corpus_id=_CORPUS, chunk_id="chunk-001"))
        save_embedding(
            db,
            _record(corpus_id="corpus-other", chunk_id="chunk-002"),
        )
        rows = list_embeddings_for_corpus(db, tenant_id=_TENANT, corpus_id=_CORPUS)
        assert len(rows) == 1
        assert rows[0].corpus_id == _CORPUS

    def test_list_scoped_to_tenant(self, db):
        save_embedding(db, _record(tenant_id="tenant-a", chunk_id="chunk-a"))
        save_embedding(db, _record(tenant_id="tenant-b", chunk_id="chunk-b"))
        rows = list_embeddings_for_corpus(db, tenant_id="tenant-a", corpus_id=_CORPUS)
        assert len(rows) == 1
        assert rows[0].tenant_id == "tenant-a"


# ---------------------------------------------------------------------------
# Tenant requirement enforcement
# ---------------------------------------------------------------------------


class TestTenantRequirement:
    # ChunkEmbeddingRecord validates tenant_id itself (raises ValueError),
    # so for save/upsert we accept either ValueError or TenantRequiredError.
    @pytest.mark.parametrize("blank", ["", "   "])
    def test_save_rejects_blank_tenant(self, db, blank):
        with pytest.raises((TenantRequiredError, ValueError)):
            save_embedding(db, _record(tenant_id=blank))

    def test_get_rejects_blank_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            get_embedding_for_chunk(db, tenant_id="", chunk_id=_CHUNK)

    def test_list_rejects_blank_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            list_embeddings_for_corpus(db, tenant_id="", corpus_id=_CORPUS)

    def test_delete_rejects_blank_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            delete_embedding(db, tenant_id="", embedding_id="some-id")

    def test_exists_rejects_blank_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            embedding_exists(
                db,
                tenant_id="",
                corpus_id=_CORPUS,
                chunk_id=_CHUNK,
                model=_MODEL.value,
                content_hash=_HASH,
            )

    def test_upsert_rejects_blank_tenant(self, db):
        with pytest.raises((TenantRequiredError, ValueError)):
            upsert_embedding(db, _record(tenant_id=""))


# ---------------------------------------------------------------------------
# Contract compatibility with PR 19 (ChunkEmbeddingRecord)
# ---------------------------------------------------------------------------


class TestContractCompatibility:
    def test_accepts_chunk_embedding_record(self, db):
        rec = ChunkEmbeddingRecord(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            content_hash=_HASH,
            embedding_model=_MODEL,
            dimensions=_DIM,
            vector=_VECTOR,
            created_at=_NOW,
        )
        row = save_embedding(db, rec)
        assert row.model == _MODEL.value
        assert row.content_hash == _HASH

    def test_from_response_factory_compat(self, db):
        from api.embeddings import (
            EmbeddingMetadata,
            EmbeddingResponse,
        )

        meta = EmbeddingMetadata(
            model=_MODEL,
            dimensions=_DIM,
            corpus_id=_CORPUS,
            chunk_id=_CHUNK,
            content_hash=_HASH,
        )
        resp = EmbeddingResponse(
            chunk_id=_CHUNK,
            tenant_id=_TENANT,
            vector=_VECTOR,
            metadata=meta,
        )
        rec = ChunkEmbeddingRecord.from_response(
            resp, corpus_id=_CORPUS, document_id=_DOCUMENT
        )
        row = save_embedding(db, rec)
        assert row.tenant_id == _TENANT
        assert row.chunk_id == _CHUNK
