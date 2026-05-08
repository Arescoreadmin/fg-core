"""
tests/security/test_embedding_tenant_isolation.py

Proves tenant A cannot read, update, or delete tenant B's embeddings.
All operations require explicit tenant_id scope.
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
    TenantRequiredError,
    delete_embedding,
    embedding_exists,
    ensure_sqlite_schema,
    get_embedding_for_chunk,
    list_embeddings_for_corpus,
    save_embedding,
    upsert_embedding,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MODEL = EmbeddingModel.INSTRUCTOR_XL
_DIM = 768
_VECTOR = tuple(0.5 for _ in range(_DIM))
_CORPUS = "shared-corpus"
_DOCUMENT = "doc-001"
_NOW = datetime.now(timezone.utc)

_TENANT_A = "tenant-alpha"
_TENANT_B = "tenant-beta"


@pytest.fixture()
def engine(tmp_path):
    e = create_engine(f"sqlite:///{tmp_path / 'isolation-test.db'}")
    ensure_sqlite_schema(e)
    return e


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session
        session.rollback()


def _make_record(
    tenant_id: str,
    chunk_id: str,
    text: str = "some content",
) -> ChunkEmbeddingRecord:
    return ChunkEmbeddingRecord(
        tenant_id=tenant_id,
        corpus_id=_CORPUS,
        document_id=_DOCUMENT,
        chunk_id=chunk_id,
        content_hash=canonical_content_hash(text),
        embedding_model=_MODEL,
        dimensions=_DIM,
        vector=_VECTOR,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Read isolation
# ---------------------------------------------------------------------------


class TestReadIsolation:
    def test_tenant_a_cannot_read_tenant_b_chunk(self, db):
        save_embedding(db, _make_record(_TENANT_B, "chunk-b"))
        result = get_embedding_for_chunk(db, tenant_id=_TENANT_A, chunk_id="chunk-b")
        assert result is None, "Tenant A must not read Tenant B's embeddings"

    def test_get_requires_matching_tenant(self, db):
        row = save_embedding(db, _make_record(_TENANT_A, "chunk-a"))
        # Reading with correct tenant works
        found = get_embedding_for_chunk(db, tenant_id=_TENANT_A, chunk_id="chunk-a")
        assert found is not None
        assert found.id == row.id

    def test_list_returns_only_own_corpus(self, db):
        save_embedding(db, _make_record(_TENANT_A, "chunk-a1", "text a1"))
        save_embedding(db, _make_record(_TENANT_A, "chunk-a2", "text a2"))
        save_embedding(db, _make_record(_TENANT_B, "chunk-b1", "text b1"))

        a_rows = list_embeddings_for_corpus(db, tenant_id=_TENANT_A, corpus_id=_CORPUS)
        b_rows = list_embeddings_for_corpus(db, tenant_id=_TENANT_B, corpus_id=_CORPUS)

        assert len(a_rows) == 2
        assert len(b_rows) == 1
        assert all(r.tenant_id == _TENANT_A for r in a_rows)
        assert all(r.tenant_id == _TENANT_B for r in b_rows)

    def test_list_never_leaks_cross_tenant(self, db):
        save_embedding(db, _make_record(_TENANT_A, "chunk-a", "a content"))
        save_embedding(db, _make_record(_TENANT_B, "chunk-b", "b content"))

        for row in list_embeddings_for_corpus(
            db, tenant_id=_TENANT_A, corpus_id=_CORPUS
        ):
            assert row.tenant_id == _TENANT_A

        for row in list_embeddings_for_corpus(
            db, tenant_id=_TENANT_B, corpus_id=_CORPUS
        ):
            assert row.tenant_id == _TENANT_B


# ---------------------------------------------------------------------------
# Delete isolation
# ---------------------------------------------------------------------------


class TestDeleteIsolation:
    def test_tenant_b_cannot_delete_tenant_a_row(self, db):
        row = save_embedding(db, _make_record(_TENANT_A, "chunk-a"))

        # Attempting delete with wrong tenant must silently fail (not raise)
        deleted = delete_embedding(db, tenant_id=_TENANT_B, embedding_id=row.id)
        assert deleted is False

        # Row must still be accessible by the correct tenant
        still_there = get_embedding_for_chunk(
            db, tenant_id=_TENANT_A, chunk_id="chunk-a"
        )
        assert still_there is not None

    def test_delete_with_correct_tenant_succeeds(self, db):
        row = save_embedding(db, _make_record(_TENANT_A, "chunk-a"))
        deleted = delete_embedding(db, tenant_id=_TENANT_A, embedding_id=row.id)
        assert deleted is True

    def test_delete_requires_tenant(self, db):
        row = save_embedding(db, _make_record(_TENANT_A, "chunk-a"))
        with pytest.raises(TenantRequiredError):
            delete_embedding(db, tenant_id="", embedding_id=row.id)


# ---------------------------------------------------------------------------
# Update (upsert) isolation
# ---------------------------------------------------------------------------


class TestUpdateIsolation:
    def test_tenant_b_upsert_does_not_overwrite_tenant_a(self, db):
        original = save_embedding(
            db, _make_record(_TENANT_A, "chunk-shared", "original text a")
        )
        # Tenant B upserts with the same chunk_id but its own tenant scope
        new_text = "tenant b content"
        upsert_embedding(
            db,
            ChunkEmbeddingRecord(
                tenant_id=_TENANT_B,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id="chunk-shared",
                content_hash=canonical_content_hash(new_text),
                embedding_model=_MODEL,
                dimensions=_DIM,
                vector=_VECTOR,
                created_at=_NOW,
            ),
        )
        # Tenant A's row must be unchanged
        a_row = get_embedding_for_chunk(
            db, tenant_id=_TENANT_A, chunk_id="chunk-shared"
        )
        assert a_row is not None
        assert a_row.content_hash == original.content_hash

    def test_upsert_requires_tenant(self, db):
        # ChunkEmbeddingRecord validates tenant_id; accept either error
        with pytest.raises((TenantRequiredError, ValueError)):
            upsert_embedding(db, _make_record("", "chunk-x"))


# ---------------------------------------------------------------------------
# Existence check isolation
# ---------------------------------------------------------------------------


class TestExistsIsolation:
    def test_tenant_a_existence_invisible_to_tenant_b(self, db):
        rec = _make_record(_TENANT_A, "chunk-a")
        save_embedding(db, rec)

        exists_for_b = embedding_exists(
            db,
            tenant_id=_TENANT_B,
            chunk_id="chunk-a",
            model=_MODEL.value,
            content_hash=rec.content_hash,
        )
        assert exists_for_b is False

    def test_exists_requires_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            embedding_exists(
                db,
                tenant_id="",
                chunk_id="chunk-a",
                model=_MODEL.value,
                content_hash="somehash",
            )


# ---------------------------------------------------------------------------
# No cross-tenant ID lookup
# ---------------------------------------------------------------------------


class TestNoIdOnlyLookup:
    def test_get_by_chunk_id_requires_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            get_embedding_for_chunk(db, tenant_id="", chunk_id="chunk-a")

    def test_list_requires_tenant(self, db):
        with pytest.raises(TenantRequiredError):
            list_embeddings_for_corpus(db, tenant_id="", corpus_id=_CORPUS)
