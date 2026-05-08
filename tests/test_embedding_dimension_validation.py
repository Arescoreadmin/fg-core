"""
tests/test_embedding_dimension_validation.py

Dimension validation tests for the embedding persistence layer.

Covers: correct dim accepted, short vector rejected, long vector rejected,
        declared vs actual mismatch, model registry mismatch.
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
    KNOWN_DIMENSIONS,
    canonical_content_hash,
)
from services.embeddings import (
    DimensionMismatchError,
    ensure_sqlite_schema,
    save_embedding,
    upsert_embedding,
)
from services.embeddings.persistence import _validate_dimensions

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-dim-test"
_CORPUS = "corpus-001"
_DOCUMENT = "doc-001"
_CHUNK = "chunk-001"
_TEXT = "Dimension validation test chunk."
_HASH = canonical_content_hash(_TEXT)
_NOW = datetime.now(timezone.utc)

# Use BGE_LARGE_EN (dim=1024) as the primary test model
_MODEL = EmbeddingModel.BGE_LARGE_EN
_DIM = KNOWN_DIMENSIONS[_MODEL]  # 1024


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    e = create_engine(f"sqlite:///{tmp_path / 'dim-test.db'}")
    ensure_sqlite_schema(e)
    return e


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session
        session.rollback()


def _record(
    *,
    model: EmbeddingModel = _MODEL,
    dimensions: int = _DIM,
    vector: tuple[float, ...] | None = None,
) -> ChunkEmbeddingRecord:
    if vector is None:
        vector = tuple(0.1 for _ in range(dimensions))
    return ChunkEmbeddingRecord(
        tenant_id=_TENANT,
        corpus_id=_CORPUS,
        document_id=_DOCUMENT,
        chunk_id=_CHUNK,
        content_hash=_HASH,
        embedding_model=model,
        dimensions=dimensions,
        vector=vector,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# _validate_dimensions unit tests
# ---------------------------------------------------------------------------


class TestValidateDimensions:
    def test_correct_dimension_passes(self):
        # Must not raise
        _validate_dimensions(_MODEL, _DIM, _DIM)

    def test_short_vector_rejected(self):
        with pytest.raises(DimensionMismatchError, match="EMBED_P002"):
            _validate_dimensions(_MODEL, _DIM, _DIM - 1)

    def test_long_vector_rejected(self):
        with pytest.raises(DimensionMismatchError, match="EMBED_P002"):
            _validate_dimensions(_MODEL, _DIM, _DIM + 1)

    def test_declared_mismatch_with_registry(self):
        wrong_dim = _DIM + 100
        with pytest.raises(DimensionMismatchError, match="EMBED_P002"):
            _validate_dimensions(_MODEL, wrong_dim, wrong_dim)

    def test_all_known_models_pass_correct_dimensions(self):
        for model, dim in KNOWN_DIMENSIONS.items():
            _validate_dimensions(model, dim, dim)


# ---------------------------------------------------------------------------
# Integration: persistence layer rejects invalid dimensions
# ---------------------------------------------------------------------------


class TestPersistenceLayerDimensionValidation:
    def test_correct_dimension_accepted(self, db):
        row = save_embedding(db, _record())
        assert row.dimensions == _DIM

    def test_short_vector_rejected_at_persistence(self, db):
        # ChunkEmbeddingRecord will reject vector/dim mismatch before we even
        # reach the persistence layer, but we verify the full stack fails.
        with pytest.raises(ValueError, match="EMBED_E005"):
            ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                embedding_model=_MODEL,
                dimensions=_DIM,
                vector=tuple(0.1 for _ in range(_DIM - 1)),  # too short
                created_at=_NOW,
            )

    def test_long_vector_rejected_at_persistence(self, db):
        with pytest.raises(ValueError, match="EMBED_E005"):
            ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                embedding_model=_MODEL,
                dimensions=_DIM,
                vector=tuple(0.1 for _ in range(_DIM + 1)),  # too long
                created_at=_NOW,
            )

    def test_declared_dim_mismatch_with_registry_rejected(self, db):
        # The vector length matches declared, but declared != KNOWN_DIMENSIONS
        wrong_dim = _DIM + 100
        with pytest.raises((DimensionMismatchError, ValueError)):
            # ChunkEmbeddingRecord enforces vector == declared.
            # persistence._validate_dimensions enforces declared == known.
            rec = ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                embedding_model=_MODEL,
                dimensions=wrong_dim,
                vector=tuple(0.1 for _ in range(wrong_dim)),
                created_at=_NOW,
            )
            save_embedding(db, rec)

    def test_upsert_also_validates_dimensions(self, db):
        wrong_dim = _DIM + 100
        with pytest.raises((DimensionMismatchError, ValueError)):
            rec = ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                embedding_model=_MODEL,
                dimensions=wrong_dim,
                vector=tuple(0.1 for _ in range(wrong_dim)),
                created_at=_NOW,
            )
            upsert_embedding(db, rec)

    def test_correct_openai_ada_dimensions(self, db):
        model = EmbeddingModel.OPENAI_ADA_002
        dim = KNOWN_DIMENSIONS[model]  # 1536
        row = save_embedding(
            db,
            ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id="chunk-ada",
                content_hash=_HASH,
                embedding_model=model,
                dimensions=dim,
                vector=tuple(0.01 for _ in range(dim)),
                created_at=_NOW,
            ),
        )
        assert row.dimensions == 1536

    def test_correct_voyage_dimensions(self, db):
        model = EmbeddingModel.VOYAGE_2
        dim = KNOWN_DIMENSIONS[model]  # 1024
        row = save_embedding(
            db,
            ChunkEmbeddingRecord(
                tenant_id=_TENANT,
                corpus_id=_CORPUS,
                document_id=_DOCUMENT,
                chunk_id="chunk-voyage",
                content_hash=canonical_content_hash("voyage content"),
                embedding_model=model,
                dimensions=dim,
                vector=tuple(0.02 for _ in range(dim)),
                created_at=_NOW,
            ),
        )
        assert row.dimensions == 1024
