"""
tests/embeddings/test_embedding_contracts.py

Contract-level tests for the embedding architecture (PR 19).

These tests verify:
- Field-level validation and error codes on all request/response types
- canonical_content_hash consistency guarantees
- ChunkEmbeddingRecord construction and from_response factory
- EmbeddingState transition guard correctness
- EmbeddingProvider Protocol structural satisfaction
- KNOWN_DIMENSIONS completeness
- No I/O, no provider calls, no DB — pure contract verification.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from api.embeddings import (
    EMBED_ERR_DIMENSION_MISMATCH,
    EMBED_ERR_EMPTY_TEXT,
    EMBED_ERR_EMPTY_VECTOR,
    EMBED_ERR_MISSING_CHUNK,
    EMBED_ERR_MISSING_CORPUS,
    EMBED_ERR_MISSING_DOCUMENT,
    EMBED_ERR_MISSING_HASH,
    EMBED_ERR_MISSING_TENANT,
    KNOWN_DIMENSIONS,
    ChunkEmbeddingRecord,
    EmbeddingMetadata,
    EmbeddingModel,
    EmbeddingProvider,
    EmbeddingRequest,
    EmbeddingResponse,
    EmbeddingState,
    canonical_content_hash,
    expected_dimensions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc

_TENANT = "tenant-abc"
_CORPUS = "corpus-001"
_DOCUMENT = "doc-001"
_CHUNK = "chunk-001"
_TEXT = "The quick brown fox jumps over the lazy dog."
_HASH = canonical_content_hash(_TEXT)
_DIM = 1536
_VECTOR = tuple(0.1 for _ in range(_DIM))
_NOW = datetime.now(_UTC)


def _metadata(
    *,
    model: EmbeddingModel = EmbeddingModel.OPENAI_ADA_002,
    dimensions: int = _DIM,
    corpus_id: str = _CORPUS,
    chunk_id: str = _CHUNK,
    content_hash: str = _HASH,
    created_at: datetime = _NOW,
) -> EmbeddingMetadata:
    return EmbeddingMetadata(
        model=model,
        dimensions=dimensions,
        corpus_id=corpus_id,
        chunk_id=chunk_id,
        content_hash=content_hash,
        created_at=created_at,
    )


def _response(
    *,
    chunk_id: str = _CHUNK,
    tenant_id: str = _TENANT,
    vector: tuple[float, ...] = _VECTOR,
    meta: EmbeddingMetadata | None = None,
) -> EmbeddingResponse:
    return EmbeddingResponse(
        chunk_id=chunk_id,
        tenant_id=tenant_id,
        vector=vector,
        metadata=meta or _metadata(),
    )


# ===========================================================================
# canonical_content_hash
# ===========================================================================


class TestCanonicalContentHash:
    def test_matches_sha256_utf8(self) -> None:
        expected = hashlib.sha256(_TEXT.encode("utf-8")).hexdigest()
        assert canonical_content_hash(_TEXT) == expected

    def test_same_text_same_hash(self) -> None:
        assert canonical_content_hash(_TEXT) == canonical_content_hash(_TEXT)

    def test_different_text_different_hash(self) -> None:
        assert canonical_content_hash("foo") != canonical_content_hash("bar")

    def test_empty_string_is_stable(self) -> None:
        h = canonical_content_hash("")
        assert h == canonical_content_hash("")
        assert len(h) == 64  # SHA-256 hex

    def test_unicode_canonical(self) -> None:
        # Unicode text must hash consistently across environments
        text = "naïve café résumé"
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert canonical_content_hash(text) == h


# ===========================================================================
# EmbeddingRequest
# ===========================================================================


class TestEmbeddingRequest:
    def test_valid_construction(self) -> None:
        req = EmbeddingRequest(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
            content_hash=_HASH,
        )
        assert req.tenant_id == _TENANT
        assert req.content_hash == _HASH

    def test_from_chunk_factory_computes_hash(self) -> None:
        req = EmbeddingRequest.from_chunk(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
        )
        assert req.content_hash == canonical_content_hash(_TEXT)

    def test_verify_hash_passes(self) -> None:
        req = EmbeddingRequest.from_chunk(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
        )
        assert req.verify_hash() is True

    def test_verify_hash_detects_mismatch(self) -> None:
        req = EmbeddingRequest(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
            content_hash="deadbeef" * 8,
        )
        assert req.verify_hash() is False

    def test_is_frozen(self) -> None:
        req = EmbeddingRequest.from_chunk(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
        )
        with pytest.raises((AttributeError, TypeError)):
            req.tenant_id = "other"  # type: ignore[misc]

    @pytest.mark.parametrize(
        "field,value,code",
        [
            ("tenant_id", "", EMBED_ERR_MISSING_TENANT),
            ("tenant_id", "   ", EMBED_ERR_MISSING_TENANT),
            ("corpus_id", "", EMBED_ERR_MISSING_CORPUS),
            ("document_id", "", EMBED_ERR_MISSING_DOCUMENT),
            ("chunk_id", "", EMBED_ERR_MISSING_CHUNK),
            ("text", "", EMBED_ERR_EMPTY_TEXT),
            ("text", "   ", EMBED_ERR_EMPTY_TEXT),
            ("content_hash", "", EMBED_ERR_MISSING_HASH),
        ],
    )
    def test_rejects_blank_required_fields(
        self, field: str, value: str, code: str
    ) -> None:
        kwargs: dict = dict(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
            content_hash=_HASH,
        )
        kwargs[field] = value
        with pytest.raises(ValueError, match=code):
            EmbeddingRequest(**kwargs)

    def test_metadata_defaults_to_empty_dict(self) -> None:
        req = EmbeddingRequest.from_chunk(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
        )
        assert req.metadata == {}

    def test_metadata_passed_through(self) -> None:
        meta = {"source": "manual", "page": 3}
        req = EmbeddingRequest.from_chunk(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
            metadata=meta,
        )
        assert req.metadata == meta


# ===========================================================================
# EmbeddingMetadata
# ===========================================================================


class TestEmbeddingMetadata:
    def test_valid_construction(self) -> None:
        m = _metadata()
        assert m.model == EmbeddingModel.OPENAI_ADA_002
        assert m.dimensions == _DIM

    def test_created_at_defaults_to_utc_aware(self) -> None:
        m = EmbeddingMetadata(
            model=EmbeddingModel.OPENAI_ADA_002,
            dimensions=_DIM,
            corpus_id=_CORPUS,
            chunk_id=_CHUNK,
            content_hash=_HASH,
        )
        assert m.created_at.tzinfo is not None

    def test_rejects_naive_datetime(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            EmbeddingMetadata(
                model=EmbeddingModel.OPENAI_ADA_002,
                dimensions=_DIM,
                corpus_id=_CORPUS,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                created_at=datetime(2025, 1, 1),  # naive
            )

    def test_rejects_zero_dimensions(self) -> None:
        with pytest.raises(ValueError):
            EmbeddingMetadata(
                model=EmbeddingModel.OPENAI_ADA_002,
                dimensions=0,
                corpus_id=_CORPUS,
                chunk_id=_CHUNK,
                content_hash=_HASH,
                created_at=_NOW,
            )

    def test_rejects_blank_corpus_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_CORPUS):
            _metadata(corpus_id="")

    def test_rejects_blank_chunk_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_CHUNK):
            _metadata(chunk_id="")

    def test_rejects_blank_content_hash(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_HASH):
            _metadata(content_hash="")


# ===========================================================================
# EmbeddingResponse
# ===========================================================================


class TestEmbeddingResponse:
    def test_valid_construction(self) -> None:
        resp = _response()
        assert resp.chunk_id == _CHUNK
        assert len(resp.vector) == _DIM

    def test_rejects_empty_vector(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_EMPTY_VECTOR):
            _response(vector=())

    def test_rejects_dimension_mismatch(self) -> None:
        short_vector = tuple(0.1 for _ in range(128))
        with pytest.raises(ValueError, match=EMBED_ERR_DIMENSION_MISMATCH):
            _response(vector=short_vector)

    def test_rejects_blank_chunk_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_CHUNK):
            _response(chunk_id="")

    def test_rejects_blank_tenant_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_TENANT):
            _response(tenant_id="")

    def test_is_frozen(self) -> None:
        resp = _response()
        with pytest.raises((AttributeError, TypeError)):
            resp.chunk_id = "other"  # type: ignore[misc]

    def test_vector_is_tuple(self) -> None:
        resp = _response()
        assert isinstance(resp.vector, tuple)


# ===========================================================================
# ChunkEmbeddingRecord
# ===========================================================================


class TestChunkEmbeddingRecord:
    def _record(self, **overrides: object) -> ChunkEmbeddingRecord:
        kwargs: dict = dict(
            tenant_id=_TENANT,
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            content_hash=_HASH,
            embedding_model=EmbeddingModel.OPENAI_ADA_002,
            dimensions=_DIM,
            vector=_VECTOR,
            created_at=_NOW,
        )
        kwargs.update(overrides)
        return ChunkEmbeddingRecord(**kwargs)

    def test_valid_construction(self) -> None:
        rec = self._record()
        assert rec.tenant_id == _TENANT
        assert rec.dimensions == _DIM
        assert len(rec.vector) == _DIM

    def test_from_response_factory(self) -> None:
        resp = _response()
        rec = ChunkEmbeddingRecord.from_response(
            resp, corpus_id=_CORPUS, document_id=_DOCUMENT
        )
        assert rec.tenant_id == resp.tenant_id
        assert rec.chunk_id == resp.chunk_id
        assert rec.corpus_id == _CORPUS
        assert rec.document_id == _DOCUMENT
        assert rec.content_hash == resp.metadata.content_hash
        assert rec.embedding_model == resp.metadata.model
        assert rec.dimensions == resp.metadata.dimensions
        assert rec.vector == resp.vector

    def test_rejects_blank_tenant_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_TENANT):
            self._record(tenant_id="")

    def test_rejects_blank_corpus_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_CORPUS):
            self._record(corpus_id="")

    def test_rejects_blank_document_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_DOCUMENT):
            self._record(document_id="")

    def test_rejects_blank_chunk_id(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_CHUNK):
            self._record(chunk_id="")

    def test_rejects_blank_content_hash(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_MISSING_HASH):
            self._record(content_hash="")

    def test_rejects_dimension_mismatch(self) -> None:
        with pytest.raises(ValueError, match=EMBED_ERR_DIMENSION_MISMATCH):
            self._record(dimensions=128)  # vector is 1536 floats

    def test_rejects_naive_created_at(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            self._record(created_at=datetime(2025, 1, 1))

    def test_is_frozen(self) -> None:
        rec = self._record()
        with pytest.raises((AttributeError, TypeError)):
            rec.tenant_id = "other"  # type: ignore[misc]


# ===========================================================================
# EmbeddingState
# ===========================================================================


class TestEmbeddingState:
    @pytest.mark.parametrize(
        "src,dst,expected",
        [
            (EmbeddingState.PENDING, EmbeddingState.PROCESSING, True),
            (EmbeddingState.PENDING, EmbeddingState.SKIPPED, True),
            (EmbeddingState.PENDING, EmbeddingState.COMPLETED, False),
            (EmbeddingState.PENDING, EmbeddingState.FAILED, False),
            (EmbeddingState.PROCESSING, EmbeddingState.COMPLETED, True),
            (EmbeddingState.PROCESSING, EmbeddingState.FAILED, True),
            (EmbeddingState.PROCESSING, EmbeddingState.PENDING, False),
            (EmbeddingState.FAILED, EmbeddingState.PENDING, True),
            (EmbeddingState.FAILED, EmbeddingState.COMPLETED, False),
            (EmbeddingState.COMPLETED, EmbeddingState.PENDING, False),
            (EmbeddingState.COMPLETED, EmbeddingState.PROCESSING, False),
            (EmbeddingState.SKIPPED, EmbeddingState.PENDING, False),
        ],
    )
    def test_transition_validity(
        self,
        src: EmbeddingState,
        dst: EmbeddingState,
        expected: bool,
    ) -> None:
        assert src.can_transition_to(dst) is expected

    def test_terminal_states(self) -> None:
        terminals = EmbeddingState.terminal_states()
        assert EmbeddingState.COMPLETED in terminals
        assert EmbeddingState.SKIPPED in terminals
        assert EmbeddingState.PENDING not in terminals
        assert EmbeddingState.PROCESSING not in terminals
        assert EmbeddingState.FAILED not in terminals

    def test_retryable_states(self) -> None:
        retryable = EmbeddingState.retryable_states()
        assert EmbeddingState.FAILED in retryable
        assert EmbeddingState.PENDING not in retryable

    def test_string_values_match_migration_check_constraint(self) -> None:
        # Migration 0037 CHECK enforces these exact string values.
        # If you rename a state, you must also update the migration.
        assert EmbeddingState.PENDING.value == "pending"
        assert EmbeddingState.PROCESSING.value == "processing"
        assert EmbeddingState.COMPLETED.value == "completed"
        assert EmbeddingState.FAILED.value == "failed"
        assert EmbeddingState.SKIPPED.value == "skipped"


# ===========================================================================
# EmbeddingModel and KNOWN_DIMENSIONS
# ===========================================================================


class TestEmbeddingModel:
    def test_all_models_have_known_dimensions(self) -> None:
        for model in EmbeddingModel:
            dim = expected_dimensions(model)
            assert dim is not None, (
                f"EmbeddingModel.{model.name} has no entry in KNOWN_DIMENSIONS. "
                "Add it or it will fail dimension validation at runtime."
            )
            assert dim > 0

    def test_known_dimensions_values_are_positive(self) -> None:
        for model, dim in KNOWN_DIMENSIONS.items():
            assert dim > 0, f"{model} has non-positive dimensions: {dim}"

    def test_model_values_use_provider_slash_name_format(self) -> None:
        for model in EmbeddingModel:
            assert "/" in model.value, (
                f"EmbeddingModel.{model.name} value {model.value!r} must be "
                "'provider/model-name' format"
            )

    def test_expected_dimensions_returns_none_for_unknown(self) -> None:
        # Ensure the function handles missing entries gracefully
        class FakeModel:
            pass

        assert expected_dimensions(FakeModel()) is None  # type: ignore[arg-type]


# ===========================================================================
# EmbeddingProvider Protocol
# ===========================================================================


class TestEmbeddingProviderProtocol:
    def test_concrete_provider_satisfies_protocol(self) -> None:
        """A minimal duck-typed provider must satisfy the Protocol."""

        class _StubProvider:
            @property
            def model(self) -> EmbeddingModel:
                return EmbeddingModel.OPENAI_ADA_002

            @property
            def dimensions(self) -> int:
                return _DIM

            def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
                return _response()

            def embed_batch(
                self, requests: list[EmbeddingRequest]
            ) -> list[EmbeddingResponse]:
                return [_response() for _ in requests]

            def is_available(self) -> bool:
                return True

        provider = _StubProvider()
        assert isinstance(provider, EmbeddingProvider)

    def test_incomplete_provider_does_not_satisfy_protocol(self) -> None:
        """A class missing required methods must NOT satisfy the Protocol."""

        class _BrokenProvider:
            @property
            def model(self) -> EmbeddingModel:
                return EmbeddingModel.OPENAI_ADA_002

            # missing: dimensions, embed, embed_batch, is_available

        broken = _BrokenProvider()
        assert not isinstance(broken, EmbeddingProvider)

    def test_provider_with_wrong_return_type_still_structurally_satisfies(
        self,
    ) -> None:
        """Protocol is structural — wrong return type is a mypy concern, not runtime."""

        class _WrongReturnProvider:
            @property
            def model(self) -> EmbeddingModel:
                return EmbeddingModel.BGE_LARGE_EN

            @property
            def dimensions(self) -> int:
                return 1024

            def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:  # type: ignore[return]
                return None  # type: ignore[return-value]

            def embed_batch(
                self, requests: list[EmbeddingRequest]
            ) -> list[EmbeddingResponse]:
                return []

            def is_available(self) -> bool:
                return False

        provider = _WrongReturnProvider()
        assert isinstance(provider, EmbeddingProvider)


# ===========================================================================
# Tenant isolation invariants
# ===========================================================================


class TestTenantIsolationInvariants:
    def test_request_preserves_tenant_id(self) -> None:
        req = EmbeddingRequest.from_chunk(
            tenant_id="tenant-x",
            corpus_id=_CORPUS,
            document_id=_DOCUMENT,
            chunk_id=_CHUNK,
            text=_TEXT,
        )
        assert req.tenant_id == "tenant-x"

    def test_response_preserves_tenant_id(self) -> None:
        resp = _response(tenant_id="tenant-y")
        assert resp.tenant_id == "tenant-y"

    def test_record_from_response_preserves_tenant_id(self) -> None:
        resp = _response(tenant_id="tenant-z")
        rec = ChunkEmbeddingRecord.from_response(
            resp, corpus_id=_CORPUS, document_id=_DOCUMENT
        )
        assert rec.tenant_id == "tenant-z"

    def test_different_tenants_produce_independent_records(self) -> None:
        resp_a = _response(tenant_id="tenant-a")
        resp_b = _response(tenant_id="tenant-b")
        rec_a = ChunkEmbeddingRecord.from_response(
            resp_a, corpus_id=_CORPUS, document_id=_DOCUMENT
        )
        rec_b = ChunkEmbeddingRecord.from_response(
            resp_b, corpus_id=_CORPUS, document_id=_DOCUMENT
        )
        assert rec_a.tenant_id != rec_b.tenant_id
