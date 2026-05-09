"""
services/embeddings/pipeline.py — Embedding generation pipeline over persisted chunks.

Orchestrates chunk → embedding → persistence for a single chunk, document, or
corpus.  All pipeline entry points:

  - require explicit tenant_id (fail closed on blank)
  - operate ONLY on persisted rag_chunks rows
  - use a deterministic local embedding provider (no network, no OpenAI)
  - call upsert_embedding for idempotent writes (no duplicate rows)
  - preserve content_hash lineage from rag_corpus_store
  - emit structured audit logs without raw chunk text or raw vectors

NOT included:
  - semantic retrieval
  - vector similarity search
  - ANN indexing
  - provider routing changes
  - background queue workers
  - async tasks requiring new infrastructure
  - OpenAI or remote inference
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.embeddings.contracts import (
    ChunkEmbeddingRecord,
    EmbeddingRequest,
    canonical_content_hash,
)
from api.embeddings.providers import EmbeddingProvider
from api.rag_corpus_store import get_chunk, get_document, list_chunks, list_documents
from services.embeddings.errors import (
    TenantRequiredError,
)
from services.embeddings.persistence import upsert_embedding

logger = logging.getLogger("frostgate.embeddings.pipeline")

# ---------------------------------------------------------------------------
# Pipeline errors
# ---------------------------------------------------------------------------

EMBED_PIPELINE_ERR_TENANT_REQUIRED = "EMBED_PIPE_001"
EMBED_PIPELINE_ERR_PROVIDER_UNAVAILABLE = "EMBED_PIPE_002"
EMBED_PIPELINE_ERR_CHUNK_NOT_FOUND = "EMBED_PIPE_003"
EMBED_PIPELINE_ERR_CORPUS_MISMATCH = "EMBED_PIPE_004"


class EmbeddingPipelineError(Exception):
    """Base error for the embedding generation pipeline."""


class PipelineTenantRequiredError(EmbeddingPipelineError):
    """tenant_id is missing or blank — all pipeline entry points require tenant scope."""


class PipelineProviderUnavailableError(EmbeddingPipelineError):
    """Provider is not available — pipeline cannot generate embeddings."""


class PipelineChunkNotFoundError(EmbeddingPipelineError):
    """chunk_id not found under the given tenant/corpus/document scope."""


class PipelineCorpusMismatchError(EmbeddingPipelineError):
    """document_id does not belong to the given corpus_id under this tenant."""


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChunkEmbeddingResult:
    """Result for a single chunk after pipeline processing.

    Audit-safe: contains no raw chunk text, no raw vectors.
    """

    tenant_id: str
    corpus_id: str
    document_id: str
    chunk_id: str
    content_hash: str
    embedding_model: str
    dimensions: int
    status: str  # "persisted" | "skipped" | "failed"
    error: Optional[str] = None


@dataclass(frozen=True)
class DocumentEmbeddingResult:
    """Aggregate result for all chunks in a document."""

    tenant_id: str
    corpus_id: str
    document_id: str
    embedding_model: str
    chunk_results: tuple[ChunkEmbeddingResult, ...]
    total_chunks: int
    persisted: int
    skipped: int
    failed: int
    duration_ms: int


@dataclass(frozen=True)
class CorpusEmbeddingResult:
    """Aggregate result for all documents/chunks in a corpus."""

    tenant_id: str
    corpus_id: str
    embedding_model: str
    document_results: tuple[DocumentEmbeddingResult, ...]
    total_documents: int
    total_chunks: int
    persisted: int
    skipped: int
    failed: int
    duration_ms: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: str) -> str:
    if not str(tenant_id or "").strip():
        raise PipelineTenantRequiredError(
            f"{EMBED_PIPELINE_ERR_TENANT_REQUIRED}: tenant_id is required"
        )
    return tenant_id.strip()


def _audit_log(event: str, **fields: object) -> None:
    """Emit a structured audit log.

    Never includes raw chunk text, raw vectors, provider secrets, or PHI.
    Permitted fields: tenant_id, corpus_id, document_id, chunk_id,
    embedding_model, dimensions, content_hash, counts, status, duration_ms.
    """
    logger.info(
        "embedding.pipeline.%s",
        event,
        extra={"event": f"embedding.pipeline.{event}", **fields},
    )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ms_since(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# Single-chunk pipeline
# ---------------------------------------------------------------------------


def generate_embedding_for_chunk(
    db: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    chunk_id: str,
    provider: EmbeddingProvider,
) -> ChunkEmbeddingResult:
    """Generate and persist the embedding for a single persisted chunk.

    Always loads the chunk from rag_chunks scoped by (tenant_id, corpus_id,
    document_id, chunk_id) to validate provenance before embedding.  Caller-
    supplied text is never trusted.

    Idempotent: if an embedding for (tenant, corpus, chunk, model, hash) already
    exists it is not duplicated.  Content-hash changes trigger a new embedding
    via upsert_embedding.

    Tenant scope is required.  Fails closed on blank tenant_id.
    Provider must satisfy the EmbeddingProvider protocol and be available.
    """
    tenant_id = _require_tenant(tenant_id)

    persisted_chunk = get_chunk(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        chunk_id=chunk_id,
    )
    if persisted_chunk is None:
        raise PipelineChunkNotFoundError(
            f"{EMBED_PIPELINE_ERR_CHUNK_NOT_FOUND}: "
            f"chunk_id={chunk_id!r} not found for "
            f"tenant_id={tenant_id!r} / corpus_id={corpus_id!r} / document_id={document_id!r}"
        )
    chunk_text = persisted_chunk["text"]

    if not provider.is_available():
        raise PipelineProviderUnavailableError(
            f"{EMBED_PIPELINE_ERR_PROVIDER_UNAVAILABLE}: "
            f"provider for model {provider.model.value!r} is not available"
        )

    content_hash = canonical_content_hash(chunk_text)

    request = EmbeddingRequest.from_chunk(
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        chunk_id=chunk_id,
        text=chunk_text,
    )

    try:
        response = provider.embed(request)
    except Exception as exc:
        _audit_log(
            "chunk_failed",
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            embedding_model=provider.model.value,
            content_hash=content_hash,
            error=str(exc),
        )
        return ChunkEmbeddingResult(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            content_hash=content_hash,
            embedding_model=provider.model.value,
            dimensions=provider.dimensions,
            status="failed",
            error=str(exc),
        )

    record = ChunkEmbeddingRecord.from_response(
        response,
        corpus_id=corpus_id,
        document_id=document_id,
    )

    try:
        upsert_embedding(db, record)
    except TenantRequiredError:
        raise
    except Exception as exc:
        _audit_log(
            "chunk_persist_failed",
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            embedding_model=provider.model.value,
            content_hash=content_hash,
            error=str(exc),
        )
        return ChunkEmbeddingResult(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            content_hash=content_hash,
            embedding_model=provider.model.value,
            dimensions=provider.dimensions,
            status="failed",
            error=str(exc),
        )

    _audit_log(
        "chunk_persisted",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        chunk_id=chunk_id,
        embedding_model=provider.model.value,
        dimensions=provider.dimensions,
        content_hash=content_hash,
    )
    return ChunkEmbeddingResult(
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        chunk_id=chunk_id,
        content_hash=content_hash,
        embedding_model=provider.model.value,
        dimensions=provider.dimensions,
        status="persisted",
    )


# ---------------------------------------------------------------------------
# Document-level pipeline
# ---------------------------------------------------------------------------


def generate_embeddings_for_document(
    db: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    provider: EmbeddingProvider,
) -> DocumentEmbeddingResult:
    """Generate and persist embeddings for all persisted chunks in a document.

    Reads chunks from rag_chunks (ordered by ordinal ascending — deterministic).
    Runs generate_embedding_for_chunk per chunk.
    Idempotent: reruns produce no duplicates.
    Tenant scope required.
    """
    tenant_id = _require_tenant(tenant_id)
    start = time.monotonic()

    doc = get_document(db, tenant_id=tenant_id, document_id=document_id)
    if doc is None or doc["corpus_id"] != corpus_id:
        raise PipelineCorpusMismatchError(
            f"{EMBED_PIPELINE_ERR_CORPUS_MISMATCH}: "
            f"document_id={document_id!r} does not belong to corpus_id={corpus_id!r} "
            f"for tenant_id={tenant_id!r}"
        )

    chunks = list_chunks(db, tenant_id=tenant_id, document_id=document_id)

    _audit_log(
        "document_started",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        embedding_model=provider.model.value,
        chunk_count=len(chunks),
    )

    results: list[ChunkEmbeddingResult] = []
    for chunk in chunks:
        result = generate_embedding_for_chunk(
            db,
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk["chunk_id"],
            provider=provider,
        )
        results.append(result)

    persisted = sum(1 for r in results if r.status == "persisted")
    skipped = sum(1 for r in results if r.status == "skipped")
    failed = sum(1 for r in results if r.status == "failed")
    duration = _ms_since(start)

    _audit_log(
        "document_completed",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        embedding_model=provider.model.value,
        total_chunks=len(results),
        persisted=persisted,
        skipped=skipped,
        failed=failed,
        duration_ms=duration,
    )

    return DocumentEmbeddingResult(
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        embedding_model=provider.model.value,
        chunk_results=tuple(results),
        total_chunks=len(results),
        persisted=persisted,
        skipped=skipped,
        failed=failed,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Corpus-level pipeline
# ---------------------------------------------------------------------------


def generate_embeddings_for_corpus(
    db: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    provider: EmbeddingProvider,
) -> CorpusEmbeddingResult:
    """Generate and persist embeddings for all chunks in a corpus.

    Reads documents from rag_documents ordered by created_at ascending
    (deterministic ordering).  Delegates to generate_embeddings_for_document
    per document.
    Idempotent: reruns produce no duplicates.
    Tenant scope required.
    Cross-tenant reads return empty results — no enumeration leakage.
    """
    tenant_id = _require_tenant(tenant_id)
    start = time.monotonic()

    documents = list_documents(db, tenant_id=tenant_id, corpus_id=corpus_id)

    _audit_log(
        "corpus_started",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        embedding_model=provider.model.value,
        document_count=len(documents),
    )

    doc_results: list[DocumentEmbeddingResult] = []
    for doc in documents:
        doc_result = generate_embeddings_for_document(
            db,
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=doc["document_id"],
            provider=provider,
        )
        doc_results.append(doc_result)

    total_chunks = sum(r.total_chunks for r in doc_results)
    total_persisted = sum(r.persisted for r in doc_results)
    total_skipped = sum(r.skipped for r in doc_results)
    total_failed = sum(r.failed for r in doc_results)
    duration = _ms_since(start)

    _audit_log(
        "corpus_completed",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        embedding_model=provider.model.value,
        total_documents=len(doc_results),
        total_chunks=total_chunks,
        persisted=total_persisted,
        skipped=total_skipped,
        failed=total_failed,
        duration_ms=duration,
    )

    return CorpusEmbeddingResult(
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        embedding_model=provider.model.value,
        document_results=tuple(doc_results),
        total_documents=len(doc_results),
        total_chunks=total_chunks,
        persisted=total_persisted,
        skipped=total_skipped,
        failed=total_failed,
        duration_ms=duration,
    )
