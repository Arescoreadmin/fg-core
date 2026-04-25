"""
RAG Corpus Update/Delete/Reindex Lifecycle — Task 16.7

Minimal, deterministic, tenant-safe in-memory lifecycle surface for RAG corpus
management.  Supports upsert (create/update), delete, reindex, and active-record
listing.

No external services.  No vector DB.  No embeddings.  No LLM calls.
No DB migrations.  No background workers.  No network calls.
Scope: in-process lifecycle store only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from api.rag.chunking import ChunkingConfig, CorpusChunk, chunk_ingested_records
from api.rag.ingest import (
    CorpusDocument,
    IngestRequest,
    IngestedCorpusRecord,
    ingest_corpus,
)

log = logging.getLogger("frostgate.rag.lifecycle")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

LIFECYCLE_ERR_MISSING_TENANT = "RAG_LIFECYCLE_E001"
LIFECYCLE_ERR_DOCUMENT_NOT_FOUND = "RAG_LIFECYCLE_E002"
LIFECYCLE_ERR_TENANT_MISMATCH = "RAG_LIFECYCLE_E003"
LIFECYCLE_ERR_INVALID_DOCUMENT = "RAG_LIFECYCLE_E004"
LIFECYCLE_ERR_INVALID_CONFIG = "RAG_LIFECYCLE_E005"

# ---------------------------------------------------------------------------
# Operation type constants
# ---------------------------------------------------------------------------

_OP_CREATE = "create"
_OP_UPDATE = "update"
_OP_DELETE = "delete"
_OP_REINDEX = "reindex"

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleOperationResult:
    """Structured, auditable result for every corpus lifecycle operation.

    Contains enough information to reconstruct what changed, for whom, and why,
    without including raw document text or unsafe metadata.
    """

    tenant_id: str
    operation: str  # "create" | "update" | "delete" | "reindex"
    status: str  # "ok"
    affected_chunk_count: int
    source_id: str | None = None  # None for reindex
    document_id: str | None = None  # None for reindex
    prior_content_hash: str | None = None  # None for create or reindex
    new_content_hash: str | None = None  # None for delete or reindex


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class LifecycleError(Exception):
    """Raised for unrecoverable lifecycle operation failures.

    error_code is always a stable RAG_LIFECYCLE_Exxx constant.
    message MUST NOT contain raw document text or foreign tenant metadata.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class CorpusLifecycleStore:
    """In-memory, tenant-bound corpus store for RAG lifecycle operations.

    Active records are keyed by (tenant_id, source_id).
    Deleted records are removed from _active — reindex never resurfaces them.
    Caller-owned inputs are never mutated.
    """

    def __init__(self) -> None:
        self._active: dict[tuple[str, str], IngestedCorpusRecord] = {}

    def _get_active_records(self, tenant_id: str) -> list[IngestedCorpusRecord]:
        """Return all active records for tenant, sorted deterministically.

        Sort order: source_id ASC → document_id ASC.
        """
        records = [r for (t, _), r in self._active.items() if t == tenant_id]
        return sorted(records, key=lambda r: (r.source_id, r.document_id))

    def _get_record(
        self, tenant_id: str, source_id: str
    ) -> IngestedCorpusRecord | None:
        return self._active.get((tenant_id, source_id))

    def _set_record(self, record: IngestedCorpusRecord) -> None:
        self._active[(record.tenant_id, record.source_id)] = record

    def _remove_record(self, tenant_id: str, source_id: str) -> None:
        self._active.pop((tenant_id, source_id), None)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_trusted_tenant(trusted_tenant_id: str) -> str:
    """Validate and return stripped trusted tenant. Raises LifecycleError on failure."""
    if not isinstance(trusted_tenant_id, str):
        raise LifecycleError(
            LIFECYCLE_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    if not trusted_tenant_id.strip():
        raise LifecycleError(
            LIFECYCLE_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    return trusted_tenant_id.strip()


def _effective_chunk_config(chunk_config: ChunkingConfig | None) -> ChunkingConfig:
    return chunk_config if chunk_config is not None else ChunkingConfig()


def _chunks_for_record(
    record: IngestedCorpusRecord, config: ChunkingConfig
) -> list[CorpusChunk]:
    return chunk_ingested_records([record], config=config)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def upsert_document(
    store: CorpusLifecycleStore,
    document: CorpusDocument,
    trusted_tenant_id: str,
    chunk_config: ChunkingConfig | None = None,
) -> LifecycleOperationResult:
    """Insert or update a document in the lifecycle store.

    If a record with the same (tenant_id, source_id) already exists it is
    replaced and the operation is reported as "update".  Otherwise it is "create".
    Old chunks for the replaced document are no longer visible in active retrieval.

    Args:
        store: CorpusLifecycleStore to mutate.
        document: CorpusDocument to upsert.  Not mutated by this call.
        trusted_tenant_id: Tenant identity from trusted execution context.
            MUST NOT be sourced from document payload or metadata.
        chunk_config: Optional chunking configuration.

    Returns:
        LifecycleOperationResult with operation="create" or "update",
        document identity, content hashes, and affected chunk count.

    Raises:
        LifecycleError(LIFECYCLE_ERR_MISSING_TENANT): missing/blank/non-string tenant.
        LifecycleError(LIFECYCLE_ERR_INVALID_DOCUMENT): blank source_id or content.

    Security invariants:
        - trusted_tenant_id is the only source of tenant authority.
        - Document payload metadata cannot override trusted tenant.
        - Old chunks for the same source_id are replaced atomically.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    if not document.source_id or not document.source_id.strip():
        raise LifecycleError(
            LIFECYCLE_ERR_INVALID_DOCUMENT,
            "source_id is required and must not be blank",
        )
    if not document.content or not document.content.strip():
        raise LifecycleError(
            LIFECYCLE_ERR_INVALID_DOCUMENT, "content is required and must not be blank"
        )

    ingest_result = ingest_corpus(
        IngestRequest(documents=[document]), trusted_tenant_id=tenant_id
    )
    record = ingest_result.records[0]

    existing = store._get_record(tenant_id, record.source_id)
    operation = _OP_UPDATE if existing is not None else _OP_CREATE
    prior_content_hash = existing.content_hash if existing is not None else None

    config = _effective_chunk_config(chunk_config)
    chunks = _chunks_for_record(record, config)

    store._set_record(record)

    log.info(
        "rag.lifecycle.upsert",
        extra={
            "tenant_id": tenant_id,
            "operation": operation,
            "source_id": record.source_id,
            "document_id": record.document_id,
            "affected_chunk_count": len(chunks),
        },
    )

    return LifecycleOperationResult(
        tenant_id=tenant_id,
        operation=operation,
        status="ok",
        affected_chunk_count=len(chunks),
        source_id=record.source_id,
        document_id=record.document_id,
        prior_content_hash=prior_content_hash,
        new_content_hash=record.content_hash,
    )


def delete_document(
    store: CorpusLifecycleStore,
    source_id: str,
    trusted_tenant_id: str,
) -> LifecycleOperationResult:
    """Delete a document from the lifecycle store.

    The document is removed from the active record set.  Subsequent reindex,
    list_active_chunks, and list_active_records calls will not return it.

    Args:
        store: CorpusLifecycleStore to mutate.
        source_id: Source identifier of the document to delete.
        trusted_tenant_id: Tenant identity from trusted execution context.

    Returns:
        LifecycleOperationResult with operation="delete".

    Raises:
        LifecycleError(LIFECYCLE_ERR_MISSING_TENANT): missing/blank/non-string tenant.
        LifecycleError(LIFECYCLE_ERR_DOCUMENT_NOT_FOUND): document not found OR belongs
            to a different tenant.  Both cases return the same error to prevent
            cross-tenant existence side-channel leakage.

    Security invariants:
        - Foreign source_id returns LIFECYCLE_ERR_DOCUMENT_NOT_FOUND, identical to
          a truly absent document.  The caller cannot distinguish the two cases.
        - Error message does not include raw document text or foreign metadata.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    record = store._get_record(tenant_id, source_id)

    if record is None:
        log.warning(
            "rag.lifecycle.delete: document not found or tenant mismatch",
            extra={
                "tenant_id": tenant_id,
                "error_code": LIFECYCLE_ERR_DOCUMENT_NOT_FOUND,
            },
        )
        raise LifecycleError(
            LIFECYCLE_ERR_DOCUMENT_NOT_FOUND,
            "document not found",
        )

    store._remove_record(tenant_id, source_id)

    log.info(
        "rag.lifecycle.delete",
        extra={
            "tenant_id": tenant_id,
            "source_id": source_id,
            "document_id": record.document_id,
        },
    )

    return LifecycleOperationResult(
        tenant_id=tenant_id,
        operation=_OP_DELETE,
        status="ok",
        affected_chunk_count=0,
        source_id=source_id,
        document_id=record.document_id,
        prior_content_hash=record.content_hash,
        new_content_hash=None,
    )


def reindex(
    store: CorpusLifecycleStore,
    trusted_tenant_id: str,
    chunk_config: ChunkingConfig | None = None,
) -> tuple[list[CorpusChunk], LifecycleOperationResult]:
    """Rebuild chunks deterministically from all active tenant records.

    Deleted records are not resurrected.  Output is deterministic for identical
    active records and config.

    Args:
        store: CorpusLifecycleStore containing active records.
        trusted_tenant_id: Tenant identity from trusted execution context.
        chunk_config: Optional chunking configuration.

    Returns:
        Tuple of (chunks, LifecycleOperationResult).
        chunks are sorted: source_id ASC → document_id ASC →
        chunk_index ASC → chunk_id ASC.

    Raises:
        LifecycleError(LIFECYCLE_ERR_MISSING_TENANT): missing/blank/non-string tenant.

    Security invariants:
        - Only processes records belonging to trusted_tenant_id.
        - Deleted documents remain absent — reindex never resurfaces them.
        - Deterministic: same active records + same config → same output.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    active_records = store._get_active_records(tenant_id)
    config = _effective_chunk_config(chunk_config)

    if not active_records:
        chunks: list[CorpusChunk] = []
    else:
        chunks = chunk_ingested_records(active_records, config=config)

    # Deterministic sort: source_id ASC → document_id ASC → chunk_index ASC → chunk_id ASC
    chunks = sorted(
        chunks,
        key=lambda c: (c.source_id, c.document_id, c.chunk_index, c.chunk_id),
    )

    log.info(
        "rag.lifecycle.reindex",
        extra={
            "tenant_id": tenant_id,
            "record_count": len(active_records),
            "chunk_count": len(chunks),
        },
    )

    result = LifecycleOperationResult(
        tenant_id=tenant_id,
        operation=_OP_REINDEX,
        status="ok",
        affected_chunk_count=len(chunks),
        source_id=None,
        document_id=None,
        prior_content_hash=None,
        new_content_hash=None,
    )

    return chunks, result


def list_active_chunks(
    store: CorpusLifecycleStore,
    trusted_tenant_id: str,
    chunk_config: ChunkingConfig | None = None,
) -> list[CorpusChunk]:
    """Return all active chunks for the tenant, in deterministic order.

    Convenience wrapper around reindex() that returns only the chunk list.
    """
    chunks, _ = reindex(store, trusted_tenant_id, chunk_config)
    return chunks


def list_active_records(
    store: CorpusLifecycleStore,
    trusted_tenant_id: str,
) -> list[IngestedCorpusRecord]:
    """Return all active IngestedCorpusRecord objects for the tenant.

    Returns a new list — caller modifications do not affect store state.

    Raises:
        LifecycleError(LIFECYCLE_ERR_MISSING_TENANT): missing/blank/non-string tenant.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)
    return list(store._get_active_records(tenant_id))
