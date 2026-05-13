"""
api/rag_corpus_console.py — Corpus Management Console API endpoints.

GET /rag/corpora/{corpus_id}
    → tenant-scoped corpus detail with document/chunk/embedding state summary
GET /rag/corpora/{corpus_id}/documents
    → paginated, filterable, sortable tenant-scoped document list with chunk counts
GET /rag/documents/{document_id}
    → tenant-scoped document detail with chunk summary

Security: All endpoints require verify_api_key + governance:write scope.
Tenant isolation: every operation scoped to require_bound_tenant(); cross-tenant
  access is structurally impossible.

Does NOT expose:
  - raw vectors, raw embeddings, embedding payloads
  - raw prompts or provider payloads
  - secrets or credentials
  - raw chunk text
  - cross-tenant corpus/document/chunk data
  - stack traces (only safe reason codes are returned)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes, verify_api_key
from api.deps import tenant_db_required
from api.rag_corpus_store import (
    INGESTION_RECEIVED,
    INGESTION_VALIDATING,
    INGESTION_DUPLICATE,
    INGESTION_QUARANTINED,
    INGESTION_CHUNKING,
    INGESTION_EMBEDDING,
    INGESTION_INDEXED,
    INGESTION_FAILED,
    INGESTION_SUPERSEDED,
    INGESTION_REINDEXING,
    get_corpus,
    get_document,
    _table_columns,
)

log = logging.getLogger("frostgate.rag_corpus_console")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KNOWN_INGESTION_STATUSES = frozenset(
    {
        INGESTION_RECEIVED,
        INGESTION_VALIDATING,
        INGESTION_DUPLICATE,
        INGESTION_QUARANTINED,
        INGESTION_CHUNKING,
        INGESTION_EMBEDDING,
        INGESTION_INDEXED,
        INGESTION_FAILED,
        INGESTION_SUPERSEDED,
        INGESTION_REINDEXING,
    }
)

_KNOWN_EMBEDDING_STATES = frozenset(
    {"pending", "processing", "completed", "failed", "skipped"}
)

_ALLOWED_SORT_FIELDS = frozenset(
    {"created_at", "updated_at", "title", "ingestion_status", "version_number"}
)

_ALLOWED_SORT_DIRS = frozenset({"asc", "desc"})

_SAFE_SOURCE_HASH_PREFIX_LEN = 12

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/rag",
    tags=["rag", "governance", "corpus-console"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("governance:write")),
    ],
)


def _tenant(request: Request) -> str:
    return require_bound_tenant(request)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_source_hash_prefix(source_hash: Optional[str]) -> Optional[str]:
    if not source_hash:
        return None
    return str(source_hash)[:_SAFE_SOURCE_HASH_PREFIX_LEN]


_BLOCKED_METADATA_KEYS = frozenset(
    {
        "embedding",
        "vector",
        "prompt",
        "credentials",
        "secret",
        "password",
        "token",
        "api_key",
        "raw_text",
        "provider_payload",
    }
)


def _is_blocked_key(key: str) -> bool:
    k = str(key).lower()
    return any(blocked in k for blocked in _BLOCKED_METADATA_KEYS)


def _sanitize_value(value: Any) -> Any:
    """Recursively strip blocked keys from nested dicts; drop list elements that are blocked dicts."""
    if isinstance(value, dict):
        return _safe_metadata(value)
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, dict):
                cleaned = _safe_metadata(item)
                if cleaned is not None:
                    result.append(cleaned)
            elif not isinstance(item, (dict, list)):
                result.append(item)
        return result
    return value


def _safe_metadata(metadata: Any) -> Optional[dict[str, Any]]:
    """Return only operator-safe metadata keys; recursively strip secrets from nested structures."""
    if not isinstance(metadata, dict):
        return None
    return {
        k: _sanitize_value(v) for k, v in metadata.items() if not _is_blocked_key(k)
    }


def _ingestion_status_summary(
    conn: Session, *, tenant_id: str, corpus_id: str
) -> dict[str, int]:
    """Return {ingestion_status: count} for all documents in the corpus."""
    rows = (
        conn.execute(
            text(
                """
                SELECT COALESCE(ingestion_status, 'indexed') AS status, COUNT(*) AS cnt
                FROM rag_documents
                WHERE tenant_id = :tenant_id AND corpus_id = :corpus_id
                GROUP BY COALESCE(ingestion_status, 'indexed')
                """
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id},
        )
        .mappings()
        .fetchall()
    )
    return {str(row["status"]): int(row["cnt"]) for row in rows}


def _embedding_state_summary(
    conn: Session, *, tenant_id: str, corpus_id: str
) -> dict[str, int]:
    """Return {embedding_state: count} for all active chunks in the corpus."""
    table_cols = _table_columns(conn, "rag_chunks")
    if "embedding_state" not in table_cols:
        return {}
    active_filter = (
        "AND COALESCE(is_active, 1) = 1" if "is_active" in table_cols else ""
    )
    rows = (
        conn.execute(
            text(
                f"""
                SELECT COALESCE(embedding_state, 'pending') AS state, COUNT(*) AS cnt
                FROM rag_chunks
                WHERE tenant_id = :tenant_id AND corpus_id = :corpus_id
                {active_filter}
                GROUP BY COALESCE(embedding_state, 'pending')
                """
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id},
        )
        .mappings()
        .fetchall()
    )
    return {str(row["state"]): int(row["cnt"]) for row in rows}


def _corpus_document_chunk_counts(
    conn: Session, *, tenant_id: str, corpus_id: str
) -> dict[str, int]:
    """Return total_document_count, active_document_count, total_chunk_count, active_chunk_count."""
    table_cols = _table_columns(conn, "rag_documents")
    chunk_cols = _table_columns(conn, "rag_chunks")
    is_current_clause = (
        "AND COALESCE(d.is_current, 1) = 1 AND COALESCE(d.ingestion_status, 'indexed') = 'indexed'"
        if "is_current" in table_cols and "ingestion_status" in table_cols
        else ""
    )
    active_chunk_clause = (
        "AND COALESCE(c.is_active, 1) = 1" if "is_active" in chunk_cols else ""
    )

    doc_row = (
        conn.execute(
            text(
                f"""
                SELECT
                    COUNT(*) AS total_documents,
                    SUM(CASE WHEN 1=1 {is_current_clause.replace("AND ", "AND ", 1)} THEN 1 ELSE 0 END) AS active_documents
                FROM rag_documents d
                WHERE d.tenant_id = :tenant_id AND d.corpus_id = :corpus_id
                """
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id},
        )
        .mappings()
        .first()
    )

    chunk_row = (
        conn.execute(
            text(
                f"""
                SELECT
                    COUNT(*) AS total_chunks,
                    SUM(CASE WHEN 1=1 {active_chunk_clause} THEN 1 ELSE 0 END) AS active_chunks
                FROM rag_chunks c
                WHERE c.tenant_id = :tenant_id AND c.corpus_id = :corpus_id
                """
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id},
        )
        .mappings()
        .first()
    )

    return {
        "total_document_count": int(doc_row["total_documents"] or 0) if doc_row else 0,
        "active_document_count": int(doc_row["active_documents"] or 0)
        if doc_row
        else 0,
        "total_chunk_count": int(chunk_row["total_chunks"] or 0) if chunk_row else 0,
        "active_chunk_count": int(chunk_row["active_chunks"] or 0) if chunk_row else 0,
    }


def _document_chunk_count(
    conn: Session, *, tenant_id: str, document_id: str
) -> dict[str, int]:
    """Return active_chunk_count and total_chunk_count for a document."""
    chunk_cols = _table_columns(conn, "rag_chunks")
    active_clause = (
        "AND COALESCE(is_active, 1) = 1" if "is_active" in chunk_cols else ""
    )
    row = (
        conn.execute(
            text(
                f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN 1=1 {active_clause} THEN 1 ELSE 0 END) AS active
                FROM rag_chunks
                WHERE tenant_id = :tenant_id AND document_id = :document_id
                """
            ),
            {"tenant_id": tenant_id, "document_id": document_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        return {"total_chunk_count": 0, "active_chunk_count": 0}
    return {
        "total_chunk_count": int(row["total"] or 0),
        "active_chunk_count": int(row["active"] or 0),
    }


def _document_embedding_summary(
    conn: Session, *, tenant_id: str, document_id: str
) -> dict[str, int]:
    """Return embedding state distribution for a document's chunks."""
    chunk_cols = _table_columns(conn, "rag_chunks")
    if "embedding_state" not in chunk_cols:
        return {}
    rows = (
        conn.execute(
            text(
                """
                SELECT COALESCE(embedding_state, 'pending') AS state, COUNT(*) AS cnt
                FROM rag_chunks
                WHERE tenant_id = :tenant_id AND document_id = :document_id
                GROUP BY COALESCE(embedding_state, 'pending')
                """
            ),
            {"tenant_id": tenant_id, "document_id": document_id},
        )
        .mappings()
        .fetchall()
    )
    return {str(row["state"]): int(row["cnt"]) for row in rows}


def _validate_sort(sort_by: str, sort_dir: str) -> tuple[str, str]:
    if sort_by not in _ALLOWED_SORT_FIELDS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_SORT_FIELD",
                "sort_by": sort_by,
                "allowed": sorted(_ALLOWED_SORT_FIELDS),
            },
        )
    if sort_dir not in _ALLOWED_SORT_DIRS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_SORT_DIR",
                "sort_dir": sort_dir,
                "allowed": sorted(_ALLOWED_SORT_DIRS),
            },
        )
    return sort_by, sort_dir


# ---------------------------------------------------------------------------
# GET /rag/corpora/{corpus_id}
# ---------------------------------------------------------------------------


@router.get("/corpora/{corpus_id}")
def get_corpus_detail(
    corpus_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """
    Return corpus detail with operational stats for the Corpus Management Console.

    Includes:
    - Basic corpus fields (id, name, description, created_at, updated_at)
    - Document counts: total, active (indexed + current)
    - Chunk counts: total, active
    - Ingestion status summary: {status: count} map
    - Embedding state summary: {state: count} map from active chunks
    - Safe metadata: no raw vectors, no prompts, no secrets

    Tenant-scoped: returns 404 if corpus_id belongs to a different tenant.
    """
    tenant_id = _tenant(request)
    corpus = get_corpus(db, tenant_id, corpus_id)
    if corpus is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CORPUS_NOT_FOUND", "corpus_id": corpus_id},
        )

    counts = _corpus_document_chunk_counts(db, tenant_id=tenant_id, corpus_id=corpus_id)
    ingestion_summary = _ingestion_status_summary(
        db, tenant_id=tenant_id, corpus_id=corpus_id
    )
    embedding_summary = _embedding_state_summary(
        db, tenant_id=tenant_id, corpus_id=corpus_id
    )

    log.info(
        "rag_corpus_console.get_corpus_detail",
        extra={
            "event": "corpus_console.corpus_detail_viewed",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "request_id": request.headers.get("x-request-id"),
        },
    )

    return {
        "corpus_id": corpus["corpus_id"],
        "name": corpus.get("name") or corpus["corpus_id"],
        "description": corpus.get("description"),
        "created_at": corpus.get("created_at"),
        "updated_at": corpus.get("updated_at"),
        "total_document_count": counts["total_document_count"],
        "active_document_count": counts["active_document_count"],
        "total_chunk_count": counts["total_chunk_count"],
        "active_chunk_count": counts["active_chunk_count"],
        "ingestion_status_summary": ingestion_summary,
        "embedding_state_summary": embedding_summary,
        "metadata": _safe_metadata(corpus.get("metadata")),
        "future_hooks": {
            "connector_type": None,
            "sync_health": None,
            "stale_warning": None,
            "duplicate_detection": None,
        },
    }


# ---------------------------------------------------------------------------
# GET /rag/corpora/{corpus_id}/documents
# ---------------------------------------------------------------------------


@router.get("/corpora/{corpus_id}/documents")
def list_corpus_documents(
    corpus_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ingestion_status: Optional[str] = Query(default=None),
    is_current: Optional[bool] = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc"),
) -> dict[str, Any]:
    """
    Return a paginated, filtered, sorted list of documents in a corpus.

    Pagination:
    - limit: 1–200 (default 20)
    - offset: 0+ (default 0)
    - Stable ordering: sort_by + deterministic tiebreaker (document_id ASC)

    Filtering:
    - ingestion_status: exact match; unknown values fail closed (422)
    - is_current: true/false boolean filter

    Sorting:
    - sort_by: created_at, updated_at, title, ingestion_status, version_number
    - sort_dir: asc, desc

    Each document includes:
    - Lifecycle fields: ingestion_status, is_current, quarantine_reason, version info
    - source_hash_prefix: 12-char prefix (operator-safe, no content disclosure)
    - active_chunk_count, total_chunk_count from rag_chunks

    Does NOT expose: raw chunk text, raw vectors, provider payloads, secrets.
    """
    tenant_id = _tenant(request)

    corpus = get_corpus(db, tenant_id, corpus_id)
    if corpus is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CORPUS_NOT_FOUND", "corpus_id": corpus_id},
        )

    if (
        ingestion_status is not None
        and ingestion_status not in _KNOWN_INGESTION_STATUSES
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_INGESTION_STATUS_FILTER",
                "ingestion_status": ingestion_status,
                "allowed": sorted(_KNOWN_INGESTION_STATUSES),
            },
        )

    sort_by, sort_dir = _validate_sort(sort_by, sort_dir)

    table_cols = _table_columns(db, "rag_documents")
    chunk_cols = _table_columns(db, "rag_chunks")
    active_chunk_clause = (
        "COALESCE(c.is_active, 1) = 1" if "is_active" in chunk_cols else "1=1"
    )
    is_current_col = "is_current" in table_cols
    ingestion_status_col = "ingestion_status" in table_cols

    # Build WHERE clause
    where_parts = [
        "d.tenant_id = :tenant_id",
        "d.corpus_id = :corpus_id",
    ]
    params: dict[str, Any] = {"tenant_id": tenant_id, "corpus_id": corpus_id}

    if ingestion_status is not None and ingestion_status_col:
        where_parts.append(
            "COALESCE(d.ingestion_status, 'indexed') = :ingestion_status"
        )
        params["ingestion_status"] = ingestion_status

    if is_current is not None and is_current_col:
        where_parts.append("COALESCE(d.is_current, 1) = :is_current_val")
        params["is_current_val"] = 1 if is_current else 0

    where_sql = " AND ".join(where_parts)

    # Resolve sort column to safe SQL identifier (validated above)
    sort_col_map = {
        "created_at": "d.created_at",
        "updated_at": "d.updated_at",
        "title": "d.title",
        "ingestion_status": "COALESCE(d.ingestion_status, 'indexed')",
        "version_number": "d.version_number",
    }
    sort_col_sql = sort_col_map[sort_by]
    sort_dir_sql = "ASC" if sort_dir == "asc" else "DESC"

    # Chunk join for counts
    chunk_join = f"""
        LEFT JOIN (
            SELECT document_id,
                   COUNT(*) AS total_chunks,
                   SUM(CASE WHEN {active_chunk_clause} THEN 1 ELSE 0 END) AS active_chunks
            FROM rag_chunks c
            WHERE c.tenant_id = :tenant_id AND c.corpus_id = :corpus_id
            GROUP BY c.document_id
        ) chunk_counts ON d.document_id = chunk_counts.document_id
        """

    # Select columns
    base_cols = "d.document_id, d.title, d.source, d.created_at, d.updated_at"
    optional_cols_parts = []
    for col in [
        "version_id",
        "source_hash",
        "version_number",
        "is_current",
        "ingestion_status",
        "quarantine_reason",
        "failure_reason",
        "indexed_at",
        "superseded_at",
    ]:
        if col in table_cols:
            optional_cols_parts.append(f"d.{col}")
    optional_cols = (
        (", " + ", ".join(optional_cols_parts)) if optional_cols_parts else ""
    )

    count_row = (
        db.execute(
            text(
                f"""
                SELECT COUNT(*) AS total
                FROM rag_documents d
                WHERE {where_sql}
                """
            ),
            params,
        )
        .mappings()
        .first()
    )
    total = int(count_row["total"] or 0) if count_row else 0

    rows = (
        db.execute(
            text(
                f"""
                SELECT {base_cols}{optional_cols},
                       COALESCE(chunk_counts.total_chunks, 0) AS total_chunk_count,
                       COALESCE(chunk_counts.active_chunks, 0) AS active_chunk_count
                FROM rag_documents d
                {chunk_join}
                WHERE {where_sql}
                ORDER BY {sort_col_sql} {sort_dir_sql}, d.document_id ASC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": limit, "offset": offset},
        )
        .mappings()
        .fetchall()
    )

    items = []
    for row in rows:
        r = dict(row)
        items.append(
            {
                "document_id": r["document_id"],
                "title": r.get("title"),
                "source": r.get("source"),
                "version_id": r.get("version_id"),
                "version_number": r.get("version_number", 1),
                "is_current": bool(
                    int(r["is_current"]) if r.get("is_current") is not None else 1
                ),
                "ingestion_status": r.get("ingestion_status") or "indexed",
                "quarantine_reason": r.get("quarantine_reason"),
                "failure_reason": r.get("failure_reason"),
                "source_hash_prefix": _safe_source_hash_prefix(r.get("source_hash")),
                "indexed_at": r.get("indexed_at"),
                "superseded_at": r.get("superseded_at"),
                "active_chunk_count": int(r["active_chunk_count"]),
                "total_chunk_count": int(r["total_chunk_count"]),
                "created_at": r.get("created_at"),
                "updated_at": r.get("updated_at"),
            }
        )

    log.info(
        "rag_corpus_console.list_corpus_documents",
        extra={
            "event": "corpus_console.documents_listed",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "count": len(items),
            "request_id": request.headers.get("x-request-id"),
        },
    )

    return {
        "corpus_id": corpus_id,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort_by": sort_by,
        "sort_dir": sort_dir,
    }


# ---------------------------------------------------------------------------
# GET /rag/documents/{document_id}
# ---------------------------------------------------------------------------


@router.get("/documents/{document_id}")
def get_document_detail(
    document_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """
    Return document detail with chunk summary for the Corpus Management Console.

    Includes:
    - All lifecycle fields: ingestion_status, is_current, quarantine_reason, etc.
    - source_hash_prefix (12-char, operator-safe)
    - Chunk summary: total, active, embedding state distribution
    - Safe metadata (no raw vectors, no prompts, no secrets)

    Does NOT expose: raw chunk text, raw vectors, provider payloads, secrets.
    Tenant-scoped: returns 404 if document_id belongs to a different tenant.
    """
    tenant_id = _tenant(request)
    doc = get_document(db, tenant_id, document_id)
    if doc is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "DOCUMENT_NOT_FOUND", "document_id": document_id},
        )

    chunk_counts = _document_chunk_count(
        db, tenant_id=tenant_id, document_id=document_id
    )
    embedding_summary = _document_embedding_summary(
        db, tenant_id=tenant_id, document_id=document_id
    )

    log.info(
        "rag_corpus_console.get_document_detail",
        extra={
            "event": "corpus_console.document_detail_viewed",
            "tenant_id": tenant_id,
            "corpus_id": doc.get("corpus_id"),
            "document_id": document_id,
            "request_id": request.headers.get("x-request-id"),
        },
    )

    return {
        "document_id": doc["document_id"],
        "corpus_id": doc.get("corpus_id"),
        "title": doc.get("title"),
        "source": doc.get("source"),
        "version_id": doc.get("version_id"),
        "version_number": doc.get("version_number", 1),
        "is_current": bool(
            int(doc["is_current"]) if doc.get("is_current") is not None else 1
        ),
        "ingestion_status": doc.get("ingestion_status") or "indexed",
        "quarantine_reason": doc.get("quarantine_reason"),
        "failure_reason": doc.get("failure_reason"),
        "source_hash_prefix": _safe_source_hash_prefix(doc.get("source_hash")),
        "indexed_at": doc.get("indexed_at"),
        "superseded_at": doc.get("superseded_at"),
        "superseded_by_version_id": doc.get("superseded_by_version_id"),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "active_chunk_count": chunk_counts["active_chunk_count"],
        "total_chunk_count": chunk_counts["total_chunk_count"],
        "embedding_state_summary": embedding_summary,
        "metadata": _safe_metadata(doc.get("metadata")),
        "future_hooks": {
            "duplicate_detection": None,
            "stale_detection": None,
            "evidence_lineage": None,
        },
    }
