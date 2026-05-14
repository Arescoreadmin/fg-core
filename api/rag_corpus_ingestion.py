"""
api/rag_corpus_ingestion.py — Document Ingestion UX API (PR 51).

POST /rag/upload
    -> tenant-scoped document upload; multipart form-data.
GET /rag/uploads
    -> paginated tenant-scoped list of uploaded documents with ingestion status.
GET /rag/documents/{document_id}/ingestion
    -> tenant-scoped ingestion lifecycle detail for a single document.
POST /rag/documents/{document_id}/retry-ingestion
    -> planned endpoint (returns 503).

Security: All endpoints require verify_api_key + governance:write scope.
Tenant isolation: every operation scoped to require_bound_tenant().
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes, verify_api_key
from api.deps import tenant_db_required
from api.rag_corpus_store import (
    INGESTION_CHUNKING,
    INGESTION_DUPLICATE,
    INGESTION_EMBEDDING,
    INGESTION_FAILED,
    INGESTION_INDEXED,
    INGESTION_QUARANTINED,
    INGESTION_RECEIVED,
    INGESTION_REINDEXING,
    INGESTION_SUPERSEDED,
    INGESTION_VALIDATING,
    QUARANTINE_EMPTY_DOCUMENT,
    QUARANTINE_ENCODING_ERROR,
    QUARANTINE_TOO_LARGE,
    QUARANTINE_UNSUPPORTED_TYPE,
    get_corpus,
    get_document,
    ingest_document_version,
    _table_columns,
)

log = logging.getLogger("frostgate.rag_corpus_ingestion")

_MAX_UPLOAD_BYTES = int(os.getenv("FG_RAG_MAX_UPLOAD_BYTES", str(1_000_000)))
_MAX_TITLE_LEN = 512
_MAX_CORPUS_ID_LEN = 256
_SAFE_SOURCE_HASH_PREFIX_LEN = 12
_SUPPORTED_CONTENT_TYPES = frozenset({"text/plain", "text/markdown"})
_EXT_TO_CONTENT_TYPE: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
}
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
_QUARANTINE_REASON_LABELS: dict[str, str] = {
    QUARANTINE_EMPTY_DOCUMENT: "Document content is empty",
    QUARANTINE_UNSUPPORTED_TYPE: "Unsupported file type",
    QUARANTINE_ENCODING_ERROR: "Document encoding error",
    QUARANTINE_TOO_LARGE: "Document exceeds size limit",
    "parse_failed": "Document parsing failed",
    "unsafe_content": "Policy rejected: unsafe content",
    "chunking_failed": "Chunking failed",
    "metadata_invalid": "Metadata validation failed",
    "unknown": "Unknown quarantine reason",
}
_ALLOWED_UPLOAD_SORT_DIRS = frozenset({"asc", "desc"})

router = APIRouter(
    prefix="/rag",
    tags=["rag", "governance", "ingestion"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("governance:write")),
    ],
)


def _tenant(request: Request) -> str:
    return require_bound_tenant(request)


def _safe_source_hash_prefix(source_hash: Optional[str]) -> Optional[str]:
    if not source_hash:
        return None
    return str(source_hash)[:_SAFE_SOURCE_HASH_PREFIX_LEN]


def _detect_content_type(filename: Optional[str], declared_ct: Optional[str]) -> str:
    if filename and "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()
        if ext in _EXT_TO_CONTENT_TYPE:
            return _EXT_TO_CONTENT_TYPE[ext]
    if declared_ct:
        base = declared_ct.split(";")[0].strip().lower()
        if base in _SUPPORTED_CONTENT_TYPES:
            return base
    return "application/octet-stream"


def _quarantine_label(reason: Optional[str]) -> str:
    if not reason:
        return _QUARANTINE_REASON_LABELS["unknown"]
    return _QUARANTINE_REASON_LABELS.get(reason, f"Quarantine: {reason}")


def _ingestion_status_label(status: str) -> str:
    _LABELS: dict[str, str] = {
        INGESTION_RECEIVED: "Upload Received",
        INGESTION_VALIDATING: "Validating",
        INGESTION_DUPLICATE: "Duplicate Detected",
        INGESTION_QUARANTINED: "Quarantined",
        INGESTION_CHUNKING: "Chunking",
        INGESTION_EMBEDDING: "Embedding",
        INGESTION_INDEXED: "Indexed",
        INGESTION_FAILED: "Failed",
        INGESTION_SUPERSEDED: "Superseded",
        INGESTION_REINDEXING: "Re-indexing",
    }
    return _LABELS.get(status, f"Unknown ({status})")


def _document_chunk_summary(
    conn: Session, *, tenant_id: str, document_id: str
) -> dict[str, int]:
    chunk_cols = _table_columns(conn, "rag_chunks")
    active_clause = (
        "AND COALESCE(is_active, 1) = 1" if "is_active" in chunk_cols else ""
    )
    row = (
        conn.execute(
            text(
                f"""
                SELECT COUNT(*) AS total,
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


def _build_ingestion_lifecycle_response(
    doc: dict[str, Any],
    chunk_summary: dict[str, int],
    embedding_summary: dict[str, int],
) -> dict[str, Any]:
    ingestion_status = str(doc.get("ingestion_status") or INGESTION_INDEXED)
    quarantine_reason = doc.get("quarantine_reason")
    failure_reason = doc.get("failure_reason")
    return {
        "document_id": doc["document_id"],
        "corpus_id": doc.get("corpus_id"),
        "title": doc.get("title"),
        "source": doc.get("source"),
        "ingestion_status": ingestion_status,
        "ingestion_status_label": _ingestion_status_label(ingestion_status),
        "is_current": bool(doc.get("is_current", True)),
        "version_id": doc.get("version_id"),
        "version_number": int(doc.get("version_number") or 1),
        "source_hash_prefix": _safe_source_hash_prefix(
            str(doc.get("source_hash") or "")
        ),
        "quarantine_reason": quarantine_reason,
        "quarantine_reason_label": _quarantine_label(quarantine_reason)
        if quarantine_reason
        else None,
        "failure_reason": failure_reason,
        "indexed_at": doc.get("indexed_at"),
        "superseded_at": doc.get("superseded_at"),
        "superseded_by_version_id": doc.get("superseded_by_version_id"),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "active_chunk_count": chunk_summary.get("active_chunk_count", 0),
        "total_chunk_count": chunk_summary.get("total_chunk_count", 0),
        "embedding_state_summary": embedding_summary,
        "audit_safe": True,
    }


@router.post("/upload")
async def upload_document(
    request: Request,
    db: Session = Depends(tenant_db_required),
    file: UploadFile = File(...),
    corpus_id: str = Form(...),
    title: str = Form(default=""),
) -> dict[str, Any]:
    """Upload a document to a corpus and begin ingestion."""
    tenant_id = _tenant(request)
    request_id = request.headers.get("x-request-id")

    corpus_id = str(corpus_id).strip()
    if not corpus_id or len(corpus_id) > _MAX_CORPUS_ID_LEN:
        raise HTTPException(status_code=422, detail={"code": "INVALID_CORPUS_ID"})

    doc_title = str(title).strip() if title else ""
    if doc_title and len(doc_title) > _MAX_TITLE_LEN:
        raise HTTPException(
            status_code=422,
            detail={"code": "TITLE_TOO_LONG", "max_length": _MAX_TITLE_LEN},
        )

    corpus = get_corpus(db, tenant_id, corpus_id)
    if corpus is None:
        raise HTTPException(
            status_code=404, detail={"code": "CORPUS_NOT_FOUND", "corpus_id": corpus_id}
        )

    filename = file.filename or "upload.txt"
    if not doc_title:
        doc_title = filename

    content_type = _detect_content_type(filename, file.content_type)
    raw_bytes = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        log.warning(
            "rag_corpus_ingestion.upload_too_large",
            extra={
                "event": "ingestion.upload_rejected",
                "tenant_id": tenant_id,
                "corpus_id": corpus_id,
                "request_id": request_id,
            },
        )
        raise HTTPException(
            status_code=413,
            detail={"code": "UPLOAD_TOO_LARGE", "max_bytes": _MAX_UPLOAD_BYTES},
        )

    if content_type in _SUPPORTED_CONTENT_TYPES:
        try:
            content = raw_bytes.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            content = ""
            content_type = "application/octet-stream"
    else:
        try:
            content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            content = ""

    ingest_ct = (
        content_type
        if content_type in _SUPPORTED_CONTENT_TYPES
        else "application/octet-stream"
    )

    log.info(
        "rag_corpus_ingestion.upload_received",
        extra={
            "event": "ingestion.upload_received",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "content_type": content_type,
            "request_id": request_id,
        },
    )

    try:
        result = ingest_document_version(
            db,
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            title=doc_title,
            source=filename,
            content=content,
            content_type=ingest_ct,
        )
    except ValueError as exc:
        log.warning(
            "rag_corpus_ingestion.ingest_error",
            extra={
                "event": "ingestion.ingest_error",
                "tenant_id": tenant_id,
                "corpus_id": corpus_id,
                "request_id": request_id,
            },
        )
        raise HTTPException(
            status_code=422, detail={"code": "INGEST_ERROR", "message": str(exc)}
        ) from exc

    ingestion_status = str(result.get("ingestion_status") or INGESTION_INDEXED)
    document_id = str(result.get("document_id", ""))
    version_id = str(result.get("version_id") or "")

    log.info(
        "rag_corpus_ingestion.upload_complete",
        extra={
            "event": "ingestion.upload_complete",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "document_id": document_id,
            "ingestion_status": ingestion_status,
            "request_id": request_id,
        },
    )

    chunk_summary = (
        _document_chunk_summary(db, tenant_id=tenant_id, document_id=document_id)
        if document_id
        else {"active_chunk_count": 0, "total_chunk_count": 0}
    )
    embedding_summary = (
        _document_embedding_summary(db, tenant_id=tenant_id, document_id=document_id)
        if document_id
        else {}
    )
    is_duplicate = ingestion_status == INGESTION_DUPLICATE
    is_quarantined = ingestion_status == INGESTION_QUARANTINED

    return {
        "document_id": document_id,
        "corpus_id": corpus_id,
        "title": doc_title,
        "source": filename,
        "ingestion_status": ingestion_status,
        "ingestion_status_label": _ingestion_status_label(ingestion_status),
        "version_id": version_id,
        "version_number": int(result.get("version_number") or 1),
        "source_hash_prefix": _safe_source_hash_prefix(
            str(result.get("source_hash") or "")
        ),
        "active_chunk_count": chunk_summary["active_chunk_count"],
        "total_chunk_count": chunk_summary["total_chunk_count"],
        "embedding_state_summary": embedding_summary,
        "is_duplicate": is_duplicate,
        "duplicate_of_document_id": result.get("duplicate_of_document_id")
        if is_duplicate
        else None,
        "is_quarantined": is_quarantined,
        "quarantine_reason": result.get("quarantine_reason")
        if is_quarantined
        else None,
        "quarantine_reason_label": _quarantine_label(result.get("quarantine_reason"))
        if is_quarantined
        else None,
        "failure_reason": result.get("failure_reason"),
        "indexed_at": result.get("indexed_at"),
        "created_at": result.get("created_at"),
        "audit_safe": True,
        "future_hooks": {
            "retry_available": False,
            "connector_sync": None,
            "batch_ingestion": None,
            "delta_sync": None,
        },
    }


@router.get("/uploads")
def list_uploads(
    request: Request,
    db: Session = Depends(tenant_db_required),
    corpus_id: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ingestion_status: Optional[str] = Query(default=None),
    sort_dir: str = Query(default="desc"),
) -> dict[str, Any]:
    """Return paginated tenant-scoped list of uploaded documents with ingestion status."""
    tenant_id = _tenant(request)

    if sort_dir not in _ALLOWED_UPLOAD_SORT_DIRS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_SORT_DIR",
                "sort_dir": sort_dir,
                "allowed": sorted(_ALLOWED_UPLOAD_SORT_DIRS),
            },
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

    table_cols = _table_columns(db, "rag_documents")
    ingestion_status_col = "ingestion_status" in table_cols
    is_current_col = "is_current" in table_cols

    where_parts = ["d.tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": tenant_id}

    if corpus_id is not None:
        c = str(corpus_id).strip()
        if not c:
            raise HTTPException(status_code=422, detail={"code": "INVALID_CORPUS_ID"})
        corpus = get_corpus(db, tenant_id, c)
        if corpus is None:
            raise HTTPException(
                status_code=404, detail={"code": "CORPUS_NOT_FOUND", "corpus_id": c}
            )
        where_parts.append("d.corpus_id = :corpus_id")
        params["corpus_id"] = c

    if ingestion_status is not None and ingestion_status_col:
        where_parts.append(
            "COALESCE(d.ingestion_status, 'indexed') = :ingestion_status"
        )
        params["ingestion_status"] = ingestion_status

    where_sql = " AND ".join(where_parts)
    sort_sql = f"d.created_at {sort_dir.upper()}, d.document_id ASC"

    count_row = (
        db.execute(
            text(f"SELECT COUNT(*) AS cnt FROM rag_documents d WHERE {where_sql}"),
            params,
        )
        .mappings()
        .first()
    )
    total = int(count_row["cnt"] or 0) if count_row else 0

    select_cols = (
        "d.document_id, d.corpus_id, d.title, d.source, d.created_at, d.updated_at"
    )
    select_cols += (
        ", COALESCE(d.ingestion_status, 'indexed') AS ingestion_status"
        if ingestion_status_col
        else ", 'indexed' AS ingestion_status"
    )
    select_cols += (
        ", COALESCE(d.is_current, 1) AS is_current"
        if is_current_col
        else ", 1 AS is_current"
    )
    select_cols += (
        ", COALESCE(d.version_number, 1) AS version_number"
        if "version_number" in table_cols
        else ", 1 AS version_number"
    )
    if "source_hash" in table_cols:
        select_cols += ", d.source_hash"
    if "quarantine_reason" in table_cols:
        select_cols += ", d.quarantine_reason"
    if "failure_reason" in table_cols:
        select_cols += ", d.failure_reason"

    rows = (
        db.execute(
            text(
                f"SELECT {select_cols} FROM rag_documents d WHERE {where_sql} ORDER BY {sort_sql} LIMIT :limit OFFSET :offset"
            ),
            {**params, "limit": limit, "offset": offset},
        )
        .mappings()
        .fetchall()
    )

    items: list[dict[str, Any]] = []
    for row in rows:
        doc_id = str(row["document_id"])
        chunks = _document_chunk_summary(db, tenant_id=tenant_id, document_id=doc_id)
        status = str(row.get("ingestion_status") or INGESTION_INDEXED)
        items.append(
            {
                "document_id": doc_id,
                "corpus_id": row.get("corpus_id"),
                "title": row.get("title"),
                "source": row.get("source"),
                "ingestion_status": status,
                "ingestion_status_label": _ingestion_status_label(status),
                "is_current": bool(row.get("is_current", 1)),
                "version_number": int(row.get("version_number") or 1),
                "source_hash_prefix": _safe_source_hash_prefix(
                    str(row.get("source_hash") or "")
                ),
                "quarantine_reason": row.get("quarantine_reason"),
                "failure_reason": row.get("failure_reason"),
                "active_chunk_count": chunks["active_chunk_count"],
                "total_chunk_count": chunks["total_chunk_count"],
                "created_at": row.get("created_at"),
                "updated_at": row.get("updated_at"),
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort_dir": sort_dir,
        "corpus_id_filter": corpus_id,
        "ingestion_status_filter": ingestion_status,
    }


@router.get("/documents/{document_id}/ingestion")
def get_document_ingestion(
    document_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Return ingestion lifecycle detail for a single document."""
    tenant_id = _tenant(request)
    request_id = request.headers.get("x-request-id")

    doc = get_document(db, tenant_id, document_id)
    if doc is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "DOCUMENT_NOT_FOUND", "document_id": document_id},
        )

    chunk_summary = _document_chunk_summary(
        db, tenant_id=tenant_id, document_id=document_id
    )
    embedding_summary = _document_embedding_summary(
        db, tenant_id=tenant_id, document_id=document_id
    )

    log.info(
        "rag_corpus_ingestion.get_document_ingestion",
        extra={
            "event": "ingestion.document_ingestion_viewed",
            "tenant_id": tenant_id,
            "document_id": document_id,
            "request_id": request_id,
        },
    )

    payload = _build_ingestion_lifecycle_response(doc, chunk_summary, embedding_summary)
    payload["future_hooks"] = {
        "retry_available": False,
        "connector_source": None,
        "delta_sync_eligible": None,
        "stale_detection": None,
        "evidence_lineage": None,
    }
    return payload


@router.post("/documents/{document_id}/retry-ingestion")
def retry_document_ingestion(
    document_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Retry ingestion — PLANNED, not yet available. Returns 503."""
    tenant_id = _tenant(request)

    doc = get_document(db, tenant_id, document_id)
    if doc is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "DOCUMENT_NOT_FOUND", "document_id": document_id},
        )

    raise HTTPException(
        status_code=503,
        detail={
            "code": "RETRY_INGESTION_NOT_AVAILABLE",
            "document_id": document_id,
            "message": "Retry ingestion is a planned capability and is not yet available.",
            "planned": True,
        },
    )
