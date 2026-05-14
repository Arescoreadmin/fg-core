"""
api/rag_corpus_store.py — Tenant-scoped RAG corpus persistence layer.

Provides create/get/list operations for rag_corpora, rag_documents, and
rag_chunks.  Persistence only — no retrieval, no embeddings, no vector DB,
no AI answer changes.

All public functions:
- Require non-empty tenant_id (raise ValueError if blank/None).
- Filter every query by tenant_id.
- Never expose data across tenant boundaries.
- Accept a SQLAlchemy Session (from api/db.py) as their first argument.

The metadata column is stored as TEXT-serialised JSON in SQLite (test DB)
and as JSONB on PostgreSQL.  Callers always pass/receive plain dicts or None.
"""

from __future__ import annotations

import json
import logging
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("frostgate.rag_corpus_store")

INGESTION_RECEIVED = "received"
INGESTION_VALIDATING = "validating"
INGESTION_DUPLICATE = "duplicate"
INGESTION_QUARANTINED = "quarantined"
INGESTION_CHUNKING = "chunking"
INGESTION_EMBEDDING = "embedding"
INGESTION_INDEXED = "indexed"
INGESTION_FAILED = "failed"
INGESTION_SUPERSEDED = "superseded"
INGESTION_REINDEXING = "reindexing"

QUARANTINE_EMPTY_DOCUMENT = "empty_document"
QUARANTINE_UNSUPPORTED_TYPE = "unsupported_type"
QUARANTINE_PARSE_FAILED = "parse_failed"
QUARANTINE_TOO_LARGE = "too_large"
QUARANTINE_UNSAFE_CONTENT = "unsafe_content"
QUARANTINE_ENCODING_ERROR = "encoding_error"
QUARANTINE_CHUNKING_FAILED = "chunking_failed"
QUARANTINE_METADATA_INVALID = "metadata_invalid"
QUARANTINE_UNKNOWN = "unknown"

_INDEXED_CURRENT_FILTER = (
    "COALESCE(d.ingestion_status, 'indexed') = 'indexed' "
    "AND COALESCE(d.is_current, 1) = 1"
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    """Generate a prefixed, collision-resistant ID using uuid4."""
    return f"{prefix}-{uuid.uuid4().hex}"


def _hash_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_source_hash(content: str) -> str:
    """Return deterministic SHA-256 over canonical source content."""
    return _hash_hex(content.replace("\r\n", "\n").replace("\r", "\n"))


def deterministic_version_id(
    *, tenant_id: str, corpus_id: str, source_hash: str, version_number: int
) -> str:
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "source_hash": source_hash,
            "version_number": version_number,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"ver-{_hash_hex(canonical)}"


def deterministic_chunk_id(
    *, tenant_id: str, document_id: str, version_id: str, ordinal: int, text: str
) -> str:
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "document_id": document_id,
            "version_id": version_id,
            "ordinal": ordinal,
            "text_hash": canonical_source_hash(text),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"ck-{_hash_hex(canonical)}"


def _require_tenant(tenant_id: Optional[str]) -> str:
    """Validate and return tenant_id; raise ValueError if blank."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id is required and must not be blank")
    return str(tenant_id).strip()


def _require_nonempty(value: Optional[str], field: str) -> str:
    """Validate and return a non-blank string field."""
    if not value or not str(value).strip():
        raise ValueError(f"{field} must not be blank")
    return str(value).strip()


def _encode_metadata(metadata: Optional[dict[str, Any]]) -> Optional[str]:
    """
    Serialize metadata dict to JSON string for storage.
    Returns None when metadata is None.
    SQLite stores TEXT; PostgreSQL JSONB accepts this string cast.
    """
    if metadata is None:
        return None
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True)


def _decode_metadata(raw: Optional[str]) -> Optional[dict[str, Any]]:
    """Deserialize stored metadata back to a plain dict (or None)."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        # PostgreSQL JSONB may already be deserialized by the driver.
        return raw
    try:
        return json.loads(raw)  # type: ignore[no-any-return]
    except (json.JSONDecodeError, TypeError):
        logger.warning("rag_corpus_store: unparseable metadata value; returning None")
        return None


def _table_columns(conn: Session, table: str) -> set[str]:
    bind = conn.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "sqlite":
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {str(row[1]) for row in rows}
    rows = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = :table"
        ),
        {"table": table},
    ).fetchall()
    return {str(row[0]) for row in rows}


def _document_select_columns(conn: Session) -> str:
    base = [
        "document_id",
        "corpus_id",
        "tenant_id",
        "title",
        "source",
        "metadata",
        "created_at",
        "updated_at",
    ]
    optional = [
        "version_id",
        "source_hash",
        "normalized_source_hash",
        "version_number",
        "is_current",
        "ingestion_status",
        "quarantine_reason",
        "failure_reason",
        "indexed_at",
        "superseded_at",
        "superseded_by_version_id",
    ]
    columns = _table_columns(conn, "rag_documents")
    return ", ".join([*base, *(column for column in optional if column in columns)])


def _chunk_select_columns(conn: Session) -> str:
    base = [
        "chunk_id",
        "document_id",
        "corpus_id",
        "tenant_id",
        "text",
        "ordinal",
        "metadata",
        "created_at",
    ]
    optional = [
        "content_hash",
        "embedding_state",
        "document_version_id",
        "source_hash",
        "is_active",
        "source_page",
        "extraction_version",
    ]
    columns = _table_columns(conn, "rag_chunks")
    return ", ".join([*base, *(column for column in optional if column in columns)])


# ---------------------------------------------------------------------------
# rag_corpora
# ---------------------------------------------------------------------------


def create_corpus(
    conn: Session,
    tenant_id: str,
    name: str,
    description: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Create a new corpus for *tenant_id*.

    Returns the persisted corpus row as a plain dict.
    Raises ValueError for blank tenant_id or blank name.
    """
    tid = _require_tenant(tenant_id)
    checked_name = _require_nonempty(name, "name")
    corpus_id = _new_id("corp")
    now = _utc_now_iso()
    meta_str = _encode_metadata(metadata)

    conn.execute(
        text(
            """
            INSERT INTO rag_corpora
                (corpus_id, tenant_id, name, description, metadata, created_at, updated_at)
            VALUES
                (:corpus_id, :tenant_id, :name, :description, :metadata, :created_at, :updated_at)
            """
        ),
        {
            "corpus_id": corpus_id,
            "tenant_id": tid,
            "name": checked_name,
            "description": description,
            "metadata": meta_str,
            "created_at": now,
            "updated_at": now,
        },
    )
    conn.commit()

    logger.info(
        "rag_corpus_store.create_corpus tenant_id=%s corpus_id=%s",
        tid,
        corpus_id,
    )
    return {
        "corpus_id": corpus_id,
        "tenant_id": tid,
        "name": checked_name,
        "description": description,
        "metadata": metadata,
        "created_at": now,
        "updated_at": now,
    }


def get_corpus(
    conn: Session,
    tenant_id: str,
    corpus_id: str,
) -> Optional[dict[str, Any]]:
    """
    Fetch a corpus by corpus_id, scoped to tenant_id.

    Returns None if not found or if the corpus belongs to a different tenant.
    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    row = (
        conn.execute(
            text(
                """
            SELECT corpus_id, tenant_id, name, description, metadata, created_at, updated_at
            FROM rag_corpora
            WHERE corpus_id = :corpus_id
              AND tenant_id = :tenant_id
            """
            ),
            {"corpus_id": corpus_id, "tenant_id": tid},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        return None

    r = dict(row)
    r["metadata"] = _decode_metadata(r.get("metadata"))
    return r


def list_corpora(
    conn: Session,
    tenant_id: str,
) -> list[dict[str, Any]]:
    """
    List all corpora for *tenant_id*, ordered by created_at ascending.

    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    rows = (
        conn.execute(
            text(
                """
            SELECT corpus_id, tenant_id, name, description, metadata, created_at, updated_at
            FROM rag_corpora
            WHERE tenant_id = :tenant_id
            ORDER BY created_at ASC
            """
            ),
            {"tenant_id": tid},
        )
        .mappings()
        .fetchall()
    )

    result = []
    for row in rows:
        r = dict(row)
        r["metadata"] = _decode_metadata(r.get("metadata"))
        result.append(r)
    return result


# ---------------------------------------------------------------------------
# rag_documents
# ---------------------------------------------------------------------------


def create_document(
    conn: Session,
    tenant_id: str,
    corpus_id: str,
    title: str,
    source: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Create a new document within *corpus_id* for *tenant_id*.

    The corpus must exist and belong to *tenant_id*.
    Raises ValueError for blank tenant_id, blank title, or corpus not found for tenant.
    """
    tid = _require_tenant(tenant_id)
    checked_title = _require_nonempty(title, "title")

    # Verify corpus ownership before inserting document.
    corpus_row = conn.execute(
        text(
            "SELECT corpus_id FROM rag_corpora WHERE corpus_id = :corpus_id AND tenant_id = :tenant_id"
        ),
        {"corpus_id": corpus_id, "tenant_id": tid},
    ).fetchone()
    if corpus_row is None:
        raise ValueError(f"corpus_id={corpus_id!r} not found for tenant_id={tid!r}")

    document_id = _new_id("doc")
    now = _utc_now_iso()
    meta_str = _encode_metadata(metadata)

    version_id = deterministic_version_id(
        tenant_id=tid,
        corpus_id=corpus_id,
        source_hash=canonical_source_hash(f"{checked_title}\n{source or ''}"),
        version_number=1,
    )

    columns = _table_columns(conn, "rag_documents")
    payload: dict[str, object] = {
        "document_id": document_id,
        "corpus_id": corpus_id,
        "tenant_id": tid,
        "title": checked_title,
        "source": source,
        "metadata": meta_str,
        "created_at": now,
        "updated_at": now,
    }
    optional_payload = {
        "version_id": version_id,
        "version_number": 1,
        "is_current": 1,
        "ingestion_status": INGESTION_INDEXED,
    }
    payload.update(
        {key: value for key, value in optional_payload.items() if key in columns}
    )
    insert_columns = list(payload)
    conn.execute(
        text(
            "INSERT INTO rag_documents "
            f"({', '.join(insert_columns)}) VALUES "
            f"({', '.join(':' + column for column in insert_columns)})"
        ),
        payload,
    )
    conn.commit()

    logger.info(
        "rag_corpus_store.create_document tenant_id=%s corpus_id=%s document_id=%s",
        tid,
        corpus_id,
        document_id,
    )
    return {
        "document_id": document_id,
        "corpus_id": corpus_id,
        "tenant_id": tid,
        "title": checked_title,
        "source": source,
        "metadata": metadata,
        "version_id": version_id,
        "version_number": 1,
        "is_current": True,
        "ingestion_status": INGESTION_INDEXED,
        "created_at": now,
        "updated_at": now,
    }


def get_document(
    conn: Session,
    tenant_id: str,
    document_id: str,
) -> Optional[dict[str, Any]]:
    """
    Fetch a document by document_id, scoped to tenant_id.

    Returns None if not found or if the document belongs to a different tenant.
    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    select_columns = _document_select_columns(conn)
    row = (
        conn.execute(
            text(
                f"""
            SELECT {select_columns}
            FROM rag_documents
            WHERE document_id = :document_id
              AND tenant_id   = :tenant_id
            """
            ),
            {"document_id": document_id, "tenant_id": tid},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        return None

    r = dict(row)
    r["metadata"] = _decode_metadata(r.get("metadata"))
    return r


def list_documents(
    conn: Session,
    tenant_id: str,
    corpus_id: str,
) -> list[dict[str, Any]]:
    """
    List all documents for *tenant_id* within *corpus_id*, ordered by created_at ascending.

    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    select_columns = _document_select_columns(conn)
    table_columns = _table_columns(conn, "rag_documents")
    order_by = (
        "created_at ASC, version_number ASC, document_id ASC"
        if "version_number" in table_columns
        else "created_at ASC, document_id ASC"
    )
    rows = (
        conn.execute(
            text(
                f"""
            SELECT {select_columns}
            FROM rag_documents
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
            ORDER BY {order_by}
            """
            ),
            {"tenant_id": tid, "corpus_id": corpus_id},
        )
        .mappings()
        .fetchall()
    )

    result = []
    for row in rows:
        r = dict(row)
        r["metadata"] = _decode_metadata(r.get("metadata"))
        result.append(r)
    return result


# ---------------------------------------------------------------------------
# rag_chunks
# ---------------------------------------------------------------------------


def store_chunks(
    conn: Session,
    tenant_id: str,
    document_id: str,
    corpus_id: str,
    chunks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Bulk-insert chunks for *document_id* / *corpus_id* scoped to *tenant_id*.

    *chunks* is a list of dicts; each must contain at minimum:
      - ``text`` (str, non-blank)
      - ``ordinal`` (int, ordering within the document)
    Optionally:
      - ``metadata`` (dict or None)

    The document must exist and belong to *tenant_id*.
    Raises ValueError for:
      - blank tenant_id
      - document not found for tenant
      - any chunk with blank text
    Returns the list of persisted chunk dicts (with generated chunk_ids).
    """
    tid = _require_tenant(tenant_id)

    # Verify document ownership using all three identifiers — tenant_id, corpus_id,
    # and document_id — so a caller cannot store chunks against a valid document_id
    # that belongs to a different corpus_id owned by the same tenant.
    doc_row = conn.execute(
        text(
            "SELECT document_id FROM rag_documents "
            "WHERE document_id = :document_id "
            "  AND corpus_id   = :corpus_id "
            "  AND tenant_id   = :tenant_id"
        ),
        {"document_id": document_id, "corpus_id": corpus_id, "tenant_id": tid},
    ).fetchone()
    if doc_row is None:
        raise ValueError(
            f"document_id={document_id!r} not found for "
            f"tenant_id={tid!r} / corpus_id={corpus_id!r}"
        )

    # Pre-validate the entire batch before any insert so that a bad chunk later
    # in the list cannot leave earlier chunks partially persisted.
    now = _utc_now_iso()
    validated: list[dict[str, Any]] = []
    for chunk in chunks:
        text_val = chunk.get("text") or ""
        if not str(text_val).strip():
            raise ValueError("chunk text must not be blank")
        ordinal = int(chunk["ordinal"])
        text_str = str(text_val).strip()
        metadata = chunk.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("chunk metadata must be a dict or None")
        version_id = chunk.get("document_version_id") or chunk.get("version_id")
        source_hash = chunk.get("source_hash")
        content_hash = chunk.get("content_hash") or canonical_source_hash(text_str)
        if source_hash is not None and not str(source_hash).strip():
            raise ValueError("source_hash must not be blank when provided")
        chunk_id = chunk.get("chunk_id")
        if chunk_id is None:
            chunk_id = _new_id("ck")
        source_page_raw = chunk.get("source_page")
        source_page: Optional[int] = (
            int(source_page_raw) if source_page_raw is not None else None
        )
        extraction_version: Optional[str] = chunk.get("extraction_version") or None
        validated.append(
            {
                "chunk_id": str(chunk_id),
                "text": text_str,
                "ordinal": ordinal,
                "metadata": metadata,
                "content_hash": str(content_hash),
                "document_version_id": str(version_id) if version_id else None,
                "source_hash": str(source_hash) if source_hash else None,
                "is_active": 1 if chunk.get("is_active", True) else 0,
                "source_page": source_page,
                "extraction_version": extraction_version,
            }
        )

    # All chunks valid — insert in a single pass.
    persisted: list[dict[str, Any]] = []
    table_columns = _table_columns(conn, "rag_chunks")
    for v in validated:
        meta_str = _encode_metadata(v["metadata"])
        payload: dict[str, object] = {
            "chunk_id": v["chunk_id"],
            "document_id": document_id,
            "corpus_id": corpus_id,
            "tenant_id": tid,
            "text": v["text"],
            "ordinal": v["ordinal"],
            "metadata": meta_str,
            "created_at": now,
        }
        optional_payload = {
            "content_hash": v["content_hash"],
            "document_version_id": v["document_version_id"],
            "source_hash": v["source_hash"],
            "is_active": v["is_active"],
            "source_page": v["source_page"],
            "extraction_version": v["extraction_version"],
        }
        payload.update(
            {
                key: value
                for key, value in optional_payload.items()
                if key in table_columns
            }
        )
        insert_columns = list(payload)
        conn.execute(
            text(
                "INSERT INTO rag_chunks "
                f"({', '.join(insert_columns)}) VALUES "
                f"({', '.join(':' + column for column in insert_columns)})"
            ),
            payload,
        )
        persisted.append(
            {
                "chunk_id": v["chunk_id"],
                "document_id": document_id,
                "corpus_id": corpus_id,
                "tenant_id": tid,
                "text": v["text"],
                "ordinal": v["ordinal"],
                "metadata": v["metadata"],
                "content_hash": v["content_hash"],
                "document_version_id": v["document_version_id"],
                "source_hash": v["source_hash"],
                "is_active": bool(v["is_active"]),
                "source_page": v["source_page"],
                "extraction_version": v["extraction_version"],
                "created_at": now,
            }
        )

    conn.commit()

    logger.info(
        "rag_corpus_store.store_chunks tenant_id=%s document_id=%s count=%d",
        tid,
        document_id,
        len(persisted),
    )
    return persisted


def get_chunk(
    conn: Session,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    chunk_id: str,
) -> Optional[dict[str, Any]]:
    """
    Fetch a chunk by chunk_id, scoped to tenant_id, corpus_id, and document_id.

    Returns None if not found or if the chunk belongs to a different tenant/corpus/document.
    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    select_columns = _chunk_select_columns(conn)
    row = (
        conn.execute(
            text(
                f"""
            SELECT {select_columns}
            FROM rag_chunks
            WHERE chunk_id    = :chunk_id
              AND document_id = :document_id
              AND corpus_id   = :corpus_id
              AND tenant_id   = :tenant_id
            """
            ),
            {
                "chunk_id": chunk_id,
                "document_id": document_id,
                "corpus_id": corpus_id,
                "tenant_id": tid,
            },
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        return None

    r = dict(row)
    r["metadata"] = _decode_metadata(r.get("metadata"))
    return r


def list_chunks(
    conn: Session,
    tenant_id: str,
    document_id: str,
) -> list[dict[str, Any]]:
    """
    List all chunks for *document_id* scoped to *tenant_id*, ordered by ordinal ascending.

    Raises ValueError for blank tenant_id.
    """
    tid = _require_tenant(tenant_id)
    select_columns = _chunk_select_columns(conn)
    active_filter = (
        "AND COALESCE(is_active, 1) = 1"
        if "is_active" in _table_columns(conn, "rag_chunks")
        else ""
    )
    rows = (
        conn.execute(
            text(
                f"""
            SELECT {select_columns}
            FROM rag_chunks
            WHERE tenant_id   = :tenant_id
              AND document_id = :document_id
              {active_filter}
            ORDER BY ordinal ASC
            """
            ),
            {"tenant_id": tid, "document_id": document_id},
        )
        .mappings()
        .fetchall()
    )

    result = []
    for row in rows:
        r = dict(row)
        r["metadata"] = _decode_metadata(r.get("metadata"))
        result.append(r)
    return result


def ingest_document_version(
    conn: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    title: str,
    source: str,
    content: str,
    content_type: str = "text/plain",
    metadata: Optional[dict[str, Any]] = None,
    max_chars: int = 1000,
) -> dict[str, Any]:
    """Create an indexed document version or a tenant-scoped quarantine record.

    This persisted ingestion helper is deterministic and audit-safe. It never
    logs raw document content and never broadens deduplication across tenants.
    """
    tid = _require_tenant(tenant_id)
    checked_title = _require_nonempty(title, "title")
    checked_source = _require_nonempty(source, "source")
    now = _utc_now_iso()
    source_hash = canonical_source_hash(content if isinstance(content, str) else "")
    normalized_source_hash = source_hash

    if content_type not in {"text/plain", "text/markdown"}:
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash or None,
            reason=QUARANTINE_UNSUPPORTED_TYPE,
            detail="unsupported document type",
            metadata=metadata,
            now=now,
        )
    if not isinstance(content, str):
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=None,
            reason=QUARANTINE_ENCODING_ERROR,
            detail="document content must be text",
            metadata=metadata,
            now=now,
        )
    if len(content) > max_chars * 1000:
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash,
            reason=QUARANTINE_TOO_LARGE,
            detail="document exceeds ingestion size limit",
            metadata=metadata,
            now=now,
        )
    if not content.strip():
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash,
            reason=QUARANTINE_EMPTY_DOCUMENT,
            detail="document content is empty",
            metadata=metadata,
            now=now,
        )

    corpus_row = get_corpus(conn, tid, corpus_id)
    if corpus_row is None:
        raise ValueError(f"corpus_id={corpus_id!r} not found for tenant_id={tid!r}")

    duplicate = _find_current_indexed_by_hash(
        conn, tenant_id=tid, corpus_id=corpus_id, source_hash=source_hash
    )
    if duplicate is not None:
        _audit_ingestion(
            "duplicate_detected",
            tenant_id=tid,
            corpus_id=corpus_id,
            document_id=str(duplicate["document_id"]),
            version_id=str(duplicate["version_id"]),
            ingestion_status=INGESTION_DUPLICATE,
            reason_code=INGESTION_DUPLICATE,
        )
        return {
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "document_id": duplicate["document_id"],
            "version_id": duplicate["version_id"],
            "ingestion_status": INGESTION_DUPLICATE,
            "duplicate_of_document_id": duplicate["document_id"],
            "source_hash": source_hash,
            "chunk_count": int(duplicate.get("chunk_count") or 0),
            "active_version": True,
            "created_at": duplicate["created_at"],
            "indexed_at": duplicate.get("indexed_at"),
        }

    version_number = _next_version_number(
        conn, tenant_id=tid, corpus_id=corpus_id, source=checked_source
    )
    document_id = _new_id("doc")
    version_id = deterministic_version_id(
        tenant_id=tid,
        corpus_id=corpus_id,
        source_hash=source_hash,
        version_number=version_number,
    )
    meta = dict(metadata or {})
    meta.update(
        {
            "source_hash": source_hash,
            "normalized_source_hash": normalized_source_hash,
            "future_hooks": {
                "evidence_graph_ready": True,
                "fact_extraction_ready": True,
                "rag_evaluation_ready": True,
            },
        }
    )
    meta_str = _encode_metadata(meta)

    conn.execute(
        text(
            """
            UPDATE rag_documents
            SET is_current = 0,
                ingestion_status = :superseded,
                superseded_at = :now,
                superseded_by_version_id = :version_id,
                updated_at = :now
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
              AND source = :source
              AND COALESCE(is_current, 1) = 1
            """
        ),
        {
            "superseded": INGESTION_SUPERSEDED,
            "now": now,
            "version_id": version_id,
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "source": checked_source,
        },
    )
    conn.execute(
        text(
            """
            UPDATE rag_chunks
            SET is_active = 0
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
              AND document_id IN (
                  SELECT document_id FROM rag_documents
                  WHERE tenant_id = :tenant_id AND corpus_id = :corpus_id AND source = :source
                    AND ingestion_status = :superseded
              )
            """
        ),
        {
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "source": checked_source,
            "superseded": INGESTION_SUPERSEDED,
        },
    )
    conn.execute(
        text(
            """
            INSERT INTO rag_documents
                (document_id, corpus_id, tenant_id, title, source, metadata,
                 created_at, updated_at, version_id, source_hash,
                 normalized_source_hash, version_number, is_current,
                 ingestion_status, indexed_at)
            VALUES
                (:document_id, :corpus_id, :tenant_id, :title, :source, :metadata,
                 :created_at, :updated_at, :version_id, :source_hash,
                 :normalized_source_hash, :version_number, 1, :ingestion_status,
                 :indexed_at)
            """
        ),
        {
            "document_id": document_id,
            "corpus_id": corpus_id,
            "tenant_id": tid,
            "title": checked_title,
            "source": checked_source,
            "metadata": meta_str,
            "created_at": now,
            "updated_at": now,
            "version_id": version_id,
            "source_hash": source_hash,
            "normalized_source_hash": normalized_source_hash,
            "version_number": version_number,
            "ingestion_status": INGESTION_CHUNKING,
            "indexed_at": None,
        },
    )

    try:
        chunk_payloads = _chunk_content(
            tenant_id=tid,
            document_id=document_id,
            version_id=version_id,
            source_hash=source_hash,
            content=content,
            max_chars=max_chars,
        )
        persisted_chunks = store_chunks(
            conn,
            tenant_id=tid,
            document_id=document_id,
            corpus_id=corpus_id,
            chunks=chunk_payloads,
        )
        conn.execute(
            text(
                """
                UPDATE rag_documents
                SET ingestion_status = :indexed,
                    indexed_at = :now,
                    updated_at = :now
                WHERE tenant_id = :tenant_id AND document_id = :document_id
                """
            ),
            {
                "indexed": INGESTION_INDEXED,
                "now": now,
                "tenant_id": tid,
                "document_id": document_id,
            },
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash,
            reason=QUARANTINE_CHUNKING_FAILED,
            detail=_safe_error(exc),
            metadata=metadata,
            now=now,
        )

    _audit_ingestion(
        "indexing_completed",
        tenant_id=tid,
        corpus_id=corpus_id,
        document_id=document_id,
        version_id=version_id,
        ingestion_status=INGESTION_INDEXED,
        reason_code=INGESTION_INDEXED,
    )
    return {
        "tenant_id": tid,
        "corpus_id": corpus_id,
        "document_id": document_id,
        "version_id": version_id,
        "source_hash": source_hash,
        "normalized_source_hash": normalized_source_hash,
        "version_number": version_number,
        "ingestion_status": INGESTION_INDEXED,
        "created_at": now,
        "indexed_at": now,
        "chunk_count": len(persisted_chunks),
        "active_version": True,
    }


def ingest_pdf_document(
    conn: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    title: str,
    source: str,
    pdf_result: "Any",
    metadata: Optional[dict[str, Any]] = None,
    max_chars: int = 1000,
) -> dict[str, Any]:
    """Ingest a validated PDF extraction result as a versioned, page-aware document.

    pdf_result must be a PDFExtractionResult from api.rag.pdf_extractor.
    The source_hash is taken from the PDF bytes hash (not the extracted text)
    to ensure stable deduplication on the original file.

    Chunk metadata includes source_page (1-based) and extraction_version for
    provenance, citation rendering, and retrieval trace.

    Security invariants:
    - tenant_id sourced from trusted execution context only (not request body).
    - Duplicate detection uses the PDF source hash.
    - Empty-extract PDFs (image-only) are quarantined cleanly.
    - Raw PDF content never appears in error messages or logs.
    """
    from api.rag.pdf_extractor import PDFExtractionResult, build_pdf_chunk_payloads

    tid = _require_tenant(tenant_id)
    checked_title = _require_nonempty(title, "title")
    checked_source = _require_nonempty(source, "source")
    now = _utc_now_iso()

    if not isinstance(pdf_result, PDFExtractionResult):
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=None,
            reason=QUARANTINE_UNSUPPORTED_TYPE,
            detail="pdf_result must be a PDFExtractionResult",
            metadata=metadata,
            now=now,
        )

    source_hash = pdf_result.source_hash  # SHA-256 of raw PDF bytes
    normalized_source_hash = source_hash

    if not pdf_result.has_text:
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash,
            reason=QUARANTINE_EMPTY_DOCUMENT,
            detail="PDF extraction produced no text; may be scanned or image-only",
            metadata=metadata,
            now=now,
        )

    corpus_row = get_corpus(conn, tid, corpus_id)
    if corpus_row is None:
        raise ValueError(f"corpus_id={corpus_id!r} not found for tenant_id={tid!r}")

    duplicate = _find_current_indexed_by_hash(
        conn, tenant_id=tid, corpus_id=corpus_id, source_hash=source_hash
    )
    if duplicate is not None:
        _audit_ingestion(
            "duplicate_detected",
            tenant_id=tid,
            corpus_id=corpus_id,
            document_id=str(duplicate["document_id"]),
            version_id=str(duplicate["version_id"]),
            ingestion_status=INGESTION_DUPLICATE,
            reason_code=INGESTION_DUPLICATE,
        )
        return {
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "document_id": duplicate["document_id"],
            "version_id": duplicate["version_id"],
            "ingestion_status": INGESTION_DUPLICATE,
            "duplicate_of_document_id": duplicate["document_id"],
            "source_hash": source_hash,
            "chunk_count": int(duplicate.get("chunk_count") or 0),
            "active_version": True,
            "created_at": duplicate["created_at"],
            "indexed_at": duplicate.get("indexed_at"),
        }

    version_number = _next_version_number(
        conn, tenant_id=tid, corpus_id=corpus_id, source=checked_source
    )
    document_id = _new_id("doc")
    version_id = deterministic_version_id(
        tenant_id=tid,
        corpus_id=corpus_id,
        source_hash=source_hash,
        version_number=version_number,
    )
    meta = dict(metadata or {})
    meta.update(
        {
            "source_hash": source_hash,
            "normalized_source_hash": normalized_source_hash,
            "content_type": "application/pdf",
            "page_count": pdf_result.page_count,
            "extraction_version": pdf_result.extraction_version,
            "future_hooks": {
                "ocr_insertion_ready": True,
                "scanned_pdf_ready": True,
                "table_extraction_ready": True,
                "image_extraction_ready": True,
                "semantic_chunking_ready": True,
                "async_worker_ready": True,
                "evidence_graph_ready": True,
                "rag_evaluation_ready": True,
            },
        }
    )
    meta_str = _encode_metadata(meta)

    conn.execute(
        text(
            """
            UPDATE rag_documents
            SET is_current = 0,
                ingestion_status = :superseded,
                superseded_at = :now,
                superseded_by_version_id = :version_id,
                updated_at = :now
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
              AND source = :source
              AND COALESCE(is_current, 1) = 1
            """
        ),
        {
            "superseded": INGESTION_SUPERSEDED,
            "now": now,
            "version_id": version_id,
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "source": checked_source,
        },
    )
    conn.execute(
        text(
            """
            UPDATE rag_chunks
            SET is_active = 0
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
              AND document_id IN (
                  SELECT document_id FROM rag_documents
                  WHERE tenant_id = :tenant_id AND corpus_id = :corpus_id
                    AND source = :source AND ingestion_status = :superseded
              )
            """
        ),
        {
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "source": checked_source,
            "superseded": INGESTION_SUPERSEDED,
        },
    )
    doc_insert_params: dict[str, Any] = {
        "document_id": document_id,
        "corpus_id": corpus_id,
        "tenant_id": tid,
        "title": checked_title,
        "source": checked_source,
        "metadata": meta_str,
        "created_at": now,
        "updated_at": now,
        "version_id": version_id,
        "source_hash": source_hash,
        "normalized_source_hash": normalized_source_hash,
        "version_number": version_number,
        "is_current": 1,
        "ingestion_status": INGESTION_CHUNKING,
        "indexed_at": None,
    }
    doc_cols = _table_columns(conn, "rag_documents")
    if "content_type" in doc_cols:
        doc_insert_params["content_type"] = "application/pdf"
    col_names = ", ".join(doc_insert_params)
    col_placeholders = ", ".join(f":{k}" for k in doc_insert_params)
    conn.execute(
        text(f"INSERT INTO rag_documents ({col_names}) VALUES ({col_placeholders})"),
        doc_insert_params,
    )

    try:
        chunk_payloads = build_pdf_chunk_payloads(
            tenant_id=tid,
            document_id=document_id,
            version_id=version_id,
            source_hash=source_hash,
            pdf_result=pdf_result,
            max_chars=max_chars,
        )
        if not chunk_payloads:
            raise ValueError("PDF page-aware chunking produced no chunks")

        persisted_chunks = store_chunks(
            conn,
            tenant_id=tid,
            document_id=document_id,
            corpus_id=corpus_id,
            chunks=chunk_payloads,
        )
        conn.execute(
            text(
                """
                UPDATE rag_documents
                SET ingestion_status = :indexed,
                    indexed_at = :now,
                    updated_at = :now
                WHERE tenant_id = :tenant_id AND document_id = :document_id
                """
            ),
            {
                "indexed": INGESTION_INDEXED,
                "now": now,
                "tenant_id": tid,
                "document_id": document_id,
            },
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return _quarantine_document(
            conn,
            tenant_id=tid,
            corpus_id=corpus_id,
            title=checked_title,
            source=checked_source,
            source_hash=source_hash,
            reason=QUARANTINE_CHUNKING_FAILED,
            detail=_safe_error(exc),
            metadata=metadata,
            now=now,
        )

    _audit_ingestion(
        "pdf_indexing_completed",
        tenant_id=tid,
        corpus_id=corpus_id,
        document_id=document_id,
        version_id=version_id,
        ingestion_status=INGESTION_INDEXED,
        reason_code=INGESTION_INDEXED,
    )
    return {
        "tenant_id": tid,
        "corpus_id": corpus_id,
        "document_id": document_id,
        "version_id": version_id,
        "source_hash": source_hash,
        "normalized_source_hash": normalized_source_hash,
        "version_number": version_number,
        "ingestion_status": INGESTION_INDEXED,
        "content_type": "application/pdf",
        "page_count": pdf_result.page_count,
        "extraction_version": pdf_result.extraction_version,
        "created_at": now,
        "indexed_at": now,
        "chunk_count": len(persisted_chunks),
        "active_version": True,
    }


def reindex_document_version(
    conn: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    version_id: str,
    content: str,
    max_chars: int = 1000,
) -> dict[str, Any]:
    tid = _require_tenant(tenant_id)
    doc = _get_document_version(
        conn,
        tenant_id=tid,
        corpus_id=corpus_id,
        document_id=document_id,
        version_id=version_id,
    )
    if doc is None:
        raise ValueError("document version not found")
    if doc.get("ingestion_status") != INGESTION_INDEXED or not doc.get("is_current"):
        raise ValueError("only current indexed document versions may be re-indexed")
    source_hash = str(doc.get("source_hash") or canonical_source_hash(content))
    if source_hash != canonical_source_hash(content):
        raise ValueError("source_hash mismatch for re-index")

    now = _utc_now_iso()
    try:
        chunk_payloads = _chunk_content(
            tenant_id=tid,
            document_id=document_id,
            version_id=version_id,
            source_hash=source_hash,
            content=content,
            max_chars=max_chars,
        )
    except Exception as exc:
        _mark_document_failed(
            conn,
            tenant_id=tid,
            document_id=document_id,
            reason=_safe_error(exc),
            now=now,
        )
        raise ValueError("re-index failed during chunking") from exc

    existing_chunks = list_chunks(conn, tenant_id=tid, document_id=document_id)
    existing_ids = [str(chunk["chunk_id"]) for chunk in existing_chunks]
    expected_ids = [str(chunk["chunk_id"]) for chunk in chunk_payloads]
    if existing_ids == expected_ids and all(
        str(chunk.get("source_hash")) == source_hash
        and str(chunk.get("document_version_id")) == version_id
        for chunk in existing_chunks
    ):
        conn.execute(
            text(
                "UPDATE rag_documents SET ingestion_status=:status, indexed_at=:now, "
                "failure_reason=NULL, updated_at=:now "
                "WHERE tenant_id=:tenant_id AND document_id=:document_id"
            ),
            {
                "status": INGESTION_INDEXED,
                "now": now,
                "tenant_id": tid,
                "document_id": document_id,
            },
        )
        conn.commit()
        _audit_ingestion(
            "reindex_completed",
            tenant_id=tid,
            corpus_id=corpus_id,
            document_id=document_id,
            version_id=version_id,
            ingestion_status=INGESTION_INDEXED,
            reason_code=INGESTION_INDEXED,
        )
        return {
            "tenant_id": tid,
            "corpus_id": corpus_id,
            "document_id": document_id,
            "version_id": version_id,
            "ingestion_status": INGESTION_INDEXED,
            "chunk_count": len(existing_chunks),
            "indexed_at": now,
        }

    conn.execute(
        text(
            "UPDATE rag_chunks SET is_active = 0 "
            "WHERE tenant_id=:tenant_id AND document_id=:document_id "
            "AND document_version_id=:version_id"
        ),
        {"tenant_id": tid, "document_id": document_id, "version_id": version_id},
    )
    persisted = store_chunks(
        conn,
        tenant_id=tid,
        document_id=document_id,
        corpus_id=corpus_id,
        chunks=chunk_payloads,
    )
    conn.execute(
        text(
            "UPDATE rag_documents SET ingestion_status=:status, indexed_at=:now, "
            "failure_reason=NULL, updated_at=:now "
            "WHERE tenant_id=:tenant_id AND document_id=:document_id"
        ),
        {
            "status": INGESTION_INDEXED,
            "now": now,
            "tenant_id": tid,
            "document_id": document_id,
        },
    )
    conn.commit()
    _audit_ingestion(
        "reindex_completed",
        tenant_id=tid,
        corpus_id=corpus_id,
        document_id=document_id,
        version_id=version_id,
        ingestion_status=INGESTION_INDEXED,
        reason_code=INGESTION_INDEXED,
    )
    return {
        "tenant_id": tid,
        "corpus_id": corpus_id,
        "document_id": document_id,
        "version_id": version_id,
        "ingestion_status": INGESTION_INDEXED,
        "chunk_count": len(persisted),
        "indexed_at": now,
    }


def _chunk_content(
    *,
    tenant_id: str,
    document_id: str,
    version_id: str,
    source_hash: str,
    content: str,
    max_chars: int,
) -> list[dict[str, Any]]:
    if max_chars < 1:
        raise ValueError("max_chars must be positive")
    words = content.split()
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for word in words:
        if len(word) > max_chars:
            raise ValueError("document contains an oversized token")
        needed = len(word) if not current else len(word) + 1
        if current and current_len + needed > max_chars:
            chunks.append(" ".join(current))
            current = []
            current_len = 0
        current.append(word)
        current_len += len(word) if len(current) == 1 else len(word) + 1
    if current:
        chunks.append(" ".join(current))
    if not chunks:
        raise ValueError("chunking produced no chunks")
    return [
        {
            "chunk_id": deterministic_chunk_id(
                tenant_id=tenant_id,
                document_id=document_id,
                version_id=version_id,
                ordinal=index,
                text=text_value,
            ),
            "text": text_value,
            "ordinal": index,
            "document_version_id": version_id,
            "source_hash": source_hash,
            "content_hash": canonical_source_hash(text_value),
            "metadata": {
                "document_version_id": version_id,
                "source_hash": source_hash,
                "chunk_index": index,
                "evidence_graph_ready": True,
                "verified_fact_binding_ready": True,
                "rag_evaluation_ready": True,
            },
        }
        for index, text_value in enumerate(chunks)
    ]


def _find_current_indexed_by_hash(
    conn: Session, *, tenant_id: str, corpus_id: str, source_hash: str
) -> Optional[dict[str, Any]]:
    row = (
        conn.execute(
            text(
                """
                SELECT d.document_id, d.version_id, d.created_at, d.indexed_at,
                       COUNT(c.chunk_id) AS chunk_count
                FROM rag_documents d
                LEFT JOIN rag_chunks c
                  ON c.tenant_id = d.tenant_id
                 AND c.document_id = d.document_id
                 AND COALESCE(c.is_active, 1) = 1
                WHERE d.tenant_id = :tenant_id
                  AND d.corpus_id = :corpus_id
                  AND d.source_hash = :source_hash
                  AND d.ingestion_status = :indexed
                  AND COALESCE(d.is_current, 1) = 1
                GROUP BY d.document_id, d.version_id, d.created_at, d.indexed_at
                LIMIT 1
                """
            ),
            {
                "tenant_id": tenant_id,
                "corpus_id": corpus_id,
                "source_hash": source_hash,
                "indexed": INGESTION_INDEXED,
            },
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def _next_version_number(
    conn: Session, *, tenant_id: str, corpus_id: str, source: str
) -> int:
    row = (
        conn.execute(
            text(
                "SELECT COALESCE(MAX(version_number), 0) AS max_version "
                "FROM rag_documents WHERE tenant_id=:tenant_id AND corpus_id=:corpus_id "
                "AND source=:source"
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id, "source": source},
        )
        .mappings()
        .first()
    )
    return int(row["max_version"] or 0) + 1 if row is not None else 1


def _quarantine_document(
    conn: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    title: str,
    source: str,
    source_hash: str | None,
    reason: str,
    detail: str,
    metadata: Optional[dict[str, Any]],
    now: str,
) -> dict[str, Any]:
    corpus_row = get_corpus(conn, tenant_id, corpus_id)
    if corpus_row is None:
        raise ValueError(
            f"corpus_id={corpus_id!r} not found for tenant_id={tenant_id!r}"
        )
    document_id = _new_id("doc")
    version_number = _next_version_number(
        conn, tenant_id=tenant_id, corpus_id=corpus_id, source=source
    )
    version_id = deterministic_version_id(
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        source_hash=source_hash or _hash_hex(f"quarantine:{document_id}"),
        version_number=version_number,
    )
    safe_metadata = dict(metadata or {})
    safe_metadata["operator_detail"] = detail
    conn.execute(
        text(
            """
            INSERT INTO rag_documents
                (document_id, corpus_id, tenant_id, title, source, metadata,
                 created_at, updated_at, version_id, source_hash,
                 normalized_source_hash, version_number, is_current,
                 ingestion_status, quarantine_reason, failure_reason)
            VALUES
                (:document_id, :corpus_id, :tenant_id, :title, :source, :metadata,
                 :created_at, :updated_at, :version_id, :source_hash,
                 :normalized_source_hash, :version_number, 0,
                 :ingestion_status, :quarantine_reason, :failure_reason)
            """
        ),
        {
            "document_id": document_id,
            "corpus_id": corpus_id,
            "tenant_id": tenant_id,
            "title": title,
            "source": source,
            "metadata": _encode_metadata(safe_metadata),
            "created_at": now,
            "updated_at": now,
            "version_id": version_id,
            "source_hash": source_hash,
            "normalized_source_hash": source_hash,
            "version_number": version_number,
            "ingestion_status": INGESTION_QUARANTINED,
            "quarantine_reason": reason,
            "failure_reason": detail,
        },
    )
    conn.commit()
    _audit_ingestion(
        "document_quarantined",
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        document_id=document_id,
        version_id=version_id,
        ingestion_status=INGESTION_QUARANTINED,
        reason_code=reason,
    )
    return {
        "tenant_id": tenant_id,
        "corpus_id": corpus_id,
        "document_id": document_id,
        "version_id": version_id,
        "source_hash": source_hash,
        "ingestion_status": INGESTION_QUARANTINED,
        "quarantine_reason": reason,
        "failure_reason": detail,
        "created_at": now,
        "chunk_count": 0,
        "active_version": False,
    }


def _get_document_version(
    conn: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    version_id: str,
) -> Optional[dict[str, Any]]:
    row = (
        conn.execute(
            text(
                """
                SELECT document_id, corpus_id, tenant_id, version_id, source_hash,
                       ingestion_status, is_current
                FROM rag_documents
                WHERE tenant_id=:tenant_id AND corpus_id=:corpus_id
                  AND document_id=:document_id AND version_id=:version_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "corpus_id": corpus_id,
                "document_id": document_id,
                "version_id": version_id,
            },
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def _mark_document_failed(
    conn: Session, *, tenant_id: str, document_id: str, reason: str, now: str
) -> None:
    conn.execute(
        text(
            "UPDATE rag_documents SET ingestion_status=:status, failure_reason=:reason, "
            "updated_at=:now WHERE tenant_id=:tenant_id AND document_id=:document_id"
        ),
        {
            "status": INGESTION_FAILED,
            "reason": reason,
            "now": now,
            "tenant_id": tenant_id,
            "document_id": document_id,
        },
    )
    conn.commit()


def _safe_error(exc: Exception) -> str:
    message = str(exc).splitlines()[0][:200]
    return message or "unknown ingestion error"


def _audit_ingestion(
    event: str,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    version_id: str,
    ingestion_status: str,
    reason_code: str,
) -> None:
    logger.info(
        "rag.ingestion.%s",
        event,
        extra={
            "event": f"rag.ingestion.{event}",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "document_id": document_id,
            "version_id": version_id,
            "ingestion_status": ingestion_status,
            "reason_code": reason_code,
        },
    )
