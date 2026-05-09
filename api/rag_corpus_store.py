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
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("frostgate.rag_corpus_store")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    """Generate a prefixed, collision-resistant ID using uuid4."""
    return f"{prefix}-{uuid.uuid4().hex}"


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

    conn.execute(
        text(
            """
            INSERT INTO rag_documents
                (document_id, corpus_id, tenant_id, title, source, metadata, created_at, updated_at)
            VALUES
                (:document_id, :corpus_id, :tenant_id, :title, :source, :metadata, :created_at, :updated_at)
            """
        ),
        {
            "document_id": document_id,
            "corpus_id": corpus_id,
            "tenant_id": tid,
            "title": checked_title,
            "source": source,
            "metadata": meta_str,
            "created_at": now,
            "updated_at": now,
        },
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
    row = (
        conn.execute(
            text(
                """
            SELECT document_id, corpus_id, tenant_id, title, source, metadata, created_at, updated_at
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
    rows = (
        conn.execute(
            text(
                """
            SELECT document_id, corpus_id, tenant_id, title, source, metadata, created_at, updated_at
            FROM rag_documents
            WHERE tenant_id = :tenant_id
              AND corpus_id = :corpus_id
            ORDER BY created_at ASC
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
        validated.append(
            {
                "chunk_id": _new_id("ck"),
                "text": str(text_val).strip(),
                "ordinal": int(chunk["ordinal"]),
                "metadata": chunk.get("metadata"),
            }
        )

    # All chunks valid — insert in a single pass.
    persisted: list[dict[str, Any]] = []
    for v in validated:
        meta_str = _encode_metadata(v["metadata"])
        conn.execute(
            text(
                """
                INSERT INTO rag_chunks
                    (chunk_id, document_id, corpus_id, tenant_id, text, ordinal, metadata, created_at)
                VALUES
                    (:chunk_id, :document_id, :corpus_id, :tenant_id, :text, :ordinal, :metadata, :created_at)
                """
            ),
            {
                "chunk_id": v["chunk_id"],
                "document_id": document_id,
                "corpus_id": corpus_id,
                "tenant_id": tid,
                "text": v["text"],
                "ordinal": v["ordinal"],
                "metadata": meta_str,
                "created_at": now,
            },
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
    row = (
        conn.execute(
            text(
                """
            SELECT chunk_id, document_id, corpus_id, tenant_id, text, ordinal, metadata, created_at
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
    rows = (
        conn.execute(
            text(
                """
            SELECT chunk_id, document_id, corpus_id, tenant_id, text, ordinal, metadata, created_at
            FROM rag_chunks
            WHERE tenant_id   = :tenant_id
              AND document_id = :document_id
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
