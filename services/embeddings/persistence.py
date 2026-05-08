"""
services/embeddings/persistence.py — pgvector persistence layer.

Storage only.  No embedding generation, no provider calls, no ANN retrieval.

Backend behaviour:
  postgres  — uses pgvector `vector` column; fails closed in prod/staging if
              the extension is not installed.
  sqlite    — stores vectors as JSON text; no ANN capability; for dev/test only.

All public functions require tenant_id.  No method allows lookup by chunk_id,
corpus_id, or embedding_id alone without tenant scope.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from api.embeddings.providers import EmbeddingModel, expected_dimensions
from services.embeddings.errors import (
    EMBED_PERSIST_ERR_DIMENSION_MISMATCH,
    EMBED_PERSIST_ERR_DIMENSION_UNKNOWN,
    EMBED_PERSIST_ERR_DUPLICATE,
    EMBED_PERSIST_ERR_NOT_FOUND,
    EMBED_PERSIST_ERR_PGVECTOR_UNAVAILABLE,
    EMBED_PERSIST_ERR_TENANT_REQUIRED,
    DimensionMismatchError,
    DimensionUnknownError,
    DuplicateEmbeddingError,
    EmbeddingRowNotFoundError,
    PgvectorUnavailableError,
    TenantRequiredError,
)

logger = logging.getLogger("frostgate.embeddings")

_PROD_ENVS = {"production", "prod", "staging"}

# ---------------------------------------------------------------------------
# Return model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbeddingRow:
    """Typed persistence record returned by all public read/write functions.

    Never contains raw vector data in logs; callers must not log `.vector`.
    """

    id: str
    tenant_id: str
    corpus_id: str
    document_id: str
    chunk_id: str
    model: str
    dimensions: int
    vector: tuple[float, ...]
    content_hash: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: str) -> None:
    if not str(tenant_id or "").strip():
        raise TenantRequiredError(
            f"{EMBED_PERSIST_ERR_TENANT_REQUIRED}: tenant_id is required"
        )


def _validate_dimensions(model: EmbeddingModel, declared: int, actual: int) -> None:
    if actual != declared:
        raise DimensionMismatchError(
            f"{EMBED_PERSIST_ERR_DIMENSION_MISMATCH}: "
            f"vector length {actual} != declared dimensions {declared}"
        )
    expected = expected_dimensions(model)
    if expected is None:
        raise DimensionUnknownError(
            f"{EMBED_PERSIST_ERR_DIMENSION_UNKNOWN}: "
            f"model {model!r} not in KNOWN_DIMENSIONS registry"
        )
    if declared != expected:
        raise DimensionMismatchError(
            f"{EMBED_PERSIST_ERR_DIMENSION_MISMATCH}: "
            f"declared dimensions {declared} != expected {expected} for model {model!r}"
        )


def _is_postgres(db: Session) -> bool:
    return db.get_bind().dialect.name == "postgresql"  # type: ignore[union-attr]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_vector_pg(vector: tuple[float, ...]) -> str:
    """Format vector for pgvector's ::vector cast."""
    return "[" + ",".join(str(v) for v in vector) + "]"


def _serialize_vector_sqlite(vector: tuple[float, ...]) -> str:
    return json.dumps(list(vector))


def _deserialize_vector(raw: object) -> tuple[float, ...]:
    """Deserialize vector from either pgvector or JSON-text storage."""
    if isinstance(raw, str):
        # pgvector returns strings like '[0.1,0.2,...]' or JSON text
        return tuple(float(x) for x in json.loads(raw.replace("[", "[").strip()))
    if isinstance(raw, (list, tuple)):
        return tuple(float(x) for x in raw)
    raise ValueError(f"Unexpected vector type: {type(raw)}")


def _row_to_embedding_row(row: object) -> EmbeddingRow:
    r = dict(row)  # type: ignore[call-overload]
    created_at = r["created_at"]
    updated_at = r["updated_at"]
    # SQLite stores as ISO string; postgres returns datetime
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    if isinstance(updated_at, str):
        updated_at = datetime.fromisoformat(updated_at)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    return EmbeddingRow(
        id=r["id"],
        tenant_id=r["tenant_id"],
        corpus_id=r["corpus_id"],
        document_id=r["document_id"],
        chunk_id=r["chunk_id"],
        model=r["model"],
        dimensions=r["dimensions"],
        vector=_deserialize_vector(r["embedding"]),
        content_hash=r["content_hash"],
        created_at=created_at,
        updated_at=updated_at,
    )


def _audit_log(event: str, **fields: object) -> None:
    """Emit a structured audit log entry.  Never includes raw vectors."""
    logger.info(
        "embedding.%s",
        event,
        extra={"event": f"embedding.{event}", **fields},
    )


# ---------------------------------------------------------------------------
# pgvector availability check
# ---------------------------------------------------------------------------


def assert_pgvector_available(engine: Engine) -> None:
    """Verify the pgvector extension is installed.

    Raises PgvectorUnavailableError if pgvector is missing *and* FG_ENV is
    prod/production/staging.  In dev/test environments, logs a warning only.

    Call this once at application startup before accepting embedding writes.
    """
    if engine.dialect.name != "postgresql":
        return

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        ).first()

    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    if row is None:
        if env in _PROD_ENVS:
            raise PgvectorUnavailableError(
                f"{EMBED_PERSIST_ERR_PGVECTOR_UNAVAILABLE}: "
                "pgvector extension is not installed. "
                "Run: CREATE EXTENSION IF NOT EXISTS vector; "
                "or apply migration 0038_embedding_vectors.sql. "
                f"FG_ENV={env} — startup aborted."
            )
        logger.warning(
            "embedding.pgvector_unavailable",
            extra={
                "event": "embedding.pgvector_unavailable",
                "env": env,
                "detail": "pgvector not installed; embedding persistence will fail",
            },
        )


# ---------------------------------------------------------------------------
# SQLite schema bootstrap (dev/test only)
# ---------------------------------------------------------------------------

_SQLITE_DDL = """\
CREATE TABLE IF NOT EXISTS embedding_vectors (
    id           TEXT    NOT NULL PRIMARY KEY,
    tenant_id    TEXT    NOT NULL,
    corpus_id    TEXT    NOT NULL,
    document_id  TEXT    NOT NULL,
    chunk_id     TEXT    NOT NULL,
    model        TEXT    NOT NULL,
    dimensions   INTEGER NOT NULL,
    embedding    TEXT    NOT NULL,
    content_hash TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_embedding_vectors_identity
    ON embedding_vectors (tenant_id, corpus_id, chunk_id, model, content_hash);
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant
    ON embedding_vectors (tenant_id);
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_corpus
    ON embedding_vectors (tenant_id, corpus_id);
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_chunk
    ON embedding_vectors (tenant_id, chunk_id);
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_model
    ON embedding_vectors (tenant_id, model);
"""


def ensure_sqlite_schema(engine: Engine) -> None:
    """Create the embedding_vectors table in a SQLite database.

    Must only be used for dev/test.  Postgres relies on the postgres migration.
    Raises if called against a postgres engine.
    """
    if engine.dialect.name == "postgresql":
        raise RuntimeError(
            "ensure_sqlite_schema must not be called against postgres. "
            "Use migration 0038_embedding_vectors.sql instead."
        )
    with engine.begin() as conn:
        for stmt in _SQLITE_DDL.strip().split(";\n"):
            stmt = stmt.strip().rstrip(";")
            if stmt:
                conn.exec_driver_sql(stmt + ";")


# ---------------------------------------------------------------------------
# Core persistence API
# ---------------------------------------------------------------------------


def save_embedding(
    db: Session,
    record: object,
) -> EmbeddingRow:
    """Insert a new embedding record.

    Raises DuplicateEmbeddingError if a record for (tenant, corpus, chunk,
    model, hash) already exists.  Use upsert_embedding for idempotent writes.
    """
    from api.embeddings.contracts import ChunkEmbeddingRecord

    rec: ChunkEmbeddingRecord = record  # type: ignore[assignment]
    _require_tenant(rec.tenant_id)
    _validate_dimensions(rec.embedding_model, rec.dimensions, len(rec.vector))

    row_id = str(uuid.uuid4())
    now = _now_utc()
    is_pg = _is_postgres(db)

    if is_pg:
        vec_expr = f"'{_serialize_vector_pg(rec.vector)}'::vector"
        stmt = text(
            f"""
            INSERT INTO embedding_vectors
                (id, tenant_id, corpus_id, document_id, chunk_id, model,
                 dimensions, embedding, content_hash, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :corpus_id, :document_id, :chunk_id, :model,
                 :dimensions, {vec_expr}, :content_hash, :created_at, :updated_at)
            """
        )
        params: dict[str, object] = {
            "id": row_id,
            "tenant_id": rec.tenant_id,
            "corpus_id": rec.corpus_id,
            "document_id": rec.document_id,
            "chunk_id": rec.chunk_id,
            "model": rec.embedding_model.value,
            "dimensions": rec.dimensions,
            "content_hash": rec.content_hash,
            "created_at": now,
            "updated_at": now,
        }
    else:
        stmt = text(
            """
            INSERT INTO embedding_vectors
                (id, tenant_id, corpus_id, document_id, chunk_id, model,
                 dimensions, embedding, content_hash, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :corpus_id, :document_id, :chunk_id, :model,
                 :dimensions, :embedding, :content_hash, :created_at, :updated_at)
            """
        )
        params = {
            "id": row_id,
            "tenant_id": rec.tenant_id,
            "corpus_id": rec.corpus_id,
            "document_id": rec.document_id,
            "chunk_id": rec.chunk_id,
            "model": rec.embedding_model.value,
            "dimensions": rec.dimensions,
            "embedding": _serialize_vector_sqlite(rec.vector),
            "content_hash": rec.content_hash,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }

    try:
        db.execute(stmt, params)
    except Exception as exc:
        exc_str = str(exc).lower()
        if "unique" in exc_str or "duplicate" in exc_str:
            _audit_log(
                "duplicate_rejected",
                tenant_id=rec.tenant_id,
                corpus_id=rec.corpus_id,
                chunk_id=rec.chunk_id,
                model=rec.embedding_model.value,
                content_hash=rec.content_hash,
            )
            raise DuplicateEmbeddingError(
                f"{EMBED_PERSIST_ERR_DUPLICATE}: "
                f"embedding for (tenant={rec.tenant_id!r}, corpus={rec.corpus_id!r}, "
                f"chunk={rec.chunk_id!r}, model={rec.embedding_model.value!r}, "
                f"hash={rec.content_hash!r}) already exists"
            ) from exc
        raise

    _audit_log(
        "persisted",
        tenant_id=rec.tenant_id,
        corpus_id=rec.corpus_id,
        chunk_id=rec.chunk_id,
        model=rec.embedding_model.value,
        dimensions=rec.dimensions,
        content_hash=rec.content_hash,
        embedding_id=row_id,
    )
    return EmbeddingRow(
        id=row_id,
        tenant_id=rec.tenant_id,
        corpus_id=rec.corpus_id,
        document_id=rec.document_id,
        chunk_id=rec.chunk_id,
        model=rec.embedding_model.value,
        dimensions=rec.dimensions,
        vector=rec.vector,
        content_hash=rec.content_hash,
        created_at=now,
        updated_at=now,
    )


def get_embedding_for_chunk(
    db: Session,
    *,
    tenant_id: str,
    chunk_id: str,
    model: str | None = None,
) -> EmbeddingRow | None:
    """Return the embedding for a specific tenant-scoped chunk.

    If model is provided, scopes to that model.  If multiple embeddings exist
    for the chunk (different models), returns the most recently created one
    unless model is specified.
    """
    _require_tenant(tenant_id)
    if model:
        row = (
            db.execute(
                text(
                    "SELECT id, tenant_id, corpus_id, document_id, chunk_id, model, "
                    "dimensions, embedding, content_hash, created_at, updated_at "
                    "FROM embedding_vectors "
                    "WHERE tenant_id=:tenant_id AND chunk_id=:chunk_id AND model=:model "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"tenant_id": tenant_id, "chunk_id": chunk_id, "model": model},
            )
            .mappings()
            .first()
        )
    else:
        row = (
            db.execute(
                text(
                    "SELECT id, tenant_id, corpus_id, document_id, chunk_id, model, "
                    "dimensions, embedding, content_hash, created_at, updated_at "
                    "FROM embedding_vectors "
                    "WHERE tenant_id=:tenant_id AND chunk_id=:chunk_id "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"tenant_id": tenant_id, "chunk_id": chunk_id},
            )
            .mappings()
            .first()
        )
    if row is None:
        return None
    return _row_to_embedding_row(row)


def list_embeddings_for_corpus(
    db: Session,
    *,
    tenant_id: str,
    corpus_id: str,
) -> list[EmbeddingRow]:
    """Return all embeddings for a tenant-scoped corpus."""
    _require_tenant(tenant_id)
    rows = (
        db.execute(
            text(
                "SELECT id, tenant_id, corpus_id, document_id, chunk_id, model, "
                "dimensions, embedding, content_hash, created_at, updated_at "
                "FROM embedding_vectors "
                "WHERE tenant_id=:tenant_id AND corpus_id=:corpus_id "
                "ORDER BY created_at ASC"
            ),
            {"tenant_id": tenant_id, "corpus_id": corpus_id},
        )
        .mappings()
        .all()
    )
    return [_row_to_embedding_row(r) for r in rows]


def delete_embedding(
    db: Session,
    *,
    tenant_id: str,
    embedding_id: str,
) -> bool:
    """Delete an embedding by tenant-scoped ID.

    Returns True if a row was deleted, False if not found.
    Raises TenantRequiredError if tenant_id is blank.
    The embedding_id alone is never sufficient — tenant_id is always required.
    """
    _require_tenant(tenant_id)
    result = db.execute(
        text("DELETE FROM embedding_vectors WHERE tenant_id=:tenant_id AND id=:id"),
        {"tenant_id": tenant_id, "id": embedding_id},
    )
    deleted = (result.rowcount or 0) > 0  # type: ignore[attr-defined]
    if deleted:
        _audit_log(
            "deleted",
            tenant_id=tenant_id,
            embedding_id=embedding_id,
        )
    return deleted


def embedding_exists(
    db: Session,
    *,
    tenant_id: str,
    chunk_id: str,
    model: str,
    content_hash: str,
) -> bool:
    """Return True if an embedding for (tenant, chunk, model, hash) exists."""
    _require_tenant(tenant_id)
    row = (
        db.execute(
            text(
                "SELECT 1 FROM embedding_vectors "
                "WHERE tenant_id=:tenant_id AND chunk_id=:chunk_id "
                "AND model=:model AND content_hash=:content_hash LIMIT 1"
            ),
            {
                "tenant_id": tenant_id,
                "chunk_id": chunk_id,
                "model": model,
                "content_hash": content_hash,
            },
        )
        .mappings()
        .first()
    )
    return row is not None


def upsert_embedding(
    db: Session,
    record: object,
) -> EmbeddingRow:
    """Insert or update an embedding record (idempotent).

    If a record for (tenant, corpus, chunk, model, hash) already exists,
    updates the vector, dimensions, and updated_at.  Otherwise inserts.
    Audit events distinguish persisted vs updated.
    """
    from api.embeddings.contracts import ChunkEmbeddingRecord

    rec: ChunkEmbeddingRecord = record  # type: ignore[assignment]
    _require_tenant(rec.tenant_id)
    _validate_dimensions(rec.embedding_model, rec.dimensions, len(rec.vector))

    existing = embedding_exists(
        db,
        tenant_id=rec.tenant_id,
        chunk_id=rec.chunk_id,
        model=rec.embedding_model.value,
        content_hash=rec.content_hash,
    )

    if not existing:
        return save_embedding(db, rec)

    now = _now_utc()
    is_pg = _is_postgres(db)

    if is_pg:
        vec_expr = f"'{_serialize_vector_pg(rec.vector)}'::vector"
        stmt = text(
            f"""
            UPDATE embedding_vectors
            SET embedding=({vec_expr}), dimensions=:dimensions, updated_at=:updated_at
            WHERE tenant_id=:tenant_id AND chunk_id=:chunk_id
              AND model=:model AND content_hash=:content_hash
            """
        )
        params: dict[str, object] = {
            "dimensions": rec.dimensions,
            "updated_at": now,
            "tenant_id": rec.tenant_id,
            "chunk_id": rec.chunk_id,
            "model": rec.embedding_model.value,
            "content_hash": rec.content_hash,
        }
    else:
        stmt = text(
            """
            UPDATE embedding_vectors
            SET embedding=:embedding, dimensions=:dimensions, updated_at=:updated_at
            WHERE tenant_id=:tenant_id AND chunk_id=:chunk_id
              AND model=:model AND content_hash=:content_hash
            """
        )
        params = {
            "embedding": _serialize_vector_sqlite(rec.vector),
            "dimensions": rec.dimensions,
            "updated_at": now.isoformat(),
            "tenant_id": rec.tenant_id,
            "chunk_id": rec.chunk_id,
            "model": rec.embedding_model.value,
            "content_hash": rec.content_hash,
        }

    db.execute(stmt, params)

    _audit_log(
        "updated",
        tenant_id=rec.tenant_id,
        corpus_id=rec.corpus_id,
        chunk_id=rec.chunk_id,
        model=rec.embedding_model.value,
        dimensions=rec.dimensions,
        content_hash=rec.content_hash,
    )

    row = get_embedding_for_chunk(
        db,
        tenant_id=rec.tenant_id,
        chunk_id=rec.chunk_id,
        model=rec.embedding_model.value,
    )
    if row is None:
        raise EmbeddingRowNotFoundError(
            f"{EMBED_PERSIST_ERR_NOT_FOUND}: row vanished after upsert"
        )
    return row
