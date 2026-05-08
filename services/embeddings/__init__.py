"""
services/embeddings — pgvector persistence layer for chunk embeddings.

Public surface.  Import from here, not from sub-modules.
"""

from services.embeddings.config import (
    EmbeddingIndexConfig,
    assert_ann_index_ready,
    ensure_sqlite_index_registry,
    get_embedding_index_config,
    is_retrieval_index_ready,
)
from services.embeddings.errors import (
    EMBED_PERSIST_ERR_DIMENSION_MISMATCH,
    EMBED_PERSIST_ERR_DIMENSION_UNKNOWN,
    EMBED_PERSIST_ERR_DUPLICATE,
    EMBED_PERSIST_ERR_INDEX_NOT_READY,
    EMBED_PERSIST_ERR_MODEL_NOT_CONFIGURED,
    EMBED_PERSIST_ERR_NOT_FOUND,
    EMBED_PERSIST_ERR_PGVECTOR_UNAVAILABLE,
    EMBED_PERSIST_ERR_TENANT_REQUIRED,
    AnnIndexNotReadyError,
    DimensionMismatchError,
    DimensionUnknownError,
    DuplicateEmbeddingError,
    EmbeddingPersistenceError,
    EmbeddingRowNotFoundError,
    PgvectorUnavailableError,
    PrimaryModelNotConfiguredError,
    TenantRequiredError,
)
from services.embeddings.persistence import (
    EmbeddingRow,
    assert_pgvector_available,
    delete_embedding,
    embedding_exists,
    ensure_sqlite_schema,
    get_embedding_for_chunk,
    list_embeddings_for_corpus,
    save_embedding,
    upsert_embedding,
)

__all__ = [
    # errors
    "EmbeddingPersistenceError",
    "TenantRequiredError",
    "DimensionMismatchError",
    "DimensionUnknownError",
    "PgvectorUnavailableError",
    "DuplicateEmbeddingError",
    "EmbeddingRowNotFoundError",
    "AnnIndexNotReadyError",
    "PrimaryModelNotConfiguredError",
    # error codes
    "EMBED_PERSIST_ERR_TENANT_REQUIRED",
    "EMBED_PERSIST_ERR_DIMENSION_MISMATCH",
    "EMBED_PERSIST_ERR_DIMENSION_UNKNOWN",
    "EMBED_PERSIST_ERR_PGVECTOR_UNAVAILABLE",
    "EMBED_PERSIST_ERR_DUPLICATE",
    "EMBED_PERSIST_ERR_NOT_FOUND",
    "EMBED_PERSIST_ERR_INDEX_NOT_READY",
    "EMBED_PERSIST_ERR_MODEL_NOT_CONFIGURED",
    # index readiness config
    "EmbeddingIndexConfig",
    "get_embedding_index_config",
    "assert_ann_index_ready",
    "is_retrieval_index_ready",
    "ensure_sqlite_index_registry",
    # persistence
    "EmbeddingRow",
    "assert_pgvector_available",
    "ensure_sqlite_schema",
    "save_embedding",
    "get_embedding_for_chunk",
    "list_embeddings_for_corpus",
    "delete_embedding",
    "embedding_exists",
    "upsert_embedding",
]
