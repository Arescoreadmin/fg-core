"""
services/embeddings/errors.py — Typed error hierarchy for embedding persistence.

Error codes are stable — never change meaning once published.
"""

from __future__ import annotations

# Stable error codes
EMBED_PERSIST_ERR_TENANT_REQUIRED = "EMBED_P001"
EMBED_PERSIST_ERR_DIMENSION_MISMATCH = "EMBED_P002"
EMBED_PERSIST_ERR_DIMENSION_UNKNOWN = "EMBED_P003"
EMBED_PERSIST_ERR_PGVECTOR_UNAVAILABLE = "EMBED_P004"
EMBED_PERSIST_ERR_DUPLICATE = "EMBED_P005"
EMBED_PERSIST_ERR_NOT_FOUND = "EMBED_P006"
EMBED_PERSIST_ERR_INDEX_NOT_READY = "EMBED_P007"
EMBED_PERSIST_ERR_MODEL_NOT_CONFIGURED = "EMBED_P008"


class EmbeddingPersistenceError(Exception):
    """Base error for the embedding persistence layer."""


class TenantRequiredError(EmbeddingPersistenceError):
    """tenant_id is missing or blank — all persistence calls require tenant scope."""


class DimensionMismatchError(EmbeddingPersistenceError):
    """Vector length does not match declared dimensions or model registry."""


class DimensionUnknownError(EmbeddingPersistenceError):
    """Model not found in KNOWN_DIMENSIONS; cannot validate dimensions."""


class PgvectorUnavailableError(EmbeddingPersistenceError):
    """pgvector extension is not installed — required in production/staging."""


class DuplicateEmbeddingError(EmbeddingPersistenceError):
    """An embedding for (tenant, corpus, chunk, model, hash) already exists."""


class EmbeddingRowNotFoundError(EmbeddingPersistenceError):
    """No embedding row found for the given tenant-scoped lookup."""


class AnnIndexNotReadyError(EmbeddingPersistenceError):
    """No production ANN index registered — semantic retrieval cannot be enabled."""


class PrimaryModelNotConfiguredError(EmbeddingPersistenceError):
    """FG_EMBEDDINGS_PRIMARY_MODEL is not set — required before enabling retrieval."""
