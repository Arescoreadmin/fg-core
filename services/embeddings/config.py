"""
services/embeddings/config.py — Vector index readiness configuration and guard.

Prevents semantic retrieval from being enabled without a production ANN index.

Environment variables:
  FG_EMBEDDINGS_PRIMARY_MODEL   — canonical model identifier (e.g.
                                  "openai/text-embedding-ada-002").
                                  Required before assert_ann_index_ready can pass.
  FG_EMBEDDINGS_ANN_INDEX_STATUS — operator override: "not_ready" (default) or
                                   "ready".  In production, BOTH this flag AND a
                                   row in vector_index_registry must be present
                                   for the guard to pass.

Fail-closed behaviour:
  - In production/staging: assert_ann_index_ready raises AnnIndexNotReadyError
    if no matching row exists in vector_index_registry or if
    FG_EMBEDDINGS_ANN_INDEX_STATUS != "ready".
  - In dev/test: logs a warning but does not raise.
  - SQLite: no-op (vector_index_registry does not exist on SQLite).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Engine

from api.embeddings.providers import EmbeddingModel, expected_dimensions
from services.embeddings.errors import (
    EMBED_PERSIST_ERR_INDEX_NOT_READY,
    EMBED_PERSIST_ERR_MODEL_NOT_CONFIGURED,
    AnnIndexNotReadyError,
    PrimaryModelNotConfiguredError,
)

logger = logging.getLogger("frostgate.embeddings")

_PROD_ENVS = {"production", "prod", "staging"}
_INDEX_READY_VALUE = "ready"

# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbeddingIndexConfig:
    """Runtime configuration for vector index readiness.

    ``primary_model`` and ``dimensions`` are sourced from env.
    ``ann_index_status`` reflects FG_EMBEDDINGS_ANN_INDEX_STATUS.
    """

    primary_model: EmbeddingModel | None
    dimensions: int | None
    ann_index_status: str  # "not_ready" | "ready"

    @property
    def is_model_configured(self) -> bool:
        return self.primary_model is not None

    @property
    def is_operator_ready(self) -> bool:
        return self.ann_index_status == _INDEX_READY_VALUE


def get_embedding_index_config() -> EmbeddingIndexConfig:
    """Build EmbeddingIndexConfig from environment variables.

    Never raises — returns a config with primary_model=None if unconfigured.
    """
    raw_model = (os.getenv("FG_EMBEDDINGS_PRIMARY_MODEL") or "").strip()
    ann_status = (
        (os.getenv("FG_EMBEDDINGS_ANN_INDEX_STATUS") or "not_ready").strip().lower()
    )

    primary_model: EmbeddingModel | None = None
    dimensions: int | None = None

    if raw_model:
        try:
            primary_model = EmbeddingModel(raw_model)
            dimensions = expected_dimensions(primary_model)
        except ValueError:
            logger.warning(
                "embedding.config_invalid_model",
                extra={
                    "event": "embedding.config_invalid_model",
                    "raw_model": raw_model,
                    "detail": "FG_EMBEDDINGS_PRIMARY_MODEL is not a known EmbeddingModel value",
                },
            )

    return EmbeddingIndexConfig(
        primary_model=primary_model,
        dimensions=dimensions,
        ann_index_status=ann_status,
    )


# ---------------------------------------------------------------------------
# Index readiness guard
# ---------------------------------------------------------------------------


def assert_ann_index_ready(
    engine: Engine,
    config: EmbeddingIndexConfig | None = None,
) -> None:
    """Gate check: verify a production ANN index exists before enabling retrieval.

    Fail-closed in production/staging: raises AnnIndexNotReadyError if either:
      - FG_EMBEDDINGS_ANN_INDEX_STATUS != "ready", OR
      - No row exists in vector_index_registry for the primary model

    In dev/test: emits a warning only.
    SQLite: no-op (ANN indexes are not supported).

    Call this at application startup before enabling semantic retrieval routes.
    Raises PrimaryModelNotConfiguredError if FG_EMBEDDINGS_PRIMARY_MODEL is unset
    and FG_ENV is production.
    """
    if engine.dialect.name != "postgresql":
        return

    if config is None:
        config = get_embedding_index_config()

    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    is_prod = env in _PROD_ENVS

    if not config.is_model_configured:
        if is_prod:
            raise PrimaryModelNotConfiguredError(
                f"{EMBED_PERSIST_ERR_MODEL_NOT_CONFIGURED}: "
                "FG_EMBEDDINGS_PRIMARY_MODEL is not set. "
                "Set it to the canonical model identifier before enabling retrieval "
                f"(e.g. FG_EMBEDDINGS_PRIMARY_MODEL=openai/text-embedding-ada-002). "
                f"FG_ENV={env} — startup aborted."
            )
        logger.warning(
            "embedding.primary_model_not_configured",
            extra={
                "event": "embedding.primary_model_not_configured",
                "env": env,
                "detail": "FG_EMBEDDINGS_PRIMARY_MODEL unset; retrieval will not be available",
            },
        )
        return

    # Check operator status flag
    if not config.is_operator_ready:
        _fail_or_warn(
            is_prod=is_prod,
            env=env,
            model=config.primary_model,
            reason="FG_EMBEDDINGS_ANN_INDEX_STATUS is not 'ready'",
        )
        return

    # At this point primary_model is guaranteed non-None (checked above).
    primary_model = config.primary_model
    assert (
        primary_model is not None
    )  # appease mypy; guarded by is_model_configured check

    # Check registry row exists for this model
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM vector_index_registry WHERE model = :model LIMIT 1"),
            {"model": primary_model.value},
        ).first()

    if row is None:
        _fail_or_warn(
            is_prod=is_prod,
            env=env,
            model=config.primary_model,
            reason="no row in vector_index_registry for this model — "
            "follow the runbook in migration 0039_vector_index_runbook.sql",
        )


def is_retrieval_index_ready(
    engine: Engine,
    config: EmbeddingIndexConfig | None = None,
) -> bool:
    """Return True if the ANN index guard passes, False otherwise.

    Never raises.  Use as a lightweight pre-flight check before building
    retrieval routes.
    """
    try:
        assert_ann_index_ready(engine, config)
        return True
    except (AnnIndexNotReadyError, PrimaryModelNotConfiguredError):
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SQLite schema for vector_index_registry (dev/test only)
# ---------------------------------------------------------------------------

_SQLITE_REGISTRY_DDL = """\
CREATE TABLE IF NOT EXISTS vector_index_registry (
    id          TEXT    NOT NULL PRIMARY KEY,
    model       TEXT    NOT NULL,
    dimensions  INTEGER NOT NULL,
    index_type  TEXT    NOT NULL,
    index_name  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    notes       TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vector_index_registry_model_type
    ON vector_index_registry (model, index_type)
"""


def ensure_sqlite_index_registry(engine: Engine) -> None:
    """Create the vector_index_registry table in a SQLite database.

    Must only be used for dev/test.  Raises if called against postgres.
    """
    if engine.dialect.name == "postgresql":
        raise RuntimeError(
            "ensure_sqlite_index_registry must not be called against postgres. "
            "Use migration 0039_vector_index_runbook.sql instead."
        )
    with engine.begin() as conn:
        for stmt in _SQLITE_REGISTRY_DDL.strip().split(";\n"):
            stmt = stmt.strip().rstrip(";")
            if stmt:
                conn.exec_driver_sql(stmt + ";")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _fail_or_warn(
    *,
    is_prod: bool,
    env: str,
    model: EmbeddingModel | None,
    reason: str,
) -> None:
    model_str = model.value if model else "unset"
    if is_prod:
        raise AnnIndexNotReadyError(
            f"{EMBED_PERSIST_ERR_INDEX_NOT_READY}: "
            f"ANN index not ready for model {model_str!r}. "
            f"Reason: {reason}. "
            "Semantic retrieval cannot be enabled until the index is created and "
            "registered.  Follow the runbook in migration 0039_vector_index_runbook.sql. "
            f"FG_ENV={env} — startup aborted."
        )
    logger.warning(
        "embedding.ann_index_not_ready",
        extra={
            "event": "embedding.ann_index_not_ready",
            "env": env,
            "model": model_str,
            "reason": reason,
            "detail": "ANN index not ready; semantic retrieval will not be available",
        },
    )
