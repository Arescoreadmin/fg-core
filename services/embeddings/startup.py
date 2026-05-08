"""
services/embeddings/startup.py — Explicit activation boundary for semantic retrieval.

Single entry point: startup_retrieval_service(engine).
Called by api/main.py:lifespan() when FG_EMBEDDINGS_RETRIEVAL_ENABLED=true.

Sequence enforced in order:
  1. assert primary model configured  (PrimaryModelNotConfiguredError on failure)
  2. assert ANN index ready            (AnnIndexNotReadyError on failure)
  3. log retrieval service enabled     (only reached if both pass)

In production/staging, any failure aborts startup.
In dev/test, failures emit warnings only.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy.engine import Engine

from services.embeddings.config import (
    assert_ann_index_ready,
    get_embedding_index_config,
)

logger = logging.getLogger("frostgate.embeddings")


def is_retrieval_enabled() -> bool:
    """True if FG_EMBEDDINGS_RETRIEVAL_ENABLED=true in the environment."""
    v = (os.getenv("FG_EMBEDDINGS_RETRIEVAL_ENABLED") or "false").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def startup_retrieval_service(engine: Engine) -> None:
    """Activation boundary for the semantic retrieval service.

    Must be called before any retrieval route or service is made live.
    Raises on the first failed gate — never silently proceeds.

    Sequence:
      1. Resolve config from env (FG_EMBEDDINGS_PRIMARY_MODEL,
         FG_EMBEDDINGS_ANN_INDEX_STATUS).
      2. Assert primary model is configured.
      3. Assert ANN index is ready.
      4. Emit audit log: retrieval service enabled.
    """
    config = get_embedding_index_config()

    # Gate 1 + Gate 2: assert_ann_index_ready enforces both in order.
    # It raises PrimaryModelNotConfiguredError before checking the index,
    # so the caller always sees the first failing gate, not both at once.
    assert_ann_index_ready(engine, config)

    # Reached only when both gates pass.
    model_str = config.primary_model.value if config.primary_model else "unset"
    logger.info(
        "embedding.retrieval_service_enabled",
        extra={
            "event": "embedding.retrieval_service_enabled",
            "model": model_str,
            "dimensions": config.dimensions,
            "ann_index_status": config.ann_index_status,
        },
    )
