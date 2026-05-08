"""
tests/test_embedding_vector_index_guard.py

PR 20A — Vector Index Readiness Guard tests.

Covers:
  - EmbeddingIndexConfig from env vars
  - assert_ann_index_ready prod fail-closed (no registry row)
  - assert_ann_index_ready prod fail-closed (operator flag not set)
  - assert_ann_index_ready prod fail-closed (primary model not configured)
  - assert_ann_index_ready passes when both flag and registry row present
  - dev/test warning-only (no raise)
  - SQLite no-op
  - is_retrieval_index_ready boolean convenience wrapper
  - Retrieval cannot be enabled in prod without index readiness
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.embeddings import EmbeddingModel
from services.embeddings import (
    AnnIndexNotReadyError,
    EmbeddingIndexConfig,
    PrimaryModelNotConfiguredError,
    assert_ann_index_ready,
    ensure_sqlite_index_registry,
    get_embedding_index_config,
    is_retrieval_index_ready,
)

os.environ.setdefault("FG_ENV", "test")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRIMARY_MODEL = EmbeddingModel.OPENAI_ADA_002
_PRIMARY_MODEL_STR = _PRIMARY_MODEL.value  # "openai/text-embedding-ada-002"
_DIM = 1536


def _fake_pg_engine(registry_row_exists: bool) -> MagicMock:
    """Mock postgres engine; controls whether vector_index_registry has a row."""
    engine = MagicMock()
    engine.dialect.name = "postgresql"

    conn = MagicMock()
    if registry_row_exists:
        conn.execute.return_value.first.return_value = (1,)
    else:
        conn.execute.return_value.first.return_value = None

    engine.connect.return_value.__enter__ = MagicMock(return_value=conn)
    engine.connect.return_value.__exit__ = MagicMock(return_value=False)
    return engine


def _ready_config() -> EmbeddingIndexConfig:
    return EmbeddingIndexConfig(
        primary_model=_PRIMARY_MODEL,
        dimensions=_DIM,
        ann_index_status="ready",
    )


def _not_ready_config() -> EmbeddingIndexConfig:
    return EmbeddingIndexConfig(
        primary_model=_PRIMARY_MODEL,
        dimensions=_DIM,
        ann_index_status="not_ready",
    )


def _unconfigured_config() -> EmbeddingIndexConfig:
    return EmbeddingIndexConfig(
        primary_model=None,
        dimensions=None,
        ann_index_status="not_ready",
    )


# ---------------------------------------------------------------------------
# EmbeddingIndexConfig from env
# ---------------------------------------------------------------------------


class TestGetEmbeddingIndexConfig:
    def test_parses_known_model(self, monkeypatch):
        monkeypatch.setenv("FG_EMBEDDINGS_PRIMARY_MODEL", _PRIMARY_MODEL_STR)
        monkeypatch.setenv("FG_EMBEDDINGS_ANN_INDEX_STATUS", "ready")
        cfg = get_embedding_index_config()
        assert cfg.primary_model == _PRIMARY_MODEL
        assert cfg.dimensions == _DIM
        assert cfg.ann_index_status == "ready"
        assert cfg.is_model_configured is True
        assert cfg.is_operator_ready is True

    def test_returns_none_model_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("FG_EMBEDDINGS_PRIMARY_MODEL", raising=False)
        cfg = get_embedding_index_config()
        assert cfg.primary_model is None
        assert cfg.dimensions is None
        assert cfg.is_model_configured is False

    def test_default_status_is_not_ready(self, monkeypatch):
        monkeypatch.delenv("FG_EMBEDDINGS_ANN_INDEX_STATUS", raising=False)
        cfg = get_embedding_index_config()
        assert cfg.ann_index_status == "not_ready"
        assert cfg.is_operator_ready is False

    def test_unknown_model_logs_warning_and_returns_none(self, monkeypatch, caplog):
        monkeypatch.setenv("FG_EMBEDDINGS_PRIMARY_MODEL", "unknown/fake-model")
        with caplog.at_level(logging.WARNING, logger="frostgate.embeddings"):
            cfg = get_embedding_index_config()
        assert cfg.primary_model is None
        assert any("config_invalid_model" in r.getMessage() for r in caplog.records)

    def test_all_known_models_parseable(self, monkeypatch):
        for model in EmbeddingModel:
            monkeypatch.setenv("FG_EMBEDDINGS_PRIMARY_MODEL", model.value)
            cfg = get_embedding_index_config()
            assert cfg.primary_model == model


# ---------------------------------------------------------------------------
# Prod fail-closed — operator flag not set
# ---------------------------------------------------------------------------


class TestProdFailClosedOperatorFlag:
    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_raises_when_status_not_ready(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=True)
        cfg = _not_ready_config()

        with pytest.raises(AnnIndexNotReadyError) as exc_info:
            assert_ann_index_ready(engine, cfg)

        msg = str(exc_info.value)
        assert "EMBED_P007" in msg
        assert "not_ready" in msg.lower() or "not 'ready'" in msg.lower()

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_error_message_references_runbook(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=True)
        cfg = _not_ready_config()

        with pytest.raises(AnnIndexNotReadyError) as exc_info:
            assert_ann_index_ready(engine, cfg)

        msg = str(exc_info.value)
        assert "0039" in msg or "runbook" in msg.lower()


# ---------------------------------------------------------------------------
# Prod fail-closed — registry row missing
# ---------------------------------------------------------------------------


class TestProdFailClosedRegistryMissing:
    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_raises_when_no_registry_row(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=False)
        cfg = _ready_config()

        with pytest.raises(AnnIndexNotReadyError) as exc_info:
            assert_ann_index_ready(engine, cfg)

        msg = str(exc_info.value)
        assert "EMBED_P007" in msg

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_raises_even_when_flag_ready_but_no_row(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=False)
        cfg = _ready_config()  # operator says ready, but no row in registry

        with pytest.raises(AnnIndexNotReadyError):
            assert_ann_index_ready(engine, cfg)


# ---------------------------------------------------------------------------
# Prod fail-closed — primary model not configured
# ---------------------------------------------------------------------------


class TestProdFailClosedModelNotConfigured:
    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_raises_when_model_not_configured(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=True)
        cfg = _unconfigured_config()

        with pytest.raises(PrimaryModelNotConfiguredError) as exc_info:
            assert_ann_index_ready(engine, cfg)

        msg = str(exc_info.value)
        assert "EMBED_P008" in msg
        assert "FG_EMBEDDINGS_PRIMARY_MODEL" in msg

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_error_message_gives_example(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=False)
        cfg = _unconfigured_config()

        with pytest.raises(PrimaryModelNotConfiguredError) as exc_info:
            assert_ann_index_ready(engine, cfg)

        msg = str(exc_info.value)
        # Must provide an example so the operator knows what to set
        assert "openai/text-embedding" in msg or "=" in msg


# ---------------------------------------------------------------------------
# Prod passes when both flag AND registry row present
# ---------------------------------------------------------------------------


class TestProdPassesWhenReady:
    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_passes_when_flag_set_and_row_exists(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=True)
        cfg = _ready_config()
        # Must not raise
        assert_ann_index_ready(engine, cfg)


# ---------------------------------------------------------------------------
# Dev/test — warning only, no raise
# ---------------------------------------------------------------------------


class TestDevWarningOnly:
    @pytest.mark.parametrize("env", ["dev", "test", "local"])
    def test_does_not_raise_when_not_ready(self, env, monkeypatch, caplog):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=False)
        cfg = _not_ready_config()

        with caplog.at_level(logging.WARNING, logger="frostgate.embeddings"):
            assert_ann_index_ready(engine, cfg)  # must not raise

        assert any("ann_index_not_ready" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("env", ["dev", "test"])
    def test_does_not_raise_when_model_not_configured(self, env, monkeypatch, caplog):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(registry_row_exists=False)
        cfg = _unconfigured_config()

        with caplog.at_level(logging.WARNING, logger="frostgate.embeddings"):
            assert_ann_index_ready(engine, cfg)  # must not raise


# ---------------------------------------------------------------------------
# SQLite no-op
# ---------------------------------------------------------------------------


class TestSqliteNoop:
    def test_sqlite_skips_check_entirely(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = create_engine(f"sqlite:///{tmp_path / 'noop-idx.db'}")
        # Must not raise even in "prod" because SQLite has no ANN support
        assert_ann_index_ready(engine, _unconfigured_config())

    def test_is_retrieval_index_ready_returns_true_for_sqlite(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = create_engine(f"sqlite:///{tmp_path / 'noop-idx2.db'}")
        assert is_retrieval_index_ready(engine, _unconfigured_config()) is True


# ---------------------------------------------------------------------------
# is_retrieval_index_ready boolean wrapper
# ---------------------------------------------------------------------------


class TestIsRetrievalIndexReady:
    def test_returns_false_when_not_ready_in_prod(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=False)
        assert is_retrieval_index_ready(engine, _ready_config()) is False

    def test_returns_false_when_flag_not_set_in_prod(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=True)
        assert is_retrieval_index_ready(engine, _not_ready_config()) is False

    def test_returns_true_when_both_conditions_met_in_prod(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=True)
        assert is_retrieval_index_ready(engine, _ready_config()) is True

    def test_returns_true_in_dev_even_when_not_ready(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "dev")
        engine = _fake_pg_engine(registry_row_exists=False)
        # In dev, assert_ann_index_ready does not raise → is_retrieval_index_ready = True
        assert is_retrieval_index_ready(engine, _not_ready_config()) is True


# ---------------------------------------------------------------------------
# SQLite registry schema (dev/test)
# ---------------------------------------------------------------------------


class TestSqliteIndexRegistry:
    def test_creates_registry_table(self, tmp_path):
        from sqlalchemy import inspect as sa_inspect

        engine = create_engine(f"sqlite:///{tmp_path / 'registry-test.db'}")
        ensure_sqlite_index_registry(engine)
        inspector = sa_inspect(engine)
        assert "vector_index_registry" in inspector.get_table_names()

    def test_idempotent(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'registry-idm.db'}")
        ensure_sqlite_index_registry(engine)
        ensure_sqlite_index_registry(engine)  # must not raise

    def test_refuses_postgres_engine(self):
        fake_engine = MagicMock()
        fake_engine.dialect.name = "postgresql"
        with pytest.raises(RuntimeError, match="postgres"):
            ensure_sqlite_index_registry(fake_engine)

    def test_insert_and_query_registry_row(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'registry-insert.db'}")
        ensure_sqlite_index_registry(engine)

        now_str = datetime.now(timezone.utc).isoformat()
        with Session(engine) as db:
            from sqlalchemy import text

            db.execute(
                text(
                    "INSERT INTO vector_index_registry "
                    "(id, model, dimensions, index_type, index_name, created_at) "
                    "VALUES (:id, :model, :dimensions, :index_type, :index_name, :created_at)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "model": _PRIMARY_MODEL_STR,
                    "dimensions": _DIM,
                    "index_type": "ivfflat",
                    "index_name": "ix_ev_ann_ada_1536",
                    "created_at": now_str,
                },
            )
            row = db.execute(
                text("SELECT model FROM vector_index_registry LIMIT 1")
            ).first()
        assert row is not None
        assert row[0] == _PRIMARY_MODEL_STR


# ---------------------------------------------------------------------------
# Retrieval cannot enable in prod without index readiness
# ---------------------------------------------------------------------------


class TestRetrievalGateInProd:
    """Prove that semantic retrieval cannot be enabled in prod without index."""

    def test_retrieval_blocked_no_flag_no_row(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=False)

        with pytest.raises((AnnIndexNotReadyError, PrimaryModelNotConfiguredError)):
            assert_ann_index_ready(engine, _not_ready_config())

    def test_retrieval_blocked_flag_set_but_no_row(self, monkeypatch):
        """Operator claimed ready but never ran the runbook."""
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=False)

        with pytest.raises(AnnIndexNotReadyError):
            assert_ann_index_ready(engine, _ready_config())

    def test_retrieval_blocked_row_exists_but_flag_not_set(self, monkeypatch):
        """Index exists in registry but operator forgot to set the flag."""
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=True)

        with pytest.raises(AnnIndexNotReadyError):
            assert_ann_index_ready(engine, _not_ready_config())

    def test_retrieval_unblocked_when_both_conditions_met(self, monkeypatch):
        """Full happy path: flag=ready + registry row → guard passes."""
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=True)
        assert_ann_index_ready(engine, _ready_config())  # must not raise

    def test_is_retrieval_index_ready_false_in_prod_without_setup(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        engine = _fake_pg_engine(registry_row_exists=False)
        assert is_retrieval_index_ready(engine, _not_ready_config()) is False
