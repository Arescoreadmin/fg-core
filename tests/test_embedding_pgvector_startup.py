"""
tests/test_embedding_pgvector_startup.py

Tests for prod fail-closed behaviour when pgvector is unavailable.

Covers:
  - prod/staging environments raise PgvectorUnavailableError when pgvector missing
  - dev/test environments only log a warning (do not raise)
  - SQLite engine is always a no-op (no check needed)
  - No raw vectors in audit/log output
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine

from services.embeddings import (
    PgvectorUnavailableError,
    assert_pgvector_available,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_pg_engine(pgvector_installed: bool) -> MagicMock:
    """Build a mock SQLAlchemy engine that reports postgres dialect."""
    engine = MagicMock()
    engine.dialect.name = "postgresql"

    conn = MagicMock()
    if pgvector_installed:
        conn.execute.return_value.first.return_value = (1,)
    else:
        conn.execute.return_value.first.return_value = None

    engine.connect.return_value.__enter__ = MagicMock(return_value=conn)
    engine.connect.return_value.__exit__ = MagicMock(return_value=False)
    return engine


# ---------------------------------------------------------------------------
# Production fail-closed tests
# ---------------------------------------------------------------------------


class TestProdFailClosed:
    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_raises_in_prod_when_pgvector_missing(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(pgvector_installed=False)

        with pytest.raises(PgvectorUnavailableError) as exc_info:
            assert_pgvector_available(engine)

        msg = str(exc_info.value)
        assert "EMBED_P004" in msg
        assert "pgvector" in msg.lower()
        # Error message must guide the operator
        assert "CREATE EXTENSION" in msg or "migration" in msg

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_passes_in_prod_when_pgvector_installed(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(pgvector_installed=True)
        # Must not raise
        assert_pgvector_available(engine)


# ---------------------------------------------------------------------------
# Dev/test warning-only behaviour
# ---------------------------------------------------------------------------


class TestDevFallbackBehaviour:
    @pytest.mark.parametrize("env", ["dev", "test", "local"])
    def test_does_not_raise_in_dev_when_pgvector_missing(
        self, env, monkeypatch, caplog
    ):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(pgvector_installed=False)

        with caplog.at_level(logging.WARNING, logger="frostgate.embeddings"):
            assert_pgvector_available(engine)  # must not raise

        # A warning must be emitted
        assert any("pgvector" in r.getMessage().lower() for r in caplog.records)

    @pytest.mark.parametrize("env", ["dev", "test"])
    def test_passes_quietly_in_dev_when_pgvector_installed(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        engine = _fake_pg_engine(pgvector_installed=True)
        assert_pgvector_available(engine)  # no raise, no warning needed


# ---------------------------------------------------------------------------
# SQLite is always safe
# ---------------------------------------------------------------------------


class TestSqliteNoop:
    def test_sqlite_engine_skips_pgvector_check(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'noop.db'}")
        # Must not raise regardless of FG_ENV
        os.environ["FG_ENV"] = "prod"
        try:
            assert_pgvector_available(engine)
        finally:
            os.environ["FG_ENV"] = "test"


# ---------------------------------------------------------------------------
# Audit log safety — no raw vectors or chunk content
# ---------------------------------------------------------------------------


class TestAuditLogSafety:
    """Verify audit logs never include raw vector data or chunk text."""

    def test_no_raw_vectors_in_audit_log(self, tmp_path, caplog):
        from datetime import datetime, timezone

        from sqlalchemy.orm import Session

        from api.embeddings import (
            ChunkEmbeddingRecord,
            EmbeddingModel,
            KNOWN_DIMENSIONS,
            canonical_content_hash,
        )
        from services.embeddings import (
            ensure_sqlite_schema,
            save_embedding,
        )

        engine = create_engine(f"sqlite:///{tmp_path / 'audit-test.db'}")
        ensure_sqlite_schema(engine)

        _model = EmbeddingModel.INSTRUCTOR_XL
        _dim = KNOWN_DIMENSIONS[_model]
        _text = "chunk text that must not appear in logs"
        _hash = canonical_content_hash(_text)
        _vector = tuple(0.123456789 for _ in range(_dim))

        with caplog.at_level(logging.INFO, logger="frostgate.embeddings"):
            with Session(engine) as db:
                save_embedding(
                    db,
                    ChunkEmbeddingRecord(
                        tenant_id="tenant-log-test",
                        corpus_id="corpus-001",
                        document_id="doc-001",
                        chunk_id="chunk-log",
                        content_hash=_hash,
                        embedding_model=_model,
                        dimensions=_dim,
                        vector=_vector,
                        created_at=datetime.now(timezone.utc),
                    ),
                )

        all_log_text = " ".join(r.getMessage() for r in caplog.records)

        # No raw vector components (the specific float value)
        assert "0.123456789" not in all_log_text
        # No raw chunk text
        assert "chunk text that must not appear in logs" not in all_log_text

    def test_delete_audit_log_safe(self, tmp_path, caplog):
        from datetime import datetime, timezone

        from sqlalchemy.orm import Session

        from api.embeddings import (
            ChunkEmbeddingRecord,
            EmbeddingModel,
            KNOWN_DIMENSIONS,
            canonical_content_hash,
        )
        from services.embeddings import (
            delete_embedding,
            ensure_sqlite_schema,
            save_embedding,
        )

        engine = create_engine(f"sqlite:///{tmp_path / 'audit-del-test.db'}")
        ensure_sqlite_schema(engine)

        _model = EmbeddingModel.INSTRUCTOR_XL
        _dim = KNOWN_DIMENSIONS[_model]
        _secret_text = "this text must not log on delete"

        with caplog.at_level(logging.INFO, logger="frostgate.embeddings"):
            with Session(engine) as db:
                row = save_embedding(
                    db,
                    ChunkEmbeddingRecord(
                        tenant_id="tenant-del-log",
                        corpus_id="corpus-001",
                        document_id="doc-001",
                        chunk_id="chunk-del",
                        content_hash=canonical_content_hash(_secret_text),
                        embedding_model=_model,
                        dimensions=_dim,
                        vector=tuple(0.999 for _ in range(_dim)),
                        created_at=datetime.now(timezone.utc),
                    ),
                )
                delete_embedding(db, tenant_id="tenant-del-log", embedding_id=row.id)

        all_log_text = " ".join(r.getMessage() for r in caplog.records)
        assert _secret_text not in all_log_text
        assert "0.999" not in all_log_text
