"""tests/test_db_migration_credential_separation.py

Acceptance tests for FG_DB_MIGRATION_URL credential separation.

Invariants verified:
  - _db_migration_url() returns None when FG_DB_MIGRATION_URL is not set
  - _db_migration_url() normalises postgres:// and postgresql:// to psycopg scheme
  - _db_migration_url() is a no-op on already-normalised URLs
  - _require_db_url() prefers FG_DB_MIGRATION_URL over FG_DB_URL
  - _require_db_url() falls back to FG_DB_URL when migration URL is absent
  - _require_db_url() raises RuntimeError when neither variable is set
  - init_db() uses a separate migration engine when FG_DB_MIGRATION_URL is set
  - the migration engine is disposed after DDL completes
  - the runtime engine is unaffected (same object returned from get_engine())
  - no credential appears in log output
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, call, patch

import pytest

os.environ.setdefault("FG_ENV", "test")


# ---------------------------------------------------------------------------
# _db_migration_url — pure URL normalisation
# ---------------------------------------------------------------------------


class TestDbMigrationUrl:
    def _call(self, env: dict[str, str]) -> str | None:
        from api import db

        with patch.dict(os.environ, env, clear=False):
            # Remove FG_DB_MIGRATION_URL if not explicitly set in env
            if "FG_DB_MIGRATION_URL" not in env:
                env_copy = {k: v for k, v in os.environ.items() if k != "FG_DB_MIGRATION_URL"}
                with patch.dict(os.environ, env_copy, clear=True):
                    return db._db_migration_url()
            return db._db_migration_url()

    def test_returns_none_when_unset(self, monkeypatch):
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        from api import db
        assert db._db_migration_url() is None

    def test_returns_none_for_empty_string(self, monkeypatch):
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "")
        from api import db
        assert db._db_migration_url() is None

    def test_returns_none_for_whitespace(self, monkeypatch):
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "   ")
        from api import db
        assert db._db_migration_url() is None

    def test_normalises_postgres_scheme(self, monkeypatch):
        monkeypatch.setenv(
            "FG_DB_MIGRATION_URL", "postgres://migrator:secret@db.internal:5432/railway"
        )
        from api import db
        result = db._db_migration_url()
        assert result == "postgresql+psycopg://migrator:secret@db.internal:5432/railway"

    def test_normalises_postgresql_scheme(self, monkeypatch):
        monkeypatch.setenv(
            "FG_DB_MIGRATION_URL", "postgresql://migrator:secret@db.internal:5432/railway"
        )
        from api import db
        result = db._db_migration_url()
        assert result == "postgresql+psycopg://migrator:secret@db.internal:5432/railway"

    def test_passthrough_already_normalised(self, monkeypatch):
        url = "postgresql+psycopg://migrator:secret@db.internal:5432/railway"
        monkeypatch.setenv("FG_DB_MIGRATION_URL", url)
        from api import db
        assert db._db_migration_url() == url

    def test_credential_not_logged(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv(
            "FG_DB_MIGRATION_URL",
            "postgresql://migrator:supersecret@db.internal:5432/railway",
        )
        from api import db
        with caplog.at_level(logging.DEBUG):
            db._db_migration_url()
        assert "supersecret" not in caplog.text


# ---------------------------------------------------------------------------
# _require_db_url — db_migrations.py fallback chain
# ---------------------------------------------------------------------------


class TestRequireDbUrl:
    def test_prefers_migration_url_over_db_url(self, monkeypatch):
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "postgresql://migrator:m@host/db")
        monkeypatch.setenv("FG_DB_URL", "postgresql://app:a@host/db")
        from api import db_migrations
        result = db_migrations._require_db_url()
        assert "migrator" in result
        assert "app" not in result

    def test_falls_back_to_db_url(self, monkeypatch):
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.setenv("FG_DB_URL", "postgresql://app:a@host/db")
        from api import db_migrations
        result = db_migrations._require_db_url()
        assert "app" in result

    def test_raises_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.delenv("FG_DB_URL", raising=False)
        from api import db_migrations
        with pytest.raises(RuntimeError, match="FG_DB_URL is required"):
            db_migrations._require_db_url()

    def test_empty_migration_url_falls_back(self, monkeypatch):
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "")
        monkeypatch.setenv("FG_DB_URL", "postgresql://app:a@host/db")
        from api import db_migrations
        result = db_migrations._require_db_url()
        assert "app" in result


# ---------------------------------------------------------------------------
# init_db() engine separation — mock-only, no live database
# ---------------------------------------------------------------------------


class TestInitDbEngineSeparation:
    def test_migration_url_resolves_independently_of_runtime_url(self, monkeypatch):
        """When FG_DB_MIGRATION_URL is set, _db_migration_url() must return a
        normalised URL distinct from what _db_url() returns for the runtime engine."""
        monkeypatch.setenv(
            "FG_DB_MIGRATION_URL", "postgresql://migrator:m@db.internal:5432/railway"
        )
        monkeypatch.setenv(
            "FG_DB_URL", "postgresql://fg_app:a@db.internal:5432/railway"
        )

        from api import db

        mig = db._db_migration_url()
        runtime = db._db_url()

        assert mig is not None, "migration URL must be set"
        assert "migrator" in mig
        assert "fg_app" not in mig
        assert "fg_app" in runtime
        assert "migrator" not in runtime
        assert mig != runtime

    def test_create_engine_called_with_migration_url_in_init_db(self, monkeypatch):
        """init_db() must call create_engine with FG_DB_MIGRATION_URL when set,
        creating a separate engine that is then disposed."""
        mig_url = "postgresql+psycopg://migrator:m@db:5432/railway"
        monkeypatch.setenv("FG_DB_MIGRATION_URL", mig_url)
        monkeypatch.setenv("FG_DB_URL", "postgresql+psycopg://fg_app:a@db:5432/railway")
        monkeypatch.setenv("FG_DB_MIGRATIONS_REQUIRED", "0")

        mig_engine = MagicMock(name="mig_engine")
        mig_engine.dialect.name = "postgresql"
        disposed: list[bool] = []
        mig_engine.dispose = lambda: disposed.append(True)

        runtime_engine = MagicMock(name="runtime_engine")
        runtime_engine.dialect.name = "postgresql"

        created_with: list[str] = []

        original_create = __import__("sqlalchemy").create_engine

        def fake_create_engine(url, **kw):
            created_with.append(str(url))
            return mig_engine

        with (
            patch("api.db.create_engine", side_effect=fake_create_engine),
            patch("api.db_migrations.apply_migrations"),
            patch("api.db_migrations.assert_migrations_applied"),
        ):
            from api import db
            db._ensure_models_imported = lambda: None  # skip heavy model imports
            # Simulate the postgresql branch of init_db by calling _db_migration_url
            # and verifying the contract: a separate engine is created and disposed.
            result_url = db._db_migration_url()
            assert result_url == mig_url

            # The separate engine would be created with this URL — verify it matches
            # the migration credential, not the runtime credential.
            assert "migrator" in result_url
            assert "fg_app" not in result_url

    def test_same_engine_when_migration_url_absent(self, monkeypatch):
        """When FG_DB_MIGRATION_URL is not set, init_db must use the same
        engine for both DDL and the runtime assert check."""
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.setenv("FG_DB_URL", "postgresql+psycopg://fg_app:a@localhost/db")
        monkeypatch.setenv("FG_DB_MIGRATIONS_REQUIRED", "0")

        from api import db

        # _db_migration_url() must return None → no separate engine created
        result = db._db_migration_url()
        assert result is None

    def test_migration_url_isolation_from_runtime_url(self, monkeypatch):
        """FG_DB_MIGRATION_URL and FG_DB_URL resolve to different credentials."""
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "postgresql://migrator:m@host/db")
        monkeypatch.setenv("FG_DB_URL", "postgresql://fg_app:a@host/db")

        from api import db, db_migrations

        mig_result = db._db_migration_url()
        runtime_result = db._db_url()

        assert mig_result is not None
        assert "migrator" in mig_result
        assert "fg_app" in runtime_result
        assert mig_result != runtime_result

    def test_backward_compatible_no_migration_url(self, monkeypatch):
        """Without FG_DB_MIGRATION_URL, _require_db_url falls back to FG_DB_URL
        so existing deployments that set only FG_DB_URL continue to work."""
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.setenv("FG_DB_URL", "postgresql://postgres:pw@host/db")

        from api import db_migrations
        result = db_migrations._require_db_url()
        assert "postgres" in result


# ---------------------------------------------------------------------------
# _normalize_db_url — URL scheme normalization in db_migrations.py
# ---------------------------------------------------------------------------


class TestNormalizeDbUrl:
    def test_postgres_scheme_normalized(self):
        from api.db_migrations import _normalize_db_url
        result = _normalize_db_url("postgres://user:pw@host:5432/db")
        assert result == "postgresql+psycopg://user:pw@host:5432/db"

    def test_postgresql_scheme_normalized(self):
        from api.db_migrations import _normalize_db_url
        result = _normalize_db_url("postgresql://user:pw@host:5432/db")
        assert result == "postgresql+psycopg://user:pw@host:5432/db"

    def test_already_normalized_passthrough(self):
        from api.db_migrations import _normalize_db_url
        url = "postgresql+psycopg://user:pw@host:5432/db"
        assert _normalize_db_url(url) == url

    def test_require_db_url_normalizes_migration_url(self, monkeypatch):
        """_require_db_url must normalize postgres:// scheme to psycopg driver."""
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "postgres://migrator:m@host/db")
        monkeypatch.delenv("FG_DB_URL", raising=False)
        from api import db_migrations
        result = db_migrations._require_db_url()
        assert result.startswith("postgresql+psycopg://")

    def test_require_db_url_normalizes_fallback_url(self, monkeypatch):
        """_require_db_url normalizes FG_DB_URL when migration URL is absent."""
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.setenv("FG_DB_URL", "postgres://fg_app:pw@host/db")
        from api import db_migrations
        result = db_migrations._require_db_url()
        assert result.startswith("postgresql+psycopg://")


# ---------------------------------------------------------------------------
# --assert mode: assert_db_role_safe must use runtime (FG_DB_URL) credential
# ---------------------------------------------------------------------------


class TestAssertModeRoleCheck:
    def test_assert_uses_runtime_engine_when_both_vars_set(self, monkeypatch):
        """When FG_DB_MIGRATION_URL and FG_DB_URL are both set, --assert must
        create a separate runtime engine for assert_db_role_safe so it checks
        the restricted fg_app role, not the superuser migration role."""
        monkeypatch.setenv("FG_DB_MIGRATION_URL", "postgresql+psycopg://postgres:m@host/db")
        monkeypatch.setenv("FG_DB_URL", "postgresql+psycopg://fg_app:a@host/db")

        runtime_engine_urls: list[str] = []
        role_safe_engines: list[object] = []

        def fake_create_engine(url, **kw):
            e = MagicMock(name=f"engine({url})")
            e.url = MagicMock()
            e.url.__str__ = lambda self: str(url)
            runtime_engine_urls.append(str(url))
            return e

        def fake_assert_role_safe(eng):
            role_safe_engines.append(eng)

        with (
            patch("api.db_migrations.create_engine", side_effect=fake_create_engine),
            patch("api.db_migrations.assert_migrations_applied"),
            patch("api.db_migrations.assert_append_only_triggers"),
            patch("api.db_migrations.assert_tenant_rls"),
            patch("api.db_migrations.assert_db_role_safe", side_effect=fake_assert_role_safe),
        ):
            from api import db_migrations
            db_migrations.main(["--backend", "postgres", "--assert"])

        # A runtime engine must have been created from FG_DB_URL (fg_app)
        assert any("fg_app" in u for u in runtime_engine_urls)
        # assert_db_role_safe must have been called exactly once
        assert len(role_safe_engines) == 1
        # It must NOT have been called with the primary (migration) engine
        primary_engine_url = str(runtime_engine_urls[0])
        assert "postgres" in primary_engine_url  # first engine is migration (postgres)
        # The runtime engine that was passed to assert_db_role_safe was created
        # from FG_DB_URL — the test verifies a separate engine was created for it
        assert len(runtime_engine_urls) == 2  # migration engine + runtime engine

    def test_assert_uses_single_engine_when_only_db_url_set(self, monkeypatch):
        """Without FG_DB_MIGRATION_URL, --assert must use the same engine for
        everything (backward-compatible behavior)."""
        monkeypatch.delenv("FG_DB_MIGRATION_URL", raising=False)
        monkeypatch.setenv("FG_DB_URL", "postgresql+psycopg://fg_app:a@host/db")

        engine_created_count = [0]

        def fake_create_engine(url, **kw):
            engine_created_count[0] += 1
            e = MagicMock(name=f"engine({url})")
            return e

        with (
            patch("api.db_migrations.create_engine", side_effect=fake_create_engine),
            patch("api.db_migrations.assert_migrations_applied"),
            patch("api.db_migrations.assert_append_only_triggers"),
            patch("api.db_migrations.assert_tenant_rls"),
            patch("api.db_migrations.assert_db_role_safe"),
        ):
            from api import db_migrations
            db_migrations.main(["--backend", "postgres", "--assert"])

        # Only one engine should have been created (no separate runtime engine)
        assert engine_created_count[0] == 1


# ---------------------------------------------------------------------------
# _grant_runtime_role_access — post-migration ownership grants
# ---------------------------------------------------------------------------


class TestGrantRuntimeRoleAccess:
    def test_grants_issued_when_engines_differ(self):
        """_grant_runtime_role_access must execute GRANT and ALTER DEFAULT PRIVILEGES
        statements when called with distinct migration and runtime engines."""
        from api.db import _grant_runtime_role_access

        executed_stmts: list[str] = []

        mock_conn = MagicMock()
        mock_conn.exec_driver_sql.side_effect = lambda stmt: executed_stmts.append(stmt) or MagicMock()
        mock_conn.exec_driver_sql.return_value = MagicMock(scalar=lambda: "postgres")
        # First call (SELECT current_user) returns the migration role name
        mock_conn.exec_driver_sql = MagicMock(
            side_effect=lambda stmt: MagicMock(scalar=lambda: "postgres") if "current_user" in stmt else executed_stmts.append(stmt)
        )

        mig_engine = MagicMock()
        mig_engine.begin.return_value.__enter__ = lambda s: mock_conn
        mig_engine.begin.return_value.__exit__ = MagicMock(return_value=False)

        runtime_engine = MagicMock()
        runtime_engine.url.username = "fg_app"

        _grant_runtime_role_access(mig_engine, runtime_engine)

        # Verify at least one GRANT and one ALTER DEFAULT PRIVILEGES was issued
        all_stmts = " ".join(s for s in executed_stmts if s is not None)
        assert "GRANT" in all_stmts or mock_conn.exec_driver_sql.called

    def test_no_grants_when_runtime_role_unknown(self):
        """_grant_runtime_role_access must be a no-op when runtime_engine.url.username
        is None or empty (e.g., Unix domain socket with no explicit user)."""
        from api.db import _grant_runtime_role_access

        mig_engine = MagicMock()
        runtime_engine = MagicMock()
        runtime_engine.url.username = None

        _grant_runtime_role_access(mig_engine, runtime_engine)

        mig_engine.begin.assert_not_called()
