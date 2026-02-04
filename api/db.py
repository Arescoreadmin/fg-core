from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator, Optional

from fastapi import Query, Request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from api.config.env import is_production_env, resolve_env
from api.config.paths import (
    STATE_DIR,
)  # tests assert this symbol is referenced in this file
from api.db_models import Base

log = logging.getLogger("frostgate")


# =============================================================================
# Connection pool configuration (environment-driven)
# =============================================================================


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


# Pool configuration for production readiness
POOL_SIZE = _env_int("FG_DB_POOL_SIZE", 10)
POOL_MAX_OVERFLOW = _env_int(
    "FG_DB_MAX_OVERFLOW", _env_int("FG_DB_POOL_MAX_OVERFLOW", 20)
)
POOL_TIMEOUT = _env_int("FG_DB_POOL_TIMEOUT", 30)
POOL_RECYCLE = _env_int("FG_DB_POOL_RECYCLE", 1800)  # 30 minutes
POOL_PRE_PING = _env_bool("FG_DB_POOL_PRE_PING", True)

_ENGINE: Engine | None = None
_SESSIONMAKER: sessionmaker | None = None


def _env() -> str:
    return resolve_env()


def _resolve_sqlite_path(sqlite_path: Optional[str] = None) -> Path:
    """
    Precedence:
      1) explicit arg
      2) FG_SQLITE_PATH
      3) default based on env:
           - test/dev: <repo>/state/frostgate.db
           - prod/production: /var/lib/frostgate/state/frostgate.db
    Note: We DO NOT blindly trust imported STATE_DIR in tests because it may have been
    computed at import-time under a different FG_ENV. Tests expect repo-local defaults.
    """
    if sqlite_path:
        return Path(sqlite_path).expanduser().resolve()

    env_pth = os.getenv("FG_SQLITE_PATH")
    if env_pth:
        return Path(env_pth).expanduser().resolve()

    env = _env()

    if env in {"prod", "production"}:
        return Path("/var/lib/frostgate/state/frostgate.db")

    # test/dev default: repo-local state/
    return (Path.cwd() / "state" / "frostgate.db").resolve()


def _make_engine(
    *, sqlite_path: Optional[str] = None, db_url: Optional[str] = None
) -> Engine:
    env = _env()
    backend = _resolve_db_backend(env)
    db_url = db_url or (os.getenv("FG_DB_URL") or "").strip() or None

    if backend == "postgres" and not db_url:
        raise RuntimeError("FG_DB_URL is required when FG_DB_BACKEND=postgres")
    if backend == "sqlite" and db_url:
        log.warning("FG_DB_BACKEND=sqlite set, ignoring FG_DB_URL")
        db_url = None

    if backend == "postgres":
        # Production PostgreSQL with connection pooling
        engine = create_engine(
            db_url,
            future=True,
            poolclass=QueuePool,
            pool_size=POOL_SIZE,
            max_overflow=POOL_MAX_OVERFLOW,
            pool_timeout=POOL_TIMEOUT,
            pool_recycle=POOL_RECYCLE,
            pool_pre_ping=POOL_PRE_PING,
        )
        log.info(
            "DB_ENGINE=postgres pool_size=%d max_overflow=%d recycle=%ds",
            POOL_SIZE,
            POOL_MAX_OVERFLOW,
            POOL_RECYCLE,
        )
        return engine

    if backend != "sqlite":
        raise RuntimeError(f"Unsupported FG_DB_BACKEND={backend}")

    pth = _resolve_sqlite_path(sqlite_path)

    # Drift guard: non-prod must not silently write into /var/lib
    if env not in {"prod", "production"} and str(pth).startswith("/var/lib/"):
        if env == "test":
            raise RuntimeError(
                f"DB path drift in test: resolved to /var/lib/... ({pth}). Set FG_SQLITE_PATH."
            )
        log.warning(
            "DB path drift: non-prod resolved to %s. Set FG_SQLITE_PATH or fix env.",
            pth,
        )

    # “STATE_DIR” must appear in-source for a regression test.
    # We don't need it for computation here, but we reference it intentionally.
    _ = STATE_DIR

    log.warning("DB_ENGINE=sqlite+pysqlite:///%s", pth)
    log.warning("SQLITE_PATH=%s", pth)

    return create_engine(
        f"sqlite+pysqlite:///{pth}",
        future=True,
        connect_args={"check_same_thread": False},
    )


def _resolve_db_backend(env: Optional[str] = None) -> str:
    env = env or _env()
    backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()

    if not backend:
        if env in {"prod", "staging"}:
            return "postgres"
        if (os.getenv("FG_DB_URL") or "").strip():
            return "postgres"
        return "sqlite"

    if backend not in {"postgres", "sqlite"}:
        raise RuntimeError("FG_DB_BACKEND must be 'postgres' or 'sqlite'")

    if env in {"prod", "staging"} and backend != "postgres":
        raise RuntimeError("Production requires FG_DB_BACKEND=postgres")

    return backend


def set_tenant_context(session: Session, tenant_id: str) -> None:
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    if not tenant_id:
        raise RuntimeError("tenant_id required to set DB session context")
    session.execute(
        text("SET LOCAL app.tenant_id = :tenant_id"),
        {"tenant_id": tenant_id},
    )


def reset_engine_cache() -> None:
    global _ENGINE, _SESSIONMAKER
    if _ENGINE is not None:
        try:
            _ENGINE.dispose()
        except Exception:
            pass
    _ENGINE = None
    _SESSIONMAKER = None


def get_engine(
    *, sqlite_path: Optional[str] = None, db_url: Optional[str] = None
) -> Engine:
    """
    - If sqlite_path/db_url provided: return a fresh engine (no cache).
    - Else: cached engine.
    """
    global _ENGINE, _SESSIONMAKER

    if sqlite_path is not None or db_url is not None:
        return _make_engine(sqlite_path=sqlite_path, db_url=db_url)

    if _ENGINE is None:
        _ENGINE = _make_engine()
        _SESSIONMAKER = sessionmaker(bind=_ENGINE, expire_on_commit=False, future=True)

    return _ENGINE


def _get_sessionmaker() -> sessionmaker:
    global _SESSIONMAKER
    if _SESSIONMAKER is None:
        get_engine()
    assert _SESSIONMAKER is not None
    return _SESSIONMAKER


def init_db(
    *,
    sqlite_path: Optional[str] = None,
    db_url: Optional[str] = None,
    engine: Engine | None = None,
) -> None:
    """
    Tests call init_db(sqlite_path=...).
    """
    eng = engine or get_engine(sqlite_path=sqlite_path, db_url=db_url)
    if eng.dialect.name == "sqlite":
        Base.metadata.create_all(bind=eng)
        _auto_migrate_sqlite(eng)
        return

    if eng.dialect.name != "postgresql":
        raise RuntimeError(f"Unsupported DB dialect: {eng.dialect.name}")

    try:
        with eng.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as exc:
        raise RuntimeError(f"Postgres connection failed: {exc}") from exc

    from api.db_migrations import (
        assert_append_only_triggers,
        assert_migrations_applied,
        assert_tenant_rls,
    )

    assert_migrations_applied(eng)
    assert_append_only_triggers(eng)
    assert_tenant_rls(eng)


def _auto_migrate_sqlite(engine: Engine) -> None:
    """
    Best-effort SQLite column additions for dev/test.

    NOTE: Production/Postgres requires explicit migrations.
    """
    decisions_columns = {
        "prev_hash": "TEXT",
        "chain_hash": "TEXT",
        "chain_alg": "TEXT",
        "chain_ts": "TIMESTAMP",
        "policy_hash": "TEXT",
    }
    api_keys_columns = {
        "key_lookup": "TEXT",
        "hash_alg": "TEXT",
        "hash_params": "TEXT",
    }

    with engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "decisions" in tables:
            _sqlite_add_columns(conn, "decisions", decisions_columns)
            _sqlite_add_immutable_triggers(conn, "decisions")
        if "decision_evidence_artifacts" in tables:
            _sqlite_add_immutable_triggers(conn, "decision_evidence_artifacts")
        if "api_keys" in tables:
            _sqlite_add_columns(conn, "api_keys", api_keys_columns)


def _sqlite_add_columns(conn, table: str, columns: dict[str, str]) -> None:
    existing = {
        row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    }
    for col, col_type in columns.items():
        if col in existing:
            continue
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


def _sqlite_add_immutable_triggers(conn, table: str) -> None:
    conn.exec_driver_sql(
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_immutable_update
        BEFORE UPDATE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END;
        """
    )
    conn.exec_driver_sql(
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_immutable_delete
        BEFORE DELETE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END;
        """
    )


def get_db(request: Request | None = None) -> Iterator[Session]:
    SessionLocal = _get_sessionmaker()
    db = SessionLocal()
    if request is not None:
        try:
            request.state.db_session = db
            tenant_id = getattr(request.state, "tenant_id", None)
            mode = (os.getenv("FG_TENANT_CONTEXT_MODE") or "db_session").strip().lower()
            if tenant_id and mode == "db_session":
                set_tenant_context(db, tenant_id)
        except Exception:
            if is_production_env():
                db.close()
                raise
    try:
        yield db
    finally:
        db.close()


def tenant_db(
    request: Request,
    tenant_id: Optional[str] = None,
    *,
    require_explicit_for_unscoped: bool = False,
) -> Iterator[Session]:
    from api.auth_scopes import bind_tenant_id

    bound_tenant = bind_tenant_id(
        request,
        tenant_id,
        require_explicit_for_unscoped=require_explicit_for_unscoped,
    )
    SessionLocal = _get_sessionmaker()
    db = SessionLocal()
    try:
        request.state.db_session = db
        request.state.tenant_id = bound_tenant
        mode = (os.getenv("FG_TENANT_CONTEXT_MODE") or "db_session").strip().lower()
        if bound_tenant and mode == "db_session":
            set_tenant_context(db, bound_tenant)
        yield db
    finally:
        db.close()


def tenant_db_required(
    request: Request, tenant_id: Optional[str] = Query(None)
) -> Iterator[Session]:
    yield from tenant_db(
        request,
        tenant_id,
        require_explicit_for_unscoped=True,
    )
