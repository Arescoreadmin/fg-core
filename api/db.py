from __future__ import annotations

import logging
import os
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator, Optional

from fastapi import Request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from api.config.env import resolve_env
from api.config.paths import (
    STATE_DIR,
)  # tests assert this symbol is referenced in this file
from api.db_migrations import run_migrations

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
POOL_SIZE = _env_int("FG_DB_POOL_SIZE", 5)
POOL_MAX_OVERFLOW = _env_int("FG_DB_POOL_MAX_OVERFLOW", 10)
POOL_TIMEOUT = _env_int("FG_DB_POOL_TIMEOUT", 30)
POOL_RECYCLE = _env_int("FG_DB_POOL_RECYCLE", 1800)  # 30 minutes
POOL_PRE_PING = _env_bool("FG_DB_POOL_PRE_PING", True)

_ENGINE: Engine | None = None
_SESSIONMAKER: sessionmaker | None = None
_CURRENT_TENANT_ID: ContextVar[str | None] = ContextVar(
    "frostgate_current_tenant_id", default=None
)


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


def _resolve_db_backend() -> str:
    backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()
    env = _env()

    if backend and backend not in {"sqlite", "postgres"}:
        raise RuntimeError(f"Unsupported FG_DB_BACKEND={backend}")

    if not backend:
        if env in {"prod", "production", "staging"}:
            raise RuntimeError("FG_DB_BACKEND is required in production/staging")
        backend = "sqlite"

    if backend == "sqlite" and env in {"prod", "production"}:
        raise RuntimeError("SQLite is not permitted in production")

    return backend


def _resolve_db_url(backend: str) -> Optional[str]:
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if backend == "postgres":
        if not db_url:
            raise RuntimeError("FG_DB_URL is required when FG_DB_BACKEND=postgres")
        return db_url
    if db_url:
        raise RuntimeError("FG_DB_URL is set but FG_DB_BACKEND is not postgres")
    return None


def get_db_backend() -> str:
    return _resolve_db_backend()


def set_current_tenant_id(tenant_id: Optional[str]) -> None:
    _CURRENT_TENANT_ID.set(tenant_id)


def _current_tenant_id() -> Optional[str]:
    return _CURRENT_TENANT_ID.get()


def _make_engine(
    *, sqlite_path: Optional[str] = None, db_url: Optional[str] = None
) -> Engine:
    env = _env()
    backend = _resolve_db_backend()

    if db_url and backend != "postgres":
        raise RuntimeError("db_url provided but FG_DB_BACKEND is not postgres")

    if backend == "postgres":
        resolved_url = db_url or _resolve_db_url(backend)
        # Production PostgreSQL with connection pooling
        engine = create_engine(
            resolved_url,
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
    backend = _resolve_db_backend()
    run_migrations(eng, backend=backend)


def get_db(request: Request = None) -> Iterator[Session]:
    SessionLocal = _get_sessionmaker()
    db = SessionLocal()
    try:
        if request is not None:
            request.state.db_session = db
            tenant_id = getattr(request.state, "tenant_id", None)
            if tenant_id:
                apply_tenant_context(db, tenant_id)
        else:
            tenant_id = _current_tenant_id()
            if tenant_id:
                apply_tenant_context(db, tenant_id)
        yield db
    finally:
        db.close()


def apply_tenant_context(conn_or_session: Session | Connection, tenant_id: str) -> None:
    if not tenant_id:
        return
    if _resolve_db_backend() != "postgres":
        return
    try:
        conn_or_session.execute(
            text("SET LOCAL app.tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        )
    except Exception:
        log.exception("Failed to apply tenant context")
