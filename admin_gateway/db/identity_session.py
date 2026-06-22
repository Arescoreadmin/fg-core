"""Synchronous identity database sessions owned by Admin Gateway."""

from __future__ import annotations

import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None
_engine_url: str | None = None


def _database_url() -> str:
    url = (os.getenv("AG_IDENTITY_DB_URL") or os.getenv("FG_DB_URL") or "").strip()
    if url:
        if url.startswith("postgres://"):
            return "postgresql+psycopg://" + url[len("postgres://") :]
        if url.startswith("postgresql://"):
            return "postgresql+psycopg://" + url[len("postgresql://") :]
        return url
    path = os.getenv("FG_SQLITE_PATH") or os.getenv(
        "AG_SQLITE_PATH", "state/admin_gateway.db"
    )
    return f"sqlite+pysqlite:///{path}"


def reset_identity_engine_cache() -> None:
    global _engine, _session_factory, _engine_url
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
    _engine_url = None


def get_identity_sessionmaker() -> sessionmaker[Session]:
    global _engine, _session_factory, _engine_url
    url = _database_url()
    if _session_factory is not None and _engine_url == url:
        return _session_factory
    reset_identity_engine_cache()
    _engine = create_engine(url, future=True, pool_pre_ping=True)
    _session_factory = sessionmaker(
        bind=_engine, autocommit=False, autoflush=False, future=True
    )
    _engine_url = url
    return _session_factory


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """Bind PostgreSQL RLS context for the current transaction."""
    if not tenant_id:
        raise RuntimeError("tenant_id required")
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )
