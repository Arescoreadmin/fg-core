"""Database Session Management.

Provides async database sessions for admin-gateway.
Supports both PostgreSQL (production) and SQLite (development/testing).
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from admin_gateway.db.models import Base

# Global engine and session factory
_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def _env_int(name: str, default: int) -> int:
    """Parse integer environment variable."""
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def get_database_url() -> str:
    """Get database URL from environment.

    Priority:
    1. AG_DB_URL (admin-gateway specific)
    2. FG_DB_URL (shared with core)
    3. AG_SQLITE_PATH (SQLite fallback)
    4. Default SQLite path
    """
    # Check for explicit PostgreSQL URL
    db_url = os.getenv("AG_DB_URL") or os.getenv("FG_DB_URL")
    if db_url:
        # Convert sync URL to async if needed
        if db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
        elif db_url.startswith("postgresql+psycopg://"):
            pass  # Already async-compatible
        return db_url

    # Fall back to SQLite
    sqlite_path = os.getenv("AG_SQLITE_PATH", "state/admin_gateway.db")
    return f"sqlite+aiosqlite:///{sqlite_path}"


def get_engine() -> AsyncEngine:
    """Get or create the async database engine."""
    global _engine

    if _engine is None:
        db_url = get_database_url()
        is_sqlite = db_url.startswith("sqlite")

        engine_kwargs = {
            "echo": os.getenv("AG_DB_ECHO", "").lower() in ("1", "true", "yes"),
        }

        if not is_sqlite:
            # PostgreSQL connection pool settings
            engine_kwargs.update(
                {
                    "pool_size": _env_int("AG_DB_POOL_SIZE", 5),
                    "max_overflow": _env_int("AG_DB_POOL_MAX_OVERFLOW", 10),
                    "pool_timeout": _env_int("AG_DB_POOL_TIMEOUT", 30),
                    "pool_recycle": _env_int("AG_DB_POOL_RECYCLE", 1800),
                }
            )

        _engine = create_async_engine(db_url, **engine_kwargs)

        # SQLite-specific settings
        if is_sqlite:

            @event.listens_for(_engine.sync_engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()

    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory."""
    global _async_session_factory

    if _async_session_factory is None:
        engine = get_engine()
        _async_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    return _async_session_factory


# Convenience alias
AsyncSessionLocal = get_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions.

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Initialize database tables.

    Creates all tables defined in Base.metadata.
    For production, use Alembic migrations instead.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    global _engine, _async_session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
