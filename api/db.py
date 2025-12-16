from __future__ import annotations

import os
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

# -----------------------------------------------------------------------------
# Config / URL
# -----------------------------------------------------------------------------
FG_ENV = os.getenv("FG_ENV", "dev").strip().lower()

_raw_url = os.getenv("FG_DB_URL", "").strip()

# In prod, refuse to start without an explicit DB URL.
# This prevents "whoops we wrote to sqlite in a container" failures.
if FG_ENV == "prod" and not _raw_url:
    raise RuntimeError("FG_DB_URL must be set when FG_ENV=prod")

# Dev fallback: sqlite file in ./state if available (keeps container writable)
if not _raw_url:
    _raw_url = os.getenv("FG_DB_URL_FALLBACK", "sqlite:///./state/frostgate_decisions.db").strip()

DATABASE_URL = _raw_url

IS_SQLITE = DATABASE_URL.startswith("sqlite")
IS_POSTGRES = DATABASE_URL.startswith("postgresql")

# -----------------------------------------------------------------------------
# Engine tuning
# -----------------------------------------------------------------------------
connect_args: dict = {}

if IS_SQLITE:
    connect_args = {
        "check_same_thread": False,
        "timeout": int(os.getenv("FG_SQLITE_TIMEOUT_SECONDS", "30")),
    }

# Pool sizing (Postgres only)
POOL_SIZE = int(os.getenv("FG_DB_POOL_SIZE", "5"))
MAX_OVERFLOW = int(os.getenv("FG_DB_MAX_OVERFLOW", "10"))
POOL_RECYCLE = int(os.getenv("FG_DB_POOL_RECYCLE_SECONDS", "1800"))  # 30m
POOL_TIMEOUT = int(os.getenv("FG_DB_POOL_TIMEOUT_SECONDS", "30"))

# Optional: cap how long we wait to establish a TCP connection (psycopg)
# This is applied via connect_args for Postgres.
if IS_POSTGRES:
    connect_timeout = int(os.getenv("FG_PG_CONNECT_TIMEOUT_SECONDS", "5"))
    connect_args = {**connect_args, "connect_timeout": connect_timeout}

engine_kwargs = dict(
    future=True,
    pool_pre_ping=True,     # avoids dead connections after DB restart
    pool_recycle=POOL_RECYCLE,
)

# SQLite doesn't use a real pool like Postgres. Keep it simple and stable.
if IS_SQLITE:
    engine_kwargs.update(
        connect_args=connect_args,
        pool_size=0,
        max_overflow=0,
    )
else:
    engine_kwargs.update(
        connect_args=connect_args,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT,
    )

engine: Engine = create_engine(DATABASE_URL, **engine_kwargs)

# -----------------------------------------------------------------------------
# SQLite pragmas (dev/local)
# -----------------------------------------------------------------------------
if IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _conn_record):
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=30000;")  # ms
            # WAL allows concurrent readers; this can reduce contention in tests.
            cur.execute("PRAGMA read_uncommitted=1;")
        finally:
            cur.close()

# -----------------------------------------------------------------------------
# Postgres session settings (safety + consistency)
# -----------------------------------------------------------------------------
if IS_POSTGRES:

    @event.listens_for(engine, "connect")
    def _postgres_session_settings(dbapi_conn, _conn_record):
        # Keep it minimal: timeouts + UTC. Anything else belongs in DB config.
        statement_timeout_ms = int(os.getenv("FG_PG_STATEMENT_TIMEOUT_MS", "5000"))
        idle_in_tx_timeout_ms = int(os.getenv("FG_PG_IDLE_IN_TX_TIMEOUT_MS", "10000"))
        lock_timeout_ms = int(os.getenv("FG_PG_LOCK_TIMEOUT_MS", "2000"))

        with dbapi_conn.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC';")
            cur.execute(f"SET statement_timeout = {statement_timeout_ms};")
            cur.execute(f"SET idle_in_transaction_session_timeout = {idle_in_tx_timeout_ms};")
            cur.execute(f"SET lock_timeout = {lock_timeout_ms};")

# -----------------------------------------------------------------------------
# Session / Base
# -----------------------------------------------------------------------------
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # avoids lazy-load surprises after commit
    bind=engine,
    future=True,
)

Base = declarative_base()


def init_db() -> None:
    # Import models so Base.metadata is populated
    from api import db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def db_ping() -> bool:
    """Quick DB liveness check for readiness probes."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
