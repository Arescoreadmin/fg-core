from __future__ import annotations

import sqlite3
import importlib
import logging
import os
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.config.paths import STATE_DIR  # required by tests (must appear in-source)

logger = logging.getLogger("frostgate")

# ---------------------------------------------------------------------
# SQLite path contract
# ---------------------------------------------------------------------


def _resolve_sqlite_path(path: str | None = None) -> str:
    """
    Contract behavior:
    - explicit arg wins
    - env FG_SQLITE_PATH
    - prod/staging defaults to /var/lib/frostgate/state/frostgate.db
    - test defaults repo-local (Path.cwd()/fg-test.db)
    - dev defaults STATE_DIR/frostgate.db (STATE_DIR must be referenced)
    """
    if path and str(path).strip():
        return str(Path(path).expanduser())

    env_path = (os.getenv("FG_SQLITE_PATH") or "").strip() or (
        os.getenv("SQLITE_PATH") or ""
    ).strip()
    if env_path:
        return str(Path(env_path).expanduser())

    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    if env in {"production", "prod", "staging"}:
        return "/var/lib/frostgate/state/frostgate.db"

    if env == "test":
        return str(Path.cwd() / "fg-test.db")

    # dev default uses STATE_DIR (tests look for this symbol in-source)
    return str(Path(STATE_DIR) / "frostgate.db")


def _sqlite_url(sqlite_path: str) -> str:
    p = Path(sqlite_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+pysqlite:///{p}"


def _db_url(*, sqlite_path: Optional[str] = None) -> str:
    """
    Resolve SQLAlchemy URL.
    Prefer FG_DB_URL if present; otherwise sqlite path contract.
    """
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if db_url:
        return db_url

    resolved = _resolve_sqlite_path(sqlite_path)
    return _sqlite_url(resolved)


# ---------------------------------------------------------------------
# Engine + sessionmaker cache
# ---------------------------------------------------------------------

_ENGINE: Engine | None = None
_SessionLocal: sessionmaker | None = None


def reset_engine_cache() -> None:
    global _ENGINE, _SessionLocal
    if _ENGINE is not None:
        try:
            _ENGINE.dispose()
        except Exception:
            pass
    _ENGINE = None
    _SessionLocal = None


def get_engine(*, sqlite_path: Optional[str] = None) -> Engine:
    global _ENGINE, _SessionLocal
    if _ENGINE is not None:
        return _ENGINE

    url = _db_url(sqlite_path=sqlite_path)
    _ENGINE = create_engine(url, future=True, pool_pre_ping=True)
    _SessionLocal = sessionmaker(
        bind=_ENGINE, autocommit=False, autoflush=False, future=True
    )

    if url.startswith("sqlite"):
        logger.info("sqlite_db=%s", url.split("///", 1)[-1])
    else:
        logger.info("db_url=%s", url.split("@", 1)[-1] if "@" in url else url)

    return _ENGINE


def get_sessionmaker(*, sqlite_path: Optional[str] = None) -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is not None:
        return _SessionLocal
    get_engine(sqlite_path=sqlite_path)
    assert _SessionLocal is not None
    return _SessionLocal


# ---------------------------------------------------------------------
# Model import + Base resolution (deterministic)
# ---------------------------------------------------------------------


def _ensure_models_imported() -> None:
    """
    Import model module(s) so Base.metadata is populated.
    """
    # This must include ApiKey + DecisionRecord tables.
    importlib.import_module("api.db_models")


def _get_base():
    from api.db_models import Base  # noqa: WPS433 (explicit import by design)

    return Base


# ---------------------------------------------------------------------
# SQLite best-effort migration helpers (tests expect api_keys hash cols)
# ---------------------------------------------------------------------


def _sqlite_add_column_if_missing(conn, table: str, col: str, col_type: str) -> None:
    existing = {r[1] for r in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
    if col not in existing:
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


def _auto_migrate_sqlite(engine: Engine) -> None:
    with engine.begin() as conn:
        tables = {
            r[0]
            for r in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "api_keys" in tables:
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_alg", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_params", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "key_lookup", "TEXT")


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def init_db(*, sqlite_path: Optional[str] = None) -> None:
    engine = get_engine(sqlite_path=sqlite_path)

    _ensure_models_imported()
    Base = _get_base()
    Base.metadata.create_all(bind=engine)

    # best-effort sqlite migrations (keeps tests + mint_key working)
    if engine.dialect.name == "sqlite":
        try:
            _auto_migrate_sqlite(engine)
        except Exception:
            logger.exception("sqlite auto-migration failed (best effort)")

    # Optional sanity check
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        if "api_keys" not in tables:
            logger.warning(
                "Expected table 'api_keys' missing; tables=%s", sorted(tables)
            )
    except Exception:
        pass


@lru_cache(maxsize=1)
def _compiled_sanity_query() -> str:
    return "SELECT 1"


def db_ping(*, sqlite_path: Optional[str] = None) -> None:
    engine = get_engine(sqlite_path=sqlite_path)
    with engine.connect() as conn:
        conn.execute(text(_compiled_sanity_query()))


def get_db_no_request(*, sqlite_path: str | None = None) -> Iterator[Session]:
    """
    Back-compat helper used by tests/tools that need a DB session outside FastAPI.
    """
    SessionLocal = get_sessionmaker(sqlite_path=sqlite_path)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db(*, sqlite_path: str | None = None) -> Iterator[Session]:
    """
    FastAPI-friendly DB generator (no auth/tenant here).
    Prefer api/deps.py for request-bound tenant logic.
    """
    yield from get_db_no_request(sqlite_path=sqlite_path)


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """
    Optional: Postgres-only session context binding via set_config.
    Safe no-op for sqlite.
    """
    bind = getattr(session, "bind", None)
    if bind is None or getattr(bind.dialect, "name", "") != "postgresql":
        return
    if not tenant_id:
        raise RuntimeError("tenant_id required")
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, false)"),
        {"tenant_id": tenant_id},
    )


# ===================== PATCH_FG_API_KEYS_SQLITE_V1 =====================
# This project mints/verifies API keys via sqlite3 in api/auth_scopes.py.
# That means init_db() MUST ensure api_keys exists (and auto-migrate columns)
# in the sqlite file chosen by FG_SQLITE_PATH or passed sqlite_path.
# ======================================================================


def _sqlite_table_exists(con: sqlite3.Connection, name: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _sqlite_cols(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def _sqlite_add_col_if_missing(
    con: sqlite3.Connection, table: str, col: str, decl: str
) -> None:
    cols = _sqlite_cols(con, table)
    if col not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


# ensure api_keys exists + has new columns (sqlite3 path is used by auth_scopes)
def _ensure_api_keys_sqlite(sqlite_path: str) -> None:
    import sqlite3

    con = sqlite3.connect(sqlite_path)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")

        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            ("api_keys",),
        ).fetchone()

        if row is None:
            con.execute(
                """
                CREATE TABLE api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    scopes_csv TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    tenant_id TEXT,
                    created_at INTEGER,
                    last_used_at INTEGER,
                    expires_at INTEGER,
                    hash_alg TEXT,
                    hash_params TEXT,
                    key_lookup TEXT
                )
                """
            )

        cols = {r[1] for r in con.execute("PRAGMA table_info(api_keys)").fetchall()}
        if "hash_alg" not in cols:
            con.execute("ALTER TABLE api_keys ADD COLUMN hash_alg TEXT")
        if "hash_params" not in cols:
            con.execute("ALTER TABLE api_keys ADD COLUMN hash_params TEXT")
        if "key_lookup" not in cols:
            con.execute("ALTER TABLE api_keys ADD COLUMN key_lookup TEXT")

        con.commit()
    finally:
        con.close()


# Call this at end of init_db()
# _ensure_api_keys_sqlite(str(sqlite_path))  # only if sqlite_path is a real path string


# Wrap existing init_db to also ensure api_keys is present (sqlite only).
try:
    _orig_init_db = init_db  # type: ignore[name-defined]
except Exception:
    _orig_init_db = None  # type: ignore[assignment]


def init_db(*, sqlite_path: Optional[str] = None) -> None:  # type: ignore[override]
    # Call original init_db first (SQLAlchemy tables), then enforce api_keys.
    if _orig_init_db is not None:
        _orig_init_db(sqlite_path=sqlite_path)

    # Resolve the sqlite path the same way the rest of api/db.py does.
    try:
        resolved = _resolve_sqlite_path(sqlite_path)  # type: ignore[name-defined]
    except Exception:
        resolved = str(sqlite_path) if sqlite_path else ""

    if resolved:
        _ensure_api_keys_sqlite(resolved)


# =================== END PATCH_FG_API_KEYS_SQLITE_V1 ====================
