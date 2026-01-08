# api/db.py
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.config.paths import STATE_DIR  # tests want this symbol referenced
from api.db_models import Base

log = logging.getLogger("frostgate")

# Engine cache keyed by db_url to avoid "env drift" across tests.
_ENGINE_BY_URL: dict[str, Engine] = {}
_SESSIONMAKER_BY_URL: dict[str, sessionmaker] = {}


def reset_engine_cache() -> None:
    """
    Test helper: clear cached engines/sessionmakers so env/sqlite_path changes take effect.
    """
    _ENGINE_BY_URL.clear()
    _SESSIONMAKER_BY_URL.clear()

# DB PATH CONTRACT (DO NOT “OPTIMIZE”):
# - FG_SQLITE_PATH wins always (absolute or relative)
# - prod/prodution default: /var/lib/frostgate/state/frostgate.db (container-only)
# - non-prod default: <repo>/state/frostgate.db
# - FAIL FAST in FG_ENV=test if resolved path is /var/lib/...

def _resolve_sqlite_path() -> Path:
    """
    Canonical sqlite contract (hard, explicit, no drift):

      - If FG_SQLITE_PATH is set -> use it (absolute or relative)
      - If FG_ENV is prod/production -> container-only default:
            /var/lib/frostgate/state/frostgate.db
      - Else (dev/test) -> repo-local default:
            ./state/frostgate.db

    Notes:
      - This intentionally prevents host/dev/test from silently writing into /var/lib/...
      - Tests can still override deterministically via FG_SQLITE_PATH.
    """
    v = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if v:
        return Path(v)

    env = (os.getenv("FG_ENV") or "").strip().lower()
    if env in {"prod", "production"}:
        return Path("/var/lib/frostgate/state/frostgate.db")

    return Path.cwd() / "state" / "frostgate.db"


def _sqlite_url_from_path(p: Path) -> str:
    p = p.expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    # SQLAlchemy sqlite URL wants 3 slashes for absolute paths; for relative, it still works.
    return f"sqlite+pysqlite:///{p.as_posix()}"


def _db_url(sqlite_path: Optional[str] = None) -> str:
    """
    If FG_DB_URL is set, trust it (postgres etc).
    Otherwise build sqlite URL from canonical sqlite path contract.
    sqlite_path (arg) overrides FG_SQLITE_PATH/FG_STATE_DIR/FG_ENV defaults.
    """
    url = (os.getenv("FG_DB_URL") or "").strip()
    if url:
        return url

    if sqlite_path:
        return _sqlite_url_from_path(Path(sqlite_path))

    return _sqlite_url_from_path(_resolve_sqlite_path())


def _sqlite_ensure_decisions_columns(engine: Engine) -> None:
    """
    SQLite does not auto-migrate schemas. We do a minimal, safe ALTER for new MVP columns.
    Never blocks startup if anything goes wrong (logs at debug).
    """
    try:
        with engine.begin() as conn:
            cols = conn.exec_driver_sql("PRAGMA table_info(decisions)").fetchall()
            if not cols:
                return

            names = {row[1] for row in cols}  # (cid, name, type, notnull, dflt_value, pk)

            # SQLite doesn't have a real JSON type; TEXT is fine for MVP.
            if "decision_diff_json" not in names:
                conn.exec_driver_sql("ALTER TABLE decisions ADD COLUMN decision_diff_json TEXT")
    except Exception as e:
        log.debug("sqlite micro-migration skipped/failed: %s", e)


def get_engine(*, sqlite_path: Optional[str] = None, db_url: Optional[str] = None) -> Engine:
    """
    Returns a cached Engine keyed by effective DB URL, so tests can run isolated DBs.
    Priority:
      - db_url arg
      - sqlite_path arg (only if FG_DB_URL not set)
      - env/config defaults
    """
    url = (db_url or "").strip() or _db_url(sqlite_path=sqlite_path)

    eng = _ENGINE_BY_URL.get(url)
    if eng is None:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        eng = create_engine(
            url,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        _ENGINE_BY_URL[url] = eng

        # Build & cache the matching sessionmaker
        _SESSIONMAKER_BY_URL[url] = sessionmaker(autocommit=False, autoflush=False, bind=eng)

        log.warning("DB_ENGINE=%s", url)

        # Anti-drift guard: non-prod should never resolve to /var/lib/... (container-only)
        try:
            env = (os.getenv("FG_ENV") or "").strip().lower()
            pth = _resolve_sqlite_path().expanduser().as_posix()
            if env not in {"prod", "production"} and pth.startswith("/var/lib/"):
                if env == "test":
                    raise RuntimeError(f"DB path drift in test: resolved to /var/lib/... ({pth}). Set FG_SQLITE_PATH.")
            log.warning("DB path drift: non-prod resolved to /var/lib/... (%s). Set FG_SQLITE_PATH or fix env.", pth)
        except Exception:
            # Never block startup on a guard
            pass

        if url.startswith("sqlite"):
            sp = Path(sqlite_path) if sqlite_path else _resolve_sqlite_path()
            log.warning("SQLITE_PATH=%s", sp.expanduser().as_posix())

    return eng


def get_sessionmaker(*, sqlite_path: Optional[str] = None, db_url: Optional[str] = None) -> sessionmaker:
    """
    Preferred way for internal callers/tests to grab the configured sessionmaker.
    Mirrors get_engine() selection so you don't get an engine/session mismatch.
    """
    url = (db_url or "").strip() or _db_url(sqlite_path=sqlite_path)
    sm = _SESSIONMAKER_BY_URL.get(url)
    if sm is None:
        # This will also populate _SESSIONMAKER_BY_URL[url]
        get_engine(sqlite_path=sqlite_path, db_url=db_url)
        sm = _SESSIONMAKER_BY_URL[url]
    return sm


def init_db(sqlite_path: Optional[str] = None) -> None:
    """
    Initialize DB schema.
    If sqlite_path is provided, it overrides default sqlite path selection.
    Backwards compatible: if sqlite_path is None, we fall back to env/defaults.
    """
    engine = get_engine(sqlite_path=sqlite_path)

    # Ensure schema (idempotent)
    Base.metadata.create_all(bind=engine)

    # SQLite micro-migration
    if str(engine.url).startswith("sqlite"):
        _sqlite_ensure_decisions_columns(engine)


def get_db() -> Generator[Session, None, None]:
    # Use default env-based sessionmaker for app runtime.
    db: Session = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()


# Backwards-compat symbol if anything imports it, but DO NOT rely on it at import time.
# It's intentionally None until get_engine/get_sessionmaker is called.
SessionLocal = None
