from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()

def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def append_if_missing(path: Path, marker: str, block: str) -> None:
    s = path.read_text(encoding="utf-8")
    if marker in s:
        return
    s = s.rstrip() + "\n\n" + block.strip() + "\n"
    path.write_text(s, encoding="utf-8")

def patch_evidence_chain(path: Path) -> None:
    s = path.read_text(encoding="utf-8")

    # Replace _latest_chain_hash_for_tenant with a safer version:
    # - ignore rows without chain_hash
    # - avoid autoflush surprises
    pat = re.compile(r"def _latest_chain_hash_for_tenant\([\s\S]*?\n\)\s*->\s*Optional\[str\]:\n[\s\S]*?\n\n", re.M)
    repl = """def _latest_chain_hash_for_tenant(
    db: Session, tenant_id: Optional[str]
) -> Optional[str]:
    # Important:
    # - Filter out rows missing chain_hash (seed/partial rows should not advance chain)
    # - Disable autoflush so pending objects in this session cannot affect "latest"
    with db.no_autoflush:
        row = (
            db.query(DecisionRecord)
            .filter(
                DecisionRecord.tenant_id == tenant_id,
                DecisionRecord.chain_hash.isnot(None),
            )
            .order_by(DecisionRecord.created_at.desc(), DecisionRecord.id.desc())
            .first()
        )
    return getattr(row, "chain_hash", None) if row is not None else None

"""
    if pat.search(s):
        s = pat.sub(repl, s, count=1)
    else:
        # If function isn't found, just append a correct one (last definition wins).
        s = s.rstrip() + "\n\n" + repl

    path.write_text(s, encoding="utf-8")

def main() -> None:
    # --- 1) deps.py (kill args/kwargs 422; provide explicit tenant_db wrapper) ---
    deps = ROOT / "api" / "deps.py"
    write(
        deps,
        """from __future__ import annotations

from collections.abc import Iterator

from fastapi import HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id
from api.db import get_sessionmaker


def get_db() -> Iterator[Session]:
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def tenant_db_required(
    request: Request,
    tenant_id: str | None = Query(None),
) -> Iterator[Session]:
    \"""
    Tenant-bound DB session dependency.

    Contract enforced by bind_tenant_id():
      - unscoped keys require explicit tenant_id (400 if missing)
      - unknown/invalid tenant_id -> 400
      - scoped key mismatch -> 403
    \"""
    bound = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if not bound:
        # bind_tenant_id should raise, but fail closed anyway.
        raise HTTPException(status_code=401, detail="Missing auth context")

    request.state.tenant_id = bound

    SessionLocal = get_sessionmaker()
    db = SessionLocal()

    # Some flows (tenant context binding) rely on this hook existing.
    request.state.db_session = db

    try:
        yield db
    finally:
        db.close()


# Back-compat alias some modules import.
# DO NOT use *args/**kwargs here, FastAPI will treat them as query params => 422.
def tenant_db(
    request: Request,
    tenant_id: str | None = Query(None),
) -> Iterator[Session]:
    yield from tenant_db_required(request=request, tenant_id=tenant_id)


__all__ = ["get_db", "tenant_db_required", "tenant_db"]
""",
    )

    # --- 2) db.py (ensure init_db creates api_keys and sqlite adds hash columns) ---
    dbpy = ROOT / "api" / "db.py"
    marker = "### PATCH_FG_CORE_DB_INIT_V1 ###"
    patch_block = f"""
### PATCH_FG_CORE_DB_INIT_V1 ###
# This block is appended (not replacing your file) so it wins with last-definition-wins.
# Goal: fix init_db() so tests create api_keys + required hash columns on sqlite.

from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

# Tests require this literal token to appear in api/db.py
from api.config.paths import STATE_DIR  # noqa: F401


_ENGINE: Optional[Engine] = None


def reset_engine_cache() -> None:
    global _ENGINE
    _ENGINE = None


def _resolve_sqlite_path(path: str | None = None) -> str:
    # explicit arg wins
    if path and str(path).strip():
        return str(Path(path).expanduser())

    env_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if env_path:
        return str(Path(env_path).expanduser())

    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    if env in {{"production", "prod", "staging"}}:
        return "/var/lib/frostgate/state/frostgate.db"

    if env == "test":
        return str(Path.cwd() / "fg-test.db")

    # dev default uses STATE_DIR (contract expects reference)
    return str(Path(STATE_DIR) / "frostgate.db")


def _db_url(sqlite_path: str | None = None) -> str:
    p = _resolve_sqlite_path(sqlite_path)
    return f"sqlite:///{p}"


def _get_base():
    # Deterministic. Stop roulette.
    from api.db_models import Base  # noqa: WPS433

    return Base


def _ensure_models_imported() -> None:
    # Ensure metadata includes api_keys and everything else
    import api.db_models  # noqa: F401


def get_engine(sqlite_path: str | None = None) -> Engine:
    global _ENGINE
    if _ENGINE is None:
        url = _db_url(sqlite_path)
        _ENGINE = create_engine(url, future=True)
    return _ENGINE


def get_sessionmaker(sqlite_path: str | None = None):
    engine = get_engine(sqlite_path)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _sqlite_add_column_if_missing(conn, table: str, col: str, col_type: str) -> None:
    existing = {{r[1] for r in conn.exec_driver_sql(f"PRAGMA table_info({{table}})")}}
    if col not in existing:
        conn.exec_driver_sql(f"ALTER TABLE {{table}} ADD COLUMN {{col}} {{col_type}}")


def _auto_migrate_sqlite(engine: Engine) -> None:
    with engine.begin() as conn:
        tables = {{r[0] for r in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'")}}
        if "api_keys" in tables:
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_alg", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_params", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "key_lookup", "TEXT")


def init_db(*, sqlite_path: str | None = None) -> None:
    engine = get_engine(sqlite_path)
    _ensure_models_imported()
    Base = _get_base()
    Base.metadata.create_all(bind=engine)

    if engine.dialect.name == "sqlite":
        _auto_migrate_sqlite(engine)
"""
    append_if_missing(dbpy, marker, patch_block)

    # --- 3) evidence_chain.py (GENESIS prev_hash fix) ---
    ev = ROOT / "api" / "evidence_chain.py"
    patch_evidence_chain(ev)

    print("Patched: api/deps.py, api/db.py (init_db patch appended), api/evidence_chain.py")

if __name__ == "__main__":
    main()
