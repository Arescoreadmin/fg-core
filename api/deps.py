from __future__ import annotations

from collections.abc import Iterator
import os

from fastapi import HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id
from api.db import get_sessionmaker, set_tenant_context


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _allow_sqlite_override() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env == "test" or _env_bool("FG_ALLOW_SQLITE_PATH_OVERRIDE", False)


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
    """
    Tenant-bound DB session dependency.

    Contract enforced by bind_tenant_id():
      - tenant is always derived from key binding
      - supplied tenant_id is optional but must match key tenant (403 on mismatch)
      - unbound keys are denied (400 fail-closed)
    """
    bound = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if not bound:
        # bind_tenant_id should raise, but fail closed anyway.
        raise HTTPException(status_code=401, detail="Missing auth context")

    request.state.tenant_id = bound

    SessionLocal = get_sessionmaker()
    db = SessionLocal()

    # Some flows (tenant context binding) rely on this hook existing.
    request.state.db_session = db
    set_tenant_context(db, bound)

    try:
        yield db
    finally:
        db.close()


def tenant_db_session(
    request: Request,
    sqlite_path: str | None = Query(None),
) -> Iterator[Session]:
    """
    Tenant-aware DB session for routes that resolve tenant after payload/header parsing.

    If auth middleware already resolved a tenant, bind DB context immediately.
    Route handlers MUST bind context after resolving explicit tenant input.
    """
    resolved_sqlite_path = sqlite_path if _allow_sqlite_override() else None
    SessionLocal = get_sessionmaker(sqlite_path=resolved_sqlite_path)
    db = SessionLocal()

    auth_ctx = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth_ctx, "tenant_id", None
    )
    if tenant_id:
        set_tenant_context(db, tenant_id)

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


__all__ = ["get_db", "tenant_db_required", "tenant_db", "tenant_db_session"]
