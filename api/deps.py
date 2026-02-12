from __future__ import annotations

from collections.abc import Iterator

from fastapi import HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id
from api.db import get_sessionmaker, set_tenant_context


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
      - unscoped keys require explicit tenant_id (400 if missing)
      - unknown/invalid tenant_id -> 400
      - scoped key mismatch -> 403
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


# Back-compat alias some modules import.
# DO NOT use *args/**kwargs here, FastAPI will treat them as query params => 422.
def tenant_db(
    request: Request,
    tenant_id: str | None = Query(None),
) -> Iterator[Session]:
    yield from tenant_db_required(request=request, tenant_id=tenant_id)


__all__ = ["get_db", "tenant_db_required", "tenant_db"]
