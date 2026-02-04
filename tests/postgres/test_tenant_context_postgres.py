from __future__ import annotations

from starlette.requests import Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id


def test_bind_tenant_sets_db_session_context(pg_engine) -> None:
    scope = {"type": "http", "headers": []}
    request = Request(scope)
    with Session(pg_engine) as session:
        request.state.db_session = session
        bound = bind_tenant_id(
            request,
            "tenant-context",
            require_explicit_for_unscoped=True,
        )
        assert bound == "tenant-context"
        current = session.execute(
            text("SELECT current_setting('app.tenant_id', true)")
        ).scalar_one()
        assert current == "tenant-context"
