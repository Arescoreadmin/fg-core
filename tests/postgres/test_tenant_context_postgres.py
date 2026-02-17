from __future__ import annotations

from starlette.requests import Request
from sqlalchemy import text
from sqlalchemy.orm import Session

import api.auth_scopes.resolution as resolution
from api.auth_scopes import bind_tenant_id


def test_bind_tenant_sets_db_session_context(pg_engine, monkeypatch) -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "scheme": "http",
        "path": "/tests/postgres/tenant-context",
        "raw_path": b"/tests/postgres/tenant-context",
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    request = Request(scope)

    # Force auth tenant resolution so bind_tenant_id applies DB context.
    monkeypatch.setattr(
        resolution, "_auth_tenant_from_request", lambda _req: "tenant-context"
    )

    with Session(pg_engine) as session:
        request.state.db_session = session

        bound = bind_tenant_id(
            request,
            "tenant-context",
            require_explicit_for_unscoped=True,
        )
        assert bound == "tenant-context"

        current = session.execute(
            text("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
        ).scalar_one()
        assert current == "tenant-context"
