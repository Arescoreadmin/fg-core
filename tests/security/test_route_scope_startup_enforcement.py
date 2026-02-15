from __future__ import annotations

from fastapi import Depends, FastAPI

from api.auth_scopes import require_scopes
from api.security.route_scope_enforcement import enforce_api_route_scope_invariant


def test_route_scope_invariant_fails_when_vacuous_in_prod(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    app = FastAPI()

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def health_ready() -> dict[str, str]:
        return {"status": "ready"}

    try:
        enforce_api_route_scope_invariant(app)
    except RuntimeError as exc:
        assert "vacuous" in str(exc)
    else:
        raise AssertionError("Expected vacuous scope invariant failure in prod")


def test_route_scope_invariant_fails_for_missing_scope_dependency(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "staging")
    app = FastAPI()

    @app.get("/sensitive")
    async def sensitive() -> dict[str, bool]:
        return {"ok": True}

    try:
        enforce_api_route_scope_invariant(app)
    except RuntimeError as exc:
        message = str(exc)
        assert "/sensitive" in message
        assert "missing scope dependency" in message
    else:
        raise AssertionError("Expected missing scope dependency failure")


def test_route_scope_invariant_passes_for_scoped_route(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    app = FastAPI()

    @app.get("/sensitive", dependencies=[Depends(require_scopes("stats:read"))])
    async def sensitive() -> dict[str, bool]:
        return {"ok": True}

    enforce_api_route_scope_invariant(app)
