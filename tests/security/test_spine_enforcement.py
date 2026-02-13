from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient

from api.auth_scopes import AuthResult, mint_key
from api.config.startup_validation import validate_startup_config
from api.middleware.auth_gate import AuthGateConfig, AuthGateMiddleware


def _build_test_app() -> FastAPI:
    app = FastAPI()
    router = APIRouter()

    @router.get("/new-route")
    async def new_route() -> dict[str, bool]:
        return {"ok": True}

    @router.get("/state")
    async def state_endpoint(request: Request) -> dict[str, bool]:
        return {
            "has_auth": hasattr(request.state, "auth"),
            "has_tenant": hasattr(request.state, "tenant_id"),
        }

    app.include_router(router)
    app.add_middleware(
        AuthGateMiddleware,
        require_status_auth=lambda _: None,
        config=AuthGateConfig(),
    )
    return app


def test_new_route_without_require_scopes_is_denied(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "test")
    app = _build_test_app()
    client = TestClient(app)

    response = client.get("/new-route")
    assert response.status_code == 401


def test_public_paths_still_public(build_app) -> None:
    app = build_app()
    client = TestClient(app, raise_server_exceptions=False)

    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code in {200, 503}
    assert client.get("/openapi.json").status_code != 401


def test_auth_context_stamped_only_when_authenticated(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "test")
    app = _build_test_app()
    client = TestClient(app)

    failed = client.get("/state")
    assert failed.status_code == 401

    monkeypatch.setattr(
        "api.middleware.auth_gate.verify_api_key_detailed",
        lambda **_: AuthResult(
            valid=True,
            reason="valid",
            tenant_id="tenant-a",
            scopes={"authenticated"},
        ),
    )
    success = client.get("/state", headers={"X-API-Key": "valid"})
    assert success.status_code == 200
    assert success.json() == {"has_auth": True, "has_tenant": True}


def test_missing_scope_claim_denied(build_app) -> None:
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-a"
    key_no_scope = mint_key(ttl_seconds=3600, tenant_id=tenant_id)

    response = client.get(
        "/stats/summary",
        headers={"X-API-Key": key_no_scope},
        params={"tenant_id": tenant_id},
    )
    assert response.status_code == 403


def test_scope_insufficient_denied(build_app) -> None:
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-a"
    wrong_scope = mint_key("feed:read", ttl_seconds=3600, tenant_id=tenant_id)

    response = client.get(
        "/stats/summary",
        headers={"X-API-Key": wrong_scope},
        params={"tenant_id": tenant_id},
    )
    assert response.status_code == 403


def test_prod_rejects_fail_open_flags(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_AUTH_DB_FAIL_OPEN", "true")
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.setenv("FG_DB_URL", "postgresql://user:pass@localhost:5432/fg")
    monkeypatch.delenv("FG_API_KEY", raising=False)

    try:
        validate_startup_config(fail_on_error=True, log_results=False)
    except RuntimeError:
        return
    raise AssertionError("Expected RuntimeError for prod fail-open flags")


def test_prod_requires_postgres_db_url(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.delenv("FG_DB_URL", raising=False)
    monkeypatch.delenv("FG_API_KEY", raising=False)
    monkeypatch.setenv("FG_AUTH_DB_FAIL_OPEN", "false")

    try:
        validate_startup_config(fail_on_error=True, log_results=False)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Expected RuntimeError when FG_DB_URL is missing")

    monkeypatch.setenv("FG_DB_URL", "sqlite:///tmp/test.db")
    try:
        validate_startup_config(fail_on_error=True, log_results=False)
    except RuntimeError:
        return
    raise AssertionError("Expected RuntimeError for sqlite FG_DB_URL in prod")
