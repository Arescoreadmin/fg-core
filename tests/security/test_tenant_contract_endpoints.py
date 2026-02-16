from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from api.auth_scopes import bind_tenant_id, mint_key, verify_api_key_detailed
import api.auth_scopes.resolution as tenant_resolution


def _defend_payload(tenant_id: str | None = None) -> dict:
    payload = {
        "event_type": "auth.bruteforce",
        "source": "security-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.10"},
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return payload


@pytest.fixture
def client(build_app, fresh_db: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FG_RL_ENABLED", "0")
    app = build_app(sqlite_path=fresh_db)
    return TestClient(app)


@pytest.mark.parametrize(
    "method,path,scopes,payload",
    [
        ("GET", "/decisions?limit=1", ("decisions:read",), None),
        ("GET", "/feed/live?limit=1", ("feed:read",), None),
        ("GET", "/stats", ("stats:read",), None),
        ("POST", "/defend", ("defend:write",), _defend_payload()),
        ("GET", "/keys", ("keys:admin",), None),
    ],
)
def test_tenant_contract_missing_invalid_and_scoped_success(
    client: TestClient,
    method: str,
    path: str,
    scopes: tuple[str, ...],
    payload: dict | None,
):
    missing = client.request(method, path, json=payload)
    assert missing.status_code == 401

    invalid = client.request(
        method, path, headers={"X-API-Key": "invalid"}, json=payload
    )
    assert invalid.status_code == 401

    key = mint_key(*scopes, tenant_id="tenant-a")
    ok = client.request(method, path, headers={"X-API-Key": key}, json=payload)
    assert 200 <= ok.status_code < 300, (method, path, ok.status_code, ok.text)


@pytest.mark.parametrize(
    "method,path,scopes,payload,expected",
    [
        (
            "GET",
            "/decisions?limit=1&tenant_id=tenant-b",
            ("decisions:read",),
            None,
            403,
        ),
        ("GET", "/feed/live?limit=1&tenant_id=tenant-b", ("feed:read",), None, 403),
        ("GET", "/stats?tenant_id=tenant-b", ("stats:read",), None, 403),
        ("POST", "/defend", ("defend:write",), _defend_payload("tenant-b"), 403),
        ("GET", "/admin/tenants/tenant-b/usage", ("admin:read",), None, 403),
    ],
)
def test_mismatched_tenant_input_surfaces_denied(
    client: TestClient,
    method: str,
    path: str,
    scopes: tuple[str, ...],
    payload: dict | None,
    expected: int,
):
    key = mint_key(*scopes, tenant_id="tenant-a")
    resp = client.request(method, path, headers={"X-API-Key": key}, json=payload)
    assert resp.status_code == expected


@pytest.mark.parametrize(
    "method,path,scopes,payload",
    [
        ("GET", "/decisions?limit=1&tenant_id=tenant-a", ("decisions:read",), None),
        ("GET", "/feed/live?limit=1&tenant_id=tenant-a", ("feed:read",), None),
        ("GET", "/stats?tenant_id=tenant-a", ("stats:read",), None),
        ("POST", "/defend", ("defend:write",), _defend_payload("tenant-a")),
        ("GET", "/admin/tenants/tenant-a/usage", ("admin:read",), None),
    ],
)
def test_unscoped_key_with_explicit_tenant_denied_400(
    client: TestClient,
    method: str,
    path: str,
    scopes: tuple[str, ...],
    payload: dict | None,
):
    key = mint_key(*scopes)
    resp = client.request(method, path, headers={"X-API-Key": key}, json=payload)
    assert resp.status_code == 400


def test_header_tenant_mismatch_surface_denied(client: TestClient):
    key = mint_key("decisions:read", tenant_id="tenant-a")
    resp = client.get(
        "/decisions?limit=1",
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-b"},
    )
    assert resp.status_code == 403


def test_prod_redaction_preserves_status_code(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    key = mint_key("decisions:read", tenant_id="tenant-a")

    dev = client.get(
        "/decisions?tenant_id=tenant-b&limit=1",
        headers={"X-API-Key": key},
    )
    assert dev.status_code == 403

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_DB_URL", "postgresql://local/test")
    monkeypatch.setenv("FG_AUTH_DB_FAIL_OPEN", "0")
    prod = client.get(
        "/decisions?tenant_id=tenant-b&limit=1",
        headers={"X-API-Key": key},
    )
    assert prod.status_code == 403
    assert prod.json().get("detail") in {"forbidden", "invalid request"}
    assert "tenant" not in str(prod.json().get("detail", "")).lower()


def test_tenant_denial_logs_allowlisted_fields(
    client: TestClient, caplog: pytest.LogCaptureFixture
):
    caplog.set_level("WARNING", logger="frostgate.security")
    key = mint_key("decisions:read", tenant_id="tenant-a")

    resp = client.get(
        "/decisions?tenant_id=tenant-b&limit=1",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 403

    records = [r for r in caplog.records if r.msg == "tenant_denial"]
    assert records
    record = records[-1]

    for field in (
        "event",
        "reason",
        "env",
        "route",
        "method",
        "request_id",
        "remote_ip",
        "tenant_id_hash",
        "key_id",
    ):
        assert hasattr(record, field), field

    assert not hasattr(record, "tenant_supplied")
    assert not hasattr(record, "tenant_from_key")


def test_tenant_resolution_called_once_per_request_with_cache(
    monkeypatch: pytest.MonkeyPatch,
):
    app = FastAPI()

    @app.middleware("http")
    async def auth_mw(request: Request, call_next):
        key = request.headers.get("X-API-Key")
        result = verify_api_key_detailed(raw=key, request=request)
        if not result.valid:
            return JSONResponse(
                status_code=401, content={"detail": "Invalid or missing API key"}
            )
        request.state.auth = result
        return await call_next(request)

    def dep_a(request: Request) -> str:
        return bind_tenant_id(request, request.query_params.get("tenant_id"))

    def dep_b(request: Request) -> str:
        return bind_tenant_id(request, request.query_params.get("tenant_id"))

    @app.get("/cache-check")
    def cache_check(
        request: Request,
        _a: str = Depends(dep_a),
        _b: str = Depends(dep_b),
    ) -> dict[str, str]:
        return {
            "tenant": bind_tenant_id(request, request.query_params.get("tenant_id"))
        }

    calls = {"count": 0}
    original = tenant_resolution._auth_tenant_from_request

    def wrapped(request: Request):
        calls["count"] += 1
        return original(request)

    monkeypatch.setattr(tenant_resolution, "_auth_tenant_from_request", wrapped)

    key = mint_key("decisions:read", tenant_id="tenant-a")
    with TestClient(app) as tc:
        resp = tc.get("/cache-check", headers={"X-API-Key": key})

    assert resp.status_code == 200
    assert resp.json()["tenant"] == "tenant-a"
    assert calls["count"] == 1


def test_proxy_headers_ignored_by_default_for_denial_logs(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("FG_TRUST_PROXY_HEADERS", raising=False)
    caplog.set_level("WARNING", logger="frostgate.security")

    key = mint_key("decisions:read", tenant_id="tenant-a")
    resp = client.get(
        "/decisions?tenant_id=tenant-b&limit=1",
        headers={"X-API-Key": key, "X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status_code == 403

    records = [r for r in caplog.records if r.msg == "tenant_denial"]
    assert records
    record = records[-1]
    # With default trust disabled, spoofed header must not be used.
    assert record.remote_ip != "203.0.113.9"


def test_proxy_headers_honored_when_explicitly_enabled(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FG_TRUST_PROXY_HEADERS", "1")
    caplog.set_level("WARNING", logger="frostgate.security")

    key = mint_key("decisions:read", tenant_id="tenant-a")
    resp = client.get(
        "/decisions?tenant_id=tenant-b&limit=1",
        headers={"X-API-Key": key, "X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status_code == 403

    records = [r for r in caplog.records if r.msg == "tenant_denial"]
    assert records
    record = records[-1]
    assert record.remote_ip == "203.0.113.11"
