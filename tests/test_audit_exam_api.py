from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from api.admin import get_tenant, require_internal_admin_gateway
from api.audit import ReproduceRequest, audit_reproduce
from api.db import init_db, reset_engine_cache
from api.error_contracts import api_error
from services.audit_engine.engine import InvariantResult


def _bound_request(tenant_id: str) -> object:
    return SimpleNamespace(
        state=SimpleNamespace(
            tenant_id=tenant_id,
            tenant_is_key_bound=True,
            auth=SimpleNamespace(
                key_prefix="test-key-audit-repro",
                scopes={"audit:read"},
            ),
            request_id="test-req-audit-repro-001",
        ),
        app=SimpleNamespace(openapi=lambda: {"openapi": "3.1.0"}),
    )


@pytest.fixture
def isolated_audit_env(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "audit_exam_api.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def test_reproduce_mismatch_returns_non_200(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "pass", "ok")],
    )
    sid = eng.run_cycle("light")
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "fail", "changed")],
    )
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        audit_reproduce(ReproduceRequest(session_id=sid), _bound_request("tenant-a"))
    assert exc.value.status_code == 409


def test_export_chain_failure_returns_non_200(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("soc-invariants", "pass", "ok")]
    )
    _ = eng.run_cycle("light")
    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "different-key-different-key-diff-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-new")
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_PREV", raising=False)
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_ID_PREV", raising=False)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        from api.audit import audit_export
        from types import SimpleNamespace

        class DummyReq:
            state = SimpleNamespace(
                tenant_id="tenant-a",
                tenant_is_key_bound=True,
                auth=SimpleNamespace(
                    key_prefix="test-key-audit-export",
                    scopes={"audit:export"},
                ),
                request_id="test-req-chain-fail-001",
            )
            app = SimpleNamespace(openapi=lambda: {"openapi": "3.1.0"})
            headers: dict = {}
            client = None
            method = "GET"
            url = SimpleNamespace(path="/audit/export")

        audit_export(DummyReq(), "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "AUDIT_CHAIN_BROKEN"


def test_reproduce_missing_session_returns_404(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    eng = AuditEngine()
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        audit_reproduce(
            ReproduceRequest(session_id="00000000-0000-0000-0000-000000000099"),
            _bound_request("tenant-a"),
        )
    assert exc.value.status_code == 404
    assert exc.value.detail["code"] == "AUDIT_RESULT_NOT_FOUND"


def test_reproduce_cross_tenant_returns_403(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "pass", "ok")],
    )
    sid = eng.run_cycle("light", tenant_id="tenant-a")
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        audit_reproduce(ReproduceRequest(session_id=sid), _bound_request("tenant-b"))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "AUDIT_RESULT_CROSS_TENANT_FORBIDDEN"


# ---------------------------------------------------------------------------
# Task 11.1 — explicit actionable error contract tests
# ---------------------------------------------------------------------------


def _admin_request(
    *,
    token: str | None = None,
    scopes: set | None = None,
) -> object:
    """Build a minimal fake Request for admin guard tests."""
    headers: dict[str, str] = {}
    if token is not None:
        headers["x-fg-internal-token"] = token
    return SimpleNamespace(
        headers=headers,
        state=SimpleNamespace(
            request_id="test-req-11-1-001",
            auth=SimpleNamespace(scopes=scopes or set()),
        ),
    )


# --- gateway auth guard ---


def test_admin_gateway_missing_token_returns_403(monkeypatch):
    """No token header → 403 when internal secret is configured."""
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-internal-secret-abcdef")
    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(_admin_request(token=None))
    assert exc.value.status_code == 403


def test_admin_gateway_wrong_token_returns_403(monkeypatch):
    """Wrong token → 403 when internal secret is configured."""
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-internal-secret-abcdef")
    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(_admin_request(token="wrong-token"))
    assert exc.value.status_code == 403


def test_admin_gateway_error_has_structured_detail(monkeypatch):
    """Gateway auth failure must carry a stable structured error code."""
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-internal-secret-abcdef")
    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(_admin_request(token=None))
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail["code"] == "ADMIN_GATEWAY_FORBIDDEN"


def test_admin_gateway_error_has_action_field(monkeypatch):
    """Gateway auth failure detail must include an actionable operator hint."""
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-internal-secret-abcdef")
    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(_admin_request(token=None))
    assert "action" in exc.value.detail
    assert exc.value.detail["action"]  # non-empty


def test_admin_gateway_error_message_no_secrets(monkeypatch):
    """Gateway auth error message must not contain the configured secret value."""
    secret = "test-internal-secret-abcdef"
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", secret)
    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(_admin_request(token="bad"))
    detail = exc.value.detail
    assert secret not in detail.get("message", "")
    assert secret not in detail.get("action", "")


def test_admin_gateway_correct_token_passes(monkeypatch):
    """Correct token must not raise."""
    secret = "test-internal-secret-abcdef"
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", secret)
    # should return None, no exception
    result = require_internal_admin_gateway(_admin_request(token=secret))
    assert result is None


# --- tenant endpoint validation ---


def test_get_tenant_invalid_format_returns_422_structured(monkeypatch):
    """Invalid tenant_id format → 422 with structured error code."""
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "")
    req = _admin_request(scopes={"admin:read"})
    with pytest.raises(HTTPException) as exc:
        import asyncio

        asyncio.run(get_tenant("bad tenant id!", req))
    assert exc.value.status_code == 422
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail["code"] == "TENANT_ID_FORMAT_INVALID"


def test_get_tenant_not_found_returns_404_structured(monkeypatch):
    """Non-existent tenant → 404 with structured error code."""
    req = _admin_request(scopes={"admin:read"})
    fake_registry: dict = {}
    with patch("api.admin.get_tenant.__wrapped__", None, create=True):
        with patch("tools.tenants.registry.load_registry", return_value=fake_registry):
            with pytest.raises(HTTPException) as exc:
                import asyncio

                asyncio.run(get_tenant("tenant-does-not-exist", req))
    assert exc.value.status_code == 404
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail["code"] == "TENANT_NOT_FOUND"


# --- error_contracts unit tests ---


def test_api_error_returns_stable_code():
    """api_error always returns dict with exact code field."""
    d = api_error("MY_CODE", "some message")
    assert d["code"] == "MY_CODE"
    assert d["message"] == "some message"
    assert "action" not in d


def test_api_error_includes_action_when_provided():
    """api_error includes action field only when explicitly given."""
    d = api_error("MY_CODE", "msg", action="do this")
    assert d["action"] == "do this"


def test_api_error_idempotent():
    """Same inputs → same output (deterministic)."""
    a = api_error("CODE", "message", action="hint")
    b = api_error("CODE", "message", action="hint")
    assert a == b
