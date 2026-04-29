"""
Provider BAA Enforcement Tests.

Covers:
  Positive:  active BAA allows regulated provider routing
             non-regulated provider passes without BAA
  Negative:  missing, expired, revoked, pending, unknown-status BAA blocks routing
             BAA for wrong tenant is invisible (missing)
             DB lookup failure blocks routing (fail-closed)
  Regression: blank tenant_id raises ValueError
              no quota charged before BAA denial
              audit event emitted for every allow and deny
              denied audit payload has no secrets / PHI / expiry_date / contract text
              enforcement is present in the /ui/ai/chat routing path
"""

from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from services.provider_baa.policy import (
    _REGULATED_PROVIDERS,
    _REASON_ACTIVE,
    _REASON_EXPIRED,
    _REASON_LOOKUP_FAILED,
    _REASON_MISSING,
    _REASON_NOT_REQUIRED,
    _REASON_PENDING,
    _REASON_REVOKED,
    _REASON_STATUS_UNKNOWN,
    check_provider_baa,
    enforce_provider_baa_for_route,
    requires_baa,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_REGULATED = next(iter(_REGULATED_PROVIDERS))  # any regulated provider for tests


def _db(tmp_path: Path) -> Session:
    db_path = str(tmp_path / "baa-test.db")
    os.environ["FG_SQLITE_PATH"] = db_path
    os.environ["FG_ENV"] = "test"
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker()()


def _insert_baa(
    db: Session,
    *,
    tenant_id: str,
    provider_id: str,
    baa_status: str,
    expiry_date: str | None = None,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO provider_baa_records
                (tenant_id, provider_id, baa_status, expiry_date, created_at, updated_at)
            VALUES (:tenant_id, :provider_id, :baa_status, :expiry_date,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, provider_id) DO UPDATE
                SET baa_status  = excluded.baa_status,
                    expiry_date = excluded.expiry_date,
                    updated_at  = CURRENT_TIMESTAMP
            """
        ),
        {
            "tenant_id": tenant_id,
            "provider_id": provider_id,
            "baa_status": baa_status,
            "expiry_date": expiry_date,
        },
    )
    db.commit()


# ---------------------------------------------------------------------------
# Section 1: requires_baa()
# ---------------------------------------------------------------------------


def test_simulated_is_not_regulated() -> None:
    assert requires_baa("simulated") is False


def test_regulated_providers_require_baa() -> None:
    for p in _REGULATED_PROVIDERS:
        assert requires_baa(p) is True, f"{p} should require BAA"


def test_unknown_provider_not_regulated() -> None:
    assert requires_baa("completely-unknown-xyz") is False


# ---------------------------------------------------------------------------
# Section 2: check_provider_baa() — non-regulated provider
# ---------------------------------------------------------------------------


def test_non_regulated_allowed_without_db(tmp_path: Path) -> None:
    db = _db(tmp_path)
    result = check_provider_baa(db, tenant_id="tenant-a", provider_id="simulated")
    assert result.allowed is True
    assert result.reason_code == _REASON_NOT_REQUIRED
    assert result.baa_status == "not_applicable"
    assert result.expiry_date is None


# ---------------------------------------------------------------------------
# Section 3: check_provider_baa() — regulated provider, positive
# ---------------------------------------------------------------------------


def test_active_baa_no_expiry_allows(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="active")
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is True
    assert result.reason_code == _REASON_ACTIVE
    assert result.baa_status == "active"


def test_active_baa_future_expiry_allows(tmp_path: Path) -> None:
    db = _db(tmp_path)
    future = (date.today() + timedelta(days=365)).isoformat()
    _insert_baa(
        db,
        tenant_id="t1",
        provider_id=_REGULATED,
        baa_status="active",
        expiry_date=future,
    )
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is True
    assert result.expiry_date == future


# ---------------------------------------------------------------------------
# Section 4: check_provider_baa() — regulated provider, negative
# ---------------------------------------------------------------------------


def test_missing_baa_record_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    result = check_provider_baa(db, tenant_id="tenant-no-baa", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_MISSING
    assert result.baa_status == "missing"


def test_expired_status_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="expired")
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_EXPIRED


def test_revoked_status_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="revoked")
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_REVOKED


def test_pending_status_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="pending")
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_PENDING


def test_active_baa_past_expiry_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    past = (date.today() - timedelta(days=1)).isoformat()
    _insert_baa(
        db,
        tenant_id="t1",
        provider_id=_REGULATED,
        baa_status="active",
        expiry_date=past,
    )
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_EXPIRED


def test_unknown_baa_status_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # Write malformed status directly — bypasses Python-level validation
    db.execute(
        text(
            "INSERT INTO provider_baa_records "
            "(tenant_id, provider_id, baa_status, created_at, updated_at) "
            "VALUES (:t, :p, 'INVALID_STATUS_XYZ', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {"t": "t1", "p": _REGULATED},
    )
    db.commit()
    result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_STATUS_UNKNOWN


def test_wrong_tenant_baa_invisible(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # tenant-b has an active BAA; tenant-a must not benefit from it
    _insert_baa(db, tenant_id="tenant-b", provider_id=_REGULATED, baa_status="active")
    result = check_provider_baa(db, tenant_id="tenant-a", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_MISSING


def test_db_lookup_failure_blocks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # Simulate DB backend failure by patching the internal lookup helper
    with patch(
        "services.provider_baa.policy._lookup_baa_record",
        side_effect=RuntimeError("db down"),
    ):
        result = check_provider_baa(db, tenant_id="t1", provider_id=_REGULATED)
    assert result.allowed is False
    assert result.reason_code == _REASON_LOOKUP_FAILED


# ---------------------------------------------------------------------------
# Section 5: check_provider_baa() — input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "  ", None])
def test_blank_tenant_id_raises(tmp_path: Path, bad_tenant: Any) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="tenant_id"):
        check_provider_baa(db, tenant_id=bad_tenant, provider_id=_REGULATED)


@pytest.mark.parametrize("bad_provider", ["", "  ", None])
def test_blank_provider_id_raises(tmp_path: Path, bad_provider: Any) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="provider_id"):
        check_provider_baa(db, tenant_id="t1", provider_id=bad_provider)


# ---------------------------------------------------------------------------
# Section 6: enforce_provider_baa_for_route()
# ---------------------------------------------------------------------------


def test_enforce_raises_403_on_missing_baa(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(HTTPException) as exc_info:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    assert exc_info.value.status_code == 403
    detail: Any = exc_info.value.detail
    assert detail["error_code"] == _REASON_MISSING
    assert detail["provider_id"] == _REGULATED
    # Ensure no internal-only fields in the user-facing detail
    assert "expiry_date" not in detail
    assert "document_ref" not in detail


def test_enforce_does_not_raise_for_active_baa(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="active")
    # Must not raise
    enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)


def test_enforce_does_not_raise_for_non_regulated(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # No BAA record needed for non-regulated
    enforce_provider_baa_for_route(db, tenant_id="t1", provider_id="simulated")


def test_enforce_403_on_revoked(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="revoked")
    with pytest.raises(HTTPException) as exc_info:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    assert exc_info.value.detail["error_code"] == _REASON_REVOKED  # type: ignore[index]


def test_enforce_403_on_pending(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="pending")
    with pytest.raises(HTTPException) as exc_info:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    assert exc_info.value.detail["error_code"] == _REASON_PENDING  # type: ignore[index]


def test_enforce_403_on_expired(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="expired")
    with pytest.raises(HTTPException) as exc_info:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    assert exc_info.value.detail["error_code"] == _REASON_EXPIRED  # type: ignore[index]


def test_enforce_403_on_lookup_failure(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with patch(
        "services.provider_baa.policy._lookup_baa_record",
        side_effect=OSError("db gone"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["error_code"] == _REASON_LOOKUP_FAILED  # type: ignore[index]


# ---------------------------------------------------------------------------
# Section 7: Audit events
# ---------------------------------------------------------------------------


def test_audit_event_emitted_on_allow(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _insert_baa(db, tenant_id="t1", provider_id=_REGULATED, baa_status="active")

    from api.security_audit import EventType

    with patch("services.provider_baa.policy.get_auditor") as mock_get:
        mock_auditor = MagicMock()
        mock_get.return_value = mock_auditor
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
        assert mock_auditor.log_event.called
        event = mock_auditor.log_event.call_args[0][0]
        assert event.event_type == EventType.PROVIDER_BAA_ALLOWED
        assert event.success is True
        assert event.tenant_id == "t1"


def test_audit_event_emitted_on_deny(tmp_path: Path) -> None:
    db = _db(tmp_path)
    from api.security_audit import EventType

    with patch("services.provider_baa.policy.get_auditor") as mock_get:
        mock_auditor = MagicMock()
        mock_get.return_value = mock_auditor
        with pytest.raises(HTTPException):
            enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
        assert mock_auditor.log_event.called
        event = mock_auditor.log_event.call_args[0][0]
        assert event.event_type == EventType.PROVIDER_BAA_DENIED
        assert event.success is False


def test_denied_audit_payload_has_no_secrets_or_phi(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # Insert a record with a document_ref that looks like a secret
    db.execute(
        text(
            "INSERT INTO provider_baa_records "
            "(tenant_id, provider_id, baa_status, document_ref, created_at, updated_at) "
            "VALUES ('t1', :p, 'revoked', 'SECRET_CONTRACT_REF_DO_NOT_LEAK', "
            "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {"p": _REGULATED},
    )
    db.commit()

    with patch("services.provider_baa.policy.get_auditor") as mock_get:
        mock_auditor = MagicMock()
        mock_get.return_value = mock_auditor
        with pytest.raises(HTTPException):
            enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)

        event = mock_auditor.log_event.call_args[0][0]
        payload_str = str(event.details)
        # expiry_date, document_ref, and raw contract text must not appear in details
        assert "SECRET_CONTRACT_REF" not in payload_str
        assert "document_ref" not in payload_str
        assert "expiry_date" not in event.details


def test_denied_http_detail_has_no_expiry_or_contract(tmp_path: Path) -> None:
    db = _db(tmp_path)
    past = (date.today() - timedelta(days=10)).isoformat()
    _insert_baa(
        db,
        tenant_id="t1",
        provider_id=_REGULATED,
        baa_status="active",
        expiry_date=past,
    )
    with pytest.raises(HTTPException) as exc_info:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
    detail = exc_info.value.detail
    assert "expiry_date" not in detail
    assert "document_ref" not in detail


# ---------------------------------------------------------------------------
# Section 8: No fallback after denial
# ---------------------------------------------------------------------------


def test_no_fallback_after_baa_denial(tmp_path: Path) -> None:
    """enforce_provider_baa_for_route raises immediately; caller has no second chance."""
    db = _db(tmp_path)
    call_count = 0

    def _fake_dispatch() -> str:
        nonlocal call_count
        call_count += 1
        return "response"

    try:
        enforce_provider_baa_for_route(db, tenant_id="t1", provider_id=_REGULATED)
        _fake_dispatch()  # must never reach here
    except HTTPException:
        pass

    assert call_count == 0, "dispatch must not be called after BAA denial"


# ---------------------------------------------------------------------------
# Section 9: Routing integration — enforcement is present in /ui/ai/chat path
# ---------------------------------------------------------------------------


def test_baa_enforcement_is_called_in_chat_route(build_app, monkeypatch, tmp_path):
    """
    Verify that enforce_provider_baa_for_route is wired into the chat routing
    path. We inject a regulated provider into KNOWN_PROVIDERS and the tenant
    policy, then confirm the route returns 403 when no BAA record exists.
    """
    import api.ui_ai_console as ai_console

    # Register "anthropic" as a known provider for this test
    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    # Make the env-allowed check pass for anthropic
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    # Make the experience policy include anthropic
    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        policy["default_provider"] = "simulated"
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

    from fastapi.testclient import TestClient

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    # Get / register device
    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp_resp.status_code == 200
    device_id = exp_resp.json()["device"]["device_id"]

    # Enable the device
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "T-1"},
    )

    # PHI message + regulated provider (anthropic) — no BAA record → 403
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={
            "message": "MRN: 4872910 — schedule appointment next week.",
            "device_id": device_id,
            "provider": "anthropic",
        },
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["error_code"] == _REASON_MISSING
    assert detail["provider_id"] == "anthropic"


def test_simulated_provider_unaffected_by_baa_enforcement(build_app, monkeypatch):
    """
    Non-regulated providers must continue to work without any BAA record.
    Regression guard: simulated provider must remain fully functional.
    """
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    from fastapi.testclient import TestClient

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp_resp.status_code == 200
    device_id = exp_resp.json()["device"]["device_id"]

    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "T-1"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_quota_not_charged_before_baa_denial(build_app, monkeypatch):
    """
    BAA enforcement runs before quota charge. A denied request must not
    consume any quota from the tenant's daily budget.
    """
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        policy["tenant_max_tokens_per_day"] = 1000
        policy["device_max_tokens_per_day"] = 500
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

    quota_consumed_calls: list[dict] = []
    original_consume = ai_console._consume_quota_atomic

    def _tracked_consume(db, **kwargs):
        quota_consumed_calls.append(kwargs)
        return original_consume(db, **kwargs)

    monkeypatch.setattr(ai_console, "_consume_quota_atomic", _tracked_consume)

    from fastapi.testclient import TestClient

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    device_id = exp_resp.json()["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "T-1"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={
            "message": "MRN: 4872910 — schedule appointment next week.",
            "device_id": device_id,
            "provider": "anthropic",
        },
    )
    assert resp.status_code == 403
    assert quota_consumed_calls == [], (
        "quota must not be consumed when BAA enforcement blocks the request"
    )
