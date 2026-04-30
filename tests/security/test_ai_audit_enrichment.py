from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.security_audit import EventType
from services.ai.audit import build_ai_audit_metadata
from services.ai.providers.base import (
    AI_PROVIDER_CALL_FAILED,
    ProviderCallError,
    ProviderResponse,
)
from services.phi_classifier.models import SensitivityLevel
from services.provider_baa.gate import (
    BaaGateResult,
    GATE_ACTION_ALLOWED,
    GATE_ACTION_DENIED,
)

_CLEAN_TEXT = "Please summarize the quarterly report."
_PHI_TEXT = "SSN 123-45-6789 and MRN 987-65 belong to patient@example.com"
_RAW_RESPONSE = "Patient response contains MRN 987-65."


def _baa_result(
    *,
    allowed: bool = True,
    contains_phi: bool = False,
    phi_types: frozenset[str] = frozenset(),
    provider_id: str = "simulated",
) -> BaaGateResult:
    return BaaGateResult(
        allowed=allowed,
        contains_phi=contains_phi,
        sensitivity_level=SensitivityLevel.HIGH
        if contains_phi
        else SensitivityLevel.NONE,
        phi_types=phi_types,
        provider_id=provider_id,
        tenant_id="tenant-a",
        reason_code="PHI_DETECTED" if contains_phi else "NO_PHI",
        enforcement_action=GATE_ACTION_ALLOWED if allowed else GATE_ACTION_DENIED,
    )


def _assert_no_raw_values(details: dict[str, object]) -> None:
    payload = str(details)
    forbidden = [
        _CLEAN_TEXT,
        _PHI_TEXT,
        _RAW_RESPONSE,
        "123-45-6789",
        "987-65",
        "patient@example.com",
        "raw provider body",
    ]
    for value in forbidden:
        assert value not in payload


def test_ai_audit_metadata_hashes_are_deterministic_and_safe() -> None:
    provider_response = ProviderResponse(
        provider_id="anthropic",
        text=_RAW_RESPONSE,
        model="claude-haiku-4-5-20251001",
        input_tokens=11,
        output_tokens=7,
    )
    baa_result = _baa_result(
        contains_phi=True,
        phi_types=frozenset({"medical_keyword", "ssn", "email", "mrn"}),
        provider_id="anthropic",
    )

    first = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text=_PHI_TEXT,
        provider_response=provider_response,
        request_id="req-1",
        device_id="dev-1",
    )
    second = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text=_PHI_TEXT,
        provider_response=provider_response,
        request_id="req-1",
        device_id="dev-1",
    )
    different = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text="different request",
        provider_response=provider_response,
    )

    assert first["request_hash"] == second["request_hash"]
    assert first["response_hash"] == second["response_hash"]
    assert first["request_hash"] != different["request_hash"]
    assert str(first["request_hash"]).startswith("sha256:")
    assert str(first["response_hash"]).startswith("sha256:")
    assert first["phi_types"] == ["email", "mrn", "ssn"]
    assert first["phi_detected"] is True
    assert first["provider_id"] == "anthropic"
    assert first["baa_check_result"] == "allowed"
    assert first["model"] == "claude-haiku-4-5-20251001"
    assert first["input_tokens"] == 11
    assert first["output_tokens"] == 7
    _assert_no_raw_values(first)


def test_ai_audit_metadata_response_hash_null_without_response() -> None:
    metadata = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=_baa_result(
            allowed=False,
            contains_phi=True,
            phi_types=frozenset({"mrn"}),
            provider_id="anthropic",
        ),
        request_text=_PHI_TEXT,
        response_text=None,
    )

    assert metadata["response_hash"] is None
    assert metadata["request_hash"]
    assert metadata["phi_types"] == ["mrn"]
    _assert_no_raw_values(metadata)


def _setup_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from api.main import build_app

    db_path = tmp_path / "ai-audit.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return TestClient(build_app(auth_enabled=True))


def _enable_device(client: TestClient, headers: dict[str, str]) -> str:
    exp = client.get("/ui/ai/experience", headers=headers)
    assert exp.status_code == 200
    device_id = exp.json()["device"]["device_id"]
    enabled = client.post(
        f"/ui/devices/{device_id}/enable",
        headers=headers,
        json={"reason": "test", "ticket": "AI-AUDIT"},
    )
    assert enabled.status_code == 200
    return str(device_id)


def _allow_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.ui_ai_console as ai_console

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id: str):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        policy["tenant_max_tokens_per_day"] = 1000
        policy["device_max_tokens_per_day"] = 1000
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda _p: True)


def _captured_admin_details(events: list[Any], reason: str) -> dict[str, object]:
    matches = [
        event.details
        for event in events
        if event.event_type == EventType.ADMIN_ACTION and event.reason == reason
    ]
    assert matches
    return matches[-1]


def test_ui_success_audit_includes_request_and_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    provider_response = ProviderResponse(
        provider_id="anthropic",
        text=_RAW_RESPONSE,
        model="claude-haiku-4-5-20251001",
        input_tokens=3,
        output_tokens=4,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **_kw: provider_response)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )

    assert response.status_code == 200
    details = _captured_admin_details(events, "ai_chat")
    assert details["phi_detected"] is False
    assert details["phi_types"] == []
    assert details["provider_id"] == "anthropic"
    assert details["baa_check_result"] == "allowed"
    assert str(details["request_hash"]).startswith("sha256:")
    assert str(details["response_hash"]).startswith("sha256:")
    _assert_no_raw_values(details)


def test_ui_phi_baa_denial_audit_has_null_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    provider_called = False

    def _provider(**_kw):
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="anthropic", text="unused", model="m")

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _PHI_TEXT, "device_id": device_id, "provider": "anthropic"},
    )

    assert response.status_code == 403
    assert provider_called is False
    details = _captured_admin_details(events, "PROVIDER_BAA_MISSING")
    assert details["phi_detected"] is True
    assert details["phi_types"] == ["email", "mrn", "ssn"]
    assert details["provider_id"] == "anthropic"
    assert details["baa_check_result"] == "denied"
    assert details["response_hash"] is None
    assert str(details["request_hash"]).startswith("sha256:")
    _assert_no_raw_values(details)


def test_ui_provider_failure_audit_has_request_hash_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)

    def _fail(**_kw):
        raise ProviderCallError(AI_PROVIDER_CALL_FAILED, "raw provider body")

    monkeypatch.setattr(ai_console, "_call_provider", _fail)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )

    assert response.status_code == 503
    details = _captured_admin_details(events, AI_PROVIDER_CALL_FAILED)
    assert details["request_hash"]
    assert details["response_hash"] is None
    assert "raw provider body" not in str(details)
    _assert_no_raw_values(details)


def test_ui_quota_denial_does_not_call_provider_or_invent_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    monkeypatch.setattr(
        ai_console,
        "_consume_quota_atomic",
        lambda *_args, **_kw: (_ for _ in ()).throw(
            HTTPException(
                status_code=429,
                detail={"error_code": "AI_QUOTA_EXCEEDED", "message": "quota exceeded"},
            )
        ),
    )
    provider_called = False

    def _provider(**_kw):
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="simulated", text="unused", model="m")

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )

    assert response.status_code == 429
    assert provider_called is False
    details = _captured_admin_details(events, "AI_QUOTA_EXCEEDED")
    assert details["provider_id"] == "simulated"
    assert details["phi_detected"] is False
    assert details["response_hash"] is None
    _assert_no_raw_values(details)


def test_ai_plane_provider_failure_audit_has_safe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "plane-audit.db"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    db = get_sessionmaker()()
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )
    monkeypatch.setattr(
        "services.ai_plane_extension.service._resolve_effective_provider",
        lambda: "simulated",
    )

    def _fail(**_kw):
        raise ProviderCallError(AI_PROVIDER_CALL_FAILED, "raw provider body")

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _fail)

    with pytest.raises(ValueError, match=AI_PROVIDER_CALL_FAILED):
        AIPlaneService().infer(db, "tenant-a", AIInferRequest(query=_CLEAN_TEXT))

    details = _captured_admin_details(events, AI_PROVIDER_CALL_FAILED)
    assert details["provider_id"] == "simulated"
    assert details["phi_detected"] is False
    assert details["request_hash"]
    assert details["response_hash"] is None
    _assert_no_raw_values(details)
