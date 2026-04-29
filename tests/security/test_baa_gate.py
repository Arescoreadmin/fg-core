"""
BAA Gate Tests.

Covers:
  Unit:        clean text → allowed, BAA enforcement not called
               PHI text → BAA enforcement called
               PHI + missing BAA → gate returns denied
               PHI + active BAA → gate returns allowed
               classifier fail-safe (contains_phi=True on error) → BAA enforced
               enforce_baa_gate_for_route raises HTTPException(403) on denial
               reason_code preserved from underlying BAA enforcement error
               audit payload excludes raw PHI text
               malformed tenant_id / provider_id raises ValueError
               BaaGateResult fields are stable and complete

  Integration: /ui/ai/chat — PHI + regulated + no BAA → 403
                             PHI + regulated + active BAA → allowed
                             no PHI + simulated → allowed
                             denied PHI request does not charge quota
               AIPlaneService.infer — PHI + regulated + no BAA → ValueError
                                       no PHI → allowed

  Regression:  gate is wired into /ui/ai/chat — removing call breaks test
               gate is wired into AIPlaneService — removing call breaks test
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from services.phi_classifier.models import PhiClassificationResult, SensitivityLevel
from services.provider_baa.gate import (
    GATE_ACTION_ALLOWED,
    GATE_ACTION_DENIED,
    GATE_REASON_MISSING_PROVIDER,
    GATE_REASON_MISSING_TENANT,
    BaaGateResult,
    enforce_baa_gate_for_route,
    evaluate_baa_gate,
)
from services.provider_baa.policy import _REASON_MISSING

_MRN_TEXT = "MRN: 4872910 — schedule appointment next week."
_CLEAN_TEXT = "Please summarize the quarterly report."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_phi_result(
    reasoning_code: str = "PHI_RULE_HIGH_RISK_IDENTIFIER",
) -> PhiClassificationResult:
    return PhiClassificationResult(
        contains_phi=True,
        phi_types=frozenset({"mrn"}),
        confidence=0.95,
        sensitivity_level=SensitivityLevel.HIGH,
        redaction_candidates=(),
        reasoning_code=reasoning_code,
    )


def _make_clean_result() -> PhiClassificationResult:
    return PhiClassificationResult(
        contains_phi=False,
        phi_types=frozenset(),
        confidence=1.0,
        sensitivity_level=SensitivityLevel.NONE,
        redaction_candidates=(),
        reasoning_code="PHI_RULE_NO_SIGNALS",
    )


def _db(tmp_path: Path) -> Any:
    db_path = str(tmp_path / "baa-gate-test.db")
    os.environ["FG_SQLITE_PATH"] = db_path
    os.environ["FG_ENV"] = "test"
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker()()


def _insert_baa(db: Any, *, tenant_id: str, provider_id: str, baa_status: str) -> None:
    db.execute(
        text(
            """
            INSERT INTO provider_baa_records
                (tenant_id, provider_id, baa_status, created_at, updated_at)
            VALUES (:tenant_id, :provider_id, :baa_status,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, provider_id) DO UPDATE
                SET baa_status = excluded.baa_status
            """
        ),
        {"tenant_id": tenant_id, "provider_id": provider_id, "baa_status": baa_status},
    )
    db.commit()


# ---------------------------------------------------------------------------
# Section 1: Unit — evaluate_baa_gate()
# ---------------------------------------------------------------------------


def test_clean_text_does_not_call_baa_enforcement() -> None:
    """Clean text → gate allows; enforce_provider_baa_for_route never called."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_clean_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route"
        ) as mock_baa:
            result = evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="simulated", text=_CLEAN_TEXT
            )

    assert result.allowed is True
    assert result.contains_phi is False
    assert result.enforcement_action == GATE_ACTION_ALLOWED
    mock_baa.assert_not_called()


def test_phi_text_calls_baa_enforcement() -> None:
    """PHI text → gate calls enforce_provider_baa_for_route."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route"
        ) as mock_baa:
            result = evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="anthropic", text=_MRN_TEXT
            )

    assert result.allowed is True
    assert result.contains_phi is True
    mock_baa.assert_called_once()


def test_phi_baa_denied_returns_denied_result() -> None:
    """PHI + BAA denial → evaluate_baa_gate returns allowed=False without raising."""
    mock_db = MagicMock()
    baa_exc = HTTPException(
        status_code=403,
        detail={"error_code": _REASON_MISSING, "provider_id": "anthropic"},
    )
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route",
            side_effect=baa_exc,
        ):
            result = evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="anthropic", text=_MRN_TEXT
            )

    assert result.allowed is False
    assert result.contains_phi is True
    assert result.reason_code == _REASON_MISSING
    assert result.enforcement_action == GATE_ACTION_DENIED
    assert result.provider_id == "anthropic"
    assert result.tenant_id == "t1"


def test_phi_baa_passed_returns_allowed_result() -> None:
    """PHI + BAA passes → evaluate_baa_gate returns allowed=True."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch("services.provider_baa.gate.enforce_provider_baa_for_route"):
            result = evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="anthropic", text=_MRN_TEXT
            )

    assert result.allowed is True
    assert result.contains_phi is True
    assert result.enforcement_action == GATE_ACTION_ALLOWED


def test_classifier_fail_safe_triggers_baa_enforcement() -> None:
    """Classifier error returns contains_phi=True (fail-safe); gate enforces BAA."""
    mock_db = MagicMock()
    fail_safe_result = PhiClassificationResult(
        contains_phi=True,
        phi_types=frozenset(),
        confidence=0.0,
        sensitivity_level=SensitivityLevel.HIGH,
        redaction_candidates=(),
        reasoning_code="PHI_RULE_CLASSIFY_ERROR",
    )
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=fail_safe_result
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route"
        ) as mock_baa:
            evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="anthropic", text="any text"
            )

    mock_baa.assert_called_once()


# ---------------------------------------------------------------------------
# Section 2: Unit — enforce_baa_gate_for_route() raises on denial
# ---------------------------------------------------------------------------


def test_enforce_gate_raises_403_on_denial() -> None:
    """enforce_baa_gate_for_route raises HTTPException(403) when BAA denies."""
    mock_db = MagicMock()
    baa_exc = HTTPException(
        status_code=403,
        detail={"error_code": _REASON_MISSING, "provider_id": "anthropic"},
    )
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route",
            side_effect=baa_exc,
        ):
            with pytest.raises(HTTPException) as exc_info:
                enforce_baa_gate_for_route(
                    mock_db,
                    tenant_id="t1",
                    provider_id="anthropic",
                    text=_MRN_TEXT,
                )

    assert exc_info.value.status_code == 403
    detail: Any = exc_info.value.detail
    assert detail["error_code"] == _REASON_MISSING
    assert detail["provider_id"] == "anthropic"


def test_enforce_gate_does_not_raise_on_clean_text() -> None:
    """enforce_baa_gate_for_route returns result without raising on clean text."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_clean_result()
    ):
        result = enforce_baa_gate_for_route(
            mock_db, tenant_id="t1", provider_id="simulated", text=_CLEAN_TEXT
        )

    assert result.allowed is True


def test_enforce_gate_does_not_raise_on_phi_with_active_baa() -> None:
    """PHI + BAA passes → enforce_baa_gate_for_route returns without raising."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch("services.provider_baa.gate.enforce_provider_baa_for_route"):
            result = enforce_baa_gate_for_route(
                mock_db, tenant_id="t1", provider_id="anthropic", text=_MRN_TEXT
            )

    assert result.allowed is True


# ---------------------------------------------------------------------------
# Section 3: Unit — audit event emissions
# ---------------------------------------------------------------------------


def test_clean_text_emits_phi_classification_audit() -> None:
    """Clean text → PHI classification audit emitted; block audit NOT emitted."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_clean_result()
    ):
        with patch(
            "services.provider_baa.gate.emit_phi_classification_audit"
        ) as mock_classify_audit:
            with patch(
                "services.provider_baa.gate.emit_phi_enforcement_block_audit"
            ) as mock_block_audit:
                evaluate_baa_gate(
                    mock_db, tenant_id="t1", provider_id="simulated", text=_CLEAN_TEXT
                )

    mock_classify_audit.assert_called_once()
    mock_block_audit.assert_not_called()


def test_phi_denial_emits_block_audit_not_classification_audit() -> None:
    """PHI + BAA denial → block audit emitted; classification audit NOT emitted."""
    mock_db = MagicMock()
    baa_exc = HTTPException(
        403, detail={"error_code": _REASON_MISSING, "provider_id": "anthropic"}
    )
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route",
            side_effect=baa_exc,
        ):
            with patch(
                "services.provider_baa.gate.emit_phi_enforcement_block_audit"
            ) as mock_block:
                with patch(
                    "services.provider_baa.gate.emit_phi_classification_audit"
                ) as mock_classify:
                    evaluate_baa_gate(
                        mock_db,
                        tenant_id="t1",
                        provider_id="anthropic",
                        text=_MRN_TEXT,
                    )

    mock_block.assert_called_once()
    mock_classify.assert_not_called()


def test_audit_payload_excludes_raw_phi_text() -> None:
    """Audit event details must not contain raw PHI text."""
    captured: list[Any] = []
    with patch(
        "api.security_audit.SecurityAuditor.log_event",
        side_effect=lambda e: captured.append(e),
    ):
        mock_db = MagicMock()
        baa_exc = HTTPException(
            403, detail={"error_code": _REASON_MISSING, "provider_id": "anthropic"}
        )
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route",
            side_effect=baa_exc,
        ):
            evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="anthropic", text=_MRN_TEXT
            )

    assert captured
    for event in captured:
        payload_str = str(event.details)
        assert _MRN_TEXT not in payload_str
        assert "4872910" not in payload_str


# ---------------------------------------------------------------------------
# Section 4: Unit — input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "  ", None])
def test_blank_tenant_raises_value_error(bad_tenant: Any) -> None:
    mock_db = MagicMock()
    with pytest.raises(ValueError, match=GATE_REASON_MISSING_TENANT):
        evaluate_baa_gate(
            mock_db, tenant_id=bad_tenant, provider_id="simulated", text="hello"
        )


@pytest.mark.parametrize("bad_provider", ["", "  ", None])
def test_blank_provider_raises_value_error(bad_provider: Any) -> None:
    mock_db = MagicMock()
    with pytest.raises(ValueError, match=GATE_REASON_MISSING_PROVIDER):
        evaluate_baa_gate(
            mock_db, tenant_id="t1", provider_id=bad_provider, text="hello"
        )


# ---------------------------------------------------------------------------
# Section 5: Unit — BaaGateResult field completeness
# ---------------------------------------------------------------------------


def test_gate_result_has_all_required_fields() -> None:
    """BaaGateResult carries all required stable fields."""
    mock_db = MagicMock()
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_clean_result()
    ):
        result = evaluate_baa_gate(
            mock_db, tenant_id="t1", provider_id="simulated", text=_CLEAN_TEXT
        )

    assert isinstance(result, BaaGateResult)
    assert isinstance(result.allowed, bool)
    assert isinstance(result.contains_phi, bool)
    assert isinstance(result.sensitivity_level, SensitivityLevel)
    assert isinstance(result.phi_types, frozenset)
    assert isinstance(result.provider_id, str) and result.provider_id
    assert isinstance(result.tenant_id, str) and result.tenant_id
    assert isinstance(result.reason_code, str) and result.reason_code
    assert result.enforcement_action in (GATE_ACTION_ALLOWED, GATE_ACTION_DENIED)


def test_denied_result_reason_code_matches_baa_error() -> None:
    """reason_code in denied result is preserved from BAA enforcement detail."""
    mock_db = MagicMock()
    baa_exc = HTTPException(
        403, detail={"error_code": "PROVIDER_BAA_REVOKED", "provider_id": "openai"}
    )
    with patch(
        "services.provider_baa.gate.classify_phi", return_value=_make_phi_result()
    ):
        with patch(
            "services.provider_baa.gate.enforce_provider_baa_for_route",
            side_effect=baa_exc,
        ):
            result = evaluate_baa_gate(
                mock_db, tenant_id="t1", provider_id="openai", text=_MRN_TEXT
            )

    assert result.reason_code == "PROVIDER_BAA_REVOKED"


# ---------------------------------------------------------------------------
# Section 6: Integration — /ui/ai/chat via BAA Gate
# ---------------------------------------------------------------------------


def test_ui_chat_phi_regulated_no_baa_denied_403(build_app, monkeypatch) -> None:
    """PHI + regulated provider + no BAA record → 403; gate is the enforcement point."""
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

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
        json={"reason": "test", "ticket": "BG-1"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == _REASON_MISSING


def test_ui_chat_phi_regulated_active_baa_allowed(build_app, monkeypatch) -> None:
    """PHI + regulated provider (anthropic) + active BAA → allowed (200)."""
    from services.ai.providers.base import ProviderResponse

    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key-not-used")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    _fake_resp = ProviderResponse(
        provider_id="anthropic",
        text="test response from anthropic",
        model="claude-haiku-4-5-20251001",
        input_tokens=10,
        output_tokens=5,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **kw: _fake_resp)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

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
        json={"reason": "test", "ticket": "BG-2"},
    )

    db = get_sessionmaker()()
    _insert_baa(
        db, tenant_id="tenant-dev", provider_id="anthropic", baa_status="active"
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 200
    assert resp.json()["provider"] == "anthropic"


def test_ui_chat_no_phi_simulated_allowed(build_app, monkeypatch) -> None:
    """No PHI + simulated provider → allowed (200); BAA gate does not block."""
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

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
        json={"reason": "test", "ticket": "BG-3"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_ui_chat_phi_denied_does_not_charge_quota(build_app, monkeypatch) -> None:
    """BAA gate denial (PHI + no BAA) fires before quota — quota not consumed."""
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
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

    quota_calls: list[dict] = []
    original_consume = ai_console._consume_quota_atomic

    def _tracked(db, **kw):
        quota_calls.append(kw)
        return original_consume(db, **kw)

    monkeypatch.setattr(ai_console, "_consume_quota_atomic", _tracked)

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
        json={"reason": "test", "ticket": "BG-4"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 403
    assert quota_calls == [], "quota must not be consumed when BAA gate denies"


# ---------------------------------------------------------------------------
# Section 7: Integration — AIPlaneService.infer via BAA Gate
# ---------------------------------------------------------------------------


def test_ai_plane_service_phi_regulated_no_baa_raises(tmp_path: Path) -> None:
    """AIPlaneService.infer: PHI + regulated provider + no BAA → ValueError."""
    db = _db(tmp_path)

    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    svc = AIPlaneService()
    payload = AIInferRequest(query=_MRN_TEXT)

    # Make effective_provider a regulated provider (anthropic) with no BAA record
    with patch(
        "services.ai_plane_extension.service._resolve_effective_provider",
        return_value="anthropic",
    ):
        with pytest.raises(ValueError, match="AI_PHI_PROVIDER_NOT_BAA_CAPABLE"):
            svc.infer(db, tenant_id="tenant-a", payload=payload)


def test_ai_plane_service_phi_regulated_active_baa_allowed(tmp_path: Path) -> None:
    """AIPlaneService.infer: PHI + regulated provider + active BAA → succeeds."""
    from services.ai.providers.base import ProviderResponse

    db = _db(tmp_path)
    _insert_baa(db, tenant_id="tenant-a", provider_id="anthropic", baa_status="active")

    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    svc = AIPlaneService()
    payload = AIInferRequest(query=_MRN_TEXT)

    _fake_resp = ProviderResponse(
        provider_id="anthropic",
        text="test response",
        model="claude-haiku-4-5-20251001",
    )
    with patch(
        "services.ai_plane_extension.service._resolve_effective_provider",
        return_value="anthropic",
    ):
        with patch(
            "services.ai_plane_extension.service._call_provider",
            return_value=_fake_resp,
        ):
            result = svc.infer(db, tenant_id="tenant-a", payload=payload)

    assert result["ok"] is True
    assert result["simulated"] is False


def test_ai_plane_service_no_phi_passes_gate(tmp_path: Path) -> None:
    """AIPlaneService.infer: no PHI → BAA gate allows; inference proceeds normally."""
    db = _db(tmp_path)

    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    svc = AIPlaneService()
    result = svc.infer(
        db, tenant_id="tenant-a", payload=AIInferRequest(query=_CLEAN_TEXT)
    )
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# Section 8: Regression — gate cannot be bypassed
# ---------------------------------------------------------------------------


def test_ui_chat_gate_is_wired_removing_it_blocks_phi(build_app, monkeypatch) -> None:
    """
    Regression: if enforce_baa_gate_for_route is removed from ui_ai_console.py,
    PHI + regulated + no BAA would return 200 instead of 403.
    This test proves the gate is wired in by verifying the 403.
    """
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

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
        json={"reason": "test", "ticket": "BG-REG-1"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    # If this fails (resp.status_code != 403), the gate has been removed or bypassed
    assert resp.status_code == 403, (
        "BAA gate must be wired into /ui/ai/chat — PHI+regulated+no-BAA must return 403"
    )


def test_ai_plane_gate_is_wired_removing_it_allows_phi(tmp_path: Path) -> None:
    """
    Regression: if enforce_baa_gate_for_route is removed from AIPlaneService,
    PHI + regulated + no BAA would succeed instead of raising.
    This test proves the gate is wired in by verifying the ValueError.
    """
    db = _db(tmp_path)

    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    svc = AIPlaneService()
    payload = AIInferRequest(query=_MRN_TEXT)

    with patch(
        "services.ai_plane_extension.service._resolve_effective_provider",
        return_value="anthropic",
    ):
        with pytest.raises(ValueError, match="AI_PHI_PROVIDER_NOT_BAA_CAPABLE"):
            svc.infer(db, tenant_id="tenant-a", payload=payload)
