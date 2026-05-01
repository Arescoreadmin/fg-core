from __future__ import annotations

import pytest

from services.ai.routing import (
    AI_PROVIDER_NOT_ALLOWED,
    AI_PROVIDER_NOT_CONFIGURED,
    AI_PROVIDER_PHI_PROVIDER_REQUIRED,
    AI_PROVIDER_SELECTED_NON_PHI_DEFAULT,
    AI_PROVIDER_SELECTED_PHI_AZURE,
    resolve_ai_provider_for_request,
)


KNOWN = frozenset({"anthropic", "azure_openai", "simulated"})


def _route(
    *,
    requested_provider: str | None = None,
    allowed: frozenset[str] = frozenset({"anthropic", "azure_openai"}),
    configured: frozenset[str] = frozenset({"anthropic", "azure_openai"}),
    phi_detected: bool = False,
):
    return resolve_ai_provider_for_request(
        tenant_id="tenant-a",
        requested_provider=requested_provider,
        tenant_allowed_providers=allowed,
        known_providers=KNOWN,
        configured_providers=configured,
        phi_detected=phi_detected,
    )


def test_no_phi_no_requested_provider_selects_anthropic() -> None:
    result = _route(phi_detected=False)

    assert result.allowed is True
    assert result.provider_id == "anthropic"
    assert result.reason_code == AI_PROVIDER_SELECTED_NON_PHI_DEFAULT


def test_phi_no_requested_provider_selects_azure_when_allowed_configured() -> None:
    result = _route(phi_detected=True)

    assert result.allowed is True
    assert result.provider_id == "azure_openai"
    assert result.reason_code == AI_PROVIDER_SELECTED_PHI_AZURE


def test_phi_azure_missing_config_denied() -> None:
    result = _route(phi_detected=True, configured=frozenset({"anthropic"}))

    assert result.allowed is False
    assert result.provider_id is None
    assert result.reason_code == AI_PROVIDER_NOT_CONFIGURED


def test_phi_azure_not_tenant_allowed_denied() -> None:
    result = _route(phi_detected=True, allowed=frozenset({"anthropic"}))

    assert result.allowed is False
    assert result.provider_id is None
    assert result.reason_code == AI_PROVIDER_NOT_ALLOWED


def test_phi_requested_anthropic_denied_without_fallback() -> None:
    result = _route(requested_provider="anthropic", phi_detected=True)

    assert result.allowed is False
    assert result.provider_id is None
    assert result.reason_code == AI_PROVIDER_PHI_PROVIDER_REQUIRED


def test_no_phi_requested_anthropic_allowed() -> None:
    result = _route(requested_provider="anthropic", phi_detected=False)

    assert result.allowed is True
    assert result.provider_id == "anthropic"


def test_unknown_requested_provider_denied() -> None:
    result = _route(requested_provider="unknown", phi_detected=False)

    assert result.allowed is False
    assert result.provider_id is None
    assert result.reason_code == AI_PROVIDER_NOT_ALLOWED


@pytest.mark.parametrize("env_name", ["prod", "production", "staging"])
def test_simulated_blocked_in_prod_staging_without_explicit_config(
    monkeypatch: pytest.MonkeyPatch, env_name: str
) -> None:
    from services.ai.routing import configured_ai_providers

    monkeypatch.setenv("FG_ENV", env_name)
    monkeypatch.delenv("FG_AI_ENABLE_SIMULATED", raising=False)

    assert "simulated" not in configured_ai_providers()


def test_no_fallback_from_azure_failure_to_anthropic() -> None:
    result = _route(phi_detected=True, configured=frozenset({"anthropic"}))

    assert result.allowed is False
    assert result.provider_id is None


def test_no_fallback_from_anthropic_failure_to_simulated() -> None:
    result = _route(phi_detected=False, configured=frozenset({"simulated"}))

    assert result.allowed is False
    assert result.provider_id is None
    assert result.reason_code == AI_PROVIDER_NOT_CONFIGURED


def test_reason_codes_are_deterministic() -> None:
    first = _route(phi_detected=True, configured=frozenset({"anthropic"}))
    second = _route(phi_detected=True, configured=frozenset({"anthropic"}))

    assert first == second
    assert first.reason_code == AI_PROVIDER_NOT_CONFIGURED
