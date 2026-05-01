from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from services.ai.policy import (
    AI_POLICY_BUILTIN_DEFAULT,
    AI_POLICY_INVALID,
    AI_POLICY_LOADED,
    AiPolicyError,
    load_ai_policy,
    resolve_ai_policy_for_tenant,
    validate_ai_policy,
)

KNOWN = frozenset({"anthropic", "azure_openai", "simulated"})


def _valid_policy() -> dict[str, object]:
    return {
        "version": 1,
        "allowed_providers": ["azure_openai", "anthropic"],
        "default_provider": "anthropic",
        "phi_provider": "azure_openai",
        "phi_rules": {
            "require_baa": True,
            "require_prompt_minimization": True,
            "deny_if_phi_provider_unavailable": True,
            "deny_explicit_non_phi_provider_for_phi": True,
        },
        "rag_rules": {
            "enabled": True,
            "require_grounded_response": True,
            "no_answer_on_ungrounded": True,
        },
        "audit_rules": {
            "require_request_hash": True,
            "require_response_hash": True,
            "include_routing_metadata": True,
        },
    }


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _rejects(payload: dict[str, object], *, environment: str = "test") -> None:
    with pytest.raises(AiPolicyError) as exc:
        validate_ai_policy(
            payload,
            known_providers=KNOWN,
            environment=environment,
            source="test",
        )
    assert exc.value.error_code == AI_POLICY_INVALID


def test_valid_policy_loads_and_normalizes_providers(tmp_path: Path) -> None:
    path = _write(tmp_path / "policy.json", _valid_policy())

    policy = load_ai_policy(path, known_providers=KNOWN, environment="test")

    assert policy.reason_code == AI_POLICY_LOADED
    assert policy.version == 1
    assert policy.allowed_providers == ("anthropic", "azure_openai")
    assert policy.default_provider == "anthropic"
    assert policy.phi_provider == "azure_openai"
    assert policy.phi_rules.require_baa is True
    assert policy.rag_rules.require_grounded_response is True
    assert policy.audit_rules.include_routing_metadata is True


def test_duplicate_providers_rejected() -> None:
    payload = _valid_policy()
    payload["allowed_providers"] = ["anthropic", "anthropic"]

    _rejects(payload)


def test_unknown_provider_rejected() -> None:
    payload = _valid_policy()
    payload["allowed_providers"] = ["anthropic", "unknown"]

    _rejects(payload)


def test_default_provider_not_allowed_rejected() -> None:
    payload = _valid_policy()
    payload["default_provider"] = "simulated"

    _rejects(payload)


def test_phi_provider_not_allowed_rejected() -> None:
    payload = _valid_policy()
    payload["phi_provider"] = "simulated"

    _rejects(payload)


def test_empty_allowed_providers_rejected() -> None:
    payload = _valid_policy()
    payload["allowed_providers"] = []

    _rejects(payload)


def test_unknown_fields_rejected() -> None:
    payload = _valid_policy()
    payload["raw_policy"] = {"secret": "nope"}

    _rejects(payload)


def test_invalid_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(AiPolicyError) as exc:
        load_ai_policy(path, known_providers=KNOWN, environment="test")

    assert exc.value.error_code == AI_POLICY_INVALID


def test_missing_policy_file_rejected_as_policy_error(tmp_path: Path) -> None:
    with pytest.raises(AiPolicyError) as exc:
        load_ai_policy(
            tmp_path / "missing-policy.json",
            known_providers=KNOWN,
            environment="test",
        )

    assert exc.value.error_code == AI_POLICY_INVALID


def test_missing_required_fields_rejected() -> None:
    payload = _valid_policy()
    payload.pop("phi_rules")

    _rejects(payload)


@pytest.mark.parametrize("env_name", ["prod", "production", "staging"])
def test_simulated_rejected_in_prod_staging(env_name: str) -> None:
    payload = _valid_policy()
    payload["allowed_providers"] = ["anthropic", "azure_openai", "simulated"]

    _rejects(payload, environment=env_name)


def test_require_baa_false_rejected_in_prod() -> None:
    payload = _valid_policy()
    phi_rules = dict(cast(dict[str, object], payload["phi_rules"]))
    phi_rules["require_baa"] = False
    payload["phi_rules"] = phi_rules

    _rejects(payload, environment="production")


def test_require_prompt_minimization_false_rejected_in_prod() -> None:
    payload = _valid_policy()
    phi_rules = dict(cast(dict[str, object], payload["phi_rules"]))
    phi_rules["require_prompt_minimization"] = False
    payload["phi_rules"] = phi_rules

    _rejects(payload, environment="production")


def test_invalid_tenant_policy_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    _write(policy_dir / "tenant-a.json", {"version": 1})
    monkeypatch.setenv("FG_AI_TENANT_POLICY_DIR", str(policy_dir))

    with pytest.raises(AiPolicyError) as exc:
        resolve_ai_policy_for_tenant(
            tenant_id="tenant-a",
            known_providers=KNOWN,
            environment="test",
        )

    assert exc.value.error_code == AI_POLICY_INVALID


def test_missing_policy_uses_safe_builtin_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FG_AI_POLICY_PATH", raising=False)
    monkeypatch.delenv("FG_AI_TENANT_POLICY_DIR", raising=False)
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)
    monkeypatch.delenv("FG_AI_PHI_PROVIDER", raising=False)

    policy = resolve_ai_policy_for_tenant(
        tenant_id="tenant-a",
        known_providers=KNOWN,
        environment="production",
    )

    assert policy.reason_code == AI_POLICY_BUILTIN_DEFAULT
    assert policy.allowed_providers == ("anthropic", "azure_openai")
    assert policy.default_provider == "anthropic"
    assert policy.phi_provider == "azure_openai"
    assert "simulated" not in policy.allowed_providers
