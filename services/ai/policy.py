from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

AI_POLICY_LOADED = "AI_POLICY_LOADED"
AI_POLICY_BUILTIN_DEFAULT = "AI_POLICY_BUILTIN_DEFAULT"
AI_POLICY_LEGACY_CONTRACT_DEFAULTS = "AI_POLICY_LEGACY_CONTRACT_DEFAULTS"
AI_POLICY_INVALID = "AI_POLICY_INVALID"

PROD_LIKE_ENVS = {"prod", "production", "staging"}
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_RULE_FIELDS = frozenset(
    {
        "phi_rules",
        "rag_rules",
        "audit_rules",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "id",
        "version",
        "allowed_providers",
        "default_provider",
        "default_model",
        "tenant_max_tokens_per_day",
        "device_max_tokens_per_day",
        "pii_deny_terms",
        "max_tokens_per_request",
        "phi_provider",
        "phi_rules",
        "rag_rules",
        "audit_rules",
    }
)
_PHI_RULE_FIELDS = frozenset(
    {
        "require_baa",
        "require_prompt_minimization",
        "deny_if_phi_provider_unavailable",
        "deny_explicit_non_phi_provider_for_phi",
    }
)
_RAG_RULE_FIELDS = frozenset(
    {
        "enabled",
        "require_grounded_response",
        "no_answer_on_ungrounded",
    }
)
_AUDIT_RULE_FIELDS = frozenset(
    {
        "require_request_hash",
        "require_response_hash",
        "include_routing_metadata",
    }
)


class AiPolicyError(ValueError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code
        self.message = message


@dataclass(frozen=True)
class AiPhiRules:
    require_baa: bool
    require_prompt_minimization: bool
    deny_if_phi_provider_unavailable: bool
    deny_explicit_non_phi_provider_for_phi: bool


@dataclass(frozen=True)
class AiRagRules:
    enabled: bool
    require_grounded_response: bool
    no_answer_on_ungrounded: bool


@dataclass(frozen=True)
class AiAuditRules:
    require_request_hash: bool
    require_response_hash: bool
    include_routing_metadata: bool


@dataclass(frozen=True)
class AiPolicy:
    version: int
    allowed_providers: tuple[str, ...]
    default_provider: str
    phi_provider: str
    phi_rules: AiPhiRules
    rag_rules: AiRagRules
    audit_rules: AiAuditRules
    source: str
    reason_code: str


def _environment(value: str | None = None) -> str:
    return (value if value is not None else os.getenv("FG_ENV") or "").strip().lower()


def _prod_like(environment: str | None = None) -> bool:
    return _environment(environment) in PROD_LIKE_ENVS


def _safe_tenant_file(tenant_policy_dir: Path, tenant_id: str) -> Path:
    if not tenant_id or not _TENANT_ID_RE.fullmatch(tenant_id):
        raise AiPolicyError(AI_POLICY_INVALID, "tenant id is not file-safe")
    return tenant_policy_dir / f"{tenant_id}.json"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AiPolicyError(AI_POLICY_INVALID, "AI policy JSON is invalid") from exc
    if not isinstance(raw, dict):
        raise AiPolicyError(AI_POLICY_INVALID, "AI policy must be a JSON object")
    return raw


def _bool_rule(raw: Mapping[str, Any], key: str) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise AiPolicyError(AI_POLICY_INVALID, f"AI policy rule {key} must be boolean")
    return value


def _require_rule_object(
    payload: Mapping[str, Any], key: str, allowed_fields: frozenset[str]
) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise AiPolicyError(AI_POLICY_INVALID, f"AI policy {key} is required")
    unknown = sorted(set(value) - allowed_fields)
    if unknown:
        raise AiPolicyError(
            AI_POLICY_INVALID,
            f"AI policy {key} has unknown fields: {','.join(unknown)}",
        )
    missing = sorted(allowed_fields - set(value))
    if missing:
        raise AiPolicyError(
            AI_POLICY_INVALID,
            f"AI policy {key} missing fields: {','.join(missing)}",
        )
    return value


def _normalize_providers(
    values: object, *, known_providers: frozenset[str]
) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise AiPolicyError(AI_POLICY_INVALID, "allowed_providers must be non-empty")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise AiPolicyError(AI_POLICY_INVALID, "provider ids must be strings")
        provider = item.strip()
        if provider in seen:
            raise AiPolicyError(
                AI_POLICY_INVALID, "duplicate providers are not allowed"
            )
        if provider not in known_providers:
            raise AiPolicyError(AI_POLICY_INVALID, f"unknown provider: {provider}")
        seen.add(provider)
        normalized.append(provider)
    return tuple(sorted(normalized))


def _version(value: object) -> int:
    if isinstance(value, int):
        version = value
    elif isinstance(value, str) and value.strip():
        try:
            version = int(value.strip().split(".", maxsplit=1)[0])
        except ValueError as exc:
            raise AiPolicyError(AI_POLICY_INVALID, "policy version is invalid") from exc
    else:
        raise AiPolicyError(AI_POLICY_INVALID, "policy version is required")
    if version != 1:
        raise AiPolicyError(AI_POLICY_INVALID, "unsupported policy version")
    return version


def _default_rules() -> dict[str, dict[str, bool]]:
    return {
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


def _legacy_payload(
    contract_policy: Mapping[str, Any], *, environment: str | None
) -> dict[str, Any]:
    payload = dict(contract_policy)
    for key, value in _default_rules().items():
        payload.setdefault(key, value)
    env_default = (os.getenv("FG_AI_DEFAULT_PROVIDER") or "").strip()
    if env_default:
        providers = payload.get("allowed_providers")
        if isinstance(providers, list) and env_default not in providers:
            payload["allowed_providers"] = [*providers, env_default]
        payload["default_provider"] = env_default
    env_phi = (os.getenv("FG_AI_PHI_PROVIDER") or "").strip()
    if env_phi:
        providers = payload.get("allowed_providers")
        if isinstance(providers, list) and env_phi not in providers:
            payload["allowed_providers"] = [*providers, env_phi]
        payload["phi_provider"] = env_phi
    else:
        providers = payload.get("allowed_providers")
        current_phi_provider = str(payload.get("phi_provider") or "").strip()
        provider_set = set(providers) if isinstance(providers, list) else set()
        if not current_phi_provider or current_phi_provider not in provider_set:
            if "azure_openai" in provider_set:
                payload["phi_provider"] = "azure_openai"
            else:
                payload["phi_provider"] = payload.get("default_provider")
        elif not payload.get("phi_provider"):
            payload["phi_provider"] = payload.get("default_provider")
    if not payload.get("version"):
        payload["version"] = 1
    return payload


def _env_list(name: str) -> list[str] | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    return [item.strip() for item in raw.split(",") if item.strip()]


def _builtin_payload(*, environment: str | None) -> dict[str, Any]:
    env_allowed = _env_list("FG_AI_ALLOWED_PROVIDERS")
    env_default = (os.getenv("FG_AI_DEFAULT_PROVIDER") or "").strip()
    env_phi = (os.getenv("FG_AI_PHI_PROVIDER") or "").strip()
    prod_like = _prod_like(environment)

    if env_allowed is not None:
        allowed = env_allowed
    elif prod_like:
        allowed = ["anthropic", "azure_openai"]
    else:
        allowed = ["simulated", "anthropic", "azure_openai"]

    default_provider = env_default or ("anthropic" if prod_like else "simulated")
    if default_provider not in allowed and not prod_like:
        allowed = [*allowed, default_provider]

    phi_provider = env_phi
    if not phi_provider:
        phi_provider = "azure_openai" if "azure_openai" in allowed else default_provider

    payload: dict[str, Any] = {
        "id": "builtin-ai-policy",
        "version": 1,
        "allowed_providers": allowed,
        "default_provider": default_provider,
        "phi_provider": phi_provider,
    }
    payload.update(_default_rules())
    return payload


def validate_ai_policy(
    payload: Mapping[str, Any],
    *,
    known_providers: Iterable[str],
    environment: str | None = None,
    source: str,
    reason_code: str = AI_POLICY_LOADED,
    strict_unknown_fields: bool = True,
) -> AiPolicy:
    if strict_unknown_fields:
        unknown = sorted(set(payload) - _TOP_LEVEL_FIELDS)
        if unknown:
            raise AiPolicyError(
                AI_POLICY_INVALID,
                f"AI policy has unknown fields: {','.join(unknown)}",
            )
    missing = sorted(
        {"version", "allowed_providers", "default_provider", "phi_provider"}
        - set(payload)
    )
    missing.extend(sorted(field for field in _RULE_FIELDS if field not in payload))
    if missing:
        raise AiPolicyError(
            AI_POLICY_INVALID, f"AI policy missing fields: {','.join(missing)}"
        )

    known = frozenset(known_providers)
    allowed = _normalize_providers(
        payload.get("allowed_providers"), known_providers=known
    )
    allowed_set = set(allowed)
    default_provider = str(payload.get("default_provider") or "").strip()
    phi_provider = str(payload.get("phi_provider") or "").strip()
    if default_provider not in allowed_set:
        raise AiPolicyError(AI_POLICY_INVALID, "default_provider is not allowed")
    if phi_provider not in allowed_set:
        raise AiPolicyError(AI_POLICY_INVALID, "phi_provider is not allowed")

    phi_raw = _require_rule_object(payload, "phi_rules", _PHI_RULE_FIELDS)
    rag_raw = _require_rule_object(payload, "rag_rules", _RAG_RULE_FIELDS)
    audit_raw = _require_rule_object(payload, "audit_rules", _AUDIT_RULE_FIELDS)
    phi_rules = AiPhiRules(
        require_baa=_bool_rule(phi_raw, "require_baa"),
        require_prompt_minimization=_bool_rule(phi_raw, "require_prompt_minimization"),
        deny_if_phi_provider_unavailable=_bool_rule(
            phi_raw, "deny_if_phi_provider_unavailable"
        ),
        deny_explicit_non_phi_provider_for_phi=_bool_rule(
            phi_raw, "deny_explicit_non_phi_provider_for_phi"
        ),
    )
    rag_rules = AiRagRules(
        enabled=_bool_rule(rag_raw, "enabled"),
        require_grounded_response=_bool_rule(rag_raw, "require_grounded_response"),
        no_answer_on_ungrounded=_bool_rule(rag_raw, "no_answer_on_ungrounded"),
    )
    audit_rules = AiAuditRules(
        require_request_hash=_bool_rule(audit_raw, "require_request_hash"),
        require_response_hash=_bool_rule(audit_raw, "require_response_hash"),
        include_routing_metadata=_bool_rule(audit_raw, "include_routing_metadata"),
    )

    if _prod_like(environment):
        if "simulated" in allowed_set:
            raise AiPolicyError(
                AI_POLICY_INVALID, "simulated provider is not allowed in production"
            )
        if not phi_rules.require_baa:
            raise AiPolicyError(
                AI_POLICY_INVALID, "PHI BAA enforcement is required in production"
            )
        if not phi_rules.require_prompt_minimization:
            raise AiPolicyError(
                AI_POLICY_INVALID,
                "PHI prompt minimization is required in production",
            )

    return AiPolicy(
        version=_version(payload.get("version")),
        allowed_providers=allowed,
        default_provider=default_provider,
        phi_provider=phi_provider,
        phi_rules=phi_rules,
        rag_rules=rag_rules,
        audit_rules=audit_rules,
        source=source,
        reason_code=reason_code,
    )


def load_ai_policy(
    path: str | Path,
    *,
    known_providers: Iterable[str],
    environment: str | None = None,
) -> AiPolicy:
    resolved = Path(path)
    payload = _load_json(resolved)
    return validate_ai_policy(
        payload,
        known_providers=known_providers,
        environment=environment,
        source=str(resolved),
        reason_code=AI_POLICY_LOADED,
    )


def resolve_ai_policy_for_tenant(
    *,
    tenant_id: str,
    known_providers: Iterable[str],
    environment: str | None = None,
    contract_policy: Mapping[str, Any] | None = None,
    policy_path: str | Path | None = None,
    tenant_policy_dir: str | Path | None = None,
) -> AiPolicy:
    if not tenant_id:
        raise AiPolicyError(AI_POLICY_INVALID, "tenant_id is required")

    tenant_dir_value = tenant_policy_dir or os.getenv("FG_AI_TENANT_POLICY_DIR")
    if tenant_dir_value:
        tenant_file = _safe_tenant_file(Path(tenant_dir_value), tenant_id)
        if tenant_file.exists():
            return load_ai_policy(
                tenant_file, known_providers=known_providers, environment=environment
            )

    path_value = policy_path or os.getenv("FG_AI_POLICY_PATH")
    if path_value:
        return load_ai_policy(
            path_value, known_providers=known_providers, environment=environment
        )

    if contract_policy is not None:
        payload = _legacy_payload(contract_policy, environment=environment)
        reason = (
            AI_POLICY_LOADED
            if _RULE_FIELDS.issubset(contract_policy.keys())
            else AI_POLICY_LEGACY_CONTRACT_DEFAULTS
        )
        return validate_ai_policy(
            payload,
            known_providers=known_providers,
            environment=environment,
            source=str(contract_policy.get("id") or "contract-policy"),
            reason_code=reason,
            strict_unknown_fields=True,
        )

    return validate_ai_policy(
        _builtin_payload(environment=environment),
        known_providers=known_providers,
        environment=environment,
        source="builtin",
        reason_code=AI_POLICY_BUILTIN_DEFAULT,
        strict_unknown_fields=True,
    )
