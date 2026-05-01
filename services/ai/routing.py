from __future__ import annotations

import os
from dataclasses import dataclass

AI_PROVIDER_SELECTED_NON_PHI_DEFAULT = "AI_PROVIDER_SELECTED_NON_PHI_DEFAULT"
AI_PROVIDER_SELECTED_PHI_AZURE = "AI_PROVIDER_SELECTED_PHI_AZURE"
AI_PROVIDER_REQUESTED_ALLOWED = "AI_PROVIDER_REQUESTED_ALLOWED"
AI_PROVIDER_NOT_ALLOWED = "AI_PROVIDER_NOT_ALLOWED"
AI_PROVIDER_NOT_CONFIGURED = "AI_PROVIDER_NOT_CONFIGURED"
AI_PROVIDER_PHI_PROVIDER_REQUIRED = "AI_PROVIDER_PHI_PROVIDER_REQUIRED"
AI_PROVIDER_PHI_PROVIDER_NOT_APPROVED = "AI_PROVIDER_PHI_PROVIDER_NOT_APPROVED"

SELECTED_BY_REQUEST = "requested_provider"
SELECTED_BY_NON_PHI_DEFAULT = "non_phi_default"
SELECTED_BY_PHI_POLICY = "phi_policy"

DEFAULT_NON_PHI_PROVIDER = "anthropic"
DEFAULT_PHI_PROVIDER = "azure_openai"
PROD_LIKE_ENVS = frozenset({"prod", "production", "staging"})


@dataclass(frozen=True)
class AiProviderRoutingResult:
    provider_id: str | None
    reason_code: str
    phi_detected: bool
    requested_provider: str | None
    selected_by: str
    requires_baa: bool
    allowed: bool


def configured_ai_providers() -> frozenset[str]:
    providers: set[str] = set()
    if (os.getenv("FG_ANTHROPIC_API_KEY") or "").strip():
        providers.add("anthropic")
    if (
        (os.getenv("FG_AZURE_AI_KEY") or "").strip()
        and (os.getenv("FG_AZURE_OPENAI_ENDPOINT") or "").strip()
        and (os.getenv("FG_AZURE_OPENAI_DEPLOYMENT") or "").strip()
    ):
        providers.add("azure_openai")
    if _simulated_provider_allowed():
        providers.add("simulated")
    return frozenset(providers)


def resolve_ai_provider_for_request(
    *,
    tenant_id: str,
    requested_provider: str | None,
    tenant_allowed_providers: set[str] | frozenset[str],
    known_providers: set[str] | frozenset[str],
    configured_providers: set[str] | frozenset[str],
    phi_detected: bool,
    default_provider: str | None = None,
    phi_provider: str | None = None,
    baa_approved: bool | None = None,
) -> AiProviderRoutingResult:
    if not tenant_id or not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required and must not be blank")

    tenant_allowed = frozenset(str(item).strip() for item in tenant_allowed_providers)
    known = frozenset(str(item).strip() for item in known_providers)
    configured = frozenset(str(item).strip() for item in configured_providers)
    requested = _clean_provider(requested_provider)
    phi_provider_id = _clean_provider(phi_provider) or DEFAULT_PHI_PROVIDER

    if requested is not None:
        if phi_detected and requested != phi_provider_id:
            return _denied(
                requested_provider=requested,
                phi_detected=True,
                reason_code=AI_PROVIDER_PHI_PROVIDER_REQUIRED,
                selected_by=SELECTED_BY_REQUEST,
                requires_baa=True,
            )
        return _resolve_candidate(
            candidate=requested,
            requested_provider=requested,
            tenant_allowed=tenant_allowed,
            known=known,
            configured=configured,
            phi_detected=phi_detected,
            reason_code=AI_PROVIDER_REQUESTED_ALLOWED,
            selected_by=SELECTED_BY_REQUEST,
            requires_baa=phi_detected,
            baa_approved=baa_approved,
        )

    if phi_detected:
        return _resolve_candidate(
            candidate=phi_provider_id,
            requested_provider=None,
            tenant_allowed=tenant_allowed,
            known=known,
            configured=configured,
            phi_detected=True,
            reason_code=AI_PROVIDER_SELECTED_PHI_AZURE,
            selected_by=SELECTED_BY_PHI_POLICY,
            requires_baa=True,
            baa_approved=baa_approved,
        )

    candidate = _clean_provider(default_provider) or DEFAULT_NON_PHI_PROVIDER
    return _resolve_candidate(
        candidate=candidate,
        requested_provider=None,
        tenant_allowed=tenant_allowed,
        known=known,
        configured=configured,
        phi_detected=False,
        reason_code=AI_PROVIDER_SELECTED_NON_PHI_DEFAULT,
        selected_by=SELECTED_BY_NON_PHI_DEFAULT,
        requires_baa=False,
        baa_approved=baa_approved,
    )


def _resolve_candidate(
    *,
    candidate: str,
    requested_provider: str | None,
    tenant_allowed: frozenset[str],
    known: frozenset[str],
    configured: frozenset[str],
    phi_detected: bool,
    reason_code: str,
    selected_by: str,
    requires_baa: bool,
    baa_approved: bool | None,
) -> AiProviderRoutingResult:
    if candidate not in known or candidate not in tenant_allowed:
        return _denied(
            requested_provider=requested_provider,
            phi_detected=phi_detected,
            reason_code=AI_PROVIDER_NOT_ALLOWED,
            selected_by=selected_by,
            requires_baa=requires_baa,
        )
    if candidate not in configured:
        return _denied(
            requested_provider=requested_provider,
            phi_detected=phi_detected,
            reason_code=AI_PROVIDER_NOT_CONFIGURED,
            selected_by=selected_by,
            requires_baa=requires_baa,
        )
    if requires_baa and baa_approved is False:
        return _denied(
            requested_provider=requested_provider,
            phi_detected=phi_detected,
            reason_code=AI_PROVIDER_PHI_PROVIDER_NOT_APPROVED,
            selected_by=selected_by,
            requires_baa=True,
        )
    return AiProviderRoutingResult(
        provider_id=candidate,
        reason_code=reason_code,
        phi_detected=phi_detected,
        requested_provider=requested_provider,
        selected_by=selected_by,
        requires_baa=requires_baa,
        allowed=True,
    )


def _denied(
    *,
    requested_provider: str | None,
    phi_detected: bool,
    reason_code: str,
    selected_by: str,
    requires_baa: bool,
) -> AiProviderRoutingResult:
    return AiProviderRoutingResult(
        provider_id=None,
        reason_code=reason_code,
        phi_detected=phi_detected,
        requested_provider=requested_provider,
        selected_by=selected_by,
        requires_baa=requires_baa,
        allowed=False,
    )


def _clean_provider(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    return cleaned or None


def _simulated_provider_allowed() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    default = "0" if env in PROD_LIKE_ENVS else "1"
    flag = (os.getenv("FG_AI_ENABLE_SIMULATED") or default).strip().lower()
    return flag in {"1", "true", "yes", "on"}
