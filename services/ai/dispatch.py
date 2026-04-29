"""
AI provider dispatch — deterministic single-provider call boundary.

Design contract:
- call_provider() is the single call site for all LLM inference.
- Provider selection is explicit: caller passes provider_id.
- No fallback: if the requested provider fails or is unconfigured, raise ProviderCallError.
- No silent switching between providers.
- simulated provider requires explicit allow flag; blocked in prod-like envs by default.

To add a new provider: add it to _KNOWN_PROVIDERS and _get_provider().
The call_provider() signature and ProviderCallError contract are stable.
"""

from __future__ import annotations

from services.ai.providers.base import (
    AI_PROVIDER_NOT_ALLOWED,
    ProviderCallError,
    ProviderRequest,
    ProviderResponse,
)

_KNOWN_PROVIDERS: frozenset[str] = frozenset({"anthropic", "simulated"})


def _get_provider(provider_id: str):
    from services.ai.providers.anthropic_provider import AnthropicProvider  # noqa: PLC0415
    from services.ai.providers.simulated_provider import SimulatedProvider  # noqa: PLC0415

    if provider_id == "anthropic":
        return AnthropicProvider()
    if provider_id == "simulated":
        return SimulatedProvider()
    raise ProviderCallError(
        AI_PROVIDER_NOT_ALLOWED, f"Provider not supported: {provider_id}"
    )


def call_provider(
    *,
    provider_id: str,
    prompt: str,
    max_tokens: int,
    request_id: str,
    tenant_id: str,
    system_prompt: str | None = None,
) -> ProviderResponse:
    """Dispatch to provider_id. Raises ProviderCallError on any failure; never falls back."""
    if provider_id not in _KNOWN_PROVIDERS:
        raise ProviderCallError(
            AI_PROVIDER_NOT_ALLOWED, f"Unknown provider: {provider_id}"
        )
    req = ProviderRequest(
        tenant_id=tenant_id,
        provider_id=provider_id,
        prompt=prompt,
        max_tokens=max_tokens,
        request_id=request_id,
        system_prompt=system_prompt,
    )
    return _get_provider(provider_id).call(req)
