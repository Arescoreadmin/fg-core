"""Provider-neutral invitation authentication adapter contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

from admin_gateway.identity.identity_context import AuthenticatedIdentity


class ProviderAdapterError(ValueError):
    def __init__(self, code: str = "PROVIDER_CALLBACK_NOT_CONFIGURED") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AuthInstructions:
    provider: str
    connection_id: str | None
    organization_id: str | None
    auth_start_url: str
    adapter: str


class ProviderAdapter(Protocol):
    def start_invitation_auth(
        self,
        *,
        provider: str,
        state: str,
        connection_id: str | None,
        organization_id: str | None,
    ) -> AuthInstructions: ...

    def validate_callback(
        self, callback_payload: dict[str, Any]
    ) -> AuthenticatedIdentity: ...


class ProviderNeutralRedirectAdapter:
    """Provides start metadata but fails closed until callback verification is configured."""

    def start_invitation_auth(
        self,
        *,
        provider: str,
        state: str,
        connection_id: str | None,
        organization_id: str | None,
    ) -> AuthInstructions:
        query = {"provider": provider, "state": state}
        if connection_id:
            query["connection_id"] = connection_id
        if organization_id:
            query["organization_id"] = organization_id
        return AuthInstructions(
            provider=provider,
            connection_id=connection_id,
            organization_id=organization_id,
            auth_start_url=f"/identity/provider/authorize?{urlencode(query)}",
            adapter="provider-neutral-redirect",
        )

    def validate_callback(
        self, callback_payload: dict[str, Any]
    ) -> AuthenticatedIdentity:
        del callback_payload
        raise ProviderAdapterError()
