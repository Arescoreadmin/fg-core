"""IdentityProvider protocol — the contract every provider must satisfy."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from api.actor_context import ActorContext


@runtime_checkable
class IdentityProvider(Protocol):
    """Validate a credential and return an ActorContext.

    Raises ValueError on any validation failure (expired, invalid signature,
    missing required claims, etc.). The caller catches ValueError and treats
    it as an authentication failure.
    """

    def extract_actor(self, token: str) -> ActorContext:
        ...
