"""api/config/identity_runtime.py — Feature flags for identity runtime integration.

Central place for all identity-runtime toggles introduced by PR-01a.1. Every
flag defaults to ``False`` so that enabling PR-01a.1 code paths is opt-in and
staged rollout is safe.

Truthy env values (case-insensitive): ``"1"``, ``"true"``, ``"yes"``, ``"on"``,
``"y"``. Anything else — including missing — is False.

Flags:
    FG_IDENTITY_AUTHORITY_ENABLED
        Wire FIAP AuthorizationContext into the JWT auth path.

    FG_SESSION_EVALUATOR_ENABLED
        Run the continuous SessionEvaluator on every session-backed request.

    FG_DEVICE_TRUST_ENFORCEMENT_ENABLED
        Enforce DeviceTrustRegistry outcomes at request time.

    FG_RISK_ENGINE_ENABLED
        Compute IdentityRiskEngine risk score during authentication.

    FG_CONDITIONAL_ACCESS_ENABLED
        Consult ConditionalAccessPolicyEngine during authentication.

    FG_BREAK_GLASS_RUNTIME_ENABLED
        Consult BreakGlassAuthority during authorization.

    FG_IDENTITY_TIMELINE_ENABLED
        Emit best-effort events to IdentityTimeline from auth paths.

    FG_IDENTITY_PERSISTENCE_ENABLED
        Use SQLAlchemy repositories backed by 0148 migration tables. Default
        is False → in-memory only, ensuring the request path never depends
        on DB availability for governance evaluation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Case-insensitive truthy strings.
_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on", "y"})


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Read a boolean feature flag from the environment.

    Truthy: ``"1"``, ``"true"``, ``"yes"``, ``"on"``, ``"y"`` (case-insensitive).
    Any other value — including missing or empty — resolves to ``default``.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if not normalized:
        return default
    return normalized in _TRUTHY


@dataclass(frozen=True)
class IdentityRuntimeFlags:
    """Snapshot of identity-runtime feature flags.

    Immutable to make behavior within a request deterministic. Call
    :func:`get_flags` at the top of a request handler; do not re-read env
    mid-request.
    """

    FG_IDENTITY_AUTHORITY_ENABLED: bool = False
    FG_SESSION_EVALUATOR_ENABLED: bool = False
    FG_DEVICE_TRUST_ENFORCEMENT_ENABLED: bool = False
    FG_RISK_ENGINE_ENABLED: bool = False
    FG_CONDITIONAL_ACCESS_ENABLED: bool = False
    FG_BREAK_GLASS_RUNTIME_ENABLED: bool = False
    FG_IDENTITY_TIMELINE_ENABLED: bool = False
    FG_IDENTITY_PERSISTENCE_ENABLED: bool = False

    @classmethod
    def from_env(cls) -> "IdentityRuntimeFlags":
        """Read all flags from the current environment."""
        return cls(
            FG_IDENTITY_AUTHORITY_ENABLED=_env_flag("FG_IDENTITY_AUTHORITY_ENABLED"),
            FG_SESSION_EVALUATOR_ENABLED=_env_flag("FG_SESSION_EVALUATOR_ENABLED"),
            FG_DEVICE_TRUST_ENFORCEMENT_ENABLED=_env_flag(
                "FG_DEVICE_TRUST_ENFORCEMENT_ENABLED"
            ),
            FG_RISK_ENGINE_ENABLED=_env_flag("FG_RISK_ENGINE_ENABLED"),
            FG_CONDITIONAL_ACCESS_ENABLED=_env_flag("FG_CONDITIONAL_ACCESS_ENABLED"),
            FG_BREAK_GLASS_RUNTIME_ENABLED=_env_flag("FG_BREAK_GLASS_RUNTIME_ENABLED"),
            FG_IDENTITY_TIMELINE_ENABLED=_env_flag("FG_IDENTITY_TIMELINE_ENABLED"),
            FG_IDENTITY_PERSISTENCE_ENABLED=_env_flag(
                "FG_IDENTITY_PERSISTENCE_ENABLED"
            ),
        )

    def any_enabled(self) -> bool:
        """Return True if any governance runtime flag is enabled."""
        return (
            self.FG_SESSION_EVALUATOR_ENABLED
            or self.FG_DEVICE_TRUST_ENFORCEMENT_ENABLED
            or self.FG_RISK_ENGINE_ENABLED
            or self.FG_CONDITIONAL_ACCESS_ENABLED
            or self.FG_BREAK_GLASS_RUNTIME_ENABLED
            or self.FG_IDENTITY_TIMELINE_ENABLED
        )


def get_flags() -> IdentityRuntimeFlags:
    """Return a fresh snapshot of the runtime feature flags.

    Flags are read fresh each call so that tests can mutate env variables
    with ``monkeypatch.setenv`` without leaking state across tests. Callers
    that want a single per-request snapshot should call this once at the
    top of the request handler and pass the result down.
    """
    return IdentityRuntimeFlags.from_env()


__all__ = [
    "IdentityRuntimeFlags",
    "get_flags",
]
