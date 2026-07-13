"""services/identity_assurance/models.py — Pydantic v2 models for Identity Assurance.

Defines assurance levels, provider identities, trust bands, provider claims,
assurance decisions, snapshots, and trust context bundles. All decision-carrying
models are immutable (``ConfigDict(frozen=True)``) — an assurance decision, once
computed, is a fixed record.

Design principles:
  - No randomness. No datetime inside computations.
  - Immutable ``AssuranceDecision`` — every field is deterministic from the
    ``ProviderClaims`` and the caller-provided ``tenant_id`` / ``actor_id``.
  - ``computed_at_sequence`` is a monotonic, deterministic sequence value
    (SHA-256 of canonical inputs) — never a wall-clock timestamp.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AssuranceLevel(str, Enum):
    """Enumeration of assurance levels — ordered from weakest to strongest.

    Note: ``SERVICE_ACCOUNT`` and ``SYSTEM_AUTONOMOUS`` are separate identity
    categories; their score ordering reflects their trust posture relative to
    human authentication paths.
    """

    UNVERIFIED = "UNVERIFIED"
    PASSWORD = "PASSWORD"
    PASSWORD_MFA = "PASSWORD_MFA"
    SSO = "SSO"
    SSO_MFA = "SSO_MFA"
    CERTIFICATE = "CERTIFICATE"
    HARDWARE_KEY = "HARDWARE_KEY"
    WORKLOAD_IDENTITY = "WORKLOAD_IDENTITY"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    SYSTEM_AUTONOMOUS = "SYSTEM_AUTONOMOUS"


class IdentityProvider(str, Enum):
    """Supported identity providers plus SYSTEM and UNKNOWN sentinels."""

    KEYCLOAK = "KEYCLOAK"
    ENTRA_ID = "ENTRA_ID"
    OKTA = "OKTA"
    GOOGLE_WORKSPACE = "GOOGLE_WORKSPACE"
    PING = "PING"
    AUTH0 = "AUTH0"
    SYSTEM = "SYSTEM"
    UNKNOWN = "UNKNOWN"


class TrustBand(str, Enum):
    """Trust score bands.

    Ranges (inclusive):
      CRITICAL   0-20
      LOW       21-40
      MODERATE  41-60
      HIGH      61-80
      VERY_HIGH 81-100
    """

    CRITICAL = "CRITICAL"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


# ---------------------------------------------------------------------------
# Provider claims (normalized)
# ---------------------------------------------------------------------------


class ProviderClaims(BaseModel):
    """Normalized claims from any identity provider.

    Every field is Optional so provider adapters can populate what is available
    without needing to fabricate defaults. The assurance engine tolerates any
    subset.
    """

    model_config = ConfigDict(frozen=True)

    subject: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    issuer: Optional[str] = None
    provider_hint: Optional[str] = None

    # Authentication modality
    authentication_method: Optional[str] = None
    mfa_verified: Optional[bool] = None
    mfa_methods: Optional[list[str]] = None
    hardware_key_verified: Optional[bool] = None
    certificate_verified: Optional[bool] = None
    smart_card_verified: Optional[bool] = None
    passwordless: Optional[bool] = None

    # Session / channel
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    device_trust: Optional[str] = None
    ip_address: Optional[str] = None

    # Workload / service account signals
    is_service_account: Optional[bool] = None
    is_workload_identity: Optional[bool] = None
    workload_identity_ref: Optional[str] = None
    is_system_autonomous: Optional[bool] = None

    # Provider metadata (opaque)
    raw_provider: Optional[str] = None


# ---------------------------------------------------------------------------
# Decisions & snapshots
# ---------------------------------------------------------------------------


class AssuranceDecision(BaseModel):
    """Immutable assurance decision.

    ``computed_at_sequence`` is a deterministic monotonic sequence derived from
    the canonical decision payload — not a timestamp. This keeps the model
    reproducible and free of wall-clock inputs.
    """

    model_config = ConfigDict(frozen=True)

    assurance_level: AssuranceLevel
    trust_score: int = Field(ge=0, le=100)
    provider: IdentityProvider
    authentication_method: str
    fingerprint: str = Field(min_length=64, max_length=64)
    computed_at_sequence: str = Field(min_length=64, max_length=64)
    tenant_id: str
    actor_id: str
    provider_claims_hash: str = Field(min_length=64, max_length=64)
    schema_version: str = "1.0"

    @field_validator("trust_score")
    @classmethod
    def _score_range(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("trust_score must be between 0 and 100")
        return v

    @model_validator(mode="after")
    def _fingerprint_hex(self) -> "AssuranceDecision":
        for name in ("fingerprint", "computed_at_sequence", "provider_claims_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"{name} must be a 64-char SHA-256 hex string")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError(f"{name} must be hexadecimal") from exc
        return self


class AssuranceSnapshot(BaseModel):
    """Snapshot of an assurance change or evaluation.

    Snapshots form an append-only chain — each row links to the previous via
    ``chain_hash``. ``sequence_number`` is monotonic per actor.
    """

    model_config = ConfigDict(frozen=True)

    actor_id: str
    tenant_id: str
    sequence_number: int = Field(ge=0)
    previous_level: Optional[AssuranceLevel] = None
    new_level: AssuranceLevel
    trust_score: int = Field(ge=0, le=100)
    identity_provider: Optional[IdentityProvider] = None
    authentication_method: Optional[str] = None
    reason: Optional[str] = None
    fingerprint: str = Field(min_length=64, max_length=64)
    chain_hash: str = Field(min_length=64, max_length=64)
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Trust context bundle
# ---------------------------------------------------------------------------


class TrustContext(BaseModel):
    """Input bundle for computing a trust score.

    Wraps a ``ProviderClaims`` object plus the tenant and actor scope so the
    engine has everything needed to produce a decision without touching request
    state.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    actor_id: str
    claims: ProviderClaims
    provider_hint: Optional[IdentityProvider] = None
