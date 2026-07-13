"""services/identity_assurance/engine.py — Pure Identity Assurance engine.

Deterministic, no-randomness computation of assurance levels and trust scores
from provider claims. No datetime is consulted during evaluation — every value
in an :class:`AssuranceDecision` is a function of its inputs.

Public API:
  compute_assurance_level(claims)          -> AssuranceLevel
  compute_trust_score(level)               -> int
  normalize_provider_claims(raw, provider) -> ProviderClaims
  evaluate_authentication_strength(claims) -> AssuranceLevel
  determine_identity_provider(claims)      -> IdentityProvider
  build_assurance_decision(claims, tid, aid) -> AssuranceDecision
  trust_band_for_score(score)              -> TrustBand
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional

from services.identity_assurance.models import (
    AssuranceDecision,
    AssuranceLevel,
    IdentityProvider,
    ProviderClaims,
    TrustBand,
)

# ---------------------------------------------------------------------------
# Score lookup
# ---------------------------------------------------------------------------

TRUST_SCORE_TABLE: dict[AssuranceLevel, int] = {
    AssuranceLevel.UNVERIFIED: 0,
    AssuranceLevel.PASSWORD: 32,
    AssuranceLevel.PASSWORD_MFA: 68,
    AssuranceLevel.SSO: 74,
    AssuranceLevel.SSO_MFA: 84,
    AssuranceLevel.CERTIFICATE: 95,
    AssuranceLevel.HARDWARE_KEY: 98,
    AssuranceLevel.WORKLOAD_IDENTITY: 100,
    AssuranceLevel.SERVICE_ACCOUNT: 72,
    AssuranceLevel.SYSTEM_AUTONOMOUS: 90,
}

# ---------------------------------------------------------------------------
# Provider issuer / hint heuristics
# ---------------------------------------------------------------------------

_ISSUER_MARKERS: tuple[tuple[str, IdentityProvider], ...] = (
    ("login.microsoftonline.com", IdentityProvider.ENTRA_ID),
    ("sts.windows.net", IdentityProvider.ENTRA_ID),
    ("microsoftonline", IdentityProvider.ENTRA_ID),
    ("okta.com", IdentityProvider.OKTA),
    ("okta.", IdentityProvider.OKTA),
    ("accounts.google.com", IdentityProvider.GOOGLE_WORKSPACE),
    ("googleapis.com", IdentityProvider.GOOGLE_WORKSPACE),
    ("pingidentity", IdentityProvider.PING),
    ("pingone", IdentityProvider.PING),
    ("auth0.com", IdentityProvider.AUTH0),
    ("keycloak", IdentityProvider.KEYCLOAK),
)

_HINT_MAP: dict[str, IdentityProvider] = {
    "keycloak": IdentityProvider.KEYCLOAK,
    "entra": IdentityProvider.ENTRA_ID,
    "entra_id": IdentityProvider.ENTRA_ID,
    "azure_ad": IdentityProvider.ENTRA_ID,
    "azuread": IdentityProvider.ENTRA_ID,
    "okta": IdentityProvider.OKTA,
    "google": IdentityProvider.GOOGLE_WORKSPACE,
    "google_workspace": IdentityProvider.GOOGLE_WORKSPACE,
    "gsuite": IdentityProvider.GOOGLE_WORKSPACE,
    "ping": IdentityProvider.PING,
    "pingone": IdentityProvider.PING,
    "auth0": IdentityProvider.AUTH0,
    "system": IdentityProvider.SYSTEM,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "y", "t"):
            return True
        if s in ("false", "0", "no", "n", "f"):
            return False
    return None


def _first(mapping: dict, keys: Iterable[str]) -> Any:
    for k in keys:
        if k in mapping and mapping[k] is not None:
            return mapping[k]
    return None


def _has_mfa_amr(amr: Any) -> Optional[bool]:
    """Interpret the OIDC ``amr`` claim for MFA hints."""
    if amr is None:
        return None
    if isinstance(amr, str):
        amr_list = [amr]
    elif isinstance(amr, (list, tuple)):
        amr_list = [str(a).lower() for a in amr]
    else:
        return None
    mfa_markers = {"mfa", "otp", "totp", "hwk", "u2f", "webauthn", "sms", "phr", "phrh"}
    return any(m in mfa_markers for m in amr_list)


def _has_hwk_amr(amr: Any) -> Optional[bool]:
    if amr is None:
        return None
    if isinstance(amr, str):
        amr_list = [amr.lower()]
    elif isinstance(amr, (list, tuple)):
        amr_list = [str(a).lower() for a in amr]
    else:
        return None
    hwk_markers = {"hwk", "u2f", "webauthn", "fido", "fido2"}
    return any(m in hwk_markers for m in amr_list)


# ---------------------------------------------------------------------------
# Provider adapters — pure structural mapping only, no business logic
# ---------------------------------------------------------------------------


def _auth_method_string(value: Any) -> Optional[str]:
    """Coerce an ``authentication_method``/``amr`` claim to a scalar string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and value:
        return ",".join(str(v) for v in value)
    return str(value)


def _normalize_keycloak(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa")) if raw.get("mfa") is not None else _has_mfa_amr(amr)
    hwk = (
        _bool(raw.get("hardware_key"))
        if raw.get("hardware_key") is not None
        else _has_hwk_amr(amr)
    )
    return ProviderClaims(
        subject=_first(raw, ["sub", "subject", "preferred_username"]),
        email=raw.get("email"),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="keycloak",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "auth_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("mfa_methods")
        if isinstance(raw.get("mfa_methods"), list)
        else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate_verified")),
        smart_card_verified=_bool(raw.get("smart_card_verified")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid") or raw.get("session_id"),
        device_id=raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="keycloak",
    )


def _normalize_entra(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa"))
    if mfa is None:
        mfa = _has_mfa_amr(amr)
    hwk = _bool(raw.get("hardware_key"))
    if hwk is None:
        hwk = _has_hwk_amr(amr)
    return ProviderClaims(
        subject=_first(raw, ["oid", "sub", "preferred_username"]),
        email=_first(raw, ["email", "upn", "preferred_username"]),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="entra_id",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("amr") if isinstance(raw.get("amr"), list) else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate")),
        smart_card_verified=_bool(raw.get("smartcard")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid"),
        device_id=raw.get("deviceid") or raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ipaddr") or raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="entra_id",
    )


def _normalize_okta(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa_verified"))
    if mfa is None:
        mfa = _has_mfa_amr(amr)
    hwk = _bool(raw.get("hardware_key"))
    if hwk is None:
        hwk = _has_hwk_amr(amr)
    return ProviderClaims(
        subject=_first(raw, ["sub", "uid"]),
        email=raw.get("email"),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="okta",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("amr") if isinstance(raw.get("amr"), list) else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate_verified")),
        smart_card_verified=_bool(raw.get("smart_card_verified")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid"),
        device_id=raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="okta",
    )


def _normalize_google(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa"))
    if mfa is None:
        mfa = _has_mfa_amr(amr)
    hwk = _bool(raw.get("hardware_key"))
    if hwk is None:
        hwk = _has_hwk_amr(amr)
    return ProviderClaims(
        subject=raw.get("sub"),
        email=raw.get("email"),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="google_workspace",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("amr") if isinstance(raw.get("amr"), list) else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate_verified")),
        smart_card_verified=_bool(raw.get("smart_card_verified")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid"),
        device_id=raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="google_workspace",
    )


def _normalize_ping(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa"))
    if mfa is None:
        mfa = _has_mfa_amr(amr)
    hwk = _bool(raw.get("hardware_key"))
    if hwk is None:
        hwk = _has_hwk_amr(amr)
    return ProviderClaims(
        subject=_first(raw, ["sub", "subject"]),
        email=raw.get("email"),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="ping",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("amr") if isinstance(raw.get("amr"), list) else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate_verified")),
        smart_card_verified=_bool(raw.get("smart_card_verified")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid"),
        device_id=raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="ping",
    )


def _normalize_auth0(raw: dict) -> ProviderClaims:
    amr = raw.get("amr")
    mfa = _bool(raw.get("mfa"))
    if mfa is None:
        mfa = _has_mfa_amr(amr)
    hwk = _bool(raw.get("hardware_key"))
    if hwk is None:
        hwk = _has_hwk_amr(amr)
    return ProviderClaims(
        subject=raw.get("sub"),
        email=raw.get("email"),
        email_verified=_bool(raw.get("email_verified")),
        issuer=raw.get("iss") or raw.get("issuer"),
        provider_hint="auth0",
        authentication_method=_auth_method_string(
            _first(raw, ["authentication_method", "amr"])
        ),
        mfa_verified=mfa,
        mfa_methods=raw.get("amr") if isinstance(raw.get("amr"), list) else None,
        hardware_key_verified=hwk,
        certificate_verified=_bool(raw.get("certificate_verified")),
        smart_card_verified=_bool(raw.get("smart_card_verified")),
        passwordless=_bool(raw.get("passwordless")),
        session_id=raw.get("sid"),
        device_id=raw.get("device_id"),
        device_trust=raw.get("device_trust"),
        ip_address=raw.get("ip_address"),
        is_service_account=_bool(raw.get("is_service_account")),
        is_workload_identity=_bool(raw.get("is_workload_identity")),
        workload_identity_ref=raw.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw.get("is_system_autonomous")),
        raw_provider="auth0",
    )


_PROVIDER_ADAPTERS = {
    IdentityProvider.KEYCLOAK: _normalize_keycloak,
    IdentityProvider.ENTRA_ID: _normalize_entra,
    IdentityProvider.OKTA: _normalize_okta,
    IdentityProvider.GOOGLE_WORKSPACE: _normalize_google,
    IdentityProvider.PING: _normalize_ping,
    IdentityProvider.AUTH0: _normalize_auth0,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def determine_identity_provider(claims: dict) -> IdentityProvider:
    """Determine the identity provider from a claims dict.

    Priority: explicit ``provider_hint``/``raw_provider`` → issuer marker → UNKNOWN.
    System / workload signals map to SYSTEM.
    """
    if not isinstance(claims, dict) or not claims:
        return IdentityProvider.UNKNOWN

    if _bool(claims.get("is_system_autonomous")) or _bool(
        claims.get("is_workload_identity")
    ):
        return IdentityProvider.SYSTEM

    hint = (
        claims.get("provider_hint")
        or claims.get("raw_provider")
        or claims.get("provider")
    )
    if isinstance(hint, str):
        norm = _HINT_MAP.get(hint.strip().lower())
        if norm is not None:
            return norm

    issuer = claims.get("iss") or claims.get("issuer")
    if isinstance(issuer, str):
        issuer_lower = issuer.lower()
        for marker, provider in _ISSUER_MARKERS:
            if marker in issuer_lower:
                return provider

    return IdentityProvider.UNKNOWN


def normalize_provider_claims(
    raw_claims: dict, provider: IdentityProvider
) -> ProviderClaims:
    """Dispatch to the provider-specific adapter.

    Non-mapped providers (SYSTEM, UNKNOWN) fall through to a minimal structural
    projection that preserves whatever the caller supplied.
    """
    if not isinstance(raw_claims, dict):
        raw_claims = {}
    adapter = _PROVIDER_ADAPTERS.get(provider)
    if adapter is not None:
        return adapter(dict(raw_claims))

    # SYSTEM / UNKNOWN — best-effort structural mapping.
    return ProviderClaims(
        subject=raw_claims.get("sub") or raw_claims.get("subject"),
        email=raw_claims.get("email"),
        email_verified=_bool(raw_claims.get("email_verified")),
        issuer=raw_claims.get("iss") or raw_claims.get("issuer"),
        provider_hint=(
            "system"
            if provider == IdentityProvider.SYSTEM
            else raw_claims.get("provider_hint")
        ),
        authentication_method=raw_claims.get("authentication_method"),
        mfa_verified=_bool(raw_claims.get("mfa_verified")),
        hardware_key_verified=_bool(raw_claims.get("hardware_key_verified")),
        certificate_verified=_bool(raw_claims.get("certificate_verified")),
        smart_card_verified=_bool(raw_claims.get("smart_card_verified")),
        passwordless=_bool(raw_claims.get("passwordless")),
        session_id=raw_claims.get("session_id") or raw_claims.get("sid"),
        device_id=raw_claims.get("device_id"),
        device_trust=raw_claims.get("device_trust"),
        ip_address=raw_claims.get("ip_address"),
        is_service_account=_bool(raw_claims.get("is_service_account")),
        is_workload_identity=_bool(raw_claims.get("is_workload_identity")),
        workload_identity_ref=raw_claims.get("workload_identity_ref"),
        is_system_autonomous=_bool(raw_claims.get("is_system_autonomous")),
        raw_provider=raw_claims.get("raw_provider")
        or (provider.value if provider != IdentityProvider.UNKNOWN else None),
    )


def evaluate_authentication_strength(claims: ProviderClaims) -> AssuranceLevel:
    """Deterministic strength ladder — strongest match wins.

    Ordered high → low so the first satisfied predicate yields the answer.
    """
    if claims is None:
        return AssuranceLevel.UNVERIFIED

    # Autonomous / workload identity are separate strength categories.
    if claims.is_system_autonomous is True:
        return AssuranceLevel.SYSTEM_AUTONOMOUS
    if claims.is_workload_identity is True:
        return AssuranceLevel.WORKLOAD_IDENTITY

    # Hardware-backed authentication.
    if claims.hardware_key_verified is True:
        return AssuranceLevel.HARDWARE_KEY
    if claims.certificate_verified is True or claims.smart_card_verified is True:
        return AssuranceLevel.CERTIFICATE

    # SSO detection — presence of a federated issuer + subject.
    is_sso = bool(claims.issuer) and bool(claims.subject)
    is_mfa = claims.mfa_verified is True

    if claims.is_service_account is True:
        return AssuranceLevel.SERVICE_ACCOUNT

    if is_sso and is_mfa:
        return AssuranceLevel.SSO_MFA
    if is_sso:
        return AssuranceLevel.SSO
    if is_mfa:
        return AssuranceLevel.PASSWORD_MFA

    method = (claims.authentication_method or "").strip().lower()
    if method == "password" or claims.passwordless is False:
        return AssuranceLevel.PASSWORD
    if claims.subject and claims.authentication_method:
        return AssuranceLevel.PASSWORD

    return AssuranceLevel.UNVERIFIED


def compute_assurance_level(claims: ProviderClaims) -> AssuranceLevel:
    """Deterministic mapping from provider claims to an assurance level."""
    return evaluate_authentication_strength(claims)


def compute_trust_score(level: AssuranceLevel) -> int:
    """Pure lookup — no side effects."""
    if level not in TRUST_SCORE_TABLE:
        return 0
    return TRUST_SCORE_TABLE[level]


def trust_band_for_score(score: int) -> TrustBand:
    """Map a 0-100 trust score to its :class:`TrustBand`."""
    if score < 0 or score > 100:
        return TrustBand.CRITICAL
    if score <= 20:
        return TrustBand.CRITICAL
    if score <= 40:
        return TrustBand.LOW
    if score <= 60:
        return TrustBand.MODERATE
    if score <= 80:
        return TrustBand.HIGH
    return TrustBand.VERY_HIGH


# ---------------------------------------------------------------------------
# Decision assembly
# ---------------------------------------------------------------------------


def _claims_canonical_payload(claims: ProviderClaims) -> dict:
    """Canonical dict payload for a ProviderClaims — stable field order via
    ``sort_keys=True`` at JSON encode time.
    """
    return {
        "subject": claims.subject,
        "email": claims.email,
        "email_verified": claims.email_verified,
        "issuer": claims.issuer,
        "provider_hint": claims.provider_hint,
        "authentication_method": claims.authentication_method,
        "mfa_verified": claims.mfa_verified,
        "mfa_methods": claims.mfa_methods,
        "hardware_key_verified": claims.hardware_key_verified,
        "certificate_verified": claims.certificate_verified,
        "smart_card_verified": claims.smart_card_verified,
        "passwordless": claims.passwordless,
        "session_id": claims.session_id,
        "device_id": claims.device_id,
        "device_trust": claims.device_trust,
        "ip_address": claims.ip_address,
        "is_service_account": claims.is_service_account,
        "is_workload_identity": claims.is_workload_identity,
        "workload_identity_ref": claims.workload_identity_ref,
        "is_system_autonomous": claims.is_system_autonomous,
        "raw_provider": claims.raw_provider,
    }


def hash_provider_claims(claims: ProviderClaims) -> str:
    """SHA-256 of the canonical claims payload — deterministic."""
    return _sha256(_canonical_json(_claims_canonical_payload(claims)))


def _provider_from_claims(claims: ProviderClaims) -> IdentityProvider:
    hint = claims.provider_hint or claims.raw_provider
    if isinstance(hint, str):
        norm = _HINT_MAP.get(hint.strip().lower())
        if norm is not None:
            return norm
    if claims.issuer:
        issuer_lower = claims.issuer.lower()
        for marker, provider in _ISSUER_MARKERS:
            if marker in issuer_lower:
                return provider
    if claims.is_system_autonomous is True or claims.is_workload_identity is True:
        return IdentityProvider.SYSTEM
    return IdentityProvider.UNKNOWN


def build_assurance_decision(
    claims: ProviderClaims,
    tenant_id: str,
    actor_id: str,
) -> AssuranceDecision:
    """Compose a full :class:`AssuranceDecision` from claims + scope.

    Deterministic in all inputs. Same ``(claims, tenant_id, actor_id)`` always
    yields the same decision — including the fingerprint and sequence value.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be a non-empty string")
    if not actor_id:
        raise ValueError("actor_id must be a non-empty string")

    level = compute_assurance_level(claims)
    score = compute_trust_score(level)
    provider = _provider_from_claims(claims)
    auth_method = claims.authentication_method or (
        level.value if level != AssuranceLevel.UNVERIFIED else "unverified"
    )

    claims_hash = hash_provider_claims(claims)

    canonical_payload = {
        "assurance_level": level.value,
        "trust_score": score,
        "provider": provider.value,
        "authentication_method": auth_method,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "provider_claims_hash": claims_hash,
        "schema_version": "1.0",
    }
    fingerprint = _sha256(_canonical_json(canonical_payload))

    # computed_at_sequence: a deterministic monotonic-ish hash of the decision
    # inputs. Not a timestamp — reproducible from inputs alone.
    sequence_payload = {
        "fp": fingerprint,
        "claims_hash": claims_hash,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
    }
    computed_at_sequence = _sha256(_canonical_json(sequence_payload))

    return AssuranceDecision(
        assurance_level=level,
        trust_score=score,
        provider=provider,
        authentication_method=auth_method,
        fingerprint=fingerprint,
        computed_at_sequence=computed_at_sequence,
        tenant_id=tenant_id,
        actor_id=actor_id,
        provider_claims_hash=claims_hash,
        schema_version="1.0",
    )


def chain_hash(previous_chain_hash: Optional[str], current_fingerprint: str) -> str:
    """Deterministic chain-hash linking a snapshot to its predecessor."""
    prev = previous_chain_hash or ("0" * 64)
    return _sha256(f"{prev}:{current_fingerprint}")
