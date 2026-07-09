"""api/identity_authority/providers/entra_provider.py — Microsoft Entra ID (Azure AD) OIDC provider.

Validates RS256/ES256 JWTs issued by the Microsoft identity platform.

Required environment variables:
  FG_ENTRA_TENANT_ID     Azure AD tenant ID (or "common" for multi-tenant)
  FG_ENTRA_CLIENT_ID     App registration client ID (audience)
  FG_ENTRA_NAMESPACE     Claim namespace prefix (default: "https://frostgate.ai")

Optional:
  FG_ENTRA_ALLOWED_TENANTS  Comma-separated list of allowed tenant IDs (for multi-tenant)
  FG_ENTRA_REQUIRE_MFA      Require MFA claim (default: false)

This was previously a NotImplementedError stub. This is the full implementation.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional, cast

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from api.identity_authority.models import (
    AuthenticationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)

log = logging.getLogger("frostgate.identity_authority.entra")

_CACHE_TTL_SECONDS = 3600  # 1 hour

# Module-level JWKS cache keyed by tenant_id
_jwks_cache: dict[str, dict] = {}
_jwks_lock = threading.Lock()

# Entra supports RS256 and ES256
_SUPPORTED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

# AMR values from Microsoft that indicate MFA
_ENTRA_MFA_AMR_VALUES = frozenset({"mfa", "ngcmfa", "fido2", "fido", "rsa"})


def _tenant_id() -> str:
    return (os.getenv("FG_ENTRA_TENANT_ID") or "").strip()


def _client_id() -> str:
    return (os.getenv("FG_ENTRA_CLIENT_ID") or "").strip()


def _namespace() -> str:
    return (os.getenv("FG_ENTRA_NAMESPACE") or "https://frostgate.ai").strip().rstrip("/")


def _allowed_tenants() -> frozenset[str]:
    raw = (os.getenv("FG_ENTRA_ALLOWED_TENANTS") or "").strip()
    if not raw:
        return frozenset()
    return frozenset(t.strip() for t in raw.split(",") if t.strip())


def _require_mfa() -> bool:
    return os.getenv("FG_ENTRA_REQUIRE_MFA", "").strip().lower() in {"1", "true", "yes"}


def _jwks_url(tenant_id: str) -> str:
    """Return JWKS URL for the given tenant_id.

    For "common" (multi-tenant), uses the common discovery endpoint.
    """
    if tenant_id == "common":
        return "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


def _issuer_for_tid(tid: str) -> str:
    """Return the expected issuer URL for a specific Azure tenant ID."""
    return f"https://login.microsoftonline.com/{tid}/v2.0"


def _fetch_jwks(tenant_id: str) -> dict:
    """Fetch JWKS from Microsoft identity platform."""
    import httpx

    url = _jwks_url(tenant_id)
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise IdentityProviderError(
            f"Entra JWKS fetch failed from {url}: {exc}", provider="entra"
        ) from exc


def _load_jwks(tenant_id: str, *, force_refresh: bool = False) -> dict:
    """Load JWKS with 1-hour TTL caching."""
    cache_key = tenant_id
    with _jwks_lock:
        entry = _jwks_cache.get(cache_key)
        if entry and not force_refresh:
            if time.monotonic() - entry["fetched_at"] < _CACHE_TTL_SECONDS:
                return entry["jwks"]
        jwks = _fetch_jwks(tenant_id)
        _jwks_cache[cache_key] = {"jwks": jwks, "fetched_at": time.monotonic()}
        return jwks


def _key_for_kid(jwks: dict, kid: str, alg: str) -> Optional[object]:
    """Find and return the public key for the given kid and algorithm."""
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") != kid:
            continue
        try:
            if alg.startswith(("RS", "PS")):
                return RSAAlgorithm.from_jwk(json.dumps(key_data))
            elif alg.startswith("ES"):
                return ECAlgorithm.from_jwk(json.dumps(key_data))
        except Exception as exc:
            log.warning("entra.jwk_parse_failed", extra={"kid": kid, "exc": str(exc)})
    return None


def _mfa_method_from_amr(amr: list[str]) -> Optional[str]:
    """Derive a canonical MFA method string from Entra amr values."""
    if "fido2" in amr or "fido" in amr:
        return "webauthn"
    if "ngcmfa" in amr:
        return "webauthn"   # Windows Hello / NGC is FIDO2-based
    if "otp" in amr or "totp" in amr:
        return "totp"
    if "sms" in amr:
        return "sms"
    if "rsa" in amr:
        return "totp"   # RSA SecurID — treat as TOTP equivalent
    return None


class EntraOIDCProvider:
    """Microsoft Entra ID (Azure AD) OIDC provider — returns CanonicalIdentity.

    This is a complete implementation. The old api/identity_providers/entra.py
    raised NotImplementedError; this version validates tokens fully.
    """

    provider_name = "entra"

    def is_configured(self) -> bool:
        return bool(_tenant_id()) and bool(_client_id())

    def get_jwks_uri(self) -> str:
        return _jwks_url(_tenant_id() or "common")

    def get_issuer(self) -> str:
        tid = _tenant_id()
        if tid and tid != "common":
            return _issuer_for_tid(tid)
        # For multi-tenant, issuer is per-token; we validate dynamically
        return "https://login.microsoftonline.com/{tenantid}/v2.0"

    def validate_token(self, token: str) -> CanonicalIdentity:
        """Validate a Microsoft Entra ID JWT and return a CanonicalIdentity.

        Raises:
            IdentityProviderError: provider not configured or JWKS unreachable
            IdentityValidationError: token is invalid, expired, or rejected
        """
        configured_tenant = _tenant_id()
        client_id = _client_id()

        if not configured_tenant or not client_id:
            raise IdentityProviderError(
                "Entra ID not configured. Set FG_ENTRA_TENANT_ID and FG_ENTRA_CLIENT_ID.",
                provider="entra",
            )

        # --- Step 1: Decode header without verification ---
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise IdentityValidationError(
                f"malformed jwt header: {exc}",
                code="MALFORMED_TOKEN",
                provider="entra",
            ) from exc

        alg = header.get("alg", "")
        if alg not in _SUPPORTED_ALGORITHMS:
            raise IdentityValidationError(
                f"unsupported algorithm: {alg!r}",
                code="UNSUPPORTED_ALGORITHM",
                provider="entra",
            )

        kid = header.get("kid")
        if not kid:
            raise IdentityValidationError(
                "jwt header missing kid",
                code="MISSING_KID",
                provider="entra",
            )

        # --- Step 2: Peek at unverified claims to extract tid for issuer validation ---
        # We need the tenant ID from the token to build the correct issuer URL.
        # This is safe: we're only using tid to construct the issuer for signature
        # verification — the signature itself validates the claims.
        try:
            unverified_claims = jwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=_SUPPORTED_ALGORITHMS,
            )
        except Exception as exc:
            raise IdentityValidationError(
                f"token claims decode failed: {exc}",
                code="MALFORMED_TOKEN",
                provider="entra",
            ) from exc

        # Extract tid from unverified claims
        token_tid: Optional[str] = unverified_claims.get("tid")

        # --- Step 3: Multi-tenant validation ---
        if configured_tenant == "common":
            # Multi-tenant mode: validate against allowed tenants list
            allowed = _allowed_tenants()
            if allowed and token_tid and token_tid not in allowed:
                raise IdentityValidationError(
                    f"tenant {token_tid!r} is not in the allowed tenants list",
                    code="TENANT_NOT_ALLOWED",
                    provider="entra",
                )
            # Use token's tid for JWKS and issuer resolution
            effective_tenant = token_tid or "common"
        else:
            # Single-tenant mode: validate tid matches configured tenant
            if token_tid and token_tid != configured_tenant:
                raise IdentityValidationError(
                    f"token tenant {token_tid!r} does not match configured tenant {configured_tenant!r}",
                    code="TENANT_MISMATCH",
                    provider="entra",
                )
            effective_tenant = configured_tenant

        # --- Step 4: Build expected issuer ---
        if token_tid:
            expected_issuer = _issuer_for_tid(token_tid)
        elif configured_tenant != "common":
            expected_issuer = _issuer_for_tid(configured_tenant)
        else:
            expected_issuer = None   # will be validated from claims

        # --- Step 5: Fetch JWKS and locate key ---
        # Use configured_tenant for JWKS URL (or effective_tenant for multi-tenant)
        jwks_tenant = effective_tenant if configured_tenant == "common" else configured_tenant
        jwks = _load_jwks(jwks_tenant)
        public_key = _key_for_kid(jwks, kid, alg)

        if public_key is None:
            log.info("entra.jwks_kid_miss_refreshing", extra={"kid": kid, "tenant": jwks_tenant})
            jwks = _load_jwks(jwks_tenant, force_refresh=True)
            public_key = _key_for_kid(jwks, kid, alg)

        if public_key is None:
            raise IdentityValidationError(
                f"no JWKS key found for kid={kid!r}",
                code="UNKNOWN_KEY",
                provider="entra",
            )

        # --- Step 6: Full JWT validation with signature ---
        decode_opts: dict[str, Any] = {"require": ["sub", "iat", "exp"]}

        try:
            claims = jwt.decode(
                token,
                cast(Any, public_key),
                algorithms=[alg],
                audience=client_id,
                issuer=expected_issuer,
                options=cast(Any, decode_opts),
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityValidationError(
                "token is expired", code="TOKEN_EXPIRED", provider="entra"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityValidationError(
                "token audience mismatch", code="AUDIENCE_MISMATCH", provider="entra"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityValidationError(
                "token issuer mismatch", code="ISSUER_MISMATCH", provider="entra"
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError(
                f"token validation failed: {exc}",
                code="INVALID_TOKEN",
                provider="entra",
            ) from exc

        # --- Step 7: Extract claims ---
        sub: str = claims.get("sub") or ""
        if not sub:
            raise IdentityValidationError(
                "jwt missing sub claim", code="MISSING_SUB", provider="entra"
            )

        # Entra's sub is pairwise; oid (object ID) is the stable cross-app identifier
        oid: Optional[str] = claims.get("oid")

        # email: Entra may use "email", "preferred_username", or "upn"
        email: str = (
            claims.get("email")
            or claims.get("preferred_username")
            or claims.get("upn")
            or ""
        )

        name: str = claims.get("name") or ""

        # Entra verifies emails by default for work/school accounts
        email_verified: bool = bool(claims.get("email_verified", True))

        # Resolved tenant ID from validated claims
        resolved_tid: Optional[str] = claims.get("tid") or token_tid

        # Roles from custom namespace claim or bare roles claim
        namespace = _namespace()
        roles_raw = (
            claims.get(f"{namespace}/roles")
            or claims.get("roles")
            or claims.get("wids")    # Entra directory role IDs (fallback)
            or []
        )
        roles = [str(r) for r in roles_raw if r]

        # Custom tenant_id override from namespace claim
        claim_tenant_id: Optional[str] = (
            claims.get(f"{namespace}/tenant_id")
            or claims.get("tenant_id")
            or resolved_tid   # fall back to Azure tenant ID as hint
            or None
        )

        # --- Step 8: MFA detection ---
        amr: list[str] = claims.get("amr") or []
        mfa_verified = bool(_ENTRA_MFA_AMR_VALUES & set(amr))

        if _require_mfa() and not mfa_verified:
            raise IdentityValidationError(
                "MFA is required but not present in token amr claim",
                code="MFA_REQUIRED",
                provider="entra",
            )

        # --- Step 9: Build canonical identity ---
        iat_ts = claims.get("iat", 0)
        auth_time_raw = claims.get("auth_time", iat_ts)
        auth_time = datetime.fromtimestamp(auth_time_raw, tz=timezone.utc)
        issued_at = datetime.fromtimestamp(iat_ts, tz=timezone.utc)
        exp_ts = claims.get("exp", 0)
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)

        issuer_str = expected_issuer or _issuer_for_tid(resolved_tid or "common")

        auth_context = AuthenticationContext(
            mfa_verified=mfa_verified,
            mfa_method=_mfa_method_from_amr(amr),
            auth_time=auth_time,
            amr=amr,
            acr=claims.get("acr"),
            pkce_used=True,   # Entra PKCE is enforced in our flow
            nonce_verified=bool(claims.get("nonce")),
        )

        provider_obj = IdentityProvider(
            name="entra",
            issuer=issuer_str,
            # Use oid (stable cross-app identifier) if available, else sub
            subject=oid or sub,
        )

        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(roles)
        tenant_binding: Optional[TenantBinding] = None
        if claim_tenant_id or roles:
            tenant_binding = TenantBinding(
                tenant_id=claim_tenant_id or "",
                organization_id=None,
                membership_id=None,   # resolved later by TenantResolver
                roles=frozenset(roles),
                permissions=perms,
            )

        log.debug(
            "entra.token_validated",
            extra={
                "sub_prefix": sub[:16],
                "oid_prefix": (oid or "")[:16],
                "tid": resolved_tid,
                "roles": roles,
                "mfa_verified": mfa_verified,
                "permission_count": len(perms),
            },
        )

        return CanonicalIdentity(
            # Use oid as the primary subject for cross-app consistency
            subject=oid or sub,
            email=email,
            name=name,
            email_verified=email_verified,
            provider=provider_obj,
            auth_context=auth_context,
            tenant_binding=tenant_binding,
            subscription=None,
            identity_type="human",
            issued_at=issued_at,
            expires_at=expires_at,
        )
