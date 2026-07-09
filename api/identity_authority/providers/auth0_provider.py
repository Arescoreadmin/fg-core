"""api/identity_authority/providers/auth0_provider.py — Auth0 OIDC provider.

Wraps the existing api/identity_providers/auth0.py implementation to produce
CanonicalIdentity instead of ActorContext. Keeps the same JWKS caching strategy.

Required env vars:
  FG_AUTH0_DOMAIN     your-domain.auth0.com
  FG_AUTH0_AUDIENCE   https://api.frostgate.ai
  FG_AUTH0_NAMESPACE  https://frostgate.ai   (default)
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
from jwt.algorithms import RSAAlgorithm

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

log = logging.getLogger("frostgate.identity_authority.auth0")

_CACHE_TTL_SECONDS = 3600  # 1 hour

# Module-level JWKS cache — same pattern as existing auth0.py
_jwks_cache: dict[str, dict] = {}
_jwks_lock = threading.Lock()


def _domain() -> str:
    return (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")


def _audience() -> str:
    return (os.getenv("FG_AUTH0_AUDIENCE") or "").strip()


def _namespace() -> str:
    return (os.getenv("FG_AUTH0_NAMESPACE") or "https://frostgate.ai").strip().rstrip("/")


def _fetch_jwks(domain: str) -> dict:
    import httpx

    url = f"https://{domain}/.well-known/jwks.json"
    resp = httpx.get(url, timeout=10.0, follow_redirects=False)
    resp.raise_for_status()
    return resp.json()


def _load_jwks(domain: str, *, force_refresh: bool = False) -> dict:
    with _jwks_lock:
        entry = _jwks_cache.get(domain)
        if entry and not force_refresh:
            if time.monotonic() - entry["fetched_at"] < _CACHE_TTL_SECONDS:
                return entry["jwks"]
        jwks = _fetch_jwks(domain)
        _jwks_cache[domain] = {"jwks": jwks, "fetched_at": time.monotonic()}
        return jwks


def _rsa_key_for_kid(jwks: dict, kid: str) -> Optional[object]:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(key))
    return None


class Auth0OIDCProvider:
    """Auth0 RS256 OIDC provider — returns CanonicalIdentity."""

    provider_name = "auth0"

    def is_configured(self) -> bool:
        return bool(_domain())

    def get_jwks_uri(self) -> str:
        domain = _domain()
        return f"https://{domain}/.well-known/jwks.json"

    def get_issuer(self) -> str:
        domain = _domain()
        return f"https://{domain}/"

    def validate_token(self, token: str) -> CanonicalIdentity:
        """Validate an Auth0 RS256 JWT and return a CanonicalIdentity.

        Raises:
            IdentityProviderError: provider not configured
            IdentityValidationError: token is invalid
        """
        domain = _domain()
        if not domain:
            raise IdentityProviderError(
                "FG_AUTH0_DOMAIN is not configured", provider="auth0"
            )

        audience = _audience()
        namespace = _namespace()

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise IdentityValidationError(
                f"malformed jwt header: {exc}",
                code="MALFORMED_TOKEN",
                provider="auth0",
            ) from exc

        alg = header.get("alg", "")
        if alg != "RS256":
            raise IdentityValidationError(
                f"unsupported algorithm: {alg!r} (expected RS256)",
                code="UNSUPPORTED_ALGORITHM",
                provider="auth0",
            )

        kid = header.get("kid")
        if not kid:
            raise IdentityValidationError(
                "jwt header missing kid",
                code="MISSING_KID",
                provider="auth0",
            )

        try:
            jwks = _load_jwks(domain)
        except Exception as exc:
            raise IdentityProviderError(
                f"JWKS fetch failed: {exc}", provider="auth0"
            ) from exc

        rsa_key = _rsa_key_for_kid(jwks, kid)
        if rsa_key is None:
            log.info("auth0.jwks_kid_miss_refreshing", extra={"kid": kid})
            try:
                jwks = _load_jwks(domain, force_refresh=True)
            except Exception as exc:
                raise IdentityProviderError(
                    f"JWKS refresh failed: {exc}", provider="auth0"
                ) from exc
            rsa_key = _rsa_key_for_kid(jwks, kid)

        if rsa_key is None:
            raise IdentityValidationError(
                f"no JWKS key found for kid={kid!r}",
                code="UNKNOWN_KEY",
                provider="auth0",
            )

        issuer = f"https://{domain}/"
        decode_opts: dict[str, Any] = {"require": ["sub", "iat", "exp"]}

        try:
            claims = jwt.decode(
                token,
                cast(Any, rsa_key),
                algorithms=["RS256"],
                audience=audience or None,
                issuer=issuer,
                options=cast(Any, decode_opts),
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityValidationError(
                "token is expired", code="TOKEN_EXPIRED", provider="auth0"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityValidationError(
                "token audience mismatch", code="AUDIENCE_MISMATCH", provider="auth0"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityValidationError(
                "token issuer mismatch", code="ISSUER_MISMATCH", provider="auth0"
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError(
                f"token validation failed: {exc}",
                code="INVALID_TOKEN",
                provider="auth0",
            ) from exc

        sub: str = claims.get("sub") or ""
        if not sub:
            raise IdentityValidationError(
                "jwt missing sub claim", code="MISSING_SUB", provider="auth0"
            )

        email: str = claims.get("email") or ""
        name: str = claims.get("name") or ""
        email_verified: bool = bool(claims.get("email_verified", False))

        # Roles from Auth0 custom namespace claim, fallback to bare "roles"
        roles_raw = claims.get(f"{namespace}/roles") or claims.get("roles") or []
        roles = [str(r) for r in roles_raw if r]

        # Tenant binding from JWT (set by Auth0 Action from app_metadata)
        tenant_id: Optional[str] = (
            claims.get(f"{namespace}/tenant_id") or claims.get("tenant_id") or None
        )

        # MFA detection from amr claim
        amr: list[str] = claims.get("amr") or []
        mfa_verified = "mfa" in amr

        # Build AuthenticationContext
        iat_ts = claims.get("iat", 0)
        auth_time_raw = claims.get("auth_time", iat_ts)
        auth_time = datetime.fromtimestamp(auth_time_raw, tz=timezone.utc)
        issued_at = datetime.fromtimestamp(iat_ts, tz=timezone.utc)
        exp_ts = claims.get("exp", 0)
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)

        auth_context = AuthenticationContext(
            mfa_verified=mfa_verified,
            mfa_method=_mfa_method_from_amr(amr),
            auth_time=auth_time,
            amr=amr,
            acr=claims.get("acr"),
            pkce_used=True,   # Auth0 always uses PKCE in our flow
            nonce_verified=False,   # not tracked in access token flow
        )

        provider_obj = IdentityProvider(
            name="auth0",
            issuer=issuer,
            subject=sub,
        )

        # Build tenant binding if we have role info
        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(roles)
        tenant_binding: Optional[TenantBinding] = None
        if tenant_id or roles:
            tenant_binding = TenantBinding(
                tenant_id=tenant_id or "",
                organization_id=None,
                membership_id=None,   # resolved later by TenantResolver
                roles=frozenset(roles),
                permissions=perms,
            )

        log.debug(
            "auth0.token_validated",
            extra={
                "sub_prefix": sub[:16],
                "roles": roles,
                "mfa_verified": mfa_verified,
                "permission_count": len(perms),
            },
        )

        return CanonicalIdentity(
            subject=sub,
            email=email,
            name=name,
            email_verified=email_verified,
            provider=provider_obj,
            auth_context=auth_context,
            tenant_binding=tenant_binding,
            subscription=None,  # resolved later by SubscriptionResolver
            identity_type="human",
            issued_at=issued_at,
            expires_at=expires_at,
        )


def _mfa_method_from_amr(amr: list[str]) -> Optional[str]:
    """Derive a canonical MFA method string from OIDC amr values."""
    if "webauthn" in amr or "fido2" in amr:
        return "webauthn"
    if "otp" in amr or "totp" in amr:
        return "totp"
    if "sms" in amr:
        return "sms"
    return None
