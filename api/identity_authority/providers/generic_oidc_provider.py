"""api/identity_authority/providers/generic_oidc_provider.py — Generic OIDC provider.

Configured via environment variables:
  FG_OIDC_ISSUER         Issuer URL (discovery endpoint at /.well-known/openid-configuration)
  FG_OIDC_CLIENT_ID      Client ID (audience)
  FG_OIDC_AUDIENCE       Explicit audience override (optional)
  FG_OIDC_NAMESPACE      Custom claim namespace for roles/permissions

Automatically discovers JWKS URI from OpenID Connect Discovery.
Discovery document is cached with 1-hour TTL.
Supports RS256, RS384, RS512, ES256, ES384, ES512.
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

log = logging.getLogger("frostgate.identity_authority.generic_oidc")

_CACHE_TTL_SECONDS = 3600  # 1 hour

# Module-level caches
_discovery_cache: dict[str, dict] = {}
_jwks_cache: dict[str, dict] = {}
_discovery_lock = threading.Lock()
_jwks_lock = threading.Lock()

_SUPPORTED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}


def _issuer() -> str:
    return (os.getenv("FG_OIDC_ISSUER") or "").strip().rstrip("/")


def _client_id() -> str:
    return (os.getenv("FG_OIDC_CLIENT_ID") or "").strip()


def _audience() -> str:
    return (os.getenv("FG_OIDC_AUDIENCE") or _client_id()).strip()


def _namespace() -> str:
    return (
        (os.getenv("FG_OIDC_NAMESPACE") or "https://frostgate.ai").strip().rstrip("/")
    )


def _fetch_discovery(issuer: str) -> dict:
    """Fetch OIDC discovery document from /.well-known/openid-configuration."""
    import httpx

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise IdentityProviderError(
            f"OIDC discovery fetch failed from {url}: {exc}",
            provider="generic_oidc",
        ) from exc


def _load_discovery(issuer: str, *, force_refresh: bool = False) -> dict:
    """Load and cache the OIDC discovery document."""
    with _discovery_lock:
        entry = _discovery_cache.get(issuer)
        if entry and not force_refresh:
            if time.monotonic() - entry["fetched_at"] < _CACHE_TTL_SECONDS:
                return entry["doc"]
        doc = _fetch_discovery(issuer)
        _discovery_cache[issuer] = {"doc": doc, "fetched_at": time.monotonic()}
        return doc


def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch JWKS from the given URI."""
    import httpx

    try:
        resp = httpx.get(jwks_uri, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise IdentityProviderError(
            f"JWKS fetch failed from {jwks_uri}: {exc}",
            provider="generic_oidc",
        ) from exc


def _load_jwks(jwks_uri: str, *, force_refresh: bool = False) -> dict:
    """Load and cache JWKS with 1-hour TTL."""
    with _jwks_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry and not force_refresh:
            if time.monotonic() - entry["fetched_at"] < _CACHE_TTL_SECONDS:
                return entry["jwks"]
        jwks = _fetch_jwks(jwks_uri)
        _jwks_cache[jwks_uri] = {"jwks": jwks, "fetched_at": time.monotonic()}
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
            log.warning(
                "generic_oidc.jwk_parse_failed",
                extra={"kid": kid, "alg": alg, "exc": str(exc)},
            )
    return None


class GenericOIDCProvider:
    """Generic standards-compliant OIDC provider (Okta, PingIdentity, OneLogin, etc.).

    Uses OIDC Discovery to automatically find the JWKS URI.
    """

    provider_name = "generic_oidc"

    def is_configured(self) -> bool:
        return bool(_issuer()) and bool(_client_id())

    def get_jwks_uri(self) -> str:
        issuer = _issuer()
        if not issuer:
            return ""
        try:
            doc = _load_discovery(issuer)
            return doc.get("jwks_uri", "")
        except Exception:
            return ""

    def get_issuer(self) -> str:
        return _issuer()

    def validate_token(self, token: str) -> CanonicalIdentity:
        """Validate a generic OIDC JWT using discovery and return a CanonicalIdentity.

        Raises:
            IdentityProviderError: provider not configured or JWKS unreachable
            IdentityValidationError: token is invalid, expired, or rejected
        """
        issuer = _issuer()
        client_id = _client_id()
        audience = _audience()

        if not issuer or not client_id:
            raise IdentityProviderError(
                "Generic OIDC not configured. Set FG_OIDC_ISSUER and FG_OIDC_CLIENT_ID.",
                provider="generic_oidc",
            )

        # Decode header
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise IdentityValidationError(
                f"malformed jwt header: {exc}",
                code="MALFORMED_TOKEN",
                provider="generic_oidc",
            ) from exc

        alg = header.get("alg", "")
        if alg not in _SUPPORTED_ALGORITHMS:
            raise IdentityValidationError(
                f"unsupported algorithm: {alg!r}",
                code="UNSUPPORTED_ALGORITHM",
                provider="generic_oidc",
            )

        kid = header.get("kid")
        if not kid:
            raise IdentityValidationError(
                "jwt header missing kid",
                code="MISSING_KID",
                provider="generic_oidc",
            )

        # Discover JWKS URI
        try:
            discovery = _load_discovery(issuer)
        except IdentityProviderError:
            raise
        except Exception as exc:
            raise IdentityProviderError(
                f"OIDC discovery failed: {exc}", provider="generic_oidc"
            ) from exc

        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            raise IdentityProviderError(
                "OIDC discovery document missing jwks_uri",
                provider="generic_oidc",
            )

        # Fetch JWKS and locate key
        jwks = _load_jwks(jwks_uri)
        public_key = _key_for_kid(jwks, kid, alg)

        if public_key is None:
            log.info("generic_oidc.jwks_kid_miss_refreshing", extra={"kid": kid})
            jwks = _load_jwks(jwks_uri, force_refresh=True)
            public_key = _key_for_kid(jwks, kid, alg)

        if public_key is None:
            raise IdentityValidationError(
                f"no JWKS key found for kid={kid!r}",
                code="UNKNOWN_KEY",
                provider="generic_oidc",
            )

        decode_opts: dict[str, Any] = {"require": ["sub", "iat", "exp"]}

        try:
            claims = jwt.decode(
                token,
                cast(Any, public_key),
                algorithms=[alg],
                audience=audience or None,
                issuer=issuer,
                options=cast(Any, decode_opts),
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityValidationError(
                "token is expired", code="TOKEN_EXPIRED", provider="generic_oidc"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityValidationError(
                "token audience mismatch",
                code="AUDIENCE_MISMATCH",
                provider="generic_oidc",
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityValidationError(
                "token issuer mismatch",
                code="ISSUER_MISMATCH",
                provider="generic_oidc",
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError(
                f"token validation failed: {exc}",
                code="INVALID_TOKEN",
                provider="generic_oidc",
            ) from exc

        sub: str = claims.get("sub") or ""
        if not sub:
            raise IdentityValidationError(
                "jwt missing sub claim", code="MISSING_SUB", provider="generic_oidc"
            )

        email: str = claims.get("email") or claims.get("preferred_username") or ""
        name: str = claims.get("name") or claims.get("preferred_username") or ""
        email_verified: bool = bool(claims.get("email_verified", False))

        namespace = _namespace()
        roles_raw = claims.get(f"{namespace}/roles") or claims.get("roles") or []
        roles = [str(r) for r in roles_raw if r]

        tenant_id: Optional[str] = (
            claims.get(f"{namespace}/tenant_id") or claims.get("tenant_id") or None
        )

        amr: list[str] = claims.get("amr") or []
        mfa_verified = "mfa" in amr

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
            pkce_used=True,
            nonce_verified=bool(claims.get("nonce")),
        )

        provider_obj = IdentityProvider(
            name="generic_oidc",
            issuer=issuer,
            subject=sub,
        )

        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(roles)
        tenant_binding: Optional[TenantBinding] = None
        if tenant_id or roles:
            tenant_binding = TenantBinding(
                tenant_id=tenant_id or "",
                organization_id=None,
                membership_id=None,
                roles=frozenset(roles),
                permissions=perms,
            )

        log.debug(
            "generic_oidc.token_validated",
            extra={"sub_prefix": sub[:16], "issuer": issuer},
        )

        return CanonicalIdentity(
            subject=sub,
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


def _mfa_method_from_amr(amr: list[str]) -> Optional[str]:
    if "webauthn" in amr or "fido2" in amr:
        return "webauthn"
    if "otp" in amr or "totp" in amr:
        return "totp"
    if "sms" in amr:
        return "sms"
    return None
