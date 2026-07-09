"""api/identity_authority/providers/google_provider.py — Google Workspace / Google OIDC provider.

Validates Google-issued ID tokens (RS256 only).

Required env vars:
  FG_GOOGLE_CLIENT_ID     Google OAuth2 client ID (audience)

Google JWKS: https://www.googleapis.com/oauth2/v3/certs
Google issuer: https://accounts.google.com

Optional:
  FG_GOOGLE_ALLOWED_DOMAINS  Comma-separated allowed Workspace domains (e.g. "acme.com")
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

log = logging.getLogger("frostgate.identity_authority.google")

_CACHE_TTL_SECONDS = 3600  # 1 hour
_GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
_GOOGLE_ISSUER = "https://accounts.google.com"

_jwks_cache: dict[str, dict] = {}
_jwks_lock = threading.Lock()


def _client_id() -> str:
    return (os.getenv("FG_GOOGLE_CLIENT_ID") or "").strip()


def _namespace() -> str:
    return (
        (os.getenv("FG_GOOGLE_NAMESPACE") or "https://frostgate.ai").strip().rstrip("/")
    )


def _allowed_domains() -> frozenset[str]:
    raw = (os.getenv("FG_GOOGLE_ALLOWED_DOMAINS") or "").strip()
    if not raw:
        return frozenset()
    return frozenset(d.strip().lower() for d in raw.split(",") if d.strip())


def _fetch_jwks() -> dict:
    import httpx

    try:
        resp = httpx.get(_GOOGLE_JWKS_URL, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise IdentityProviderError(
            f"Google JWKS fetch failed: {exc}", provider="google"
        ) from exc


def _load_jwks(*, force_refresh: bool = False) -> dict:
    cache_key = "google"
    with _jwks_lock:
        entry = _jwks_cache.get(cache_key)
        if entry and not force_refresh:
            if time.monotonic() - entry["fetched_at"] < _CACHE_TTL_SECONDS:
                return entry["jwks"]
        jwks = _fetch_jwks()
        _jwks_cache[cache_key] = {"jwks": jwks, "fetched_at": time.monotonic()}
        return jwks


def _rsa_key_for_kid(jwks: dict, kid: str) -> Optional[object]:
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            try:
                return RSAAlgorithm.from_jwk(json.dumps(key_data))
            except Exception as exc:
                log.warning(
                    "google.jwk_parse_failed", extra={"kid": kid, "exc": str(exc)}
                )
    return None


class GoogleOIDCProvider:
    """Google Workspace / Google OIDC identity provider — returns CanonicalIdentity."""

    provider_name = "google"

    def is_configured(self) -> bool:
        return bool(_client_id())

    def get_jwks_uri(self) -> str:
        return _GOOGLE_JWKS_URL

    def get_issuer(self) -> str:
        return _GOOGLE_ISSUER

    def validate_token(self, token: str) -> CanonicalIdentity:
        """Validate a Google-issued ID token and return a CanonicalIdentity.

        Raises:
            IdentityProviderError: provider not configured or JWKS unreachable
            IdentityValidationError: token is invalid, expired, or rejected
        """
        client_id = _client_id()
        if not client_id:
            raise IdentityProviderError(
                "Google OIDC not configured. Set FG_GOOGLE_CLIENT_ID.",
                provider="google",
            )

        # Decode header
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise IdentityValidationError(
                f"malformed jwt header: {exc}",
                code="MALFORMED_TOKEN",
                provider="google",
            ) from exc

        alg = header.get("alg", "")
        if alg != "RS256":
            raise IdentityValidationError(
                f"unsupported algorithm: {alg!r} (Google uses RS256)",
                code="UNSUPPORTED_ALGORITHM",
                provider="google",
            )

        kid = header.get("kid")
        if not kid:
            raise IdentityValidationError(
                "jwt header missing kid",
                code="MISSING_KID",
                provider="google",
            )

        # Fetch JWKS and locate key
        jwks = _load_jwks()
        public_key = _rsa_key_for_kid(jwks, kid)

        if public_key is None:
            log.info("google.jwks_kid_miss_refreshing", extra={"kid": kid})
            jwks = _load_jwks(force_refresh=True)
            public_key = _rsa_key_for_kid(jwks, kid)

        if public_key is None:
            raise IdentityValidationError(
                f"no JWKS key found for kid={kid!r}",
                code="UNKNOWN_KEY",
                provider="google",
            )

        decode_opts: dict[str, Any] = {"require": ["sub", "iat", "exp"]}

        try:
            claims = jwt.decode(
                token,
                cast(Any, public_key),
                algorithms=["RS256"],
                audience=client_id,
                issuer=_GOOGLE_ISSUER,
                options=cast(Any, decode_opts),
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityValidationError(
                "token is expired", code="TOKEN_EXPIRED", provider="google"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityValidationError(
                "token audience mismatch", code="AUDIENCE_MISMATCH", provider="google"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityValidationError(
                "token issuer mismatch", code="ISSUER_MISMATCH", provider="google"
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError(
                f"token validation failed: {exc}",
                code="INVALID_TOKEN",
                provider="google",
            ) from exc

        sub: str = claims.get("sub") or ""
        if not sub:
            raise IdentityValidationError(
                "jwt missing sub claim", code="MISSING_SUB", provider="google"
            )

        email: str = claims.get("email") or ""
        name: str = claims.get("name") or ""
        email_verified: bool = bool(claims.get("email_verified", False))

        # Google Workspace hosted domain restriction
        hd: Optional[str] = claims.get("hd")  # hosted domain
        allowed_domains = _allowed_domains()
        if allowed_domains:
            token_domain = (hd or "").lower()
            if not token_domain or token_domain not in allowed_domains:
                raise IdentityValidationError(
                    f"Google Workspace domain {hd!r} is not in the allowed domains list",
                    code="DOMAIN_NOT_ALLOWED",
                    provider="google",
                )

        # Roles from namespace claim
        namespace = _namespace()
        roles_raw = claims.get(f"{namespace}/roles") or claims.get("roles") or []
        roles = [str(r) for r in roles_raw if r]

        tenant_id: Optional[str] = (
            claims.get(f"{namespace}/tenant_id") or claims.get("tenant_id") or None
        )

        # Google does not emit amr; MFA state is not available in standard tokens
        amr: list[str] = []
        mfa_verified = False

        iat_ts = claims.get("iat", 0)
        auth_time_raw = claims.get("auth_time", iat_ts)
        auth_time = datetime.fromtimestamp(auth_time_raw, tz=timezone.utc)
        issued_at = datetime.fromtimestamp(iat_ts, tz=timezone.utc)
        exp_ts = claims.get("exp", 0)
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)

        auth_context = AuthenticationContext(
            mfa_verified=mfa_verified,
            mfa_method=None,
            auth_time=auth_time,
            amr=amr,
            acr=claims.get("acr"),
            pkce_used=True,
            nonce_verified=bool(claims.get("nonce")),
        )

        provider_obj = IdentityProvider(
            name="google",
            issuer=_GOOGLE_ISSUER,
            subject=sub,
        )

        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(roles)
        tenant_binding: Optional[TenantBinding] = None
        if tenant_id or roles:
            tenant_binding = TenantBinding(
                tenant_id=tenant_id or "",
                organization_id=hd,
                membership_id=None,
                roles=frozenset(roles),
                permissions=perms,
            )

        log.debug(
            "google.token_validated",
            extra={
                "sub_prefix": sub[:16],
                "hd": hd,
                "email_verified": email_verified,
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
            subscription=None,
            identity_type="human",
            issued_at=issued_at,
            expires_at=expires_at,
        )
