"""Auth0 RS256 JWT identity provider (H14).

Validates Bearer JWTs issued by Auth0, extracts:
  - sub                          → actor_subject (non-repudiation anchor)
  - email                        → actor_email
  - name                         → actor_name
  - {FG_AUTH0_NAMESPACE}/roles   → actor_roles (e.g. ["qa_reviewer"])

Configuration (add to .env / Railway):
  FG_AUTH0_DOMAIN     your-domain.auth0.com
  FG_AUTH0_AUDIENCE   https://api.frostgate.ai
  FG_AUTH0_NAMESPACE  https://frostgate.ai   (default)

Auth0 Action to inject roles (paste into Auth0 Dashboard → Actions → Flows → Login):

  exports.onExecutePostLogin = async (event, api) => {
    const namespace = 'https://frostgate.ai';
    const roles = event.authorization?.roles ?? [];
    api.idToken.setCustomClaim(`${namespace}/roles`, roles);
    api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
    api.accessToken.setCustomClaim(`${namespace}/tenant_id`,
      event.user.app_metadata?.tenant_id ?? null);
  };

JWKS keys are cached with a 1-hour TTL to survive key rotation without a
restart. On kid mismatch, the cache is invalidated and refetched once.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Optional

import jwt
from jwt.algorithms import RSAAlgorithm

from api.actor_context import ActorContext, roles_to_permissions

log = logging.getLogger("frostgate.identity.auth0")

_CACHE_TTL_SECONDS = 3600  # 1 hour

# Module-level JWKS cache keyed by domain
_jwks_cache: dict[str, dict] = {}
_jwks_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def _domain() -> str:
    return (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")


def _audience() -> str:
    return (os.getenv("FG_AUTH0_AUDIENCE") or "").strip()


def _namespace() -> str:
    return (os.getenv("FG_AUTH0_NAMESPACE") or "https://frostgate.ai").strip().rstrip("/")


# ---------------------------------------------------------------------------
# JWKS fetching and caching
# ---------------------------------------------------------------------------


def _fetch_jwks(domain: str) -> dict:
    import httpx  # lazy import — httpx is in requirements but not always in test envs

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


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def validate_auth0_token(token: str) -> ActorContext:
    """Validate an Auth0 RS256 Bearer JWT and return an ActorContext.

    Raises ValueError on any validation failure (expired, bad signature,
    missing claims, unsupported algorithm, misconfigured domain).
    """
    domain = _domain()
    if not domain:
        raise ValueError("FG_AUTH0_DOMAIN is not configured")

    audience = _audience()
    namespace = _namespace()

    # Decode header without verification to get kid + alg
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise ValueError(f"malformed jwt header: {exc}") from exc

    alg = header.get("alg", "")
    if alg != "RS256":
        raise ValueError(f"unsupported algorithm: {alg!r} (expected RS256)")

    kid = header.get("kid")
    if not kid:
        raise ValueError("jwt header missing kid")

    # Fetch JWKS and locate the signing key
    jwks = _load_jwks(domain)
    rsa_key = _rsa_key_for_kid(jwks, kid)

    if rsa_key is None:
        # Key not found — may be a recent rotation; refresh cache once
        log.info("auth0.jwks_kid_miss_refreshing", extra={"kid": kid})
        jwks = _load_jwks(domain, force_refresh=True)
        rsa_key = _rsa_key_for_kid(jwks, kid)

    if rsa_key is None:
        raise ValueError(f"no JWKS key found for kid={kid!r}")

    issuer = f"https://{domain}/"
    decode_opts: dict = {"require": ["sub", "iat", "exp"]}

    try:
        claims = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=audience or None,
            issuer=issuer,
            options=decode_opts,
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("token is expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise ValueError("token audience mismatch") from exc
    except jwt.InvalidIssuerError as exc:
        raise ValueError("token issuer mismatch") from exc
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"token validation failed: {exc}") from exc

    sub: str = claims.get("sub") or ""
    if not sub:
        raise ValueError("jwt missing sub claim")

    email: str = claims.get("email") or ""
    name: str = claims.get("name") or ""

    # Roles from Auth0 custom namespace claim, with fallback to bare "roles"
    roles_raw = claims.get(f"{namespace}/roles") or claims.get("roles") or []
    roles = [str(r) for r in roles_raw if r]

    permissions = roles_to_permissions(roles)

    # Optional tenant binding from JWT (set by Auth0 Action from app_metadata)
    tenant_id: Optional[str] = (
        claims.get(f"{namespace}/tenant_id") or claims.get("tenant_id") or None
    )

    log.debug(
        "auth0.token_validated",
        extra={
            "sub_prefix": sub[:16],
            "roles": roles,
            "permission_count": len(permissions),
        },
    )

    return ActorContext(
        subject=sub,
        email=email,
        name=name,
        permissions=permissions,
        roles=roles,
        auth_source="oidc_auth0",
        tenant_id=tenant_id,
    )
