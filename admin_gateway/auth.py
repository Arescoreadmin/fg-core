"""Authentication and authorization helpers for admin-gateway."""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlencode

import httpx
from fastapi import Depends, HTTPException, Request, status


OIDC_ENV_VARS = (
    "FG_OIDC_ISSUER",
    "FG_OIDC_CLIENT_ID",
    "FG_OIDC_CLIENT_SECRET",
    "FG_OIDC_REDIRECT_URL",
)

REQUIRED_SCOPES = {
    "console:admin",
    "product:read",
    "product:write",
    "keys:read",
    "keys:write",
    "policies:write",
    "audit:read",
}

DEV_USER = {
    "sub": "dev-user",
    "email": "dev@frostgate.local",
    "scopes": sorted(REQUIRED_SCOPES),
    "tenants": ["tenant-dev"],
}

_OIDC_CACHE: dict[str, dict] = {}
_JWKS_CACHE: dict[str, dict] = {}


@dataclass(frozen=True)
class AuthUser:
    sub: str
    email: Optional[str]
    scopes: list[str]
    tenants: list[str]
    exp: Optional[int]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def environment() -> str:
    return os.getenv("FG_ENV", "dev").strip().lower()


def dev_bypass_enabled() -> bool:
    return _env_bool("FG_DEV_AUTH_BYPASS", False)


def require_session_secret() -> str:
    secret = os.getenv("FG_SESSION_SECRET")
    if secret:
        return secret
    if environment() == "prod":
        raise RuntimeError("FG_SESSION_SECRET must be set in production.")
    return secrets.token_urlsafe(32)


def require_oidc_env() -> None:
    if environment() != "prod":
        return
    missing = [name for name in OIDC_ENV_VARS if not os.getenv(name)]
    if missing:
        raise RuntimeError(
            f"Missing OIDC configuration in production: {', '.join(missing)}"
        )


def session_max_age() -> int:
    return int(os.getenv("FG_SESSION_MAX_AGE", "3600"))


def _from_session(payload: dict) -> Optional[AuthUser]:
    try:
        exp = payload.get("exp")
        if exp is not None and int(exp) < int(time.time()):
            return None
        return AuthUser(
            sub=payload["sub"],
            email=payload.get("email"),
            scopes=list(payload.get("scopes", [])),
            tenants=list(payload.get("tenants", [])),
            exp=exp,
        )
    except KeyError:
        return None


def get_user_from_session(request: Request) -> Optional[AuthUser]:
    data = request.session.get("user") if hasattr(request, "session") else None
    if not data:
        return None
    user = _from_session(data)
    if not user:
        request.session.pop("user", None)
        return None
    return user


def set_session_user(request: Request, user: AuthUser) -> None:
    request.session["user"] = {
        "sub": user.sub,
        "email": user.email,
        "scopes": user.scopes,
        "tenants": user.tenants,
        "exp": user.exp,
    }


def ensure_dev_user(request: Request) -> Optional[AuthUser]:
    if environment() == "prod":
        return None
    if not dev_bypass_enabled():
        return None
    user = AuthUser(
        sub=DEV_USER["sub"],
        email=DEV_USER["email"],
        scopes=list(DEV_USER["scopes"]),
        tenants=list(DEV_USER["tenants"]),
        exp=int(time.time()) + session_max_age(),
    )
    set_session_user(request, user)
    return user


def get_current_user(request: Request) -> AuthUser:
    user = get_user_from_session(request)
    if not user:
        user = ensure_dev_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    request.state.user = user
    return user


def require_scopes(required: Iterable[str]):
    required_set = set(required)

    def _dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        missing = required_set.difference(user.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scopes: {', '.join(sorted(missing))}",
            )
        return user

    return _dependency


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def get_allowed_tenant(
    request: Request,
    tenant_id: Optional[str],
    user: AuthUser,
) -> Optional[str]:
    if tenant_id and tenant_id not in user.tenants:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant access denied",
        )
    request.state.tenant_id = tenant_id
    return tenant_id


async def _fetch_oidc_config(issuer: str) -> dict:
    cached = _OIDC_CACHE.get(issuer)
    if cached:
        return cached
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
    _OIDC_CACHE[issuer] = data
    return data


async def _fetch_jwks(jwks_uri: str) -> dict:
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        data = response.json()
    _JWKS_CACHE[jwks_uri] = data
    return data


def _parse_scopes(claims: dict, token_scope: Optional[str]) -> list[str]:
    if token_scope:
        return token_scope.split()
    if "scope" in claims and isinstance(claims["scope"], str):
        return claims["scope"].split()
    if "scopes" in claims and isinstance(claims["scopes"], list):
        return list(claims["scopes"])
    if "scp" in claims and isinstance(claims["scp"], list):
        return list(claims["scp"])
    return []


async def build_login_redirect(request: Request) -> str:
    issuer = os.getenv("FG_OIDC_ISSUER")
    client_id = os.getenv("FG_OIDC_CLIENT_ID")
    redirect_uri = os.getenv("FG_OIDC_REDIRECT_URL")
    if not issuer or not client_id or not redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC configuration missing",
        )
    config = await _fetch_oidc_config(issuer)
    auth_endpoint = config["authorization_endpoint"]
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce
    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
    }
    return f"{auth_endpoint}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> dict:
    issuer = os.getenv("FG_OIDC_ISSUER")
    client_id = os.getenv("FG_OIDC_CLIENT_ID")
    client_secret = os.getenv("FG_OIDC_CLIENT_SECRET")
    redirect_uri = os.getenv("FG_OIDC_REDIRECT_URL")
    if not issuer or not client_id or not client_secret or not redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC configuration missing",
        )
    config = await _fetch_oidc_config(issuer)
    token_endpoint = config["token_endpoint"]
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(token_endpoint, data=payload)
        response.raise_for_status()
        return response.json()


async def verify_id_token(id_token: str, nonce: str) -> dict:
    from jose import JWTError, jwt

    issuer = os.getenv("FG_OIDC_ISSUER")
    client_id = os.getenv("FG_OIDC_CLIENT_ID")
    if not issuer or not client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC configuration missing",
        )
    config = await _fetch_oidc_config(issuer)
    jwks = await _fetch_jwks(config["jwks_uri"])
    try:
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        keys = jwks.get("keys", [])
        key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[header.get("alg", "RS256")],
            audience=client_id,
            issuer=issuer,
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from exc
    if claims.get("nonce") != nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token nonce"
        )
    return claims


def build_user_from_claims(claims: dict, token_scope: Optional[str]) -> AuthUser:
    scopes = _parse_scopes(claims, token_scope)
    tenants = claims.get("tenants") or claims.get("allowed_tenants") or []
    if isinstance(tenants, str):
        tenants = [t for t in tenants.split(",") if t]
    return AuthUser(
        sub=claims.get("sub", "unknown"),
        email=claims.get("email"),
        scopes=scopes,
        tenants=list(tenants),
        exp=claims.get("exp"),
    )
