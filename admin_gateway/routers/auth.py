"""Authentication router.

Handles OIDC login, callback, and logout flows.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.oidc import OIDCClient
from admin_gateway.auth.session import SessionManager

log = logging.getLogger("admin-gateway.auth-router")

router = APIRouter(prefix="/auth", tags=["auth"])

_DEFAULT_RETURN_TO = "/admin/me"
_MAX_RETURN_TO_LEN = 2048


def _safe_return_to(value: Optional[str]) -> Optional[str]:
    """Return ``value`` only if it is a same-origin relative path, else None.

    Post-login redirects must never leave the gateway origin (CWE-601).
    Accepts a single leading ``/`` path; rejects absolute and scheme URLs,
    protocol-relative ``//host``, backslashes (browsers read them as ``/``)
    and control characters (browsers strip tab/newline, turning ``/\\t/host``
    into ``//host``).
    """
    if not value or len(value) > _MAX_RETURN_TO_LEN:
        return None
    if "\\" in value or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    return value


def get_oidc_client(config: AuthConfig = Depends(get_auth_config)) -> OIDCClient:
    """Get OIDC client dependency."""
    return OIDCClient(config)


def get_session_manager(
    config: AuthConfig = Depends(get_auth_config),
) -> SessionManager:
    """Get session manager dependency."""
    return SessionManager(config)


def get_csrf(config: AuthConfig = Depends(get_auth_config)) -> CSRFProtection:
    """Get CSRF protection dependency."""
    return CSRFProtection(config)


@router.get("/login")
async def login(
    request: Request,
    return_to: Optional[str] = Query(None, description="URL to return to after login"),
    oidc: OIDCClient = Depends(get_oidc_client),
    config: AuthConfig = Depends(get_auth_config),
):
    """Initiate OIDC login flow.

    If OIDC is not configured and dev bypass is enabled, creates a dev session.
    Otherwise, redirects to the OIDC provider.
    """
    safe_return_to = _safe_return_to(return_to)
    if return_to and safe_return_to is None:
        # Value is attacker-controlled: log its length only, never the value.
        log.warning("auth_login_return_to_rejected length=%d", len(return_to))

    if config.dev_bypass_allowed and not config.oidc_enabled:
        session_manager = SessionManager(config)
        csrf = CSRFProtection(config)

        session = get_dev_bypass_session(config)
        if session:
            redirect_url = safe_return_to or _DEFAULT_RETURN_TO
            response = RedirectResponse(url=redirect_url, status_code=302)
            session_manager.set_session_cookie(response, session)
            csrf.set_token_cookie(response)
            return response

    if not config.oidc_enabled:
        raise HTTPException(
            status_code=503,
            detail="Authentication not configured. Set FG_OIDC_* environment variables.",
        )

    url, state, _ = await oidc.get_authorization_url()

    if safe_return_to:
        request.app.state.pending_returns = getattr(
            request.app.state, "pending_returns", {}
        )
        request.app.state.pending_returns[state] = safe_return_to

    return RedirectResponse(url=url, status_code=302)


@router.get("/csrf")
async def csrf_token(
    request: Request,
    csrf: CSRFProtection = Depends(get_csrf),
) -> JSONResponse:
    """Return a CSRF token tied to the session."""
    response = JSONResponse(content={})
    token = csrf.set_token_cookie(response)
    response = JSONResponse(content={"csrf_token": token})
    csrf.set_token_cookie(response, token)
    return response


@router.get("/callback")
async def callback(
    request: Request,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State parameter"),
    error: Optional[str] = Query(None, description="Error code"),
    error_description: Optional[str] = Query(None, description="Error description"),
    oidc: OIDCClient = Depends(get_oidc_client),
    session_manager: SessionManager = Depends(get_session_manager),
    csrf: CSRFProtection = Depends(get_csrf),
):
    """Handle OIDC callback.

    Exchanges authorization code for tokens and creates session.
    """
    if error:
        log.warning("OIDC error: %s - %s", error, error_description)
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed: {error_description or error}",
        )

    try:
        tokens = await oidc.exchange_code(code, state)
        session = await oidc.create_session_from_tokens(tokens)

        # Generic OIDC authentication is not tenant authorization. Only the
        # /identity invitation binding flow may issue a tenant-scoped session.
        session.tenant_id = None
        session.scopes = set()
        session.claims = {
            k: v
            for k, v in session.claims.items()
            if k not in {"tenant_id", "allowed_tenants", "roles", "fg_scopes"}
        }

        pending_returns = getattr(request.app.state, "pending_returns", {})
        # Re-validate at the sink (defence in depth); fall back to the default.
        return_to = (
            _safe_return_to(pending_returns.pop(state, None)) or _DEFAULT_RETURN_TO
        )

        response = RedirectResponse(url=return_to, status_code=302)
        session_manager.set_session_cookie(response, session)
        csrf.set_token_cookie(response)

        log.info("User logged in: %s", session.user_id)
        return response

    except ValueError as e:
        log.warning("OIDC callback error: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception("OIDC callback failed: %s", e)
        raise HTTPException(status_code=500, detail="Authentication failed")


@router.get("/logout")
async def logout(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    csrf: CSRFProtection = Depends(get_csrf),
    config: AuthConfig = Depends(get_auth_config),
):
    """Log out user.

    Clears session cookie and optionally redirects to IdP logout.
    """
    session = session_manager.get_session(request)
    if session:
        log.info("User logged out: %s", session.user_id)

    response = RedirectResponse(url="/", status_code=302)
    session_manager.clear_session_cookie(response)
    csrf.clear_token_cookie(response)

    return response


@router.post("/token-exchange")
async def token_exchange(
    request: Request,
    oidc: OIDCClient = Depends(get_oidc_client),
    session_manager: SessionManager = Depends(get_session_manager),
    csrf: CSRFProtection = Depends(get_csrf),
    config: AuthConfig = Depends(get_auth_config),
):
    """Exchange a bearer token for a gateway session cookie.

    Accepts an OIDC access token in the Authorization header and issues a
    authentication-only signed session cookie. Raw provider tokens and
    tenant authorization claims are not stored in the session. All
    gateway→core proxy calls use the internal trust
    credential (AG_CORE_INTERNAL_TOKEN), not the user bearer token.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        JSON {"session_id", "expires_in", "user_id"} and sets Set-Cookie.
    """
    if not config.oidc_enabled:
        raise HTTPException(
            status_code=503,
            detail="OIDC not configured — set FG_OIDC_* or FG_KEYCLOAK_* environment variables",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    access_token = auth_header[len("Bearer ") :].strip()
    if not access_token:
        raise HTTPException(status_code=401, detail="Bearer token required")

    try:
        # verify_access_token enforces signature, issuer, audience, and expiry.
        # Any failure raises HTTPException(401) — no fallback path.
        claims = await oidc.verify_access_token(access_token)

        session = session_manager.create_session(
            user_id=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name") or claims.get("preferred_username"),
            scopes=set(),
            claims={
                k: v
                for k, v in claims.items()
                if k not in {"tenant_id", "allowed_tenants", "roles", "fg_scopes"}
            },
            tenant_id=None,
        )

        response = JSONResponse(
            content={
                "session_id": session.session_id,
                "expires_in": session.remaining_ttl,
                "user_id": session.user_id,
            }
        )
        session_manager.set_session_cookie(response, session)
        csrf.set_token_cookie(response)
        log.info("Token exchange: session issued for sub=%s", claims["sub"])
        return response

    except HTTPException:
        raise
    except Exception as e:
        log.warning("Token exchange failed: %s", e)
        raise HTTPException(status_code=401, detail="Token exchange failed")


@router.post("/logout")
async def logout_post(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    csrf: CSRFProtection = Depends(get_csrf),
):
    """Log out user (POST version for CSRF-safe logout)."""
    csrf.validate_request(request)

    session = session_manager.get_session(request)
    if session:
        log.info("User logged out: %s", session.user_id)

    response = RedirectResponse(url="/", status_code=302)
    session_manager.clear_session_cookie(response)
    csrf.clear_token_cookie(response)

    return response
