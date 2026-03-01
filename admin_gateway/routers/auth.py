"""Authentication router.

Handles OIDC login, callback, and logout flows.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.oidc import OIDCClient
from admin_gateway.auth.session import SessionManager

log = logging.getLogger("admin-gateway.auth-router")

_SAFE_RETURN_TO_DEFAULT = "/admin/me"


def _is_safe_return_to(url: Optional[str]) -> bool:
    """Return True only for safe same-origin relative paths.

    Blocks protocol-relative (//evil.com) and absolute URLs (https://evil.com)
    to prevent open-redirect attacks.
    """
    if not url:
        return False
    if url.startswith("//") or "://" in url:
        return False
    return url.startswith("/")


def _safe_return_to(url: Optional[str]) -> str:
    """Return validated return_to or the safe default."""
    if _is_safe_return_to(url):
        return url  # type: ignore[return-value]
    if url:
        log.warning("Rejected unsafe return_to value: %r", url)
    return _SAFE_RETURN_TO_DEFAULT


router = APIRouter(prefix="/auth", tags=["auth"])


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
    # Check for dev bypass first
    if config.dev_bypass_allowed and not config.oidc_enabled:
        # Create dev session and redirect to return_to or /admin/me
        session_manager = SessionManager(config)
        csrf = CSRFProtection(config)

        session = get_dev_bypass_session(config)
        if session:
            redirect_url = _safe_return_to(return_to)
            response = RedirectResponse(url=redirect_url, status_code=302)
            session_manager.set_session_cookie(response, session)
            csrf.set_token_cookie(response)
            return response

    # OIDC login flow
    if not config.oidc_enabled:
        raise HTTPException(
            status_code=503,
            detail="Authentication not configured. Set FG_OIDC_* environment variables.",
        )

    # Generate authorization URL
    url, state, _ = await oidc.get_authorization_url()

    # Store validated return_to against state (allowlist-enforced)
    safe_url = _safe_return_to(return_to)
    if safe_url != _SAFE_RETURN_TO_DEFAULT or return_to:
        request.app.state.pending_returns = getattr(
            request.app.state, "pending_returns", {}
        )
        request.app.state.pending_returns[state] = safe_url

    return RedirectResponse(url=url, status_code=302)


@router.get("/csrf")
async def csrf_token(
    request: Request,
    csrf: CSRFProtection = Depends(get_csrf),
) -> dict:
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
    # Handle error from IdP
    if error:
        log.warning("OIDC error: %s - %s", error, error_description)
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed: {error_description or error}",
        )

    try:
        # Exchange code for tokens
        tokens = await oidc.exchange_code(code, state)

        # Create session from tokens
        session = await oidc.create_session_from_tokens(tokens)

        # Get return URL — re-validate to defend against corrupted state store
        _stored = None
        pending_returns = getattr(request.app.state, "pending_returns", {})
        if state in pending_returns:
            _stored = pending_returns.pop(state)
        return_to = _safe_return_to(_stored)

        # Set session cookie and redirect
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
    # Get current session for logging
    session = session_manager.get_session(request)
    if session:
        log.info("User logged out: %s", session.user_id)

    # Clear cookies
    response = RedirectResponse(url="/", status_code=302)
    session_manager.clear_session_cookie(response)
    csrf.clear_token_cookie(response)

    # TODO: Optionally redirect to IdP end_session_endpoint
    return response


@router.post("/logout")
async def logout_post(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    csrf: CSRFProtection = Depends(get_csrf),
):
    """Log out user (POST version for CSRF-safe logout)."""
    # Validate CSRF for POST
    csrf.validate_request(request)

    session = session_manager.get_session(request)
    if session:
        log.info("User logged out: %s", session.user_id)

    response = RedirectResponse(url="/", status_code=302)
    session_manager.clear_session_cookie(response)
    csrf.clear_token_cookie(response)

    return response
