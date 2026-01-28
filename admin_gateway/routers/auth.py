"""Authentication router.

Handles OIDC login, callback, and logout flows.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.oidc import OIDCClient
from admin_gateway.auth.session import SessionManager

log = logging.getLogger("admin-gateway.auth-router")

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
            redirect_url = return_to or "/admin/me"
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

    # Store return_to in session (using state as key)
    # In a real implementation, you'd store this in a more persistent way
    if return_to:
        request.app.state.pending_returns = getattr(
            request.app.state, "pending_returns", {}
        )
        request.app.state.pending_returns[state] = return_to

    return RedirectResponse(url=url, status_code=302)


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

        # Get return URL
        return_to = "/admin/me"
        pending_returns = getattr(request.app.state, "pending_returns", {})
        if state in pending_returns:
            return_to = pending_returns.pop(state)

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
