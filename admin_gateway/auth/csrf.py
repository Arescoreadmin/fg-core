"""CSRF protection for state-changing requests.

Implements double-submit cookie pattern for CSRF protection.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from typing import Optional

from fastapi import HTTPException, Request, Response

from admin_gateway.auth.config import AuthConfig, get_auth_config

log = logging.getLogger("admin-gateway.csrf")

# Methods that modify state and require CSRF protection
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths that are exempt from CSRF (e.g., OIDC callback which comes from IdP)
CSRF_EXEMPT_PATHS = {
    "/auth/callback",
    "/auth/oidc/callback",
}


class CSRFProtection:
    """CSRF protection using double-submit cookie pattern.

    The token is:
    1. Generated and stored in a cookie (HttpOnly=False so JS can read it)
    2. Must be sent back in a header for state-changing requests
    3. Cookie and header values must match
    """

    TOKEN_TTL = 3600 * 8  # 8 hours

    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize CSRF protection.

        Args:
            config: Auth configuration
        """
        self.config = config or get_auth_config()
        self._secret = self.config.session_secret.encode()

    def _generate_token(self) -> str:
        """Generate a new CSRF token.

        Format: random_bytes + "." + timestamp + "." + hmac
        """
        random_part = secrets.token_urlsafe(24)
        timestamp = str(int(time.time()))
        data = f"{random_part}.{timestamp}".encode()
        signature = hmac.new(self._secret, data, hashlib.sha256).hexdigest()[:16]
        return f"{random_part}.{timestamp}.{signature}"

    def _validate_token(self, token: str) -> bool:
        """Validate a CSRF token.

        Checks:
        1. Token format is valid
        2. Signature is correct
        3. Token is not expired
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False

            random_part, timestamp_str, signature = parts

            # Verify signature
            data = f"{random_part}.{timestamp_str}".encode()
            expected = hmac.new(self._secret, data, hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(expected, signature):
                log.warning("CSRF token signature mismatch")
                return False

            # Check expiration
            timestamp = int(timestamp_str)
            if time.time() - timestamp > self.TOKEN_TTL:
                log.warning("CSRF token expired")
                return False

            return True

        except (ValueError, AttributeError) as e:
            log.warning("CSRF token validation error: %s", e)
            return False

    def get_token_from_request(
        self, request: Request
    ) -> tuple[Optional[str], Optional[str]]:
        """Get CSRF token from cookie and header.

        Returns:
            Tuple of (cookie_token, header_token)
        """
        cookie_token = request.cookies.get(self.config.csrf_cookie_name)
        header_token = request.headers.get(self.config.csrf_header_name)
        return cookie_token, header_token

    def validate_request(self, request: Request) -> None:
        """Validate CSRF for a request.

        Raises:
            HTTPException: If CSRF validation fails
        """
        method = request.method.upper()

        # Skip non-state-changing methods
        if method not in STATE_CHANGING_METHODS:
            return

        # Skip exempt paths
        if request.url.path in CSRF_EXEMPT_PATHS:
            return

        cookie_token, header_token = self.get_token_from_request(request)

        # Must have both tokens
        if not cookie_token:
            log.warning("CSRF cookie missing for %s %s", method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="CSRF token missing from cookie",
            )

        if not header_token:
            log.warning("CSRF header missing for %s %s", method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail=f"CSRF token missing from {self.config.csrf_header_name} header",
            )

        # Tokens must match (constant-time comparison)
        if not hmac.compare_digest(cookie_token, header_token):
            log.warning("CSRF token mismatch for %s %s", method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="CSRF token mismatch",
            )

        # Validate token format and signature
        if not self._validate_token(cookie_token):
            log.warning("CSRF token invalid for %s %s", method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="CSRF token invalid or expired",
            )

    def set_token_cookie(self, response: Response, token: Optional[str] = None) -> str:
        """Set CSRF token cookie on response.

        Args:
            response: FastAPI response object
            token: Token to set (generates new if not provided)

        Returns:
            The token that was set
        """
        if token is None:
            token = self._generate_token()

        response.set_cookie(
            key=self.config.csrf_cookie_name,
            value=token,
            httponly=False,  # JS needs to read this
            secure=self.config.is_prod,
            samesite="strict",
            path="/",
            max_age=self.TOKEN_TTL,
        )

        return token

    def clear_token_cookie(self, response: Response) -> None:
        """Clear CSRF token cookie."""
        response.delete_cookie(
            key=self.config.csrf_cookie_name,
            path="/",
        )


def requires_csrf_protection(method: str, path: str) -> bool:
    """Check if a request requires CSRF protection.

    Args:
        method: HTTP method
        path: Request path

    Returns:
        True if CSRF protection is required
    """
    if method.upper() not in STATE_CHANGING_METHODS:
        return False
    if path in CSRF_EXEMPT_PATHS:
        return False
    return True
