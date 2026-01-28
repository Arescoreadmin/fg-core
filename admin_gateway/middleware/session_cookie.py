"""Session cookie hardening middleware."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SessionCookieMiddleware(BaseHTTPMiddleware):
    """Ensure the session cookie is always HttpOnly."""

    def __init__(self, app, cookie_name: str = "session"):
        super().__init__(app)
        self.cookie_name = cookie_name

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        headers = response.headers
        cookies = headers.getlist("set-cookie")
        if not cookies:
            return response

        updated = []
        changed = False
        for cookie in cookies:
            if cookie.startswith(f"{self.cookie_name}=") and "httponly" not in (
                cookie.lower()
            ):
                cookie = f"{cookie}; HttpOnly"
                changed = True
            updated.append(cookie)

        if not changed:
            return response

        for _ in range(len(cookies)):
            headers.pop("set-cookie", None)
        for cookie in updated:
            headers.append("set-cookie", cookie)

        return response
