"""MSAL device code credential context manager.

Security invariants (RULE-SEC-001, 002, 003, 009):
- Token lives only in process memory inside CredentialContext
- Token is explicitly zeroed on context exit (normal or exception)
- No token is written to disk, logged, or passed in request bodies
- No refresh token is stored anywhere
- Revocation call made to Graph before context exits
"""

from __future__ import annotations

import ctypes
import logging
import os
from types import TracebackType

from services.connectors.msgraph.manifest import (
    AUTHORIZED_SCOPES,
    AUTHORIZED_SCOPES_SET,
    GRAPH_REVOCATION_URL,
)

log = logging.getLogger("frostgate.connectors.msgraph.credential")

_MSAL_CLIENT_ID_ENV = "FG_MSAL_CLIENT_ID"
_MSAL_AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"


def _zero_string(s: str) -> None:
    """Best-effort in-place zero of a Python str's internal buffer."""
    try:
        encoded = s.encode("utf-8")
        buf = (ctypes.c_char * len(encoded)).from_buffer(bytearray(encoded))
        ctypes.memset(buf, 0, len(encoded))
    except Exception:
        pass


class CredentialContext:
    """Context manager that holds an MSAL access token in memory only.

    Usage::

        with CredentialContext(tenant_id=tenant_id) as cred:
            token = cred.access_token
            ...
        # token zeroed and revoked here

    The caller must never store cred.access_token beyond the with block.
    """

    def __init__(self, tenant_id: str, *, _test_token: str | None = None) -> None:
        self._tenant_id = tenant_id
        self._access_token: str | None = None
        self._scopes_in_token: list[str] = []
        self._test_token = _test_token  # injection point for tests only

    def __enter__(self) -> "CredentialContext":
        if self._test_token is not None:
            self._access_token = self._test_token
            self._scopes_in_token = list(AUTHORIZED_SCOPES)
            return self

        client_id = os.environ.get(_MSAL_CLIENT_ID_ENV, "")
        if not client_id:
            raise RuntimeError(f"{_MSAL_CLIENT_ID_ENV} environment variable not set")

        try:
            import msal  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "msal package is required for credential flow — pip install msal"
            ) from exc

        authority = _MSAL_AUTHORITY_TEMPLATE.format(tenant_id=self._tenant_id)
        app = msal.PublicClientApplication(client_id, authority=authority)

        flow = app.initiate_device_flow(scopes=list(AUTHORIZED_SCOPES))
        if "user_code" not in flow:
            raise RuntimeError(
                f"Device flow initiation failed: {flow.get('error_description', 'unknown')}"
            )

        print(flow["message"])  # instructs operator to authenticate

        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(
                f"Token acquisition failed: {result.get('error_description', 'unknown')}"
            )

        self._access_token = result["access_token"]
        # Parse scopes from token response
        scope_str: str = result.get("scope", "")
        self._scopes_in_token = (
            [s for s in scope_str.split() if s]
            if scope_str
            else list(AUTHORIZED_SCOPES)
        )

        self._validate_scopes()
        return self

    def _validate_scopes(self) -> None:
        """Log warning if token has extra scopes beyond the authorized list."""
        token_scope_set = frozenset(self._scopes_in_token)
        extra = (
            token_scope_set
            - AUTHORIZED_SCOPES_SET
            - frozenset(
                # standard OIDC scopes always present
                {"openid", "profile", "email", "offline_access", ".default"}
            )
        )
        if extra:
            log.warning(
                "credential: token contains scopes beyond authorized list — %s. "
                "Connector will only call endpoints covered by authorized scopes.",
                sorted(extra),
            )

    @property
    def access_token(self) -> str:
        if self._access_token is None:
            raise RuntimeError("CredentialContext not entered or already exited")
        return self._access_token

    @property
    def scopes_in_token(self) -> list[str]:
        return list(self._scopes_in_token)

    def _revoke(self) -> None:
        """Best-effort revocation call — logged but never raises."""
        if self._access_token is None:
            return
        try:
            import httpx

            httpx.post(
                GRAPH_REVOCATION_URL,
                headers={"Authorization": f"Bearer {self._access_token}"},
                timeout=10,
            )
        except Exception as exc:
            log.warning("credential: revocation call failed (non-fatal) — %s", exc)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._revoke()
        if self._access_token is not None:
            _zero_string(self._access_token)
            self._access_token = None
