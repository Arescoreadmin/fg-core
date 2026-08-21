"""Shared test helper for admin-gateway delegation proof headers.

After PR-CORE-002 / #645 / #646 / #647, every admin-gateway request that binds a
caller-supplied X-Tenant-ID must carry a valid HMAC delegation proof. This helper
generates the four required headers using the same canonical format Core verifies
in ``api.auth_scopes.resolution._verify_delegation_proof``:

    v1\\n{request_id}\\n{tenant_id}\\n{METHOD}\\n{path}\\n{iat}\\n{exp}

Tests exercising the admin-gateway path should call ``delegation_headers()`` and
merge the result into their existing header dict. The helper uses the secret from
``FG_GATEWAY_DELEGATION_SECRET_CURRENT`` when present, or a deterministic test
secret otherwise, mirroring the pattern in tests/test_core_002_admin_gateway_tenant_binding.py.

For deterministic behaviour tests should also set
``FG_GATEWAY_DELEGATION_SECRET_CURRENT`` in the environment so Core's verifier
uses the same secret (see ``configure_delegation_env``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

# Matches the pattern used in tests/test_core_002_admin_gateway_tenant_binding.py.
TEST_DELEGATION_SECRET = "test-delegation-secret-not-for-production-use"


def _resolve_secret() -> str:
    env_secret = (os.getenv("FG_GATEWAY_DELEGATION_SECRET_CURRENT") or "").strip()
    return env_secret or TEST_DELEGATION_SECRET


def configure_delegation_env(monkeypatch) -> str:
    """Pin ``FG_GATEWAY_DELEGATION_SECRET_CURRENT`` so Core and the test agree.

    Returns the secret in use so callers can pass it back into
    :func:`delegation_headers` if they want to be explicit.
    """
    secret = _resolve_secret()
    monkeypatch.setenv("FG_GATEWAY_DELEGATION_SECRET_CURRENT", secret)
    return secret


def delegation_headers(
    *,
    tenant_id: str,
    method: str,
    path: str,
    request_id: str,
    secret: str | None = None,
    lifetime: int = 60,
    offset_seconds: int = 0,
) -> dict[str, str]:
    """Return the four X-FG-Delegation-* headers for a canonical request.

    The generated proof binds (version, request_id, tenant_id, method, path,
    issued_at, expires_at). Callers must send the same request_id in
    ``X-Request-ID`` and the same tenant_id in ``X-Tenant-ID`` (or the
    request's URL path) for Core's verifier to accept the proof.
    """
    resolved_secret = (secret or _resolve_secret()).strip()
    issued_at = int(time.time()) + offset_seconds
    expires_at = issued_at + lifetime
    canonical = (
        f"v1\n{request_id}\n{tenant_id}\n{method.upper()}\n{path}"
        f"\n{issued_at}\n{expires_at}"
    )
    proof = hmac.new(
        resolved_secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    return {
        "X-FG-Delegation-Version": "v1",
        "X-FG-Delegation-Issued-At": str(issued_at),
        "X-FG-Delegation-Expires-At": str(expires_at),
        "X-FG-Delegation-Proof": proof,
    }
