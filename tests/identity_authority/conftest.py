"""tests/identity_authority/conftest.py — Shared fixtures for identity authority tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_ia_singletons():
    """Reset module-level singletons between tests."""
    import api.identity_authority.authority as _auth_mod
    import api.identity_authority.machine_identity as _machine_mod
    import api.identity_authority.migration as _migration_mod
    import api.identity_authority.portal_identity as _portal_mod
    import api.identity_authority.audit as _audit_mod

    _auth_mod._authority = None
    _machine_mod._machine_authority = None
    _migration_mod._migrator = None
    _portal_mod._bridge = None
    _audit_mod._auditor = _audit_mod.IdentityAuditor()
    yield
    _auth_mod._authority = None
    _machine_mod._machine_authority = None
    _migration_mod._migrator = None
    _portal_mod._bridge = None


# ---------------------------------------------------------------------------
# JWKS / key fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate a session-scoped RSA key pair for JWT signing in tests."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        return private_key, private_key.public_key()
    except ImportError:
        pytest.skip("cryptography package not available")


@pytest.fixture(scope="session")
def mock_jwks_response(rsa_key_pair):
    """Build a mock JWKS response from the RSA public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        import base64 as b64

        _, public_key = rsa_key_pair
        pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, "public_key") else public_key.public_numbers()

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "test-key-1",
                    "n": _int_to_base64url(pub_numbers.n),
                    "e": _int_to_base64url(pub_numbers.e),
                }
            ]
        }
    except Exception:
        pytest.skip("cannot build JWKS fixture")


def _make_jwt(claims: dict, private_key, kid: str = "test-key-1") -> str:
    """Sign a JWT with the given RSA private key."""
    try:
        import jwt as pyjwt

        header = {"alg": "RS256", "kid": kid}
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return pyjwt.encode(claims, pem, algorithm="RS256", headers=header)
    except ImportError:
        pytest.skip("PyJWT or cryptography not available")


# ---------------------------------------------------------------------------
# Session token fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def session_secret() -> bytes:
    return b"test-session-secret-32-bytes!!!!!"


@pytest.fixture
def session_authority(session_secret, monkeypatch):
    monkeypatch.setenv("FG_SESSION_SECRET", session_secret.decode())
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    from api.identity_authority.session_authority import SessionAuthority
    return SessionAuthority()


@pytest.fixture
def valid_session_token(session_authority):
    token = session_authority.create_session(
        subject="user|test-subject-001",
        email="test@example.com",
        tenant_id="tenant-123",
        identity_type="human",
        provider="auth0",
        mfa_verified=True,
    )
    return token.token, token.session_id


# ---------------------------------------------------------------------------
# Legacy token helpers
# ---------------------------------------------------------------------------

def _build_legacy_token(payload: dict, secret: str) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    b64 = base64.urlsafe_b64encode(raw.encode()).decode()
    sig = hmac.new(secret.encode(), b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


@pytest.fixture
def legacy_portal_token():
    """A valid legacy portal HMAC token."""
    now = int(time.time())
    payload = {
        "sub": "portal-user@acme.com",
        "email": "portal-user@acme.com",
        "tid": "tenant-acme",
        "roles": ["viewer"],
        "iat": now,
        "exp": now + 3600,
        "sid": "legacy-sid-001",
    }
    return _build_legacy_token(payload, "test-portal-password")


# ---------------------------------------------------------------------------
# CanonicalIdentity fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def canonical_identity():
    from datetime import datetime, timezone
    from api.identity_authority.models import (
        AuthenticationContext,
        CanonicalIdentity,
        IdentityProvider,
        TenantBinding,
    )
    from api.actor_context import roles_to_permissions

    now = datetime.now(tz=timezone.utc)
    provider = IdentityProvider(
        name="auth0",
        issuer="https://test.auth0.com/",
        subject="auth0|test-subject-001",
    )
    auth_ctx = AuthenticationContext(
        mfa_verified=True,
        mfa_method="totp",
        auth_time=now,
        amr=["mfa", "otp"],
        acr="urn:mace:incommon:iap:silver",
        pkce_used=True,
        nonce_verified=True,
    )
    binding = TenantBinding(
        tenant_id="tenant-123",
        organization_id=None,
        membership_id="member-001",
        roles=frozenset(["assessor"]),
        permissions=roles_to_permissions(["assessor"]),
    )
    return CanonicalIdentity(
        subject="auth0|test-subject-001",
        email="user@acme.com",
        name="Test User",
        email_verified=True,
        provider=provider,
        auth_context=auth_ctx,
        tenant_binding=binding,
        subscription=None,
        identity_type="human",
        issued_at=now,
        expires_at=now,
    )
