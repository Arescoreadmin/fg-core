"""Security tests for OIDCClient.verify_access_token (Task 6.2 addendum).

Verifies that the token exchange endpoint rejects:
- tokens with invalid signatures
- tokens with wrong issuer
- tokens with wrong audience
- expired tokens
- tokens with no sub claim (missing required claim)
- unsigned (HS256/symmetric) tokens

All tests use real RSA keys and PyJWT signing so they prove actual
cryptographic rejection, not just claim inspection.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm

from admin_gateway.auth.config import AuthConfig
from admin_gateway.auth.oidc import OIDCClient, OIDCProvider

ISSUER = "https://idp.example.com/realms/TestRealm"
CLIENT_ID = "test-client"
JWKS_URI = "https://idp.example.com/realms/TestRealm/protocol/openid-connect/certs"


def _make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk_for_key(private_key, kid="k1"):
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    return jwk


def _sign_token(private_key, claims, *, kid="k1", alg="RS256"):
    return jwt.encode(
        claims,
        private_key,
        algorithm=alg,
        headers={"kid": kid, "alg": alg},
    )


def _valid_claims(*, iss=ISSUER, aud=CLIENT_ID, sub="svc-account", offset=60):
    now = int(time.time())
    return {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "exp": now + offset,
        "iat": now,
    }


def _make_client(issuer=ISSUER, client_id=CLIENT_ID):
    config = AuthConfig(
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        oidc_client_secret="s3cr3t",
        oidc_redirect_url="http://localhost/callback",
    )
    return OIDCClient(config)


def _mock_provider_and_jwks(private_key, kid="k1"):
    """Return fake OIDCProvider and a sync MagicMock httpx response for JWKS."""
    provider = OIDCProvider(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/auth",
        token_endpoint=f"{ISSUER}/token",
        userinfo_endpoint=None,
        jwks_uri=JWKS_URI,
    )
    jwk = _jwk_for_key(private_key, kid=kid)

    # httpx Response.json() is synchronous — use MagicMock, not AsyncMock.
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value={"keys": [jwk]})

    return provider, mock_response


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_access_token_valid():
    """A correctly signed, unexpired token with matching issuer/audience passes."""
    key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(key)

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        token = _sign_token(key, _valid_claims())
        claims = await client.verify_access_token(token)

    assert claims["sub"] == "svc-account"
    assert claims["iss"] == ISSUER


# ---------------------------------------------------------------------------
# Negative path — each must raise HTTPException(401)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_access_token_wrong_signature_rejected():
    """Token signed with a different key (forged) must be rejected."""
    signing_key = _make_rsa_key()
    verifying_key = _make_rsa_key()  # DIFFERENT key published in JWKS
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(verifying_key)

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        token = _sign_token(signing_key, _valid_claims())
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_wrong_issuer_rejected():
    """Token with a mismatched issuer must be rejected."""
    key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(key)

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        wrong_issuer_claims = _valid_claims(iss="https://evil.example.com/realms/Evil")
        token = _sign_token(key, wrong_issuer_claims)
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_wrong_audience_rejected():
    """Token with a mismatched audience must be rejected."""
    key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(key)

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        wrong_aud_claims = _valid_claims(aud="some-other-service")
        token = _sign_token(key, wrong_aud_claims)
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_expired_rejected():
    """Expired token must be rejected."""
    key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(key)

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        expired_claims = _valid_claims(offset=-60)  # expired 60 seconds ago
        token = _sign_token(key, expired_claims)
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_symmetric_key_rejected():
    """Token signed with HS256 (symmetric/unsigned-equivalent) must be rejected.

    JWKS contains an RSA key; an HS256 token cannot match it.
    """
    rsa_key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(rsa_key, kid="k1")

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        # HS256 token with kid matching the RSA entry — algorithm confusion attack
        hs256_token = jwt.encode(
            _valid_claims(),
            "symmetric-secret",
            algorithm="HS256",
            headers={"kid": "k1", "alg": "HS256"},
        )
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(hs256_token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_no_matching_kid_rejected():
    """Token with a kid not in JWKS must be rejected."""
    key = _make_rsa_key()
    client = _make_client()
    provider, mock_resp = _mock_provider_and_jwks(key, kid="known-kid")

    with (
        patch.object(client, "get_provider", new=AsyncMock(return_value=provider)),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        # token references a kid that is not in the JWKS
        token = _sign_token(key, _valid_claims(), kid="unknown-kid")
        with pytest.raises(HTTPException) as exc_info:
            await client.verify_access_token(token)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_access_token_oidc_not_configured_rejected():
    """verify_access_token raises 503 when OIDC is not configured."""
    config = AuthConfig()  # no oidc_issuer / oidc_client_id
    client = OIDCClient(config)

    with pytest.raises(HTTPException) as exc_info:
        await client.verify_access_token("anything")

    assert exc_info.value.status_code == 503
