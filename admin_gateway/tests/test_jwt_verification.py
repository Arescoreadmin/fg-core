import json
import time
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import sys

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm

_AUTH_PATH = Path(__file__).resolve().parents[1] / "auth.py"
_AUTH_MODULE_NAME = "admin_gateway_auth_module"
_AUTH_SPEC = spec_from_loader(
    _AUTH_MODULE_NAME, SourceFileLoader(_AUTH_MODULE_NAME, str(_AUTH_PATH))
)
_AUTH_MODULE = module_from_spec(_AUTH_SPEC)
sys.modules[_AUTH_MODULE_NAME] = _AUTH_MODULE
_AUTH_SPEC.loader.exec_module(_AUTH_MODULE)  # type: ignore[assignment]
verify_id_token = _AUTH_MODULE.verify_id_token


def _generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk_for_key(key, kid="test-key"):
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    return jwk


def _encode_token(private_key, *, kid, alg, claims):
    return jwt.encode(
        claims,
        private_key,
        algorithm=alg,
        headers={"kid": kid, "alg": alg},
    )


@pytest.mark.asyncio
async def test_verify_id_token_valid(monkeypatch):
    key = _generate_rsa_key()
    jwk = _jwk_for_key(key, kid="valid")
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "nonce": "nonce-123",
        "aud": "client-1",
        "iss": "https://issuer.example",
        "exp": now + 60,
    }
    token = _encode_token(key, kid="valid", alg="RS256", claims=claims)

    async def fake_config(_issuer):
        return {"jwks_uri": "https://issuer.example/jwks"}

    async def fake_jwks(_uri):
        return {"keys": [jwk]}

    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-1")
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_oidc_config", fake_config)
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_jwks", fake_jwks)

    result = await verify_id_token(token, "nonce-123")

    assert result["sub"] == "user-1"


@pytest.mark.asyncio
async def test_verify_id_token_expired(monkeypatch):
    key = _generate_rsa_key()
    jwk = _jwk_for_key(key, kid="expired")
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "nonce": "nonce-123",
        "aud": "client-1",
        "iss": "https://issuer.example",
        "exp": now - 10,
    }
    token = _encode_token(key, kid="expired", alg="RS256", claims=claims)

    async def fake_config(_issuer):
        return {"jwks_uri": "https://issuer.example/jwks"}

    async def fake_jwks(_uri):
        return {"keys": [jwk]}

    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-1")
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_oidc_config", fake_config)
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_jwks", fake_jwks)

    with pytest.raises(HTTPException):
        await verify_id_token(token, "nonce-123")


@pytest.mark.asyncio
async def test_verify_id_token_wrong_signature(monkeypatch):
    key = _generate_rsa_key()
    other_key = _generate_rsa_key()
    jwk = _jwk_for_key(key, kid="sig")
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "nonce": "nonce-123",
        "aud": "client-1",
        "iss": "https://issuer.example",
        "exp": now + 60,
    }
    token = _encode_token(other_key, kid="sig", alg="RS256", claims=claims)

    async def fake_config(_issuer):
        return {"jwks_uri": "https://issuer.example/jwks"}

    async def fake_jwks(_uri):
        return {"keys": [jwk]}

    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-1")
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_oidc_config", fake_config)
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_jwks", fake_jwks)

    with pytest.raises(HTTPException):
        await verify_id_token(token, "nonce-123")


@pytest.mark.asyncio
async def test_verify_id_token_algorithm_mismatch(monkeypatch):
    key = _generate_rsa_key()
    jwk = _jwk_for_key(key, kid="alg")
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "nonce": "nonce-123",
        "aud": "client-1",
        "iss": "https://issuer.example",
        "exp": now + 60,
    }
    token = jwt.encode(
        claims,
        "secret",
        algorithm="HS256",
        headers={"kid": "alg", "alg": "HS256"},
    )

    async def fake_config(_issuer):
        return {"jwks_uri": "https://issuer.example/jwks"}

    async def fake_jwks(_uri):
        return {"keys": [jwk]}

    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-1")
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_oidc_config", fake_config)
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_jwks", fake_jwks)

    with pytest.raises(HTTPException):
        await verify_id_token(token, "nonce-123")


@pytest.mark.asyncio
async def test_verify_id_token_wrong_audience_or_issuer(monkeypatch):
    key = _generate_rsa_key()
    jwk = _jwk_for_key(key, kid="audiss")
    now = int(time.time())
    claims = {
        "sub": "user-1",
        "nonce": "nonce-123",
        "aud": "client-1",
        "iss": "https://issuer.example",
        "exp": now + 60,
    }
    token = _encode_token(key, kid="audiss", alg="RS256", claims=claims)

    async def fake_config(_issuer):
        return {"jwks_uri": "https://issuer.example/jwks"}

    async def fake_jwks(_uri):
        return {"keys": [jwk]}

    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-2")
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_oidc_config", fake_config)
    monkeypatch.setattr(_AUTH_MODULE, "_fetch_jwks", fake_jwks)

    with pytest.raises(HTTPException):
        await verify_id_token(token, "nonce-123")

    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client-1")
    monkeypatch.setenv("FG_OIDC_ISSUER", "https://other-issuer.example")

    with pytest.raises(HTTPException):
        await verify_id_token(token, "nonce-123")
