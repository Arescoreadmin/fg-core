"""Cryptographic federation token validation tests (P0-12).

Covers 6 positive and 15 negative cases using locally generated RSA keys.
No live network calls — JWKS cache is pre-seeded in fixtures.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from services.federation_extension.service import (
    FEDERATION_CLOCK_SKEW_SECONDS,
    FederationPrincipal,
    FederationService,
    FederationValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_jwks(public_key: object, kid: str = "test-key-1") -> dict[str, Any]:
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))  # type: ignore[arg-type]
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    return {"keys": [jwk_dict]}


def _sign(private_key: object, claims: dict[str, Any], kid: str = "test-key-1") -> str:
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})  # type: ignore[arg-type]


def _raw_token(header: dict[str, Any], payload: dict[str, Any], sig: str = "") -> str:
    """Build a token manually without signing (for alg=none / HS256 tests)."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


def _base_claims(
    *,
    tenant_id: str = "tenant-abc",
    sub: str = "user@example.com",
    iss: str = "https://idp.example.com/",
    aud: str | list[str] = "https://api.frostgate.ai",
    exp_offset: int = 300,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "tenant_id": tenant_id,
        "exp": now + exp_offset,
        "iat": now,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    return _generate_keypair()


@pytest.fixture(scope="module")
def jwks(keypair):
    _, pub = keypair
    return _make_jwks(pub)


@pytest.fixture
def svc(monkeypatch, jwks):
    """Configured service with JWKS cache pre-seeded (no network)."""
    monkeypatch.setenv(
        "FG_FEDERATION_JWKS_URL", "https://idp.example.com/.well-known/jwks.json"
    )
    monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com/")
    monkeypatch.setenv("FG_FEDERATION_AUDIENCE", "https://api.frostgate.ai")
    s = FederationService()
    s.cache._doc = jwks
    s.cache._exp = time.time() + 3600
    return s


# ---------------------------------------------------------------------------
# Positive tests
# ---------------------------------------------------------------------------


def test_valid_rs256_token_succeeds(svc, keypair):
    priv, _ = keypair
    token = _sign(priv, _base_claims())
    principal = svc.validate_token(token)
    assert isinstance(principal, FederationPrincipal)
    assert principal.subject == "user@example.com"
    assert principal.tenant_id == "tenant-abc"
    assert principal.issuer == "https://idp.example.com/"


def test_groups_extracted_into_principal(svc, keypair):
    priv, _ = keypair
    claims = {**_base_claims(), "groups": ["admins", "devs"]}
    principal = svc.validate_token(_sign(priv, claims))
    assert principal.groups == ["admins", "devs"]


def test_token_near_expiry_within_clock_skew_accepted(svc, keypair):
    """Token expired 30s ago but still within the 60s skew window."""
    priv, _ = keypair
    claims = {
        **_base_claims(),
        "exp": int(time.time()) - (FEDERATION_CLOCK_SKEW_SECONDS // 2),
    }
    principal = svc.validate_token(_sign(priv, claims))
    assert principal.subject == "user@example.com"


def test_tenant_resolved_from_tid_fallback(svc, keypair):
    """'tid' claim is accepted when 'tenant_id' is absent."""
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k != "tenant_id"}
    claims["tid"] = "tenant-xyz"
    principal = svc.validate_token(_sign(priv, claims))
    assert principal.tenant_id == "tenant-xyz"


def test_kid_cache_miss_triggers_refresh_and_succeeds(monkeypatch, keypair, jwks):
    """On kid miss, the service refreshes the cache and retries."""
    monkeypatch.setenv(
        "FG_FEDERATION_JWKS_URL", "https://idp.example.com/.well-known/jwks.json"
    )
    monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com/")
    monkeypatch.setenv("FG_FEDERATION_AUDIENCE", "https://api.frostgate.ai")

    priv, _ = keypair
    token = _sign(priv, _base_claims())

    call_count = [0]

    def fake_get(
        url: str, ttl_seconds: int = 300, *, force_refresh: bool = False
    ) -> dict:
        call_count[0] += 1
        return {"keys": []} if call_count[0] == 1 else jwks

    svc = FederationService()
    monkeypatch.setattr(svc.cache, "get", fake_get)

    principal = svc.validate_token(token)
    assert principal.subject == "user@example.com"
    assert call_count[0] == 2


def test_audience_as_list_accepted(svc, keypair):
    """aud claim may be a list that contains the configured audience."""
    priv, _ = keypair
    claims = {
        **_base_claims(),
        "aud": ["https://api.frostgate.ai", "https://other.example.com"],
    }
    principal = svc.validate_token(_sign(priv, claims))
    assert principal.subject == "user@example.com"


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------


def test_alg_none_rejected(svc):
    token = _raw_token({"alg": "none", "typ": "JWT"}, _base_claims())
    with pytest.raises(
        FederationValidationError, match="federation_algorithm_rejected"
    ):
        svc.validate_token(token)


def test_alg_hs256_rejected(svc):
    token = jwt.encode(
        _base_claims(), "s" * 32, algorithm="HS256", headers={"kid": "test-key-1"}
    )
    with pytest.raises(
        FederationValidationError, match="federation_algorithm_rejected"
    ):
        svc.validate_token(token)


def test_tampered_payload_rejected(svc, keypair):
    """Original signature cannot validate a replaced payload."""
    priv, _ = keypair
    original = _sign(priv, _base_claims())
    header_b64, _, sig_b64 = original.split(".")
    forged = {**_base_claims(), "sub": "attacker@evil.com", "tenant_id": "victim"}
    forged_payload = (
        base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    )
    tampered = f"{header_b64}.{forged_payload}.{sig_b64}"
    with pytest.raises(FederationValidationError, match="federation_invalid_token"):
        svc.validate_token(tampered)


def test_missing_exp_rejected(svc, keypair):
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k != "exp"}
    with pytest.raises(FederationValidationError, match="federation_missing_claim"):
        svc.validate_token(_sign(priv, claims))


def test_missing_sub_rejected(svc, keypair):
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k != "sub"}
    with pytest.raises(FederationValidationError):
        svc.validate_token(_sign(priv, claims))


def test_expired_token_beyond_skew_rejected(svc, keypair):
    """Token expired well beyond the clock skew window."""
    priv, _ = keypair
    claims = {
        **_base_claims(),
        "exp": int(time.time()) - (FEDERATION_CLOCK_SKEW_SECONDS + 120),
    }
    with pytest.raises(FederationValidationError, match="federation_token_expired"):
        svc.validate_token(_sign(priv, claims))


def test_not_yet_valid_beyond_skew_rejected(svc, keypair):
    """Token with nbf far in the future is rejected."""
    priv, _ = keypair
    claims = {
        **_base_claims(),
        "nbf": int(time.time()) + (FEDERATION_CLOCK_SKEW_SECONDS + 120),
    }
    with pytest.raises(
        FederationValidationError, match="federation_token_not_yet_valid"
    ):
        svc.validate_token(_sign(priv, claims))


def test_wrong_issuer_rejected(svc, keypair):
    priv, _ = keypair
    claims = {**_base_claims(), "iss": "https://evil-idp.example.com/"}
    with pytest.raises(FederationValidationError, match="federation_invalid_issuer"):
        svc.validate_token(_sign(priv, claims))


def test_wrong_audience_rejected(svc, keypair):
    priv, _ = keypair
    claims = {**_base_claims(), "aud": "https://wrong-api.example.com"}
    with pytest.raises(FederationValidationError, match="federation_invalid_audience"):
        svc.validate_token(_sign(priv, claims))


def test_missing_aud_claim_rejected(svc, keypair):
    """When audience is configured, a token without aud must be rejected."""
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k != "aud"}
    with pytest.raises(FederationValidationError, match="federation_missing_claim"):
        svc.validate_token(_sign(priv, claims))


def test_unknown_kid_rejected(monkeypatch, keypair, jwks):
    """kid not present in JWKS is rejected even after cache refresh (no network)."""
    monkeypatch.setenv(
        "FG_FEDERATION_JWKS_URL", "https://idp.example.com/.well-known/jwks.json"
    )
    monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com/")
    monkeypatch.setenv("FG_FEDERATION_AUDIENCE", "https://api.frostgate.ai")
    priv, _ = keypair
    token = _sign(priv, _base_claims(), kid="no-such-key-99")
    svc = FederationService()
    # jwks only contains "test-key-1"; always return it, even on force_refresh
    monkeypatch.setattr(
        svc.cache, "get", lambda url, ttl_seconds=300, *, force_refresh=False: jwks
    )
    with pytest.raises(FederationValidationError, match="federation_unknown_kid"):
        svc.validate_token(token)


def test_token_signed_by_unauthorized_key_rejected(svc, keypair):
    """Token signed by an attacker key (not in JWKS) is rejected."""
    attacker_priv, _ = _generate_keypair()
    claims = {**_base_claims(), "sub": "attacker@evil.com"}
    token = _sign(attacker_priv, claims)
    with pytest.raises(FederationValidationError, match="federation_invalid_token"):
        svc.validate_token(token)


def test_missing_iss_claim_rejected(svc, keypair):
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k != "iss"}
    with pytest.raises(FederationValidationError):
        svc.validate_token(_sign(priv, claims))


def test_missing_tenant_claim_rejected(svc, keypair):
    """Token missing both tenant_id and tid is rejected after signature verification."""
    priv, _ = keypair
    claims = {k: v for k, v in _base_claims().items() if k not in ("tenant_id", "tid")}
    with pytest.raises(FederationValidationError, match="federation_missing_tenant"):
        svc.validate_token(_sign(priv, claims))


def test_unconfigured_service_rejected(monkeypatch):
    """validate_token must fail immediately when required env vars are absent."""
    monkeypatch.delenv("FG_FEDERATION_JWKS_URL", raising=False)
    monkeypatch.delenv("FG_FEDERATION_ISSUER", raising=False)
    monkeypatch.delenv("FG_FEDERATION_AUDIENCE", raising=False)
    svc = FederationService()
    with pytest.raises(FederationValidationError, match="federation_not_configured"):
        svc.validate_token("any.token.here")
