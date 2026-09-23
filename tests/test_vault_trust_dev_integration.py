"""Live integration tests for the Customer-Zero trust adapter against a local Vault dev server.

DEVELOPMENT ONLY — these tests require a running local Vault server configured by
`make trust-dev-up`. They prove the adapter works against real Vault Transit + AppRole
behavior but do NOT constitute CUSTOMER-ZERO-TRUST-001 production evidence.

Run: make trust-dev-test
Skip condition: VAULT_ADDR env var not set or vault not reachable.
"""

from __future__ import annotations

import os

import httpx
import pytest

from services.cgin.key_management.vault_transit import (
    TrustAnchor,
    TrustAnchorRegistry,
    TrustRole,
    VaultCustomerZeroSigner,
    VaultTransitClient,
    VaultTransitError,
    public_key_fingerprint,
)

DEV_VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
DEV_VAULT_TOKEN = os.getenv("VAULT_TOKEN", "dev-only-trust-token")

KEY_IDS = {
    TrustRole.IDENTITY: "customer-zero-identity",
    TrustRole.ACCEPTANCE: "customer-zero-acceptance",
    TrustRole.APPROVAL: "customer-zero-approval",
}

ROLE_NAMES = {
    TrustRole.IDENTITY: "frostgate-cz-identity",
    TrustRole.ACCEPTANCE: "frostgate-cz-acceptance",
    TrustRole.APPROVAL: "frostgate-cz-approval",
}


def _vault_reachable() -> bool:
    try:
        r = httpx.get(f"{DEV_VAULT_ADDR}/v1/sys/health", timeout=2.0)
        return r.status_code in (200, 429, 472, 473, 501, 503)
    except Exception:
        return False


pytestmark = pytest.mark.integration

skip_no_vault = pytest.mark.skipif(
    not _vault_reachable(),
    reason="local Vault dev server not running — run `make trust-dev-up` first",
)


def _root_client() -> VaultTransitClient:
    return VaultTransitClient(
        DEV_VAULT_ADDR,
        token=DEV_VAULT_TOKEN,
        operational=False,
    )


def _approle_secret_id(role_name: str) -> str:
    """Generate a new SecretID for the given AppRole role via the root token."""
    client = httpx.Client(follow_redirects=False)
    resp = client.post(
        f"{DEV_VAULT_ADDR}/v1/auth/approle/role/{role_name}/secret-id",
        headers={"X-Vault-Token": DEV_VAULT_TOKEN},
    )
    assert resp.status_code == 200, f"SecretID generation failed: {resp.text}"
    return resp.json()["data"]["secret_id"]


def _approle_role_id(role_name: str) -> str:
    """Read the role ID for the given AppRole role via the root token."""
    client = httpx.Client(follow_redirects=False)
    resp = client.get(
        f"{DEV_VAULT_ADDR}/v1/auth/approle/role/{role_name}/role-id",
        headers={"X-Vault-Token": DEV_VAULT_TOKEN},
    )
    assert resp.status_code == 200, f"Role ID read failed: {resp.text}"
    return resp.json()["data"]["role_id"]


# ── Key existence and algorithm ───────────────────────────────────────────────


@skip_no_vault
def test_all_three_keys_exist_and_are_ed25519():
    client = _root_client()
    for role, key_id in KEY_IDS.items():
        data = client._get(f"transit/keys/{key_id}", role)
        assert data.get("type") == "ed25519", f"Key {key_id} is not ed25519"
        assert data.get("deletion_allowed") is False, (
            f"Key {key_id} has deletion_allowed=True"
        )


@skip_no_vault
def test_public_key_retrievable_for_all_roles():
    client = _root_client()
    for role, key_id in KEY_IDS.items():
        pk = client.public_key(key_id, 1, role)
        assert isinstance(pk, str) and len(pk) > 10, f"Public key missing for {key_id}"
        fp = public_key_fingerprint(pk)
        assert len(fp) == 64, f"Invalid fingerprint for {key_id}"


# ── Signing and verification ──────────────────────────────────────────────────


@skip_no_vault
def test_root_token_client_signs_payload():
    client = _root_client()
    payload = b"frostgate-dev-test-payload"
    sig, version = client.sign(KEY_IDS[TrustRole.APPROVAL], payload, TrustRole.APPROVAL)
    assert sig.startswith("vault:v"), "Signature must use vault:v prefix"
    assert version >= 1


@skip_no_vault
def test_signer_produces_verifiable_managed_signature():
    client = _root_client()
    signer = VaultCustomerZeroSigner(client, KEY_IDS, issuer="vault-transit-dev")
    payload = b"frostgate-trust-authority-dev-test"

    for role in TrustRole:
        ms = signer.sign(role, payload)
        assert ms.trust_role == role
        assert ms.algorithm == "ed25519"
        assert ms.key_id == KEY_IDS[role]
        assert ms.issuer == "vault-transit-dev"
        # Build anchor and verify
        pk = client.public_key(ms.key_id, ms.key_version, role)
        anchor = TrustAnchor(
            issuer=ms.issuer,
            trust_role=ms.trust_role,
            key_id=ms.key_id,
            key_version=ms.key_version,
            algorithm=ms.algorithm,
            public_key=pk,
            public_key_fingerprint=ms.public_key_fingerprint,
        )
        assert anchor.verify(payload, ms.signature), f"Verification failed for {role}"


@skip_no_vault
def test_signature_does_not_verify_with_wrong_payload():
    client = _root_client()
    signer = VaultCustomerZeroSigner(client, KEY_IDS, issuer="vault-transit-dev")
    ms = signer.sign(TrustRole.IDENTITY, b"correct-payload")
    pk = client.public_key(ms.key_id, ms.key_version, TrustRole.IDENTITY)
    anchor = TrustAnchor(
        issuer=ms.issuer,
        trust_role=ms.trust_role,
        key_id=ms.key_id,
        key_version=ms.key_version,
        algorithm=ms.algorithm,
        public_key=pk,
        public_key_fingerprint=ms.public_key_fingerprint,
    )
    assert not anchor.verify(b"tampered-payload", ms.signature)


# ── AppRole policy isolation ──────────────────────────────────────────────────


def _approle_login(role_name: str) -> str:
    """Obtain a bounded Vault token via AppRole login using raw HTTP.

    AppRoleAuthenticator enforces HTTPS (the production safety guard), so policy
    isolation tests against the local http:// dev server use raw httpx calls to
    obtain bounded tokens, then test Vault's policy enforcement directly.
    """
    client = httpx.Client(follow_redirects=False)
    role_id = _approle_role_id(role_name)
    secret_id = _approle_secret_id(role_name)
    resp = client.post(
        f"{DEV_VAULT_ADDR}/v1/auth/approle/login",
        json={"role_id": role_id, "secret_id": secret_id},
    )
    assert resp.status_code == 200, f"AppRole login failed: {resp.text}"
    return resp.json()["auth"]["client_token"]


@skip_no_vault
def test_each_approle_signs_only_its_own_key():
    """Vault policy isolation: each AppRole token signs its own key and is denied others.

    Uses raw bounded tokens (not AppRoleAuthenticator — that correctly enforces HTTPS
    for the operational adapter). This test proves Vault policy enforcement, not the
    adapter's HTTPS guard (which is proven by test_operational_client_requires_https).
    """
    bounded_tokens = {r: _approle_login(ROLE_NAMES[r]) for r in TrustRole}
    payload = b"authority-isolation-check"
    http = httpx.Client(follow_redirects=False)

    for role in TrustRole:
        token = bounded_tokens[role]
        # Own key: must succeed
        resp = http.post(
            f"{DEV_VAULT_ADDR}/v1/transit/sign/{KEY_IDS[role]}",
            headers={"X-Vault-Token": token},
            json={"input": __import__("base64").b64encode(payload).decode()},
        )
        assert resp.status_code == 200, f"Own-key sign failed for {role}: {resp.text}"
        assert resp.json()["data"]["signature"].startswith("vault:v")

        # Cross-role keys: must be denied
        other_keys = [k for r, k in KEY_IDS.items() if r != role]
        for other_key in other_keys:
            denied = http.post(
                f"{DEV_VAULT_ADDR}/v1/transit/sign/{other_key}",
                headers={"X-Vault-Token": token},
                json={"input": __import__("base64").b64encode(payload).decode()},
            )
            assert denied.status_code == 403, (
                f"{role} should be denied signing {other_key}, got {denied.status_code}"
            )


@skip_no_vault
def test_approle_wrong_secret_id_is_rejected():
    """Vault rejects AppRole login with an invalid SecretID."""
    role_id = _approle_role_id(ROLE_NAMES[TrustRole.IDENTITY])
    http = httpx.Client(follow_redirects=False)
    resp = http.post(
        f"{DEV_VAULT_ADDR}/v1/auth/approle/login",
        json={"role_id": role_id, "secret_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for bad SecretID, got {resp.status_code}"
    )


@skip_no_vault
def test_trust_anchor_registry_rejects_unknown_issuer():
    client = _root_client()
    pk = client.public_key(KEY_IDS[TrustRole.APPROVAL], 1, TrustRole.APPROVAL)
    anchor = TrustAnchor(
        issuer="vault-transit-dev",
        trust_role=TrustRole.APPROVAL,
        key_id=KEY_IDS[TrustRole.APPROVAL],
        key_version=1,
        algorithm="ed25519",
        public_key=pk,
        public_key_fingerprint=public_key_fingerprint(pk),
    )
    registry = TrustAnchorRegistry([anchor])
    with pytest.raises(ValueError, match="unknown Vault trust anchor"):
        registry.resolve(
            "wrong-issuer", TrustRole.APPROVAL, KEY_IDS[TrustRole.APPROVAL], 1
        )


# ── Unavailable vault fails closed ────────────────────────────────────────────


def test_unreachable_vault_fails_closed():
    """No live vault needed — verifies fail-closed on unreachable address."""
    client = VaultTransitClient(
        "http://127.0.0.1:19999",  # nothing listening here
        token="any-token",
        operational=False,
    )
    with pytest.raises(VaultTransitError, match="transport failure"):
        client.sign("any-key", b"payload", TrustRole.APPROVAL)


def test_dev_mode_guard_prevents_operational_static_token():
    """Static token mode is blocked in operational=True — guard is enforced."""
    with pytest.raises(ValueError, match="static.*token"):
        VaultTransitClient(
            "https://vault.example",
            token="any-token",
            operational=True,
        )
