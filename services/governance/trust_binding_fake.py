"""TEST-ONLY ephemeral trust binding fake for unit/integration tests.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

SECURITY: This module MUST NEVER be used in production.  It generates ephemeral
Ed25519 keys in-process and is explicitly rejected if a production environment
is detected.

Usage in tests:
    from services.governance.trust_binding_fake import make_test_authority

    authority = make_test_authority()
    env = authority.sign_qualification(payload_dict)
    assert authority.verify_qualification(payload_dict, env)
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from services.cgin.key_management.vault_transit import (
    ManagedSignature,
    TrustRole,
    public_key_fingerprint,
)
from services.governance.trust_binding import TrustBindingAuthority

_PRODUCTION_ENVIRONMENTS = {"production", "staging", "prod"}

_ISSUER = "trust-binding-fake-test-only"


def _assert_not_production() -> None:
    env = os.getenv("FG_ENV", "test").lower()
    if env in _PRODUCTION_ENVIRONMENTS:
        raise RuntimeError(
            f"TrustBindingFake is test-only and cannot be used in environment '{env}'"
        )
    cz_env = os.getenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "").lower()
    if cz_env in _PRODUCTION_ENVIRONMENTS:
        raise RuntimeError(
            f"TrustBindingFake is test-only and cannot be used in environment '{cz_env}'"
        )


class _FakeRoleKey:
    """Per-role ephemeral Ed25519 key pair for test signing."""

    def __init__(self, role: TrustRole) -> None:
        self._priv = Ed25519PrivateKey.generate()
        self._pub: Ed25519PublicKey = self._priv.public_key()
        self._role = role
        self._key_id = f"fake-{role.value}"
        self._version = 1
        pub_raw = self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._pub_b64 = base64.b64encode(pub_raw).decode("ascii")
        self._fingerprint = public_key_fingerprint(self._pub_b64)

    def sign(self, payload: bytes) -> ManagedSignature:
        sig_raw = self._priv.sign(payload)
        # Mimic vault:v<n>:<base64> format for interface compatibility
        sig_str = f"vault:v{self._version}:" + base64.b64encode(sig_raw).decode(
            "ascii"
        )
        return ManagedSignature(
            issuer=_ISSUER,
            trust_role=self._role,
            key_id=self._key_id,
            key_version=self._version,
            algorithm="ed25519",
            public_key_fingerprint=self._fingerprint,
            signature=sig_str,
        )

    def verify(self, payload: bytes, signature: str) -> bool:
        if not signature.startswith(f"vault:v{self._version}:"):
            return False
        try:
            parts = signature.split(":", 2)
            if len(parts) != 3:
                return False
            raw = base64.b64decode(parts[2])
            self._pub.verify(raw, payload)
            return True
        except Exception:
            return False

    @property
    def public_key_b64(self) -> str:
        return self._pub_b64

    @property
    def fingerprint(self) -> str:
        return self._fingerprint


class TrustBindingFake:
    """Deterministic per-process fake backend for tests.

    Each role gets a freshly-generated Ed25519 key; keys are NOT shared across
    roles, so cross-role substitution tests fail correctly.
    """

    def __init__(self) -> None:
        _assert_not_production()
        self._keys = {role: _FakeRoleKey(role) for role in TrustRole}

    def sign(self, role: TrustRole, payload: bytes) -> ManagedSignature:
        return self._keys[role].sign(payload)

    def verify(self, role: TrustRole, payload: bytes, signature: str) -> bool:
        return self._keys[role].verify(payload, signature)

    def public_key_b64(self, role: TrustRole) -> str:
        return self._keys[role].public_key_b64

    def fingerprint(self, role: TrustRole) -> str:
        return self._keys[role].fingerprint

    def wrong_role_verify(
        self, intended_role: TrustRole, payload: bytes, signature: str
    ) -> bool:
        """Verify a signature against the wrong role's key (must return False)."""
        for role, key in self._keys.items():
            if role != intended_role:
                if key.verify(payload, signature):
                    return True
        return False


def make_test_authority() -> TrustBindingAuthority:
    """Create a TrustBindingAuthority backed by a TrustBindingFake for unit tests."""
    _assert_not_production()
    fake = TrustBindingFake()
    return TrustBindingAuthority(fake)


def make_test_fake() -> TrustBindingFake:
    """Return a raw TrustBindingFake for adversarial tests that need direct access."""
    _assert_not_production()
    return TrustBindingFake()
