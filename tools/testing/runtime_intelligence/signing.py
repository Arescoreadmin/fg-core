"""Ed25519 signing abstraction for validation manifests.

Provides a thin wrapper around ``cryptography``'s Ed25519 primitives so the
rest of the runtime intelligence package can sign and verify manifests
without importing low-level asymmetric APIs directly.

Security invariants enforced here:

* Private key bytes never appear in ``repr`` or string conversions.
* Private keys are read only from :data:`Ed25519KeyProvider.PRIVATE_KEY_ENV`
  or explicit constructor arguments; nothing is logged.
* Verification never raises on bad signatures — it returns a structured
  :class:`VerificationResult` so callers can make policy decisions.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .manifest import ValidationManifest, canonical_bytes, manifest_to_dict

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureResult:
    """Value object returned when a signature is produced."""

    signature_hex: str
    signing_identity: str
    algorithm: str
    public_key_hex: str


@dataclass(frozen=True)
class VerificationResult:
    """Structured verification outcome.

    Always returned by verification APIs. ``valid`` is the only truthy
    signal; ``reason`` and ``detail`` exist for logs and human review.
    """

    valid: bool
    algorithm: str
    signing_identity: str
    reason: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def _hex_to_bytes(value: str, expected_len: int, name: str) -> bytes:
    """Decode a hex string to raw bytes with a length check."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid hex") from exc
    if len(raw) != expected_len:
        raise ValueError(f"{name} must decode to {expected_len} bytes (got {len(raw)})")
    return raw


def _key_id_from_public_bytes(public_bytes: bytes) -> str:
    """Deterministic 16-char identity derived from the public key bytes."""
    return hashlib.sha256(public_bytes).hexdigest()[:16]


class Ed25519KeyProvider:
    """Load Ed25519 keys from environment variables or explicit hex inputs.

    Three usage modes:

    * ``Ed25519KeyProvider()`` — generates an ephemeral key pair (dev/test).
    * ``Ed25519KeyProvider(private_key_hex=...)`` — signer + verifier; the
      public key is derived from the private key.
    * ``Ed25519KeyProvider(public_key_hex=...)`` — verifier only.
    """

    PRIVATE_KEY_ENV = "FG_MANIFEST_SIGNING_KEY"
    PUBLIC_KEY_ENV = "FG_MANIFEST_VERIFY_KEY"

    def __init__(
        self,
        private_key_hex: str | None = None,
        public_key_hex: str | None = None,
    ) -> None:
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None

        if private_key_hex:
            raw_priv = _hex_to_bytes(private_key_hex, 32, "private key")
            self._private_key = Ed25519PrivateKey.from_private_bytes(raw_priv)
            self._public_key = self._private_key.public_key()
        elif public_key_hex:
            raw_pub = _hex_to_bytes(public_key_hex, 32, "public key")
            self._public_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        else:
            # Ephemeral pair for local / test usage.
            self._private_key = Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()

        # If a public key was also provided alongside a private key, verify
        # they match. Silent mismatch would produce unverifiable signatures.
        if private_key_hex and public_key_hex:
            derived = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            provided = _hex_to_bytes(public_key_hex, 32, "public key")
            if derived != provided:
                print(
                    "[manifest-signing] warning: provided public key does not "
                    "match private key; using derived public key.",
                    file=sys.stderr,
                )

    # -- introspection --------------------------------------------------

    def has_private_key(self) -> bool:
        return self._private_key is not None

    def has_public_key(self) -> bool:
        return self._public_key is not None

    def key_id(self) -> str:
        if self._public_key is None:
            return ""
        return _key_id_from_public_bytes(
            self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    # -- raw material ---------------------------------------------------

    def get_private_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise RuntimeError("no private key available")
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def get_public_key_bytes(self) -> bytes:
        if self._public_key is None:
            raise RuntimeError("no public key available")
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def get_public_key_hex(self) -> str:
        return self.get_public_key_bytes().hex()

    # -- signing --------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Produce a raw 64-byte Ed25519 signature over ``data``."""
        if self._private_key is None:
            raise RuntimeError("cannot sign without a private key")
        return self._private_key.sign(data)

    # -- repr / debug ---------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"Ed25519KeyProvider(key_id={self.key_id()!r}, "
            f"has_private={self.has_private_key()})"
        )

    __str__ = __repr__

    # -- constructors ---------------------------------------------------

    @classmethod
    def from_env(cls) -> Ed25519KeyProvider:
        """Load a provider from environment variables.

        Missing variables fall back to ``None``. If both are absent, an
        ephemeral pair is generated — callers who need production keys
        should call :meth:`has_private_key` to detect this.
        """
        private_hex = os.environ.get(cls.PRIVATE_KEY_ENV, "").strip()
        public_hex = os.environ.get(cls.PUBLIC_KEY_ENV, "").strip()
        return cls(
            private_key_hex=private_hex or None,
            public_key_hex=public_hex or None,
        )


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 key pair.

    Returns ``(private_hex, public_hex)`` — both 64-character hex strings
    encoding 32 raw bytes each. Intended for tests and one-off tooling.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_bytes.hex(), public_bytes.hex()


def sign_manifest(
    manifest: ValidationManifest, provider: Ed25519KeyProvider
) -> ValidationManifest:
    """Attach an Ed25519 signature to ``manifest``.

    The signature is computed over :func:`manifest.canonical_bytes`, which
    excludes signature fields — so re-signing the same manifest twice yields
    the same signature (Ed25519 is deterministic).
    """
    if not provider.has_private_key():
        raise RuntimeError("signing requires a provider with a private key")

    data = canonical_bytes(manifest_to_dict(manifest))
    signature = provider.sign(data)
    signing_identity = provider.key_id()

    return replace(
        manifest,
        signature=signature.hex(),
        signing_identity=signing_identity,
        signature_algorithm="ed25519",
        verification_status="pending",
    )


def sign_manifest_detail(
    manifest: ValidationManifest, provider: Ed25519KeyProvider
) -> tuple[ValidationManifest, SignatureResult]:
    """Sign ``manifest`` and also return a :class:`SignatureResult` record."""
    signed = sign_manifest(manifest, provider)
    result = SignatureResult(
        signature_hex=signed.signature,
        signing_identity=signed.signing_identity,
        algorithm=signed.signature_algorithm,
        public_key_hex=provider.get_public_key_hex(),
    )
    return signed, result


def verify_signature_bytes(
    data: bytes, signature_hex: str, public_key_hex: str
) -> VerificationResult:
    """Verify a raw Ed25519 signature over ``data``.

    Returns a structured :class:`VerificationResult`. Never raises on bad
    input — malformed hex, wrong-length keys, and invalid signatures all
    surface as ``valid=False``.
    """
    if not signature_hex:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity="",
            reason="empty signature",
        )
    if not public_key_hex:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity="",
            reason="empty public key",
        )

    try:
        raw_pub = _hex_to_bytes(public_key_hex, 32, "public key")
    except ValueError as exc:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity="",
            reason="invalid public key",
            detail=str(exc),
        )

    try:
        raw_sig = bytes.fromhex(signature_hex)
    except ValueError:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity=_key_id_from_public_bytes(raw_pub),
            reason="signature is not valid hex",
        )

    if len(raw_sig) != 64:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity=_key_id_from_public_bytes(raw_pub),
            reason=f"signature must be 64 bytes (got {len(raw_sig)})",
        )

    identity = _key_id_from_public_bytes(raw_pub)
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, data)
    except InvalidSignature:
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity=identity,
            reason="signature does not match canonical content",
        )
    except Exception as exc:  # pragma: no cover - defensive
        return VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity=identity,
            reason="signature verification error",
            detail=type(exc).__name__,
        )

    return VerificationResult(
        valid=True,
        algorithm="ed25519",
        signing_identity=identity,
        reason="signature valid",
    )
