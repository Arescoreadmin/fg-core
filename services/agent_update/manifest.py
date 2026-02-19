from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


@dataclass
class UpdateManifest:
    version: str
    sha256: str
    size: int
    min_supported_version: str
    download_url: str
    signature: str


def _canonical_payload(manifest: UpdateManifest) -> bytes:
    payload = {
        "version": manifest.version,
        "sha256": manifest.sha256,
        "size": manifest.size,
        "min_supported_version": manifest.min_supported_version,
        "download_url": manifest.download_url,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_manifest_signature(manifest: UpdateManifest, public_key_pem: str) -> bool:
    signature = base64.b64decode(manifest.signature)
    msg = _canonical_payload(manifest)
    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(signature, msg)
        return True
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    raise ValueError("unsupported signing key")


def verify_update_payload(binary: bytes, expected_sha256: str, expected_size: int) -> bool:
    if len(binary) != int(expected_size):
        return False
    digest = hashlib.sha256(binary).hexdigest()
    return digest == expected_sha256


def verify_rollback_constraints(
    *, current_version: str, target_version: str, min_supported_version: str
) -> bool:
    def _parts(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

    return _parts(target_version) >= _parts(current_version) and _parts(
        current_version
    ) >= _parts(min_supported_version)
