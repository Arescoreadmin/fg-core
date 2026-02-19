from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.agent_update.manifest import (
    UpdateManifest,
    verify_manifest_signature,
    verify_rollback_constraints,
    verify_update_payload,
)


def _sign_manifest(payload: dict, private_key: ed25519.Ed25519PrivateKey) -> str:
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(private_key.sign(msg)).decode("utf-8")


def test_invalid_signature_rejected():
    private = ed25519.Ed25519PrivateKey.generate()
    public = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    payload = {
        "version": "2.0.1",
        "sha256": "a" * 64,
        "size": 5,
        "min_supported_version": "1.0.0",
        "download_url": "https://updates.example/agent.bin",
    }
    manifest = UpdateManifest(**payload, signature=_sign_manifest(payload, private))
    manifest.sha256 = "b" * 64

    with pytest.raises(Exception):
        verify_manifest_signature(manifest, public)


def test_rollback_attempt_rejected():
    assert not verify_rollback_constraints(
        current_version="2.0.0",
        target_version="1.9.9",
        min_supported_version="1.0.0",
    )


def test_corrupted_binary_rejected():
    binary = b"binary-data"
    assert not verify_update_payload(
        binary + b"x", hashlib.sha256(binary).hexdigest(), len(binary)
    )
