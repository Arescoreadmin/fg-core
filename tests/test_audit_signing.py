from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.audit_engine.signing import sign_manifest_payload, verify_manifest_signature


def test_ed25519_sign_verify_success(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode("utf-8")
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("utf-8")

    monkeypatch.setenv("FG_AUDIT_EXPORT_SIGNING_MODE", "ed25519")
    monkeypatch.setenv("FG_AUDIT_ED25519_ACTIVE_KID", "kid-1")
    monkeypatch.setenv("FG_AUDIT_ED25519_PRIVATE_KEYS_JSON", '{"kid-1":"' + priv_b64 + '"}')
    monkeypatch.setenv("FG_AUDIT_ED25519_PUBLIC_KEYS_JSON", '{"kid-1":"' + pub_b64 + '"}')

    payload = {"root_hash": "a" * 64, "bundle_hash": "b" * 64, "sections": {"x": "y"}}
    sig = sign_manifest_payload(payload)
    assert sig["signature_algo"] == "ed25519"
    assert (
        verify_manifest_signature(
            payload,
            signature_algo=sig["signature_algo"],
            kid=sig["kid"],
            signature=sig["signature"],
        )
        is True
    )


def test_ed25519_kid_mismatch_fails(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode("utf-8")
    wrong_pub_b64 = base64.b64encode(
        wrong.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("utf-8")

    monkeypatch.setenv("FG_AUDIT_EXPORT_SIGNING_MODE", "ed25519")
    monkeypatch.setenv("FG_AUDIT_ED25519_ACTIVE_KID", "kid-a")
    monkeypatch.setenv("FG_AUDIT_ED25519_PRIVATE_KEYS_JSON", '{"kid-a":"' + priv_b64 + '"}')
    monkeypatch.setenv("FG_AUDIT_ED25519_PUBLIC_KEYS_JSON", '{"kid-b":"' + wrong_pub_b64 + '"}')

    payload = {"root_hash": "a" * 64, "bundle_hash": "b" * 64, "sections": {}}
    sig = sign_manifest_payload(payload)
    assert (
        verify_manifest_signature(
            payload,
            signature_algo=sig["signature_algo"],
            kid="kid-b",
            signature=sig["signature"],
        )
        is False
    )


def test_ed25519_rotation_window_supports_previous_kid(monkeypatch):
    old_priv = Ed25519PrivateKey.generate()
    new_priv = Ed25519PrivateKey.generate()
    old_priv_b64 = base64.b64encode(
        old_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode("utf-8")
    old_pub_b64 = base64.b64encode(
        old_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("utf-8")
    new_priv_b64 = base64.b64encode(
        new_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode("utf-8")
    new_pub_b64 = base64.b64encode(
        new_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("utf-8")

    monkeypatch.setenv("FG_AUDIT_EXPORT_SIGNING_MODE", "ed25519")
    monkeypatch.setenv("FG_AUDIT_ED25519_ACTIVE_KID", "old-kid")
    monkeypatch.setenv("FG_AUDIT_ED25519_PRIVATE_KEYS_JSON", '{"old-kid":"' + old_priv_b64 + '","new-kid":"' + new_priv_b64 + '"}')
    monkeypatch.setenv("FG_AUDIT_ED25519_PUBLIC_KEYS_JSON", '{"old-kid":"' + old_pub_b64 + '","new-kid":"' + new_pub_b64 + '"}')

    payload = {"root_hash": "a" * 64, "bundle_hash": "b" * 64, "sections": {}}
    sig = sign_manifest_payload(payload)

    monkeypatch.setenv("FG_AUDIT_ED25519_ACTIVE_KID", "new-kid")
    monkeypatch.setenv("FG_AUDIT_ED25519_PREV_KIDS", "old-kid")

    assert verify_manifest_signature(payload, signature_algo=sig["signature_algo"], kid=sig["kid"], signature=sig["signature"]) is True

    monkeypatch.setenv("FG_AUDIT_ED25519_PREV_KIDS", "")
    assert verify_manifest_signature(payload, signature_algo=sig["signature_algo"], kid=sig["kid"], signature=sig["signature"]) is False
