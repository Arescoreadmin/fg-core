"""Tests for scan manifest generation and HMAC verification."""

from __future__ import annotations

import pytest

from services.connectors.msgraph.integrity import build_manifest, verify_manifest


class _FakeClient:
    """Minimal stand-in for GraphClient manifest properties."""

    @property
    def endpoints_called(self):
        return ["/users", "/groups"]

    @property
    def record_counts(self):
        return {"/users": 50, "/groups": 10}

    @property
    def structure_hashes(self):
        return {"/users": "abc123", "/groups": "def456"}


@pytest.fixture(autouse=True)
def set_manifest_key(monkeypatch):
    monkeypatch.setenv("FG_MANIFEST_KEY", "test-manifest-key-32-bytes-padded!")


def test_build_manifest_produces_valid_hmac():
    manifest = build_manifest(_FakeClient())
    assert verify_manifest(manifest)


def test_tampered_manifest_fails_verification():
    manifest = build_manifest(_FakeClient())
    tampered = manifest.model_copy(update={"manifest_hmac": "00" * 32})
    assert not verify_manifest(tampered)


def test_manifest_records_endpoints():
    manifest = build_manifest(_FakeClient())
    assert "/users" in manifest.endpoints_called
    assert "/groups" in manifest.endpoints_called


def test_manifest_records_counts():
    manifest = build_manifest(_FakeClient())
    assert manifest.record_counts["/users"] == 50
    assert manifest.record_counts["/groups"] == 10


def test_manifest_is_frozen():
    manifest = build_manifest(_FakeClient())
    with pytest.raises(Exception):
        manifest.manifest_id = "changed"  # type: ignore[misc]
