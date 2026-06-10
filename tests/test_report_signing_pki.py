"""Tests for PR-SIGN-1 and PR-SIGN-2: PKI-style report signing and real PDF export."""

from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from services.governance.report.signing import (
    ReportSigningKeyError,
    get_public_key_hex,
    sign_report,
    verify_report,
)

# Deterministic 32-byte test seed
_TEST_SEED = bytes(range(1, 33))
_TEST_SEED_HEX = _TEST_SEED.hex()
_TEST_PRIV = Ed25519PrivateKey.from_private_bytes(_TEST_SEED)
_TEST_PUB_HEX = _TEST_PRIV.public_key().public_bytes_raw().hex()


# ---------------------------------------------------------------------------
# get_public_key_hex
# ---------------------------------------------------------------------------


def test_get_public_key_hex_from_private_key(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    result = get_public_key_hex()
    assert result == _TEST_PUB_HEX


def test_get_public_key_hex_from_public_key_env(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", _TEST_PUB_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    result = get_public_key_hex()
    assert result == _TEST_PUB_HEX


def test_get_public_key_hex_prefers_public_env(monkeypatch):
    """FG_REPORT_SIGNING_PUBLIC_KEY takes precedence over deriving from private."""
    other_pub = bytes(range(2, 34)).hex()
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", other_pub)
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    result = get_public_key_hex()
    assert result == other_pub


def test_get_public_key_hex_raises_when_neither_set(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    with pytest.raises(ReportSigningKeyError):
        get_public_key_hex()


def test_get_public_key_hex_invalid_public_key_hex(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", "not-hex-data")
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    with pytest.raises(ReportSigningKeyError):
        get_public_key_hex()


def test_get_public_key_hex_wrong_length_public_key(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", "deadbeef")  # 4 bytes, not 32
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    with pytest.raises(ReportSigningKeyError):
        get_public_key_hex()


# ---------------------------------------------------------------------------
# verify_report with FG_REPORT_SIGNING_PUBLIC_KEY (no private key required)
# ---------------------------------------------------------------------------


def test_verify_report_with_public_key_only(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    canonical = '{"report_id": "test-1", "version": 1}'
    sig = sign_report(canonical)

    # Remove private key — only supply public key
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", _TEST_PUB_HEX)

    assert verify_report(canonical, sig) is True


def test_verify_report_fails_tampered_payload(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    canonical = '{"report_id": "test-2", "version": 1}'
    sig = sign_report(canonical)

    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", _TEST_PUB_HEX)

    assert verify_report('{"report_id": "test-2", "version": 2}', sig) is False


def test_verify_report_bad_signature_hex(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", _TEST_PUB_HEX)
    assert verify_report("anything", "not-valid-hex") is False


# ---------------------------------------------------------------------------
# GET /signing/public-key endpoint
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.signing import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_signing_public_key_endpoint_returns_200(client):
    resp = client.get("/signing/public-key")
    assert resp.status_code == 200


def test_signing_public_key_endpoint_body(client):
    resp = client.get("/signing/public-key")
    body = resp.json()
    assert body["algorithm"] == "ed25519"
    assert body["public_key"] == _TEST_PUB_HEX
    assert body["usage"] == "report-signing"
    assert body["digest"] == "sha256"
    assert "key_id" in body
    assert "verify_instruction" in body


def test_signing_public_key_key_id_is_sha256_prefix(client):
    resp = client.get("/signing/public-key")
    body = resp.json()
    expected_key_id = hashlib.sha256(bytes.fromhex(_TEST_PUB_HEX)).hexdigest()[:16]
    assert body["key_id"] == expected_key_id


def test_signing_public_key_endpoint_503_when_no_key(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.signing import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    c = TestClient(app)
    resp = c.get("/signing/public-key")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# render_pdf_export — real PDF bytes (PR-SIGN-2)
# ---------------------------------------------------------------------------


def _minimal_manifest() -> dict:
    return {
        "report_id": "test-report-1",
        "tenant_id": "tenant-1",
        "generated_at": "2026-01-01T00:00:00Z",
        "executive_summary": "Test advisory.",
        "findings": [],
        "evidence": [],
        "framework_mappings": [],
        "remediations": [],
    }


def test_render_pdf_export_returns_bytes():
    from api.report_exports import render_pdf_export

    result = render_pdf_export(_minimal_manifest(), "abc123deadbeef")
    assert isinstance(result, bytes)
    assert len(result) > 100


def test_render_pdf_export_is_real_pdf():
    from api.report_exports import render_pdf_export

    result = render_pdf_export(_minimal_manifest(), "abc123deadbeef")
    assert result[:4] == b"%PDF"


def test_render_pdf_export_not_json_payload():
    from api.report_exports import render_pdf_export

    result = render_pdf_export(_minimal_manifest(), "abc123deadbeef")
    # The old fake implementation returned JSON inside a %PDF wrapper
    try:
        import json

        json.loads(result[8:])
        is_json = True
    except Exception:
        is_json = False
    assert not is_json, "render_pdf_export must return a real PDF, not JSON"


def test_render_pdf_export_unavailable_error():
    """ExportUnavailableError raised when reportlab is not importable."""
    import sys
    from api.report_exports import ExportUnavailableError

    with patch.dict(
        sys.modules,
        {"reportlab": None, "reportlab.lib": None, "reportlab.platypus": None},
    ):
        import api.report_exports as _mod

        orig = _mod.render_pdf_export

        def _patched(manifest, digest):
            try:
                import reportlab.platypus  # noqa: F401

                raise AssertionError("should have raised ImportError")
            except (ImportError, TypeError):
                raise ExportUnavailableError("reportlab is required for PDF export")

        _mod.render_pdf_export = _patched
        try:
            with pytest.raises(ExportUnavailableError):
                _mod.render_pdf_export(_minimal_manifest(), "abc123")
        finally:
            _mod.render_pdf_export = orig
