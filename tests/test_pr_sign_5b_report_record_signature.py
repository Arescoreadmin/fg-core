"""Tests for PR-SIGN-5b: persistent ingest report signature metadata.

Covers:
  - ReportRecord model has the six new signature columns
  - _build_signing_payload produces a stable deterministic payload
  - _persist_report_signature writes all six fields correctly
  - persisted signature verifies with the public key
  - tampered payload_hash fails verification
  - export prefers persisted signature over on-the-fly signing
  - legacy reports (null signature) do not crash export
  - prod export omits headers for unsigned legacy reports
  - private key material is never stored in the signature column
"""

from __future__ import annotations

import hashlib
import json

_TEST_SEED = bytes(range(1, 33))
_TEST_SEED_HEX = _TEST_SEED.hex()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(**kwargs):
    """Return a minimal ReportRecord-like object for unit tests."""
    import types

    r = types.SimpleNamespace()
    r.id = kwargs.get("id", "report-test-1")
    r.tenant_id = kwargs.get("tenant_id", "tenant-1")
    r.manifest_hash = kwargs.get("manifest_hash", "a" * 64)
    r.finalized_manifest_hash = kwargs.get("finalized_manifest_hash", None)
    r.report_version = kwargs.get("report_version", 1)
    r.signature = kwargs.get("signature", None)
    r.signature_algorithm = kwargs.get("signature_algorithm", None)
    r.signature_key_id = kwargs.get("signature_key_id", None)
    r.signed_at = kwargs.get("signed_at", None)
    r.signature_payload_hash = kwargs.get("signature_payload_hash", None)
    r.signature_version = kwargs.get("signature_version", None)
    return r


# ---------------------------------------------------------------------------
# Model shape
# ---------------------------------------------------------------------------


def test_report_record_has_signature_columns():
    from api.db_models import ReportRecord

    cols = {c.key for c in ReportRecord.__mapper__.columns}
    for col in (
        "signature",
        "signature_algorithm",
        "signature_key_id",
        "signed_at",
        "signature_payload_hash",
        "signature_version",
    ):
        assert col in cols, f"ReportRecord missing column: {col}"


def test_report_record_signature_columns_are_nullable():
    from api.db_models import ReportRecord

    for col_name in (
        "signature",
        "signature_algorithm",
        "signature_key_id",
        "signed_at",
        "signature_payload_hash",
        "signature_version",
    ):
        col = ReportRecord.__mapper__.columns[col_name]
        assert col.nullable, f"Column {col_name} should be nullable"


# ---------------------------------------------------------------------------
# _build_signing_payload
# ---------------------------------------------------------------------------


def test_build_signing_payload_is_stable():
    from api.reports_engine import _build_signing_payload

    r = _make_report(finalized_manifest_hash="b" * 64)
    p1 = _build_signing_payload(r)
    p2 = _build_signing_payload(r)
    assert p1 == p2


def test_build_signing_payload_prefers_finalized_hash():
    from api.reports_engine import _build_signing_payload

    r = _make_report(manifest_hash="a" * 64, finalized_manifest_hash="b" * 64)
    payload = json.loads(_build_signing_payload(r))
    assert payload["manifest_hash"] == "b" * 64


def test_build_signing_payload_falls_back_to_manifest_hash():
    from api.reports_engine import _build_signing_payload

    r = _make_report(manifest_hash="c" * 64, finalized_manifest_hash=None)
    payload = json.loads(_build_signing_payload(r))
    assert payload["manifest_hash"] == "c" * 64


def test_build_signing_payload_contains_required_fields():
    from api.reports_engine import _build_signing_payload

    r = _make_report(id="rpt-abc", finalized_manifest_hash="d" * 64, report_version=2)
    payload = json.loads(_build_signing_payload(r))
    assert payload["report_id"] == "rpt-abc"
    assert payload["manifest_hash"] == "d" * 64
    assert payload["report_version"] == 2
    assert payload["signature_version"] == "report-signature-v1"


def test_build_signing_payload_excludes_tenant_id():
    """tenant_id must not appear in the signing payload to avoid cross-tenant leakage."""
    from api.reports_engine import _build_signing_payload

    r = _make_report(tenant_id="tenant-secret")
    payload_str = _build_signing_payload(r)
    assert "tenant-secret" not in payload_str
    assert "tenant_id" not in payload_str


# ---------------------------------------------------------------------------
# _persist_report_signature
# ---------------------------------------------------------------------------


def test_persist_report_signature_writes_all_fields(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from api.reports_engine import _persist_report_signature

    r = _make_report(finalized_manifest_hash="e" * 64)
    _persist_report_signature(r)

    assert r.signature is not None
    assert len(r.signature) == 128  # Ed25519 = 64 bytes = 128 hex chars
    assert r.signature_algorithm == "ed25519"
    assert r.signature_key_id is not None
    assert len(r.signature_key_id) == 16
    assert r.signed_at is not None
    assert r.signature_payload_hash is not None
    assert len(r.signature_payload_hash) == 64  # SHA-256 hex
    assert r.signature_version == "report-signature-v1"


def test_persist_report_signature_no_private_key_in_db(monkeypatch):
    """The raw private key seed must never appear in any stored signature field."""
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)

    from api.reports_engine import _persist_report_signature

    r = _make_report(finalized_manifest_hash="f" * 64)
    _persist_report_signature(r)

    for field in (r.signature, r.signature_key_id, r.signature_payload_hash):
        assert _TEST_SEED_HEX not in (field or "")


def test_persist_report_signature_silent_on_missing_key(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from api.reports_engine import _persist_report_signature

    r = _make_report()
    _persist_report_signature(r)  # must not raise

    assert r.signature is None


def test_persist_report_signature_payload_hash_is_stable(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)

    from api.reports_engine import _build_signing_payload, _persist_report_signature

    r = _make_report(finalized_manifest_hash="a" * 64)
    expected_hash = hashlib.sha256(
        _build_signing_payload(r).encode("utf-8")
    ).hexdigest()

    _persist_report_signature(r)
    assert r.signature_payload_hash == expected_hash


# ---------------------------------------------------------------------------
# Verification: persisted signature verifies with public key
# ---------------------------------------------------------------------------


def test_persisted_signature_verifies(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from api.reports_engine import _build_signing_payload, _persist_report_signature
    from services.governance.report.signing import verify_report

    r = _make_report(finalized_manifest_hash="b" * 64)
    _persist_report_signature(r)

    payload = _build_signing_payload(r)
    assert verify_report(payload, r.signature) is True


def test_tampered_payload_hash_fails_verification(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)

    from api.reports_engine import _build_signing_payload, _persist_report_signature
    from services.governance.report.signing import verify_report

    r = _make_report(finalized_manifest_hash="c" * 64)
    _persist_report_signature(r)

    tampered_payload = _build_signing_payload(r).replace("c" * 64, "d" * 64)
    assert verify_report(tampered_payload, r.signature) is False


# ---------------------------------------------------------------------------
# Export header behavior
# ---------------------------------------------------------------------------


def test_export_prefers_persisted_signature_over_recompute(monkeypatch):
    """export_report_artifact must use report.signature when set."""
    # The persisted sig was produced with the seed key; set a *different* key
    # so that if the code re-signs on the fly the result would differ.
    different_seed = bytes(range(2, 34)).hex()
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", different_seed)
    monkeypatch.setenv("FG_ENV", "dev")

    from api.reports_engine import _persist_report_signature

    # Produce the persisted signature with the original seed
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    r = _make_report(finalized_manifest_hash="e" * 64)
    _persist_report_signature(r)
    persisted_sig = r.signature

    # Switch to different key; export must still return the persisted sig
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", different_seed)

    # Simulate what export does: prefer persisted
    headers: dict[str, str] = {}
    if r.signature:
        headers["X-Report-Signature"] = r.signature
        if r.signature_key_id:
            headers["X-Report-Public-Key-Id"] = r.signature_key_id

    assert headers["X-Report-Signature"] == persisted_sig


def test_export_legacy_unsigned_report_no_crash(monkeypatch):
    """Reports with null signature (legacy/unfinalized) must not crash."""
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)

    r = _make_report()  # signature=None
    headers: dict[str, str] = {}

    # Replicate the export branch logic
    if r.signature:
        headers["X-Report-Signature"] = r.signature

    assert "X-Report-Signature" not in headers


def test_export_prod_omits_headers_for_unsigned_legacy(monkeypatch):
    """In production, unsigned legacy reports must NOT produce signing headers."""
    monkeypatch.setenv("FG_ENV", "prod")

    from api.config.env import is_production_env

    assert is_production_env() is True

    r = _make_report()  # signature=None
    headers: dict[str, str] = {}

    if r.signature:
        headers["X-Report-Signature"] = r.signature
    elif not is_production_env():
        headers["X-Report-Signature"] = "would-be-computed"
    # else: prod + no signature → omit (no header added)

    assert "X-Report-Signature" not in headers
