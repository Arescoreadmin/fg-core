"""Tests for PR-SIGN-3 (billing HMAC key), PR-SIGN-4 (startup validation),
and PR-SIGN-5 (ingest path signing headers)."""

from __future__ import annotations

import hashlib

import pytest


# ---------------------------------------------------------------------------
# PR-SIGN-3: billing _attest() fails closed without FG_BILLING_EVIDENCE_HMAC_KEY
# ---------------------------------------------------------------------------


def test_attest_raises_without_billing_key(monkeypatch):
    monkeypatch.delenv("FG_BILLING_EVIDENCE_HMAC_KEY", raising=False)
    from api.billing import _attest

    with pytest.raises(RuntimeError, match="FG_BILLING_EVIDENCE_HMAC_KEY"):
        _attest(b"payload")


def test_attest_succeeds_with_billing_key(monkeypatch):
    monkeypatch.setenv(
        "FG_BILLING_EVIDENCE_HMAC_KEY", "test-secret-key-32-chars-xxxxxxxx"
    )
    from api.billing import _attest

    sig, key_id = _attest(b"payload")
    assert len(sig) == 64  # SHA-256 hex digest
    assert key_id == "hmac-sha256:key_id=fg_billing_default"


def test_attest_sig_differs_with_different_key(monkeypatch):
    from api.billing import _attest

    monkeypatch.setenv(
        "FG_BILLING_EVIDENCE_HMAC_KEY", "key-one-xxxxxxxxxxxxxxxxxxxxxxxx"
    )
    sig1, _ = _attest(b"payload")

    monkeypatch.setenv(
        "FG_BILLING_EVIDENCE_HMAC_KEY", "key-two-xxxxxxxxxxxxxxxxxxxxxxxx"
    )
    sig2, _ = _attest(b"payload")

    assert sig1 != sig2


def test_attest_no_default_key_fallback(monkeypatch):
    """Static 'billing-dev-key' fallback must be gone."""
    monkeypatch.delenv("FG_BILLING_EVIDENCE_HMAC_KEY", raising=False)
    import inspect
    from api import billing

    src = inspect.getsource(billing._attest)
    assert "billing-dev-key" not in src


# ---------------------------------------------------------------------------
# PR-SIGN-4: startup validation checks for signing key and billing HMAC key
# ---------------------------------------------------------------------------


def test_startup_warns_missing_report_signing_key(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "dev"
    v.is_production = False
    report = v.validate()

    names = [r.name for r in report.results]
    assert "report_signing_key_missing" in names
    result = next(r for r in report.results if r.name == "report_signing_key_missing")
    assert not result.passed


def test_startup_errors_missing_report_signing_key_in_prod(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "prod"
    v.is_production = True
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "report_signing_key_missing"), None
    )
    assert result is not None
    assert result.severity == "error"


def test_startup_passes_when_signing_key_set(monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", "a" * 64)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    assert "report_signing_key_missing" not in [r.name for r in report.results]


def test_startup_passes_when_public_key_only_set(monkeypatch):
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.setenv("FG_REPORT_SIGNING_PUBLIC_KEY", "b" * 64)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    assert "report_signing_key_missing" not in [r.name for r in report.results]


def test_startup_warns_missing_billing_hmac_key(monkeypatch):
    monkeypatch.delenv("FG_BILLING_EVIDENCE_HMAC_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "dev"
    v.is_production = False
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "billing_hmac_key_missing"), None
    )
    assert result is not None
    assert not result.passed


def test_startup_errors_missing_billing_hmac_key_in_prod(monkeypatch):
    monkeypatch.delenv("FG_BILLING_EVIDENCE_HMAC_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "prod"
    v.is_production = True
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "billing_hmac_key_missing"), None
    )
    assert result is not None
    assert result.severity == "error"


def test_validate_startup_config_raises_in_prod_missing_signing_key(monkeypatch):
    """Full boot chain: FG_ENV=prod + fail_on_error=True + missing signing key → RuntimeError."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)
    from api.config.startup_validation import validate_startup_config

    with pytest.raises(RuntimeError, match="FG_REPORT_SIGNING_KEY"):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_validate_startup_config_raises_in_prod_missing_billing_key(monkeypatch):
    """Full boot chain: FG_ENV=prod + fail_on_error=True + missing billing key → RuntimeError."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.delenv("FG_BILLING_EVIDENCE_HMAC_KEY", raising=False)
    from api.config.startup_validation import validate_startup_config

    with pytest.raises(RuntimeError, match="FG_BILLING_EVIDENCE_HMAC_KEY"):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_startup_passes_billing_hmac_key_present(monkeypatch):
    monkeypatch.setenv(
        "FG_BILLING_EVIDENCE_HMAC_KEY", "some-strong-secret-key-here-xxx"
    )
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    result = next((r for r in report.results if r.name == "billing_hmac_key"), None)
    assert result is not None
    assert result.passed


# ---------------------------------------------------------------------------
# PR-SIGN-5: ingest report export signing logic (tested via sign_report directly;
# the HTTP route is auth-gated so we test the signing layer, not the route layer)
# ---------------------------------------------------------------------------

_TEST_SEED = bytes(range(1, 33))
_TEST_SEED_HEX = _TEST_SEED.hex()


def _minimal_manifest() -> dict:
    return {
        "report_id": "ingest-test-1",
        "tenant_id": "tenant-1",
        "generated_at": "2026-01-01T00:00:00Z",
        "executive_summary": "Test.",
        "findings": [],
        "evidence": [],
        "framework_mappings": [],
        "remediations": [],
    }


def test_ingest_sign_produces_valid_signature(monkeypatch):
    """sign_report() over canonical manifest JSON produces a verifiable Ed25519 sig."""
    import json

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from services.governance.report.signing import sign_report, verify_report

    manifest = _minimal_manifest()
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    sig = sign_report(canonical)

    assert len(sig) == 128  # Ed25519 = 64 bytes = 128 hex chars
    assert verify_report(canonical, sig) is True


def test_ingest_sign_fails_closed_without_key(monkeypatch):
    """sign_report() raises ReportSigningKeyError when no key is configured."""
    import json

    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from services.governance.report.signing import ReportSigningKeyError, sign_report

    canonical = json.dumps(_minimal_manifest(), sort_keys=True, separators=(",", ":"))
    with pytest.raises(ReportSigningKeyError):
        sign_report(canonical)


def test_ingest_pdf_headers_built_correctly(monkeypatch):
    """Header dict built in export_report_artifact contains correct keys and values."""
    import json

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _TEST_SEED_HEX)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from services.governance.report.signing import get_public_key_hex, sign_report

    manifest = _minimal_manifest()
    digest = "abc123deadbeef"

    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    sig = sign_report(canonical)
    pub_hex = get_public_key_hex()
    key_id = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]

    # Replicate header construction logic from export_report_artifact
    headers: dict[str, str] = {"X-FrostGate-Manifest-Hash": digest}
    headers["X-Report-Signature"] = sig
    headers["X-Report-Public-Key-Id"] = key_id

    assert len(headers["X-Report-Signature"]) == 128
    assert len(headers["X-Report-Public-Key-Id"]) == 16
    assert headers["X-FrostGate-Manifest-Hash"] == digest

    # Verify the signature is valid
    from services.governance.report.signing import verify_report

    assert verify_report(canonical, headers["X-Report-Signature"]) is True


def test_ingest_header_absent_when_no_signing_key(monkeypatch):
    """ReportSigningKeyError is caught and no signing headers are added."""
    monkeypatch.delenv("FG_REPORT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("FG_REPORT_SIGNING_PUBLIC_KEY", raising=False)

    from services.governance.report.signing import ReportSigningKeyError, sign_report

    headers: dict[str, str] = {"X-FrostGate-Manifest-Hash": "digest"}
    try:
        sig = sign_report("{}")
        headers["X-Report-Signature"] = sig
    except ReportSigningKeyError:
        pass

    assert "X-Report-Signature" not in headers
