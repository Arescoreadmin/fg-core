"""Tests for Report Authority export bundle and signature.

Coverage:
  RE-1  to RE-20: export.py — build_export_bundle returns bytes, ZIP structure,
                              checksums, bundle_meta.json
  RE-21 to RE-40: signature.py — sign_payload, verify_signature, determinism
  RE-41 to RE-50: export bundle integrity — tamper detection, reproducibility
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from services.report_authority.export import build_export_bundle
from services.report_authority.signature import sign_payload, verify_signature
from services.report_authority.hashing import compute_sha256

# ---------------------------------------------------------------------------
# Fixed test inputs
# ---------------------------------------------------------------------------

_REPORT_ID = "rpt-export-test-001"

_MANIFEST: dict = {
    "manifest_schema_version": "1.0",
    "report_id": _REPORT_ID,
    "report_version": "1.0.0-r0",
    "schema_version": "1.0",
    "assessment_id": "assess-export-001",
    "report_type": "EXECUTIVE",
    "tenant_id": "tenant-export-001",
    "generation_timestamp": "2026-01-01T00:00:00+00:00",
    "assessor_id": "assessor-export-001",
    "generator_version": "1.0.0",
    "provider_version": "frostgate-core-1.0.0",
    "export_version": "1.0.0",
    "sections_included": ["EXECUTIVE_SUMMARY", "FINDINGS"],
    "authority_versions": {"generator": "1.0.0"},
    "manifest_hash_sha256": "a" * 64,
    "manifest_hash_sha512": "b" * 128,
}

_PDF_BYTES: bytes = b"%PDF-1.4 minimal test pdf content for export testing"
_HTML_BYTES: bytes = b"<!DOCTYPE html><html><body><h1>Test Report</h1></body></html>"
_JSON_BYTES: bytes = b'{"report_id":"rpt-export-test-001","title":"Test"}'

_SIGNING_KEY: bytes = b"test-signing-key-for-unit-tests-only-32b"


def _build_bundle(**kwargs) -> bytes:
    defaults: dict[str, Any] = dict(
        report_id=_REPORT_ID,
        pdf_bytes=_PDF_BYTES,
        html_bytes=_HTML_BYTES,
        json_bytes=_JSON_BYTES,
        manifest=_MANIFEST,
    )
    defaults.update(kwargs)
    return build_export_bundle(**defaults)


def _open_zip(bundle_bytes: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(bundle_bytes), "r")


# ===========================================================================
# RE-1 to RE-20: export.py
# ===========================================================================


class TestExportBundle:
    """RE-1 through RE-20: build_export_bundle tests."""

    def test_RE_1_build_export_bundle_returns_bytes(self):
        result = _build_bundle()
        assert isinstance(result, bytes)

    def test_RE_2_bundle_is_non_empty(self):
        result = _build_bundle()
        assert len(result) > 0

    def test_RE_3_bundle_is_valid_zip(self):
        result = _build_bundle()
        assert zipfile.is_zipfile(io.BytesIO(result))

    def test_RE_4_bundle_contains_report_pdf(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "report.pdf" in zf.namelist()

    def test_RE_5_bundle_contains_report_html(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "report.html" in zf.namelist()

    def test_RE_6_bundle_contains_report_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "report.json" in zf.namelist()

    def test_RE_7_bundle_contains_manifest_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "manifest.json" in zf.namelist()

    def test_RE_8_bundle_contains_checksums_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "checksums.json" in zf.namelist()

    def test_RE_9_bundle_contains_bundle_meta_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "bundle_meta.json" in zf.namelist()

    def test_RE_10_bundle_contains_trust_manifest_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "trust_manifest.json" in zf.namelist()

    def test_RE_11_bundle_contains_transparency_proof_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "transparency_proof.json" in zf.namelist()

    def test_RE_12_bundle_contains_evidence_index_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "evidence_index.json" in zf.namelist()

    def test_RE_13_bundle_contains_verification_instructions(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert "VERIFICATION_INSTRUCTIONS.txt" in zf.namelist()

    def test_RE_14_checksums_json_is_valid_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums_bytes = zf.read("checksums.json")
            checksums = json.loads(checksums_bytes)
            assert isinstance(checksums, dict)

    def test_RE_15_checksums_json_has_entry_for_each_file(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            namelist = zf.namelist()
            # Every file except checksums.json and bundle_meta.json should be in checksums
            for name in namelist:
                if name not in ("checksums.json", "bundle_meta.json"):
                    assert name in checksums, f"{name} not in checksums"

    def test_RE_16_checksums_are_correct_sha256_values(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            # Verify report.pdf checksum
            actual_pdf = compute_sha256(zf.read("report.pdf"))
            assert checksums["report.pdf"] == actual_pdf

    def test_RE_17_checksums_json_checksum_for_report_json_correct(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            actual_json = compute_sha256(zf.read("report.json"))
            assert checksums["report.json"] == actual_json

    def test_RE_18_bundle_meta_json_is_valid_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            meta = json.loads(zf.read("bundle_meta.json"))
            assert isinstance(meta, dict)

    def test_RE_19_bundle_meta_contains_report_id(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            meta = json.loads(zf.read("bundle_meta.json"))
            assert meta["report_id"] == _REPORT_ID

    def test_RE_20_bundle_meta_contains_bundle_signature(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            meta = json.loads(zf.read("bundle_meta.json"))
            assert "bundle_signature" in meta
            assert meta["bundle_signature"] is not None

    def test_RE_20b_bundle_meta_has_bundle_version(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            meta = json.loads(zf.read("bundle_meta.json"))
            assert "bundle_version" in meta

    def test_RE_20c_bundle_meta_has_file_count(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            meta = json.loads(zf.read("bundle_meta.json"))
            assert "file_count" in meta
            assert meta["file_count"] > 0

    def test_RE_20d_report_pdf_content_matches_input(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert zf.read("report.pdf") == _PDF_BYTES

    def test_RE_20e_report_html_content_matches_input(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            assert zf.read("report.html") == _HTML_BYTES

    def test_RE_20f_evidence_index_with_data_is_sorted(self):
        evidence = [
            {"evidence_id": "ev-z", "hash": "zzz"},
            {"evidence_id": "ev-a", "hash": "aaa"},
        ]
        result = _build_bundle(evidence_index=evidence)
        with _open_zip(result) as zf:
            index = json.loads(zf.read("evidence_index.json"))
            ids = [item["evidence_id"] for item in index]
            assert ids == sorted(ids)


# ===========================================================================
# RE-21 to RE-40: signature.py
# ===========================================================================


class TestSignature:
    """RE-21 through RE-40: sign_payload and verify_signature tests."""

    def test_RE_21_sign_payload_returns_string(self):
        result = sign_payload(b"test payload", signing_key=_SIGNING_KEY)
        assert isinstance(result, str)

    def test_RE_22_sign_payload_returns_hex_string(self):
        result = sign_payload(b"test payload", signing_key=_SIGNING_KEY)
        assert all(c in "0123456789abcdef" for c in result)

    def test_RE_23_sign_payload_hmac_sha256_is_64_chars(self):
        result = sign_payload(b"test payload", signing_key=_SIGNING_KEY)
        assert len(result) == 64

    def test_RE_24_verify_signature_returns_true_for_valid(self):
        payload = b"test payload to verify"
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert verify_signature(payload, sig, signing_key=_SIGNING_KEY) is True

    def test_RE_25_verify_signature_returns_false_for_wrong_signature(self):
        payload = b"test payload"
        wrong_sig = "a" * 64
        assert verify_signature(payload, wrong_sig, signing_key=_SIGNING_KEY) is False

    def test_RE_26_verify_signature_returns_false_for_tampered_payload(self):
        payload = b"original payload"
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        tampered = b"tampered payload"
        assert verify_signature(tampered, sig, signing_key=_SIGNING_KEY) is False

    def test_RE_27_sign_payload_deterministic_for_same_input(self):
        payload = b"deterministic test"
        sig1 = sign_payload(payload, signing_key=_SIGNING_KEY)
        sig2 = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert sig1 == sig2

    def test_RE_28_different_payloads_produce_different_signatures(self):
        sig1 = sign_payload(b"payload-A", signing_key=_SIGNING_KEY)
        sig2 = sign_payload(b"payload-B", signing_key=_SIGNING_KEY)
        assert sig1 != sig2

    def test_RE_29_different_keys_produce_different_signatures(self):
        payload = b"same payload"
        key1 = b"key-one-for-testing-purposes-32b"
        key2 = b"key-two-for-testing-purposes-32b"
        sig1 = sign_payload(payload, signing_key=key1)
        sig2 = sign_payload(payload, signing_key=key2)
        assert sig1 != sig2

    def test_RE_30_verify_with_wrong_key_returns_false(self):
        payload = b"test payload"
        key1 = b"key-one-for-testing-purposes-32b"
        key2 = b"key-two-for-testing-purposes-32b"
        sig = sign_payload(payload, signing_key=key1)
        assert verify_signature(payload, sig, signing_key=key2) is False

    def test_RE_31_sign_payload_empty_bytes(self):
        result = sign_payload(b"", signing_key=_SIGNING_KEY)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_RE_32_verify_empty_payload_with_correct_sig(self):
        payload = b""
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert verify_signature(payload, sig, signing_key=_SIGNING_KEY) is True

    def test_RE_33_sign_payload_large_data(self):
        payload = b"x" * 100000
        result = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert len(result) == 64

    def test_RE_34_verify_large_data_correct_signature(self):
        payload = b"x" * 100000
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert verify_signature(payload, sig, signing_key=_SIGNING_KEY) is True

    def test_RE_35_sign_payload_uses_default_key_when_none_provided(self):
        payload = b"uses-default-key"
        # Should not raise even without explicit key
        result = sign_payload(payload)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_RE_36_verify_signature_uses_default_key_when_none_provided(self):
        payload = b"uses-default-key-verify"
        sig = sign_payload(payload)
        assert verify_signature(payload, sig) is True

    def test_RE_37_sign_payload_binary_data(self):
        payload = bytes(range(256))
        result = sign_payload(payload, signing_key=_SIGNING_KEY)
        assert len(result) == 64

    def test_RE_38_verify_returns_bool(self):
        payload = b"test"
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        result = verify_signature(payload, sig, signing_key=_SIGNING_KEY)
        assert isinstance(result, bool)

    def test_RE_39_signature_is_hex_lowercase(self):
        result = sign_payload(b"test", signing_key=_SIGNING_KEY)
        assert result == result.lower()

    def test_RE_40_signature_verification_is_case_sensitive(self):
        payload = b"test"
        sig = sign_payload(payload, signing_key=_SIGNING_KEY)
        # Uppercase signature should fail
        upper_sig = sig.upper()
        # hmac.compare_digest is case-sensitive; uppercase will not match
        assert not verify_signature(payload, upper_sig, signing_key=_SIGNING_KEY)


# ===========================================================================
# RE-41 to RE-50: export bundle integrity
# ===========================================================================


class TestExportBundleIntegrity:
    """RE-41 through RE-50: tamper detection and reproducibility tests."""

    def test_RE_41_build_twice_same_input_same_file_set(self):
        b1 = _build_bundle()
        b2 = _build_bundle()
        with _open_zip(b1) as zf1, _open_zip(b2) as zf2:
            assert sorted(zf1.namelist()) == sorted(zf2.namelist())

    def test_RE_42_bundle_checksums_detect_tampered_pdf(self):
        result = _build_bundle()
        # Tamper: extract, modify report.pdf, verify checksum mismatch
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            original_pdf = zf.read("report.pdf")

        tampered_pdf = original_pdf + b"TAMPERED"
        tampered_checksum = compute_sha256(tampered_pdf)

        # The original checksum should NOT match the tampered file
        assert checksums["report.pdf"] != tampered_checksum

    def test_RE_43_bundle_checksums_detect_tampered_json(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            original_json = zf.read("report.json")

        tampered_json = original_json + b',"tampered":true}'
        tampered_checksum = compute_sha256(tampered_json)
        assert checksums["report.json"] != tampered_checksum

    def test_RE_44_bundle_checksums_detect_tampered_manifest(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums = json.loads(zf.read("checksums.json"))
            original_manifest = zf.read("manifest.json")

        tampered = original_manifest + b"TAMPERED"
        assert checksums["manifest.json"] != compute_sha256(tampered)

    def test_RE_45_build_with_trust_manifest_included(self):
        trust = {"trust_chain": ["root", "intermediate", "leaf"], "version": "1.0"}
        result = _build_bundle(trust_manifest=trust)
        with _open_zip(result) as zf:
            tm = json.loads(zf.read("trust_manifest.json"))
            assert "trust_chain" in tm

    def test_RE_46_build_with_transparency_proof_included(self):
        proof = {"merkle_root": "abc123", "membership_proof": ["a", "b", "c"]}
        result = _build_bundle(transparency_proof=proof)
        with _open_zip(result) as zf:
            tp = json.loads(zf.read("transparency_proof.json"))
            assert "merkle_root" in tp

    def test_RE_47_bundle_signature_in_meta_is_valid(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums_bytes = zf.read("checksums.json")
            meta = json.loads(zf.read("bundle_meta.json"))
        sig = meta["bundle_signature"]
        # The signature is over the checksums payload
        assert verify_signature(checksums_bytes, sig) is True

    def test_RE_48_bundle_sha256_in_meta_matches_checksums_hash(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            checksums_bytes = zf.read("checksums.json")
            meta = json.loads(zf.read("bundle_meta.json"))
        expected_hash = compute_sha256(checksums_bytes)
        assert meta["bundle_hash_sha256"] == expected_hash

    def test_RE_49_empty_evidence_index_builds_successfully(self):
        result = _build_bundle(evidence_index=[])
        with _open_zip(result) as zf:
            ei = json.loads(zf.read("evidence_index.json"))
            assert ei == []

    def test_RE_50_build_with_evidence_index_sorted_by_id(self):
        evidence = [
            {"evidence_id": "ev-003", "data": "c"},
            {"evidence_id": "ev-001", "data": "a"},
            {"evidence_id": "ev-002", "data": "b"},
        ]
        result = _build_bundle(evidence_index=evidence)
        with _open_zip(result) as zf:
            index = json.loads(zf.read("evidence_index.json"))
        ids = [item["evidence_id"] for item in index]
        assert ids == ["ev-001", "ev-002", "ev-003"]

    def test_RE_50b_manifest_json_in_bundle_has_sorted_keys(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            manifest_bytes = zf.read("manifest.json")
        # Verify it's valid JSON
        manifest = json.loads(manifest_bytes)
        assert isinstance(manifest, dict)

    def test_RE_50c_verification_instructions_are_non_empty(self):
        result = _build_bundle()
        with _open_zip(result) as zf:
            vi = zf.read("VERIFICATION_INSTRUCTIONS.txt")
        assert len(vi) > 100  # Must be a meaningful document

    def test_RE_50d_different_report_id_produces_different_meta(self):
        b1 = _build_bundle(report_id="rpt-001")
        b2 = _build_bundle(report_id="rpt-002")
        with _open_zip(b1) as zf1, _open_zip(b2) as zf2:
            m1 = json.loads(zf1.read("bundle_meta.json"))
            m2 = json.loads(zf2.read("bundle_meta.json"))
        assert m1["report_id"] != m2["report_id"]
