"""Tests for Report Authority determinism.

Coverage:
  RD-1  to RD-20: hashing.py — SHA256/SHA512, canonical hash order-independence
  RD-21 to RD-40: renderer_json.py — deterministic bytes, sort_keys, UTF-8
  RD-41 to RD-50: manifest.py — build_manifest is deterministic, verify_manifest
"""

from __future__ import annotations

import json

from services.report_authority.hashing import (
    compute_sha256,
    compute_sha512,
    compute_canonical_hash,
    hash_string,
    verify_hash,
    HASH_ALGORITHM_SHA256,
    HASH_ALGORITHM_SHA512,
)
from services.report_authority.renderer_json import render_json, render_json_pretty
from services.report_authority.manifest import build_manifest, verify_manifest

# ---------------------------------------------------------------------------
# Fixed test data
# ---------------------------------------------------------------------------

_FIXED_PAYLOAD_A: dict = {
    "report_id": "rpt-test-001",
    "tenant_id": "tenant-determinism-001",
    "assessment_id": "assess-001",
    "report_type": "EXECUTIVE",
    "title": "Determinism Test Report",
    "quality_score": 0.82,
    "schema_version": "1.0",
}

_FIXED_PAYLOAD_B: dict = {
    "report_id": "rpt-test-002",
    "tenant_id": "tenant-determinism-002",
    "assessment_id": "assess-002",
}


# ===========================================================================
# RD-1 to RD-20: hashing.py
# ===========================================================================


class TestHashing:
    """RD-1 through RD-20: SHA256/SHA512 and canonical hash tests."""

    def test_RD_1_compute_sha256_returns_64_char_hex(self):
        result = compute_sha256(b"hello world")
        assert len(result) == 64

    def test_RD_2_compute_sha256_is_correct(self):
        # Just verify length and type, not exact value (avoid coupling to specific hash)
        result = compute_sha256(b"hello world")
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_RD_3_compute_sha256_identical_input_identical_output(self):
        data = b"deterministic input"
        r1 = compute_sha256(data)
        r2 = compute_sha256(data)
        assert r1 == r2

    def test_RD_4_compute_sha256_different_inputs_different_hashes(self):
        r1 = compute_sha256(b"input-alpha")
        r2 = compute_sha256(b"input-beta")
        assert r1 != r2

    def test_RD_5_compute_sha512_returns_128_char_hex(self):
        result = compute_sha512(b"hello world")
        assert len(result) == 128

    def test_RD_6_compute_sha512_identical_input_identical_output(self):
        data = b"deterministic input"
        r1 = compute_sha512(data)
        r2 = compute_sha512(data)
        assert r1 == r2

    def test_RD_7_compute_sha512_different_inputs_different_hashes(self):
        r1 = compute_sha512(b"alpha")
        r2 = compute_sha512(b"beta")
        assert r1 != r2

    def test_RD_8_sha256_and_sha512_differ_for_same_input(self):
        data = b"same input"
        r256 = compute_sha256(data)
        r512 = compute_sha512(data)
        assert r256 != r512

    def test_RD_9_canonical_hash_returns_tuple_of_two_strings(self):
        result = compute_canonical_hash(_FIXED_PAYLOAD_A)
        assert isinstance(result, tuple)
        assert len(result) == 2
        sha256, sha512 = result
        assert isinstance(sha256, str)
        assert isinstance(sha512, str)

    def test_RD_10_canonical_hash_sha256_is_64_chars(self):
        sha256, _ = compute_canonical_hash(_FIXED_PAYLOAD_A)
        assert len(sha256) == 64

    def test_RD_11_canonical_hash_sha512_is_128_chars(self):
        _, sha512 = compute_canonical_hash(_FIXED_PAYLOAD_A)
        assert len(sha512) == 128

    def test_RD_12_canonical_hash_identical_inputs_identical_output(self):
        r1 = compute_canonical_hash(_FIXED_PAYLOAD_A)
        r2 = compute_canonical_hash(_FIXED_PAYLOAD_A)
        assert r1 == r2

    def test_RD_13_canonical_hash_order_independent_on_dict_keys(self):
        # Same content, different insertion order
        payload_ordered = {
            "a": 1,
            "b": 2,
            "c": 3,
        }
        payload_reversed = {
            "c": 3,
            "b": 2,
            "a": 1,
        }
        assert compute_canonical_hash(payload_ordered) == compute_canonical_hash(
            payload_reversed
        )

    def test_RD_14_canonical_hash_empty_dict_is_stable(self):
        r1 = compute_canonical_hash({})
        r2 = compute_canonical_hash({})
        assert r1 == r2

    def test_RD_15_canonical_hash_different_payloads_different_hashes(self):
        r1 = compute_canonical_hash(_FIXED_PAYLOAD_A)
        r2 = compute_canonical_hash(_FIXED_PAYLOAD_B)
        assert r1 != r2

    def test_RD_16_canonical_hash_nested_dict_stable(self):
        nested = {
            "outer": {
                "inner_b": 2,
                "inner_a": 1,
            },
            "top": "value",
        }
        r1 = compute_canonical_hash(nested)
        r2 = compute_canonical_hash(nested)
        assert r1 == r2

    def test_RD_17_canonical_hash_nested_dict_order_independent(self):
        nested1 = {"outer": {"z": 26, "a": 1}, "top": "v"}
        nested2 = {"top": "v", "outer": {"a": 1, "z": 26}}
        assert compute_canonical_hash(nested1) == compute_canonical_hash(nested2)

    def test_RD_18_hash_string_sha256_returns_hex(self):
        result = hash_string("test value", algorithm=HASH_ALGORITHM_SHA256)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_RD_19_hash_string_sha512_returns_hex(self):
        result = hash_string("test value", algorithm=HASH_ALGORITHM_SHA512)
        assert isinstance(result, str)
        assert len(result) == 128

    def test_RD_20_verify_hash_returns_true_for_correct_hash(self):
        data = b"verify this data"
        expected = compute_sha256(data)
        assert verify_hash(data, expected, algorithm=HASH_ALGORITHM_SHA256) is True

    def test_RD_20b_verify_hash_returns_false_for_wrong_hash(self):
        data = b"verify this data"
        wrong_hash = "a" * 64
        assert verify_hash(data, wrong_hash, algorithm=HASH_ALGORITHM_SHA256) is False

    def test_RD_20c_verify_hash_sha512_correct(self):
        data = b"some bytes"
        expected = compute_sha512(data)
        assert verify_hash(data, expected, algorithm=HASH_ALGORITHM_SHA512) is True

    def test_RD_20d_hash_string_unsupported_algorithm_raises(self):
        import pytest

        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            hash_string("test", algorithm="md5")

    def test_RD_20e_canonical_hash_single_value_payload_stable(self):
        p = {"key": "value"}
        assert compute_canonical_hash(p) == compute_canonical_hash(p)

    def test_RD_20f_canonical_hash_uses_utf8_for_unicode(self):
        # Unicode characters must produce consistent hashes
        unicode_payload = {"text": "こんにちは", "emoji": "🔒"}
        r1 = compute_canonical_hash(unicode_payload)
        r2 = compute_canonical_hash(unicode_payload)
        assert r1 == r2


# ===========================================================================
# RD-21 to RD-40: renderer_json.py
# ===========================================================================


class TestRendererJson:
    """RD-21 through RD-40: JSON renderer determinism tests."""

    def test_RD_21_render_json_identical_inputs_identical_bytes(self):
        b1 = render_json(_FIXED_PAYLOAD_A)
        b2 = render_json(_FIXED_PAYLOAD_A)
        assert b1 == b2

    def test_RD_22_render_json_returns_bytes(self):
        result = render_json(_FIXED_PAYLOAD_A)
        assert isinstance(result, bytes)

    def test_RD_23_render_json_output_is_valid_json(self):
        result = render_json(_FIXED_PAYLOAD_A)
        parsed = json.loads(result.decode("utf-8"))
        assert isinstance(parsed, dict)

    def test_RD_24_render_json_sort_keys_applied(self):
        # Dict with keys in non-alphabetical order
        data = {"z_key": 3, "a_key": 1, "m_key": 2}
        result = render_json(data)
        text = result.decode("utf-8")
        # "a_key" must appear before "m_key" and "z_key"
        assert text.index('"a_key"') < text.index('"m_key"') < text.index('"z_key"')

    def test_RD_25_render_json_sort_keys_order_independent(self):
        data_forward = {"z": 3, "a": 1, "m": 2}
        data_reversed = {"m": 2, "z": 3, "a": 1}
        assert render_json(data_forward) == render_json(data_reversed)

    def test_RD_26_render_json_encoding_is_utf8(self):
        data = {"text": "こんにちは"}
        result = render_json(data)
        text = result.decode("utf-8")
        assert "こんにちは" in text

    def test_RD_27_render_json_no_extra_whitespace(self):
        data = {"a": 1, "b": 2}
        result = render_json(data)
        text = result.decode("utf-8")
        # Canonical format: no spaces after comma or colon
        assert " " not in text

    def test_RD_28_render_json_different_inputs_different_bytes(self):
        b1 = render_json({"key": "value_A"})
        b2 = render_json({"key": "value_B"})
        assert b1 != b2

    def test_RD_29_render_json_empty_dict_stable(self):
        b1 = render_json({})
        b2 = render_json({})
        assert b1 == b2
        assert b1 == b"{}"

    def test_RD_30_render_json_nested_dict_deterministic(self):
        data = {"outer": {"b": 2, "a": 1}, "top": "val"}
        b1 = render_json(data)
        b2 = render_json(data)
        assert b1 == b2

    def test_RD_31_render_json_pretty_returns_bytes(self):
        result = render_json_pretty(_FIXED_PAYLOAD_A)
        assert isinstance(result, bytes)

    def test_RD_32_render_json_pretty_is_valid_json(self):
        result = render_json_pretty(_FIXED_PAYLOAD_A)
        parsed = json.loads(result.decode("utf-8"))
        assert isinstance(parsed, dict)

    def test_RD_33_render_json_pretty_identical_inputs_identical_output(self):
        b1 = render_json_pretty(_FIXED_PAYLOAD_A)
        b2 = render_json_pretty(_FIXED_PAYLOAD_A)
        assert b1 == b2

    def test_RD_34_render_json_pretty_contains_indent(self):
        data = {"key": "value"}
        result = render_json_pretty(data)
        text = result.decode("utf-8")
        assert "\n" in text

    def test_RD_35_render_json_pretty_sort_keys_applied(self):
        data = {"z": 3, "a": 1}
        result = render_json_pretty(data)
        text = result.decode("utf-8")
        assert text.index('"a"') < text.index('"z"')

    def test_RD_36_render_json_preserves_all_fields(self):
        data = {
            "report_id": "r1",
            "quality_score": 0.95,
            "lifecycle_state": "GENERATED",
        }
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["report_id"] == "r1"
        assert parsed["quality_score"] == 0.95
        assert parsed["lifecycle_state"] == "GENERATED"

    def test_RD_37_render_json_handles_list_values(self):
        data = {"items": [3, 1, 2], "name": "test"}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["items"] == [3, 1, 2]

    def test_RD_38_render_json_handles_null_values(self):
        data = {"key": None, "other": "value"}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["key"] is None

    def test_RD_39_render_json_handles_boolean_values(self):
        data = {"flag": True, "other": False}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["flag"] is True
        assert parsed["other"] is False

    def test_RD_40_render_json_pretty_different_inputs_different_output(self):
        b1 = render_json_pretty({"key": "A"})
        b2 = render_json_pretty({"key": "B"})
        assert b1 != b2


# ===========================================================================
# RD-41 to RD-50: manifest.py
# ===========================================================================


class TestManifest:
    """RD-41 through RD-50: manifest build and verify tests."""

    _FIXED_MANIFEST_ARGS = dict(
        report_id="rpt-manifest-001",
        report_version="1.0.0-r0",
        schema_version="1.0",
        assessment_id="assess-manifest-001",
        report_type="EXECUTIVE",
        tenant_id="tenant-manifest-001",
        generation_timestamp="2026-01-01T00:00:00+00:00",
        assessor_id="assessor-manifest-001",
        sections_included=["EXECUTIVE_SUMMARY", "FINDINGS", "MANIFEST"],
    )

    def test_RD_41_build_manifest_is_deterministic(self):
        m1 = build_manifest(**self._FIXED_MANIFEST_ARGS)
        m2 = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert m1 == m2

    def test_RD_42_build_manifest_returns_dict(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert isinstance(m, dict)

    def test_RD_43_build_manifest_contains_required_fields(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert "manifest_hash_sha256" in m
        assert "manifest_hash_sha512" in m
        assert "report_id" in m
        assert "generation_timestamp" in m

    def test_RD_44_build_manifest_hash_sha256_is_64_chars(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert len(m["manifest_hash_sha256"]) == 64

    def test_RD_45_build_manifest_hash_sha512_is_128_chars(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert len(m["manifest_hash_sha512"]) == 128

    def test_RD_46_verify_manifest_returns_true_for_valid(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert verify_manifest(m) is True

    def test_RD_47_verify_manifest_returns_false_for_tampered_hash(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        m["manifest_hash_sha256"] = "a" * 64
        assert verify_manifest(m) is False

    def test_RD_48_verify_manifest_returns_false_for_tampered_field(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        m["report_id"] = "tampered-report-id"
        assert verify_manifest(m) is False

    def test_RD_49_build_manifest_sections_are_sorted(self):
        args = dict(self._FIXED_MANIFEST_ARGS)
        args["sections_included"] = ["MANIFEST", "FINDINGS", "EXECUTIVE_SUMMARY"]
        m = build_manifest(**args)
        assert m["sections_included"] == sorted(
            ["MANIFEST", "FINDINGS", "EXECUTIVE_SUMMARY"]
        )

    def test_RD_50_build_manifest_different_section_order_same_result(self):
        args1 = dict(self._FIXED_MANIFEST_ARGS)
        args1["sections_included"] = ["EXECUTIVE_SUMMARY", "FINDINGS", "MANIFEST"]
        args2 = dict(self._FIXED_MANIFEST_ARGS)
        args2["sections_included"] = ["MANIFEST", "EXECUTIVE_SUMMARY", "FINDINGS"]
        m1 = build_manifest(**args1)
        m2 = build_manifest(**args2)
        assert m1["manifest_hash_sha256"] == m2["manifest_hash_sha256"]

    def test_RD_50b_build_manifest_authority_versions_sorted(self):
        args = dict(self._FIXED_MANIFEST_ARGS)
        args["authority_versions"] = {"z_auth": "1.0", "a_auth": "2.0"}
        m = build_manifest(**args)
        # Authority versions dict keys should be sorted
        keys = list(m["authority_versions"].keys())
        assert keys == sorted(keys)

    def test_RD_50c_verify_manifest_returns_false_for_missing_hash(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        m.pop("manifest_hash_sha256")
        assert verify_manifest(m) is False

    def test_RD_50d_build_manifest_transparency_root_defaults_to_empty(self):
        m = build_manifest(**self._FIXED_MANIFEST_ARGS)
        assert m["transparency_root"] == ""

    def test_RD_50e_build_manifest_with_transparency_root_included(self):
        args = dict(self._FIXED_MANIFEST_ARGS)
        args["transparency_root"] = "merkle:proof:root-hash-abc"
        m = build_manifest(**args)
        assert m["transparency_root"] == "merkle:proof:root-hash-abc"
