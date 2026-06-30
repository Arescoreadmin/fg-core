"""Tests for Report Authority rendering.

Coverage:
  RR-1  to RR-20: renderer_json — valid JSON, sort_keys, unicode
  RR-21 to RR-40: renderer_html — DOCTYPE, CSS, HTML entity escaping, section headers
  RR-41 to RR-50: renderer_pdf — starts with %PDF, non-empty, deterministic size
"""

from __future__ import annotations

import json

from services.report_authority.renderer_json import render_json, render_json_pretty
from services.report_authority.renderer_html import render_html
from services.report_authority.renderer_pdf import render_pdf

# ---------------------------------------------------------------------------
# Fixed test report data
# ---------------------------------------------------------------------------

_REPORT_DATA: dict = {
    "report_id": "rpt-render-001",
    "tenant_id": "tenant-render-001",
    "report_type": "EXECUTIVE",
    "lifecycle_state": "GENERATED",
    "title": "FrostGate Annual Security Assessment 2026",
    "scope": "Full organizational scope including all subsidiaries",
    "objectives": "Assess AI governance maturity and compliance posture",
    "assessor_id": "assessor-render-001",
    "reviewer_id": "reviewer-render-002",
    "quality": {
        "quality_score": 0.82,
        "quality_grade": "GOOD",
    },
    "hashes": {
        "report_hash_sha256": "a" * 64,
        "manifest_hash": "b" * 64,
    },
    "findings": [
        {"id": "f1", "severity": "HIGH", "description": "Missing encryption"},
        {"id": "f2", "severity": "LOW", "description": "Minor logging gap"},
    ],
}

_EMPTY_DATA: dict = {}

_UNICODE_DATA: dict = {
    "title": "Rapport de sécurité — 日本語テスト",
    "content": "こんにちは世界！ <script>alert('xss')</script>",
    "special": "Café & Résumé",
}

_NESTED_DATA: dict = {
    "executive_summary": {
        "overall_risk": "MEDIUM",
        "key_findings": "Three critical gaps identified",
        "recommendation": "Immediate remediation required",
    },
    "findings": [
        {"severity": "CRITICAL", "category": "Access Control"},
        {"severity": "HIGH", "category": "Data Protection"},
    ],
}


# ===========================================================================
# RR-1 to RR-20: renderer_json
# ===========================================================================


class TestRendererJson:
    """RR-1 through RR-20: JSON renderer output tests."""

    def test_RR_1_output_is_valid_json(self):
        result = render_json(_REPORT_DATA)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_RR_2_output_is_bytes(self):
        result = render_json(_REPORT_DATA)
        assert isinstance(result, bytes)

    def test_RR_3_sort_keys_applied(self):
        data = {"z_field": "last", "a_field": "first", "m_field": "middle"}
        result = render_json(data)
        text = result.decode("utf-8")
        a_idx = text.index('"a_field"')
        m_idx = text.index('"m_field"')
        z_idx = text.index('"z_field"')
        assert a_idx < m_idx < z_idx

    def test_RR_4_unicode_characters_preserved(self):
        data = {"title": "こんにちは"}
        result = render_json(data)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["title"] == "こんにちは"

    def test_RR_5_unicode_not_ascii_escaped(self):
        data = {"title": "日本語"}
        result = render_json(data)
        text = result.decode("utf-8")
        # ensure_ascii=False means actual unicode chars, not \\uXXXX escapes
        assert "日本語" in text

    def test_RR_6_empty_dict_produces_empty_json_object(self):
        result = render_json(_EMPTY_DATA)
        assert result == b"{}"

    def test_RR_7_no_extra_whitespace_in_compact_output(self):
        data = {"a": 1, "b": 2}
        result = render_json(data)
        text = result.decode("utf-8")
        assert " " not in text

    def test_RR_8_nested_dict_output_valid(self):
        result = render_json(_NESTED_DATA)
        parsed = json.loads(result)
        assert "executive_summary" in parsed
        assert isinstance(parsed["findings"], list)

    def test_RR_9_list_values_preserved_in_order(self):
        data = {"items": ["c", "a", "b"]}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["items"] == ["c", "a", "b"]

    def test_RR_10_null_values_preserved(self):
        data = {"key": None}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["key"] is None

    def test_RR_11_float_values_preserved(self):
        data = {"score": 0.8234567}
        result = render_json(data)
        parsed = json.loads(result)
        assert abs(parsed["score"] - 0.8234567) < 1e-6

    def test_RR_12_boolean_values_preserved(self):
        data = {"active": True, "disabled": False}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["active"] is True
        assert parsed["disabled"] is False

    def test_RR_13_identical_inputs_produce_identical_bytes(self):
        b1 = render_json(_REPORT_DATA)
        b2 = render_json(_REPORT_DATA)
        assert b1 == b2

    def test_RR_14_different_inputs_produce_different_bytes(self):
        b1 = render_json({"key": "value_A"})
        b2 = render_json({"key": "value_B"})
        assert b1 != b2

    def test_RR_15_render_json_pretty_is_valid_json(self):
        result = render_json_pretty(_REPORT_DATA)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_RR_16_render_json_pretty_contains_newlines(self):
        data = {"a": 1, "b": 2}
        result = render_json_pretty(data)
        assert b"\n" in result

    def test_RR_17_render_json_pretty_sort_keys(self):
        data = {"z": 3, "a": 1}
        result = render_json_pretty(data)
        text = result.decode("utf-8")
        assert text.index('"a"') < text.index('"z"')

    def test_RR_18_render_json_pretty_deterministic(self):
        b1 = render_json_pretty(_REPORT_DATA)
        b2 = render_json_pretty(_REPORT_DATA)
        assert b1 == b2

    def test_RR_19_compact_and_pretty_parse_to_same_structure(self):
        compact = json.loads(render_json(_REPORT_DATA))
        pretty = json.loads(render_json_pretty(_REPORT_DATA))
        assert compact == pretty

    def test_RR_20_deeply_nested_structure_rendered(self):
        data = {"level1": {"level2": {"level3": {"value": "deep"}}}}
        result = render_json(data)
        parsed = json.loads(result)
        assert parsed["level1"]["level2"]["level3"]["value"] == "deep"


# ===========================================================================
# RR-21 to RR-40: renderer_html
# ===========================================================================


class TestRendererHtml:
    """RR-21 through RR-40: HTML renderer output tests."""

    def test_RR_21_output_starts_with_doctype(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert text.strip().startswith("<!DOCTYPE html>")

    def test_RR_22_output_is_bytes(self):
        result = render_html(_REPORT_DATA)
        assert isinstance(result, bytes)

    def test_RR_23_output_contains_html_tag(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "<html" in text
        assert "</html>" in text

    def test_RR_24_output_contains_embedded_css(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "<style>" in text
        assert "font-family" in text

    def test_RR_25_output_contains_body_tags(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "<body>" in text
        assert "</body>" in text

    def test_RR_26_output_escapes_html_entities_in_content(self):
        data = {"content": "<script>alert('xss')</script>"}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "<script>" not in text
        assert "&lt;script&gt;" in text

    def test_RR_27_ampersand_escaped(self):
        data = {"name": "Café & Résumé"}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "&amp;" in text

    def test_RR_28_section_headers_present_for_each_key(self):
        data = {"findings": [], "executive_summary": {}}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "<h2>" in text

    def test_RR_29_sorted_keys_in_tables(self):
        data = {"section_a": {"z_key": "last", "a_key": "first"}}
        result = render_html(data)
        text = result.decode("utf-8")
        assert text.index("a_key") < text.index("z_key")

    def test_RR_30_section_keys_sorted_alphabetically(self):
        data = {"z_section": {}, "a_section": {}}
        result = render_html(data)
        text = result.decode("utf-8")
        assert text.index("a_section") < text.index("z_section")

    def test_RR_31_dict_section_rendered_as_table(self):
        data = {"metadata": {"key1": "value1", "key2": "value2"}}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "<table>" in text
        assert "<th>" in text

    def test_RR_32_list_section_rendered_as_list(self):
        data = {"items": ["alpha", "beta", "gamma"]}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "<ul>" in text
        assert "<li>" in text

    def test_RR_33_title_in_html_title_tag(self):
        result = render_html(_REPORT_DATA, title="Custom Title")
        text = result.decode("utf-8")
        assert "Custom Title" in text
        assert "<title>" in text

    def test_RR_34_default_title_used_when_not_specified(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "FrostGate Assessment Report" in text

    def test_RR_35_utf8_encoding_preserved(self):
        data = {"title": "こんにちは"}
        result = render_html(data)
        text = result.decode("utf-8")
        assert "こんにちは" in text

    def test_RR_36_meta_charset_utf8_present(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "UTF-8" in text

    def test_RR_37_identical_inputs_produce_identical_output(self):
        b1 = render_html(_REPORT_DATA)
        b2 = render_html(_REPORT_DATA)
        assert b1 == b2

    def test_RR_38_empty_data_produces_valid_html(self):
        result = render_html(_EMPTY_DATA)
        text = result.decode("utf-8")
        assert "<!DOCTYPE html>" in text
        assert "</html>" in text

    def test_RR_39_quotes_escaped_in_html(self):
        data = {"attr": 'He said "hello"'}
        result = render_html(data)
        text = result.decode("utf-8")
        # Should not have raw unescaped quotes inside table cells
        assert "&quot;" in text

    def test_RR_40_section_class_present(self):
        result = render_html(_REPORT_DATA)
        text = result.decode("utf-8")
        assert "class='section'" in text


# ===========================================================================
# RR-41 to RR-50: renderer_pdf
# ===========================================================================


class TestRendererPdf:
    """RR-41 through RR-50: PDF renderer output tests."""

    def test_RR_41_output_starts_with_pdf_magic_bytes(self):
        result = render_pdf(_REPORT_DATA)
        assert result[:4] == b"%PDF"

    def test_RR_42_output_is_bytes(self):
        result = render_pdf(_REPORT_DATA)
        assert isinstance(result, bytes)

    def test_RR_43_output_is_non_empty(self):
        result = render_pdf(_REPORT_DATA)
        assert len(result) > 0

    def test_RR_44_output_size_reasonable(self):
        result = render_pdf(_REPORT_DATA)
        # A minimal PDF should be at least 1KB but not absurdly large
        assert len(result) > 1024

    def test_RR_45_identical_inputs_produce_same_size(self):
        b1 = render_pdf(_REPORT_DATA)
        b2 = render_pdf(_REPORT_DATA)
        # PDF with same data should produce the same (or very similar) byte count
        # ReportLab timestamps may cause minor variation — allow small delta
        assert abs(len(b1) - len(b2)) < 1024

    def test_RR_46_empty_data_produces_pdf(self):
        result = render_pdf(_EMPTY_DATA)
        assert result[:4] == b"%PDF"

    def test_RR_47_different_data_produces_different_pdf(self):
        b1 = render_pdf({"section_a": {"key": "value_1"}})
        b2 = render_pdf({"section_a": {"key": "value_2"}})
        # Different content should produce different PDFs
        assert b1 != b2

    def test_RR_48_custom_title_accepted(self):
        result = render_pdf(_REPORT_DATA, title="Custom PDF Title")
        # Should not raise; output is valid PDF
        assert result[:4] == b"%PDF"

    def test_RR_49_nested_report_data_produces_pdf(self):
        result = render_pdf(_NESTED_DATA)
        assert result[:4] == b"%PDF"
        assert len(result) > 1024

    def test_RR_50_pdf_ends_with_eof_marker(self):
        result = render_pdf(_REPORT_DATA)
        # PDF files end with %%EOF
        assert b"%%EOF" in result

    def test_RR_50b_list_sections_produce_valid_pdf(self):
        data = {
            "findings": [
                {"severity": "CRITICAL", "title": "Missing MFA"},
                {"severity": "HIGH", "title": "Weak passwords"},
            ]
        }
        result = render_pdf(data)
        assert result[:4] == b"%PDF"

    def test_RR_50c_unicode_content_does_not_crash_pdf_renderer(self):
        data = {"summary": "Résumé de sécurité", "notes": "日本語テスト"}
        result = render_pdf(data)
        assert result[:4] == b"%PDF"
