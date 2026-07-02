"""Tests for PR 18.5A — Signed Explainability Export Package.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import hashlib
import json

from services.governance_intelligence.export_package import (
    EXPORT_FORMATS,
    _strip_tenant_id,
    build_export_manifest,
    build_html_export,
    build_json_export,
    compute_package_hash,
)


# ---------------------------------------------------------------------------
# EXPORT_FORMATS
# ---------------------------------------------------------------------------


class TestExportFormats:
    def test_is_frozenset(self):
        assert isinstance(EXPORT_FORMATS, frozenset)

    def test_contains_json(self):
        assert "JSON" in EXPORT_FORMATS

    def test_contains_html(self):
        assert "HTML" in EXPORT_FORMATS

    def test_contains_manifest(self):
        assert "MANIFEST" in EXPORT_FORMATS

    def test_does_not_contain_pdf(self):
        assert "PDF" not in EXPORT_FORMATS

    def test_has_exactly_3_formats(self):
        assert len(EXPORT_FORMATS) == 3


# ---------------------------------------------------------------------------
# compute_package_hash
# ---------------------------------------------------------------------------


class TestComputePackageHash:
    def test_returns_64_char_hex(self):
        h = compute_package_hash({"a": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic_same_input(self):
        h1 = compute_package_hash({"x": 1, "y": 2})
        h2 = compute_package_hash({"x": 1, "y": 2})
        assert h1 == h2

    def test_key_order_independent(self):
        h1 = compute_package_hash({"a": 1, "b": 2})
        h2 = compute_package_hash({"b": 2, "a": 1})
        assert h1 == h2

    def test_different_values_different_hash(self):
        h1 = compute_package_hash({"a": 1})
        h2 = compute_package_hash({"a": 2})
        assert h1 != h2

    def test_empty_dict(self):
        expected = hashlib.sha256(
            json.dumps({}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        assert compute_package_hash({}) == expected

    def test_nested_structures(self):
        h = compute_package_hash({"nested": {"key": [1, 2, 3]}})
        assert len(h) == 64

    def test_unicode_content(self):
        h = compute_package_hash({"text": "日本語テスト"})
        assert len(h) == 64


# ---------------------------------------------------------------------------
# _strip_tenant_id
# ---------------------------------------------------------------------------


class TestStripTenantId:
    def test_strips_top_level_tenant_id(self):
        result = _strip_tenant_id({"tenant_id": "t1", "name": "test"})
        assert "tenant_id" not in result
        assert result["name"] == "test"

    def test_strips_nested_tenant_id(self):
        result = _strip_tenant_id({"nested": {"tenant_id": "t1", "value": "v"}})
        assert "tenant_id" not in result["nested"]
        assert result["nested"]["value"] == "v"

    def test_strips_in_list(self):
        result = _strip_tenant_id(
            [{"tenant_id": "t1", "v": 1}, {"tenant_id": "t2", "v": 2}]
        )
        assert isinstance(result, list)
        for item in result:
            assert "tenant_id" not in item

    def test_deeply_nested_stripped(self):
        data = {"a": {"b": {"c": {"tenant_id": "t1", "val": 42}}}}
        result = _strip_tenant_id(data)
        assert "tenant_id" not in result["a"]["b"]["c"]
        assert result["a"]["b"]["c"]["val"] == 42

    def test_non_dict_passthrough(self):
        assert _strip_tenant_id("hello") == "hello"
        assert _strip_tenant_id(42) == 42
        assert _strip_tenant_id(None) is None

    def test_preserves_other_keys(self):
        result = _strip_tenant_id({"tenant_id": "t1", "a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# build_json_export
# ---------------------------------------------------------------------------


class TestBuildJsonExport:
    def _json_export(self, package_id: str = "pkg-1") -> dict:
        return build_json_export(
            package_id=package_id,
            tenant_id="tenant-123",
            evidence_graph={"nodes": [], "tenant_id": "tenant-123"},
            recommendation_matrix={"tenant_id": "tenant-123", "data": "x"},
            trust_refs=["tr-1", "tr-2"],
            transparency_refs=["tx-1"],
            confidence={"tenant_id": "tenant-123", "score": 0.9},
            replay=None,
            simulation_comparison=None,
        )

    def test_returns_dict(self):
        assert isinstance(self._json_export(), dict)

    def test_package_id_present(self):
        r = self._json_export("pkg-42")
        assert r["package_id"] == "pkg-42"

    def test_export_format_is_json(self):
        r = self._json_export()
        assert r["export_format"] == "JSON"

    def test_schema_version_present(self):
        r = self._json_export()
        assert r["schema_version"] == "1.0"

    def test_created_at_present(self):
        r = self._json_export()
        assert "created_at" in r

    def test_package_hash_present(self):
        r = self._json_export()
        assert "package_hash" in r

    def test_package_hash_is_64_chars(self):
        r = self._json_export()
        assert len(r["package_hash"]) == 64

    def test_evidence_graph_tenant_id_stripped(self):
        r = self._json_export()
        assert "tenant_id" not in r["evidence_graph"]

    def test_recommendation_matrix_tenant_id_stripped(self):
        r = self._json_export()
        assert "tenant_id" not in r["recommendation_matrix"]

    def test_confidence_tenant_id_stripped(self):
        r = self._json_export()
        assert "tenant_id" not in r["confidence"]

    def test_trust_refs_sorted(self):
        r = self._json_export()
        assert r["trust_refs"] == sorted(r["trust_refs"])

    def test_transparency_refs_sorted(self):
        r = self._json_export()
        assert r["transparency_refs"] == sorted(r["transparency_refs"])

    def test_replay_included_when_provided(self):
        r = build_json_export(
            package_id="pkg",
            tenant_id="t1",
            evidence_graph={},
            recommendation_matrix={},
            trust_refs=[],
            transparency_refs=[],
            confidence={},
            replay={"replay_label": "REPLAY", "tenant_id": "t1"},
            simulation_comparison=None,
        )
        assert "replay" in r
        assert "tenant_id" not in r["replay"]

    def test_replay_excluded_when_none(self):
        r = self._json_export()
        assert "replay" not in r

    def test_simulation_comparison_included_when_provided(self):
        r = build_json_export(
            package_id="pkg",
            tenant_id="t1",
            evidence_graph={},
            recommendation_matrix={},
            trust_refs=[],
            transparency_refs=[],
            confidence={},
            replay=None,
            simulation_comparison={
                "comparison_label": "DETERMINISTIC_COMPARISON",
                "tenant_id": "t1",
            },
        )
        assert "simulation_comparison" in r
        assert "tenant_id" not in r["simulation_comparison"]

    def test_no_tenant_id_anywhere_in_output(self):
        r = self._json_export()
        serialised = json.dumps(r)
        # The package itself should not contain tenant_id keys
        # (note: package_id or other IDs may appear, but not "tenant_id")
        parsed = json.loads(serialised)

        def _check_no_tenant_id(obj):
            if isinstance(obj, dict):
                assert "tenant_id" not in obj, f"Found tenant_id in {obj}"
                for v in obj.values():
                    _check_no_tenant_id(v)
            elif isinstance(obj, list):
                for item in obj:
                    _check_no_tenant_id(item)

        _check_no_tenant_id(parsed)


# ---------------------------------------------------------------------------
# build_html_export
# ---------------------------------------------------------------------------


class TestBuildHtmlExport:
    def _html(self) -> str:
        pkg = {
            "package_id": "pkg-1",
            "export_format": "JSON",
            "schema_version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "package_hash": "abc123",
            "evidence_graph": {"nodes": [], "node_count": 0},
        }
        return build_html_export(pkg)

    def test_returns_string(self):
        assert isinstance(self._html(), str)

    def test_starts_with_doctype(self):
        html = self._html()
        assert html.startswith("<!DOCTYPE html>")

    def test_starts_with_html_tag(self):
        html = self._html()
        assert "<html" in html

    def test_contains_body_tag(self):
        html = self._html()
        assert "<body>" in html

    def test_contains_h1(self):
        html = self._html()
        assert "<h1>" in html

    def test_contains_package_id(self):
        html = self._html()
        assert "pkg-1" in html

    def test_contains_hash(self):
        html = self._html()
        assert "abc123" in html

    def test_contains_table(self):
        html = self._html()
        assert "<table" in html

    def test_ends_with_html_close(self):
        html = self._html()
        assert html.endswith("</html>")

    def test_utf8_safe(self):
        pkg = {
            "package_id": "pkg-日本語",
            "schema_version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "package_hash": "abc",
            "evidence_graph": {},
        }
        html = build_html_export(pkg)
        assert "日本語" in html


# ---------------------------------------------------------------------------
# build_export_manifest
# ---------------------------------------------------------------------------


class TestBuildExportManifest:
    def _manifest(self) -> dict:
        return build_export_manifest(
            package_id="pkg-1",
            tenant_id="tenant-123",
            contents={"node_ids": ["n-1", "n-2"]},
        )

    def test_returns_dict(self):
        assert isinstance(self._manifest(), dict)

    def test_package_id_present(self):
        m = self._manifest()
        assert m["package_id"] == "pkg-1"

    def test_tenant_id_present(self):
        m = self._manifest()
        assert m["tenant_id"] == "tenant-123"

    def test_created_at_present(self):
        m = self._manifest()
        assert "created_at" in m

    def test_contents_hash_present(self):
        m = self._manifest()
        assert "contents_hash" in m

    def test_schema_version_is_1_0(self):
        m = self._manifest()
        assert m["schema_version"] == "1.0"

    def test_export_format_is_manifest(self):
        m = self._manifest()
        assert m["export_format"] == "MANIFEST"

    def test_offline_verification_supported(self):
        m = self._manifest()
        assert m["offline_verification_supported"] is True

    def test_contents_hash_deterministic(self):
        m1 = build_export_manifest("pkg-1", "t1", {"a": 1})
        m2 = build_export_manifest("pkg-1", "t1", {"a": 1})
        assert m1["contents_hash"] == m2["contents_hash"]

    def test_different_contents_different_hash(self):
        m1 = build_export_manifest("pkg-1", "t1", {"a": 1})
        m2 = build_export_manifest("pkg-1", "t1", {"a": 2})
        assert m1["contents_hash"] != m2["contents_hash"]
