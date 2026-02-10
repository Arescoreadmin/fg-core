"""Tests for BP-C-003 gate: Schema Registry Integrity Gate.

All tests use tmp_path to create isolated repo-like structures.
Never depend on real repo state.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verify_bp_c_003 import (
    GATE_ID,
    INVARIANT,
    check_orphans_and_missing,
    collect_refs,
    extract_component_schemas,
    extract_referenced_schema_names,
    run_gate,
    validate_align_map,
    validate_schemas,
)


def _make_openapi(
    schemas: dict | None = None,
    paths: dict | None = None,
) -> dict:
    """Build a minimal OpenAPI document with given component schemas and paths."""
    doc: dict = {
        "openapi": "3.1.0",
        "info": {"title": "test", "version": "0.1.0"},
        "paths": paths or {},
    }
    if schemas is not None:
        doc["components"] = {"schemas": schemas}
    return doc


def _setup_repo(
    tmp_path: Path,
    *,
    schemas_api_docs: dict[str, dict] | None = None,
    core_openapi: dict | None = None,
    align_value: str = "make bp-c-003-gate",
    skip_schemas_dir: bool = False,
    skip_align: bool = False,
) -> Path:
    """Create a minimal fake repo for BP-C-003 testing.

    schemas_api_docs: mapping of filename -> JSON content for schemas/api/*.json.
    core_openapi: content for contracts/core/openapi.json (only if distinct from schemas/api/).
    """
    if not skip_schemas_dir:
        schemas_dir = tmp_path / "schemas" / "api"
        schemas_dir.mkdir(parents=True, exist_ok=True)
        if schemas_api_docs:
            for fname, content in schemas_api_docs.items():
                (schemas_dir / fname).write_text(
                    json.dumps(content, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

    if core_openapi is not None:
        core_path = tmp_path / "contracts" / "core" / "openapi.json"
        core_path.parent.mkdir(parents=True, exist_ok=True)
        core_path.write_text(
            json.dumps(core_openapi, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not skip_align:
        align_path = tmp_path / "tools" / "align_score_map.json"
        align_path.parent.mkdir(parents=True, exist_ok=True)
        align_path.write_text(
            json.dumps({GATE_ID: align_value}, indent=2) + "\n",
            encoding="utf-8",
        )

    return tmp_path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_valid_schemas_pass(self, tmp_path: Path) -> None:
        """All schemas valid, referenced, and non-orphaned -> PASS."""
        schemas = {
            "Pet": {"type": "object", "properties": {"name": {"type": "string"}}},
        }
        paths = {
            "/pets": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Pet"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc})

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True
        assert report["gate_id"] == GATE_ID
        assert report["errors"] == []

    def test_report_structure_exact(self, tmp_path: Path) -> None:
        """Report JSON has exactly the required keys."""
        schemas = {
            "Item": {"type": "object"},
        }
        paths = {
            "/items": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Item"}
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc})

        passed, report = run_gate(repo_root=tmp_path)
        required_keys = {
            "gate_id",
            "passed",
            "generated_at_utc",
            "invariant",
            "checked_files",
            "errors",
            "notes",
        }
        assert set(report.keys()) == required_keys
        assert report["invariant"] == INVARIANT


# ---------------------------------------------------------------------------
# Single invariant violation: invalid schema
# ---------------------------------------------------------------------------


class TestInvalidSchema:
    def test_invalid_schema_type_fails(self, tmp_path: Path) -> None:
        """Schema with invalid type -> FAIL."""
        schemas = {
            "Bad": {"type": "not_a_real_type"},
        }
        paths = {
            "/bad": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Bad"}
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc})

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("Bad" in e and "invalid" in e.lower() for e in report["errors"])


class TestOrphanedSchema:
    def test_unused_schema_fails(self, tmp_path: Path) -> None:
        """Schema defined but never referenced -> FAIL (orphaned)."""
        schemas = {
            "Used": {"type": "object"},
            "Orphan": {"type": "string"},
        }
        paths = {
            "/used": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Used"}
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc})

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("Orphan" in e and "orphaned" in e.lower() for e in report["errors"])


class TestMissingReferencedSchema:
    def test_ref_to_nonexistent_schema_fails(self, tmp_path: Path) -> None:
        """$ref points to a schema not defined -> FAIL."""
        schemas = {
            "Exists": {"type": "object"},
        }
        paths = {
            "/items": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/DoesNotExist"
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/Exists"
                                }
                            }
                        }
                    },
                    "responses": {"201": {}},
                },
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc})

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "DoesNotExist" in e and "not defined" in e for e in report["errors"]
        )


# ---------------------------------------------------------------------------
# Align score map mismatch
# ---------------------------------------------------------------------------


class TestAlignMapMismatch:
    def test_wrong_align_value_fails(self, tmp_path: Path) -> None:
        """Incorrect align_score_map.json mapping -> FAIL."""
        schemas = {"X": {"type": "object"}}
        paths = {
            "/x": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/X"}
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc}, align_value="MISSING")

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(GATE_ID in e for e in report["errors"])

    def test_missing_align_file_fails(self, tmp_path: Path) -> None:
        """Missing align_score_map.json -> FAIL."""
        schemas = {"X": {"type": "object"}}
        paths = {
            "/x": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/X"}
                                }
                            }
                        }
                    }
                }
            }
        }
        doc = _make_openapi(schemas=schemas, paths=paths)
        _setup_repo(tmp_path, schemas_api_docs={"openapi.json": doc}, skip_align=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("not found" in e for e in report["errors"])


# ---------------------------------------------------------------------------
# Missing required file
# ---------------------------------------------------------------------------


class TestMissingRequiredFile:
    def test_missing_schemas_dir_fails(self, tmp_path: Path) -> None:
        """Missing schemas/api/ directory -> FAIL."""
        _setup_repo(tmp_path, skip_schemas_dir=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("not found" in e.lower() or "directory" in e.lower() for e in report["errors"])

    def test_empty_schemas_dir_fails(self, tmp_path: Path) -> None:
        """schemas/api/ exists but has no JSON files -> FAIL."""
        _setup_repo(tmp_path, schemas_api_docs={})

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("No JSON" in e for e in report["errors"])


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------


class TestExtractComponentSchemas:
    def test_extracts_schemas(self) -> None:
        doc = {"components": {"schemas": {"A": {"type": "string"}}}}
        assert extract_component_schemas(doc) == {"A": {"type": "string"}}

    def test_empty_when_no_components(self) -> None:
        assert extract_component_schemas({}) == {}

    def test_empty_when_no_schemas(self) -> None:
        assert extract_component_schemas({"components": {}}) == {}


class TestCollectRefs:
    def test_finds_refs(self) -> None:
        obj = {
            "a": {"$ref": "#/components/schemas/X"},
            "b": [{"$ref": "#/components/schemas/Y"}],
        }
        assert collect_refs(obj) == {
            "#/components/schemas/X",
            "#/components/schemas/Y",
        }

    def test_no_refs(self) -> None:
        assert collect_refs({"a": "b"}) == set()


class TestCheckOrphansAndMissing:
    def test_no_issues(self) -> None:
        unused, missing = check_orphans_and_missing({"A", "B"}, {"A", "B"})
        assert unused == []
        assert missing == []

    def test_orphan_detected(self) -> None:
        unused, missing = check_orphans_and_missing({"A", "B"}, {"A"})
        assert len(unused) == 1
        assert "B" in unused[0]
        assert missing == []

    def test_missing_detected(self) -> None:
        unused, missing = check_orphans_and_missing({"A"}, {"A", "C"})
        assert unused == []
        assert len(missing) == 1
        assert "C" in missing[0]
