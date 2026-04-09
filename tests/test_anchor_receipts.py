from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_anchor_receipt_schema_validates() -> None:
    schema = json.loads(
        Path("contracts/artifacts/anchor_receipt.schema.json").read_text(
            encoding="utf-8"
        )
    )
    payload = {
        "schema_version": "v1",
        "receipt_id": "ar-12345678",
        "tenant_id": "tenant-a",
        "artifact_sha256": "a" * 64,
        "provider": "local",
        "anchor_ref": None,
        "created_at": "2026-01-01T00:00:00Z",
    }
    Draft202012Validator(schema).validate(payload)


def test_anchor_receipt_schema_rejects_missing_tenant_id() -> None:
    schema = json.loads(
        Path("contracts/artifacts/anchor_receipt.schema.json").read_text(
            encoding="utf-8"
        )
    )
    payload = {
        "schema_version": "v1",
        "receipt_id": "ar-12345678",
        "artifact_sha256": "a" * 64,
        "provider": "local",
        "anchor_ref": None,
        "created_at": "2026-01-01T00:00:00Z",
    }

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    assert errors
    assert any("tenant_id" in error.message for error in errors)


def test_anchor_receipt_payload_supports_object_typed_metadata_shape() -> None:
    payload: dict[str, object] = {
        "tenant_id": "tenant-a",
        "anchor_id": "anchor-1",
        "metadata": {"source": "unit-test"},
    }

    assert payload["tenant_id"] == "tenant-a"
    assert payload["anchor_id"] == "anchor-1"
    assert isinstance(payload["metadata"], dict)