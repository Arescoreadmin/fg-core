from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_anchor_receipt_schema_validates() -> None:
    schema = json.loads(Path("contracts/artifacts/anchor_receipt.schema.json").read_text(encoding="utf-8"))
    payload = {
        "receipt_id": "ar-123",
        "tenant_id": "tenant-a",
        "artifact_sha256": "a" * 64,
        "provider": "local",
        "anchor_ref": None,
        "created_at": "2026-01-01T00:00:00Z",
    }
    Draft202012Validator(schema).validate(payload)
