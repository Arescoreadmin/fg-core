from __future__ import annotations

import json
from pathlib import Path

from services.schema_validation import validate_payload_against_schema

_CONNECTOR_SCHEMA = Path("contracts/connectors/schema/connector.schema.json")
_CONNECTOR_DIR = Path("contracts/connectors/connectors")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def list_connector_manifests() -> list[dict[str, object]]:
    schema = _load_json(_CONNECTOR_SCHEMA)
    manifests: list[dict[str, object]] = []
    for path in sorted(_CONNECTOR_DIR.glob("*.json")):
        payload = _load_json(path)
        validate_payload_against_schema(payload, schema)
        manifests.append(payload)
    return manifests


def manifest_by_id(connector_id: str) -> dict[str, object]:
    for manifest in list_connector_manifests():
        if manifest.get("id") == connector_id:
            return manifest
    raise ValueError("CONNECTOR_NOT_FOUND")
