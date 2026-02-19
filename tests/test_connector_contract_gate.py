from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.ci.validate_connector_contracts as gate


def test_validator_catches_bad_connector_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "contracts" / "connectors"
    (root / "schema").mkdir(parents=True)
    (root / "connectors").mkdir(parents=True)
    (root / "policies").mkdir(parents=True)

    (root / "schema" / "connector.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["id", "provider", "required_scopes", "version"],
                "properties": {
                    "id": {"type": "string"},
                    "provider": {"type": "string"},
                    "required_scopes": {"type": "array"},
                    "version": {"type": "string"},
                },
                "additionalProperties": True,
            }
        ),
        encoding="utf-8",
    )
    (root / "schema" / "policy.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": [
                    "enabled_connectors",
                    "connector_scopes",
                    "allowed_resources",
                ],
                "properties": {
                    "enabled_connectors": {"type": "array"},
                    "connector_scopes": {"type": "object"},
                    "allowed_resources": {"type": "object"},
                },
                "additionalProperties": True,
            }
        ),
        encoding="utf-8",
    )
    (root / "connectors" / "one.json").write_text(
        json.dumps(
            {
                "id": "one",
                "provider": "slack",
                "required_scopes": ["channels:history"],
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (root / "policies" / "default.json").write_text(
        json.dumps(
            {
                "enabled_connectors": ["unknown"],
                "connector_scopes": {},
                "allowed_resources": {},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(gate, "ROOT", root)

    with pytest.raises(SystemExit, match="unknown connectors"):
        gate.main()
