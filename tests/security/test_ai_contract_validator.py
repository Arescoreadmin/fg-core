from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.ci.validate_ai_contracts as validator


def test_ai_contract_validator_passes() -> None:
    assert validator.main() == 0


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_ai_contract_validator_referential_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "contracts" / "ai"
    monkeypatch.setattr(validator, "ROOT", root)

    _write(
        root / "schema" / "experience.schema.json",
        {
            "type": "object",
            "required": ["id", "version", "tenant_id", "policy_id", "theme_id", "capabilities"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "version": {"type": "string"},
                "tenant_id": {"type": "string"},
                "policy_id": {"type": "string"},
                "theme_id": {"type": "string"},
                "capabilities": {"type": "object"},
            },
        },
    )
    _write(
        root / "schema" / "policy.schema.json",
        {
            "type": "object",
            "required": ["id", "version", "allowed_providers", "default_provider", "default_model", "tenant_max_tokens_per_day"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "version": {"type": "string"},
                "allowed_providers": {"type": "array"},
                "default_provider": {"type": "string"},
                "default_model": {"type": "string"},
                "tenant_max_tokens_per_day": {"type": "integer"},
            },
        },
    )
    _write(
        root / "schema" / "theme.schema.json",
        {
            "type": "object",
            "required": ["id", "version", "name", "colors"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "version": {"type": "string"},
                "name": {"type": "string"},
                "colors": {"type": "object"},
            },
        },
    )

    _write(
        root / "policies" / "p1.json",
        {
            "id": "p1",
            "version": "1",
            "allowed_providers": ["simulated"],
            "default_provider": "simulated",
            "default_model": "SIMULATED_V1",
            "tenant_max_tokens_per_day": 1,
        },
    )
    _write(root / "themes" / "t1.json", {"id": "t1", "version": "1", "name": "ok", "colors": {"bg": "#000"}})
    _write(
        root / "experiences" / "e1.json",
        {
            "id": "e1",
            "version": "1",
            "tenant_id": "tenant-dev",
            "policy_id": "missing",
            "theme_id": "t1",
            "capabilities": {},
        },
    )

    with pytest.raises(SystemExit):
        validator.main()
