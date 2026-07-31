"""Manifest schema tests.

The manifest is the durable record that ties a dump file to its provenance,
checksum, and verification state. These tests lock down the required fields
and shape so future edits to fg_backup.sh cannot silently drop information.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

REQUIRED_FIELDS = {
    "backup_id",
    "manifest_schema_version",
    "timestamp",
    "backup_type",
    "db_version",
    "migration_version",
    "backup_size_bytes",
    "dump_size_bytes",
    "compression",
    "checksum_sha256",
    "checksum_algorithm",
    "storage_location",
    "restore_compatibility",
    "pg_dump_version",
    "pg_restore_version",
    "verification_status",
    "verified_at",
    "operator",
    "encrypted",
    "offsite_uploaded",
    "offsite_provider",
    "duration_seconds",
    "railway_plan",
    "manifest_signature",
    "manifest_signing_key_id",
}


MANIFEST_SCHEMA = {
    "type": "object",
    "additionalProperties": True,
    "required": sorted(REQUIRED_FIELDS),
    "properties": {
        "manifest_schema_version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "timestamp": {"type": "string"},
        "backup_type": {
            "type": "string",
            "enum": [
                "scheduled",
                "manual",
                "pre-deploy",
                "pre-migration",
                "pre-maintenance",
                "pre-engagement",
            ],
        },
        "db_version": {"type": "string"},
        "migration_version": {"type": "string"},
        "backup_size_bytes": {"type": "integer", "minimum": 0},
        "dump_size_bytes": {"type": "integer", "minimum": 0},
        "compression": {"type": "string"},
        "checksum_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        "checksum_algorithm": {"type": "string", "enum": ["sha256"]},
        "storage_location": {"type": "string"},
        "restore_compatibility": {"type": "string"},
        "pg_dump_version": {"type": "string"},
        "pg_restore_version": {"type": "string"},
        "verification_status": {
            "type": "string",
            "enum": ["unverified", "verified", "failed"],
        },
        "verified_at": {"type": ["string", "null"]},
        "operator": {"type": "string"},
        "encrypted": {"type": "boolean"},
        "offsite_uploaded": {"type": "boolean"},
        "offsite_provider": {"type": ["string", "null"]},
        "duration_seconds": {"type": "integer", "minimum": 0},
        "railway_plan": {"type": "string"},
        "backup_id": {"type": "string", "pattern": r"^FG-BKP-\d{8}-\d{5}$"},
        "manifest_signature": {"type": "string"},
        "manifest_signing_key_id": {"type": "string"},
    },
}


def test_manifest_schema_accepts_valid_document(seed_backup, backup_dir: Path):
    archive, manifest_path = seed_backup()
    doc = json.loads(manifest_path.read_text())
    jsonschema.validate(doc, MANIFEST_SCHEMA)


def test_manifest_has_all_required_fields(seed_backup):
    _archive, manifest_path = seed_backup()
    doc = json.loads(manifest_path.read_text())
    missing = REQUIRED_FIELDS - set(doc.keys())
    assert not missing, f"manifest missing required fields: {sorted(missing)}"


def test_manifest_rejects_invalid_checksum(seed_backup):
    _archive, manifest_path = seed_backup(checksum_sha256="not-a-real-hash")
    doc = json.loads(manifest_path.read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, MANIFEST_SCHEMA)


def test_manifest_rejects_unknown_backup_type(seed_backup):
    _archive, manifest_path = seed_backup(backup_type="wildcard")
    doc = json.loads(manifest_path.read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, MANIFEST_SCHEMA)


def test_manifest_encrypted_flag_is_bool(seed_backup):
    _archive, manifest_path = seed_backup(encrypted=True)
    doc = json.loads(manifest_path.read_text())
    assert isinstance(doc["encrypted"], bool)


def test_manifest_size_matches_archive(seed_backup, backup_dir: Path):
    archive, manifest_path = seed_backup(contents=b"a" * 4096)
    doc = json.loads(manifest_path.read_text())
    assert doc["backup_size_bytes"] == archive.stat().st_size == 4096
    assert doc["dump_size_bytes"] == 4096
