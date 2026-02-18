from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.evidence_anchor_extension.service import (
    MAX_RECEIPT_BYTES,
    _write_anchor_receipt,
    safe_path_join,
)


def test_safe_path_join_blocks_traversal(tmp_path: Path) -> None:
    base = tmp_path / "artifacts" / "anchor_receipts"
    base.mkdir(parents=True)
    with pytest.raises(ValueError, match="ANCHOR_RECEIPT_PATH_INVALID"):
        safe_path_join(base, "..", "escape.json")


def test_receipt_rejects_unsafe_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    payload = {
        "receipt_id": "../../evil",
        "tenant_id": "tenant-a",
        "artifact_sha256": "a" * 64,
        "provider": "local",
        "anchor_ref": None,
        "created_at": "2026-01-01T00:00:00Z",
    }
    with pytest.raises(ValueError, match="ANCHOR_RECEIPT_ID_INVALID"):
        _write_anchor_receipt(payload)


def test_receipt_rejects_oversize_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    payload = {
        "receipt_id": "safe-id-1",
        "tenant_id": "tenant-a",
        "artifact_sha256": "b" * 64,
        "provider": "local",
        "anchor_ref": "x" * MAX_RECEIPT_BYTES,
        "created_at": "2026-01-01T00:00:00Z",
    }
    with pytest.raises(ValueError, match="ANCHOR_RECEIPT_TOO_LARGE"):
        _write_anchor_receipt(payload)


def test_receipt_uses_restricted_permissions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    payload = {
        "receipt_id": "safe-id-2",
        "tenant_id": "tenant-a",
        "artifact_sha256": "c" * 64,
        "provider": "local",
        "anchor_ref": "unicode-✓",
        "created_at": "2026-01-01T00:00:00Z",
    }
    out = Path(_write_anchor_receipt(payload))
    mode = out.stat().st_mode & 0o777
    assert mode == 0o600
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["receipt_id"] == "safe-id-2"
