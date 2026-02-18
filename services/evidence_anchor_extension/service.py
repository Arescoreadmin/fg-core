from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from services.schema_validation import validate_payload_against_schema
from sqlalchemy.orm import Session

from services.evidence_anchor_extension.models import EvidenceAnchorCreate


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


MAX_RECEIPT_BYTES = 64 * 1024
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def safe_path_join(base: Path, *parts: str) -> Path:
    base_resolved = base.resolve()
    candidate = (base_resolved / Path(*parts)).resolve()
    if not str(candidate).startswith(str(base_resolved) + os.sep):
        raise ValueError("ANCHOR_RECEIPT_PATH_INVALID")
    return candidate


def _write_anchor_receipt(payload: dict[str, object]) -> str:
    schema_path = Path("contracts/artifacts/anchor_receipt.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validate_payload_against_schema(payload, schema)

    receipt_id = str(payload.get("receipt_id") or "")
    if not _SAFE_ID_RE.fullmatch(receipt_id):
        raise ValueError("ANCHOR_RECEIPT_ID_INVALID")

    out_dir = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts")) / "anchor_receipts"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = safe_path_join(out_dir, f"{receipt_id}.json")
    tmp_path = out_path.with_suffix(".tmp")
    body = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(body) > MAX_RECEIPT_BYTES:
        raise ValueError("ANCHOR_RECEIPT_TOO_LARGE")
    with tmp_path.open("wb") as fh:
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, out_path)
    return str(out_path)


class EvidenceAnchorService:
    def create_anchor(
        self, db: Session, tenant_id: str, payload: EvidenceAnchorCreate
    ) -> dict[str, object]:
        p = Path(payload.artifact_path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(payload.artifact_path)
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        db.execute(
            text(
                """
                INSERT INTO evidence_anchor_records(tenant_id, artifact_path, artifact_sha256, anchored_at_utc, external_anchor_ref, immutable_retention)
                VALUES (:tenant_id, :artifact_path, :artifact_sha256, :anchored_at_utc, :external_anchor_ref, :immutable_retention)
                """
            ),
            {
                "tenant_id": tenant_id,
                "artifact_path": str(p),
                "artifact_sha256": digest,
                "anchored_at_utc": _utc_now(),
                "external_anchor_ref": payload.external_anchor_ref,
                "immutable_retention": payload.immutable_retention,
            },
        )
        db.commit()
        receipt = {
            "receipt_id": f"ar-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "artifact_sha256": digest,
            "provider": "local",
            "anchor_ref": payload.external_anchor_ref,
            "created_at": _utc_now(),
        }
        receipt_path = _write_anchor_receipt(receipt)
        return {
            "tenant_id": tenant_id,
            "artifact_path": str(p),
            "artifact_sha256": digest,
            "external_anchor_ref": payload.external_anchor_ref,
            "immutable_retention": payload.immutable_retention,
            "anchor_receipt_path": receipt_path,
        }

    def list_anchors(self, db: Session, tenant_id: str) -> list[dict[str, object]]:
        rows = db.execute(
            text(
                "SELECT id, artifact_path, artifact_sha256, anchored_at_utc, external_anchor_ref, immutable_retention "
                "FROM evidence_anchor_records WHERE tenant_id=:tenant_id ORDER BY id DESC"
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(r) for r in rows]
