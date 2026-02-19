from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from services.exception_breakglass_extension.models import (
    BreakglassSessionCreate,
    ExceptionApproval,
    ExceptionRequestCreate,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ExceptionBreakglassService:
    def create_exception(
        self, db: Session, tenant_id: str, payload: ExceptionRequestCreate
    ) -> dict[str, object]:
        request_id = f"exc-{uuid.uuid4().hex[:10]}"
        entry = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "status": "pending",
            "subject_type": payload.subject_type,
            "subject_id": payload.subject_id,
            "justification": payload.justification,
            "expires_at_utc": payload.expires_at_utc,
            "scope": getattr(payload, "scope", None) or "global",
            "risk_tier": getattr(payload, "risk_tier", None) or "medium",
            "created_at_utc": _utc_now(),
            "approvals": [],
        }
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()
        db.execute(
            text(
                "INSERT INTO approval_logs(tenant_id, subject_type, subject_id, seq, entry_json, entry_hash, prev_chain_hash, chain_hash, signature, key_id) "
                "VALUES (:tenant_id, 'exception', :subject_id, 1, :entry_json, :entry_hash, 'GENESIS', :chain_hash, 'local:none', 'local')"
            ),
            {
                "tenant_id": tenant_id,
                "subject_id": request_id,
                "entry_json": json.dumps(entry),
                "entry_hash": digest,
                "chain_hash": digest,
            },
        )
        db.commit()
        return entry

    def approve_exception(
        self, db: Session, tenant_id: str, request_id: str, payload: ExceptionApproval
    ) -> dict[str, object]:
        row = db.execute(
            text(
                "SELECT id, entry_json FROM approval_logs WHERE tenant_id=:tenant_id AND subject_type='exception' AND subject_id=:subject_id ORDER BY id DESC LIMIT 1"
            ),
            {"tenant_id": tenant_id, "subject_id": request_id},
        ).mappings().first()
        if row is None:
            raise ValueError("exception_not_found")
        entry = json.loads(row["entry_json"])
        approvals = list(entry.get("approvals", []))
        approvals.append({"role": payload.approver_role, "notes": payload.notes, "at": _utc_now()})
        entry["approvals"] = approvals
        entry["status"] = "approved"
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()
        db.execute(
            text(
                "INSERT INTO approval_logs(tenant_id, subject_type, subject_id, seq, entry_json, entry_hash, prev_chain_hash, chain_hash, signature, key_id) "
                "VALUES (:tenant_id, 'exception', :subject_id, 2, :entry_json, :entry_hash, :prev_chain_hash, :chain_hash, 'local:none', 'local')"
            ),
            {
                "tenant_id": tenant_id,
                "subject_id": request_id,
                "entry_json": json.dumps(entry),
                "entry_hash": digest,
                "prev_chain_hash": digest,
                "chain_hash": digest,
            },
        )
        db.commit()
        return entry

    def create_breakglass(
        self, db: Session, tenant_id: str, payload: BreakglassSessionCreate
    ) -> dict[str, object]:
        session_id = f"bg-{uuid.uuid4().hex[:12]}"
        entry = {
            "session_id": session_id,
            "tenant_id": tenant_id,
            "status": "active",
            "reason": payload.reason,
            "expires_at_utc": payload.expires_at_utc,
            "scope": getattr(payload, "scope", None) or "global",
            "risk_tier": getattr(payload, "risk_tier", None) or "medium",
            "created_at_utc": _utc_now(),
        }
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()
        db.execute(
            text(
                "INSERT INTO approval_logs(tenant_id, subject_type, subject_id, seq, entry_json, entry_hash, prev_chain_hash, chain_hash, signature, key_id) "
                "VALUES (:tenant_id, 'breakglass', :subject_id, 1, :entry_json, :entry_hash, 'GENESIS', :chain_hash, 'local:none', 'local')"
            ),
            {
                "tenant_id": tenant_id,
                "subject_id": session_id,
                "entry_json": json.dumps(entry),
                "entry_hash": digest,
                "chain_hash": digest,
            },
        )
        db.commit()
        return entry
