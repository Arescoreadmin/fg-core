"""
services/cp_commands.py — Control Plane v2 Command Service.

Command lifecycle:
  1. Operator POST → DB record created (status=queued) → ledger event emitted.
  2. Executor polls/subscribes → status → executing → ledger event.
  3. Executor POST receipt → receipt appended → status → completed|failed.
  4. All transitions are ledger-backed.

Security invariants:
  - Command enum strictly allowlisted (VALID_CP_COMMANDS).
  - idempotency_key stored as SHA-256 hash only.
  - client IP stored as SHA-256 hash only.
  - Receipt endpoint validates executor identity.
  - Fail-closed: write failures raise RuntimeError.
  - No subprocess, no shell, no dynamic dispatch.

Cancel semantics:
  - queued → cancellable (status → cancelled)
  - executing → CONFLICT (409)
  - completed/failed/cancelled → CONFLICT
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.cp_commands")

# ---------------------------------------------------------------------------
# Constants — command enum (strictly allowlisted)
# ---------------------------------------------------------------------------

VALID_CP_COMMANDS = frozenset(
    {
        "restart",
        "pause",
        "resume",
        "quarantine",
        "stop",
        "drain",
        "force_close_breaker",
        "trigger_playbook",
    }
)

VALID_TARGET_TYPES = frozenset(
    {
        "locker",
        "module",
        "connector",
        "playbook",
    }
)

VALID_STATUSES = frozenset(
    {
        "queued",
        "executing",
        "completed",
        "failed",
        "cancelled",
    }
)

VALID_EXECUTOR_TYPES = frozenset({"agent", "system", "operator"})

# Reason field constraints
REASON_MIN_LEN = 4
REASON_MAX_LEN = 512
REASON_PATTERN = re.compile(r"^[\w\s.,;:!?()\-\/\[\]#@]+$", re.UNICODE)

# Error codes
ERR_UNKNOWN_COMMAND_ID = "CP_CMD_UNKNOWN_COMMAND_ID"
ERR_INVALID_COMMAND = "CP_CMD_INVALID_COMMAND"
ERR_INVALID_TARGET_TYPE = "CP_CMD_INVALID_TARGET_TYPE"
ERR_REASON_REQUIRED = "CP_CMD_REASON_REQUIRED"
ERR_REASON_TOO_SHORT = "CP_CMD_REASON_TOO_SHORT"
ERR_REASON_TOO_LONG = "CP_CMD_REASON_TOO_LONG"
ERR_REASON_INVALID_CHARS = "CP_CMD_REASON_INVALID_CHARS"
ERR_IDEMPOTENT_DUPLICATE = "CP_CMD_IDEMPOTENT_DUPLICATE"
ERR_CANCEL_CONFLICT = "CP_CMD_CANCEL_CONFLICT"
ERR_NOT_EXECUTOR = "CP_CMD_NOT_EXECUTOR"
ERR_ALREADY_RECEIPTED = "CP_CMD_ALREADY_RECEIPTED"
ERR_DB_WRITE = "CP_CMD_DB_WRITE_FAILED"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CommandRecord:
    command_id: str
    ts: str
    tenant_id: str
    actor_id: str
    actor_role: str
    target_type: str
    target_id: str
    command: str
    reason: str
    status: str
    trace_id: str
    idempotent: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_id": self.command_id,
            "ts": self.ts,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "command": self.command,
            "reason": self.reason,
            "status": self.status,
            "trace_id": self.trace_id,
            "idempotent": self.idempotent,
        }


@dataclass
class ReceiptRecord:
    receipt_id: str
    command_id: str
    ts: str
    executor_id: str
    executor_type: str
    ok: bool
    error_code: Optional[str]
    evidence_hash: str
    duration_ms: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "command_id": self.command_id,
            "ts": self.ts,
            "executor_id": self.executor_id,
            "executor_type": self.executor_type,
            "ok": self.ok,
            "error_code": self.error_code,
            "evidence_hash": self.evidence_hash,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hash_idempotency_key(raw: str) -> str:
    return _sha256(f"ikey:{raw}")


def _hash_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return _sha256(f"ip:{ip}")


def _validate_reason(reason: Optional[str]) -> str:
    """Validate reason field. Returns normalised reason or raises ValueError."""
    if not reason:
        raise ValueError(ERR_REASON_REQUIRED)
    reason = reason.strip()
    if len(reason) < REASON_MIN_LEN:
        raise ValueError(ERR_REASON_TOO_SHORT)
    if len(reason) > REASON_MAX_LEN:
        raise ValueError(ERR_REASON_TOO_LONG)
    if not REASON_PATTERN.match(reason):
        raise ValueError(ERR_REASON_INVALID_CHARS)
    return reason


# ---------------------------------------------------------------------------
# Command service
# ---------------------------------------------------------------------------

class ControlPlaneCommandService:
    """
    Thread-safe service for operator command lifecycle.

    All write methods raise on failure (fail-closed).
    """

    def create_command(
        self,
        *,
        db_session: Any,
        ledger: Any,  # ControlPlaneLedger
        tenant_id: str,
        actor_id: str,
        actor_role: str,
        target_type: str,
        target_id: str,
        command: str,
        reason: str,
        idempotency_key: str,
        trace_id: str = "",
        client_ip: Optional[str] = None,
    ) -> CommandRecord:
        """
        Create a new command record.

        Returns existing record if idempotency key matched (idempotent=True).
        Raises ValueError with stable error code on validation failure.
        Raises RuntimeError on DB failure (fail-closed).
        """
        from api.db_models_cp_v2 import ControlPlaneCommand

        # Validate inputs
        if command not in VALID_CP_COMMANDS:
            raise ValueError(ERR_INVALID_COMMAND)
        if target_type not in VALID_TARGET_TYPES:
            raise ValueError(ERR_INVALID_TARGET_TYPE)

        reason = _validate_reason(reason)
        ikey_hash = _hash_idempotency_key(idempotency_key)
        ip_hash = _hash_ip(client_ip)
        command_id = str(uuid.uuid4())
        ts_now = datetime.now(timezone.utc)

        # Check idempotency (unique constraint covers this)
        existing = (
            db_session.query(ControlPlaneCommand)
            .filter_by(
                tenant_id=tenant_id,
                actor_id=actor_id,
                idempotency_key_hash=ikey_hash,
                command=command,
                target_id=target_id,
            )
            .first()
        )
        if existing:
            return self._row_to_record(existing, idempotent=True)

        row = ControlPlaneCommand(
            command_id=command_id,
            ts=ts_now,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=target_id,
            command=command,
            reason=reason,
            idempotency_key_hash=ikey_hash,
            status="queued",
            trace_id=trace_id or "",
            requested_from_ip_hash=ip_hash,
        )
        try:
            db_session.add(row)
            db_session.flush()
        except Exception as exc:
            log.error("cp_commands.create_failed command=%s error=%s", command, exc)
            raise RuntimeError(f"{ERR_DB_WRITE}: {exc}") from exc

        # Emit ledger event
        try:
            ledger.append_event(
                db_session=db_session,
                event_type="cp_command_created",
                actor_id=actor_id,
                actor_role=actor_role,
                tenant_id=tenant_id,
                payload={
                    "command_id": command_id,
                    "command": command,
                    "target_type": target_type,
                    "target_id": target_id,
                    "reason": reason,
                    "trace_id": trace_id,
                },
                trace_id=trace_id,
                severity="info",
                source="api",
            )
        except Exception as exc:
            log.error("cp_commands.ledger_emit_failed command_id=%s error=%s", command_id, exc)
            raise RuntimeError(f"Ledger write failed after command insert: {exc}") from exc

        ts_iso = ts_now.isoformat().replace("+00:00", "Z")
        return CommandRecord(
            command_id=command_id,
            ts=ts_iso,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=target_id,
            command=command,
            reason=reason,
            status="queued",
            trace_id=trace_id or "",
            idempotent=False,
        )

    def cancel_command(
        self,
        *,
        db_session: Any,
        ledger: Any,
        command_id: str,
        tenant_id: str,
        actor_id: str,
        actor_role: str,
        trace_id: str = "",
    ) -> CommandRecord:
        """
        Cancel a queued command.

        Only queued commands may be cancelled.
        executing/completed/failed → 409 CONFLICT.
        """
        from api.db_models_cp_v2 import ControlPlaneCommand

        row = (
            db_session.query(ControlPlaneCommand)
            .filter_by(command_id=command_id, tenant_id=tenant_id)
            .first()
        )
        if not row:
            raise ValueError(ERR_UNKNOWN_COMMAND_ID)

        if row.status != "queued":
            raise ValueError(ERR_CANCEL_CONFLICT)

        row.status = "cancelled"
        try:
            db_session.flush()
        except Exception as exc:
            raise RuntimeError(f"{ERR_DB_WRITE}: {exc}") from exc

        try:
            ledger.append_event(
                db_session=db_session,
                event_type="cp_command_cancelled",
                actor_id=actor_id,
                actor_role=actor_role,
                tenant_id=tenant_id,
                payload={"command_id": command_id, "cancelled_by": actor_id},
                trace_id=trace_id,
                severity="info",
                source="api",
            )
        except Exception as exc:
            log.error("cp_commands.cancel_ledger_failed command_id=%s error=%s", command_id, exc)
            raise RuntimeError(f"Ledger write failed after cancel: {exc}") from exc

        return self._row_to_record(row)

    def submit_receipt(
        self,
        *,
        db_session: Any,
        ledger: Any,
        command_id: str,
        executor_id: str,
        executor_type: str,
        ok: bool,
        error_code: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        trace_id: str = "",
    ) -> ReceiptRecord:
        """
        Submit an executor receipt for a command.

        Validates executor type. Appends receipt row. Updates command status.
        Emits ledger event. All fail-closed.
        """
        from api.db_models_cp_v2 import ControlPlaneCommand, ControlPlaneCommandReceipt
        from api.signed_artifacts import canonical_hash

        if executor_type not in VALID_EXECUTOR_TYPES:
            raise ValueError(ERR_NOT_EXECUTOR)

        row = (
            db_session.query(ControlPlaneCommand)
            .filter_by(command_id=command_id)
            .first()
        )
        if not row:
            raise ValueError(ERR_UNKNOWN_COMMAND_ID)

        # Check for existing receipt (idempotency)
        existing = (
            db_session.query(ControlPlaneCommandReceipt)
            .filter_by(command_id=command_id, executor_id=executor_id)
            .first()
        )
        if existing:
            raise ValueError(ERR_ALREADY_RECEIPTED)

        evidence_data = evidence or {}
        evidence_hash = canonical_hash(evidence_data)
        receipt_id = str(uuid.uuid4())
        ts_now = datetime.now(timezone.utc)

        receipt_row = ControlPlaneCommandReceipt(
            receipt_id=receipt_id,
            command_id=command_id,
            ts=ts_now,
            executor_id=executor_id,
            executor_type=executor_type,
            ok=ok,
            error_code=error_code,
            evidence_hash=evidence_hash,
            duration_ms=duration_ms,
            details_json=evidence_data,
        )

        # Update command status
        new_status = "completed" if ok else "failed"
        row.status = new_status

        try:
            db_session.add(receipt_row)
            db_session.flush()
        except Exception as exc:
            log.error("cp_commands.receipt_write_failed command_id=%s error=%s", command_id, exc)
            raise RuntimeError(f"{ERR_DB_WRITE}: {exc}") from exc

        tenant_id = row.tenant_id
        try:
            ledger.append_event(
                db_session=db_session,
                event_type="cp_receipt_submitted",
                actor_id=executor_id,
                actor_role=executor_type,
                tenant_id=tenant_id,
                payload={
                    "receipt_id": receipt_id,
                    "command_id": command_id,
                    "ok": ok,
                    "error_code": error_code,
                    "evidence_hash": evidence_hash,
                    "duration_ms": duration_ms,
                },
                trace_id=trace_id,
                severity="info" if ok else "warning",
                source="agent" if executor_type == "agent" else "system",
            )
        except Exception as exc:
            log.error("cp_commands.receipt_ledger_failed command_id=%s error=%s", command_id, exc)
            raise RuntimeError(f"Ledger write failed after receipt: {exc}") from exc

        ts_iso = ts_now.isoformat().replace("+00:00", "Z")
        return ReceiptRecord(
            receipt_id=receipt_id,
            command_id=command_id,
            ts=ts_iso,
            executor_id=executor_id,
            executor_type=executor_type,
            ok=ok,
            error_code=error_code,
            evidence_hash=evidence_hash,
            duration_ms=duration_ms,
        )

    def get_commands(
        self,
        db_session: Any,
        tenant_id: str,
        is_global_admin: bool,
        status: Optional[str] = None,
        target_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query commands with tenant isolation."""
        from api.db_models_cp_v2 import ControlPlaneCommand

        q = db_session.query(ControlPlaneCommand)
        if not is_global_admin:
            q = q.filter(ControlPlaneCommand.tenant_id == tenant_id)
        if status:
            q = q.filter(ControlPlaneCommand.status == status)
        if target_id:
            q = q.filter(ControlPlaneCommand.target_id == target_id)

        rows = (
            q.order_by(ControlPlaneCommand.ts.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [self._row_to_record(r).to_dict() for r in rows]

    def get_receipts(
        self,
        db_session: Any,
        command_id: str,
        tenant_id: str,
        is_global_admin: bool,
    ) -> List[Dict[str, Any]]:
        """Get receipts for a command, with tenant isolation via command lookup."""
        from api.db_models_cp_v2 import ControlPlaneCommand, ControlPlaneCommandReceipt

        # Verify command belongs to tenant
        cmd = db_session.query(ControlPlaneCommand).filter_by(command_id=command_id).first()
        if not cmd:
            return []
        if not is_global_admin and cmd.tenant_id != tenant_id:
            return []

        rows = (
            db_session.query(ControlPlaneCommandReceipt)
            .filter_by(command_id=command_id)
            .order_by(ControlPlaneCommandReceipt.ts)
            .all()
        )
        result = []
        for row in rows:
            ts_iso = (
                row.ts.isoformat().replace("+00:00", "Z")
                if isinstance(row.ts, datetime)
                else str(row.ts)
            )
            result.append(
                {
                    "receipt_id": str(row.receipt_id),
                    "command_id": str(row.command_id),
                    "ts": ts_iso,
                    "executor_id": row.executor_id,
                    "executor_type": row.executor_type,
                    "ok": row.ok,
                    "error_code": row.error_code,
                    "evidence_hash": row.evidence_hash,
                    "duration_ms": row.duration_ms,
                }
            )
        return result

    @staticmethod
    def _row_to_record(row: Any, *, idempotent: bool = False) -> CommandRecord:
        ts_iso = (
            row.ts.isoformat().replace("+00:00", "Z")
            if isinstance(row.ts, datetime)
            else str(row.ts)
        )
        return CommandRecord(
            command_id=str(row.command_id),
            ts=ts_iso,
            tenant_id=row.tenant_id,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            target_type=row.target_type,
            target_id=row.target_id,
            command=row.command,
            reason=row.reason,
            status=row.status,
            trace_id=row.trace_id or "",
            idempotent=idempotent,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_command_svc_instance: Optional[ControlPlaneCommandService] = None


def get_command_service() -> ControlPlaneCommandService:
    global _command_svc_instance
    if _command_svc_instance is None:
        _command_svc_instance = ControlPlaneCommandService()
    return _command_svc_instance
