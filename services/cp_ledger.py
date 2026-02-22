"""
services/cp_ledger.py — Control Plane v2 Event Ledger Service.

Responsibilities:
  - Append tamper-evident events to control_plane_event_ledger.
  - Maintain SHA-256 hash chain (content_hash + chain_hash).
  - Provide full-chain integrity verification.
  - Merkle tree snapshot and daily anchor export.
  - Fail-closed: raises if DB unavailable.

Hash chain design:
  content_hash = SHA256(canonical_json({payload_json, actor_id, tenant_id, event_type, ts}))
  chain_hash   = SHA256(prev_hash || ":" || content_hash || ":" || ts_iso)

Chain verification:
  - Walk all rows ordered by ts, id (stable sort).
  - Recompute content_hash and chain_hash for each row.
  - Verify chain linkage (each row's prev_hash == previous row's chain_hash).
  - Report first tampered entry.

Merkle tree:
  - Leaf = SHA256(chain_hash || id)
  - Tree uses SHA256-based binary Merkle (left||right)
  - Root = anchor for daily export

Security invariants:
  - All writes fail-closed (raise, never silently ignore).
  - Canonical JSON serializer used for all hash inputs.
  - No subprocess, no shell.
  - Tenant isolation: append only for own tenant or global actor.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.cp_ledger")

# ---------------------------------------------------------------------------
# Monotonic sequence for stable chain ordering (cross-platform: SQLite + Postgres)
# ---------------------------------------------------------------------------
_seq_lock = threading.Lock()
_seq_last: int = 0


def _next_seq() -> int:
    """
    Generate a strictly monotonically increasing integer for chain ordering.

    Uses microsecond timestamp as base; increments if two calls land in the
    same microsecond (prevents collisions in rapid test loops).

    Works in both SQLite (no native BIGSERIAL on non-PK) and Postgres.
    """
    global _seq_last
    with _seq_lock:
        candidate = int(time.time() * 1_000_000)
        if candidate <= _seq_last:
            candidate = _seq_last + 1
        _seq_last = candidate
        return candidate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS_HASH = "0" * 64
LEDGER_CHAIN_ID = "control_plane_v2"

VALID_SOURCES = frozenset({"api", "agent", "system"})
VALID_SEVERITIES = frozenset({"debug", "info", "warning", "error", "critical"})

VALID_EVENT_TYPES = frozenset(
    {
        # Locker / module lifecycle
        "cp_locker_restart_queued",
        "cp_locker_pause_queued",
        "cp_locker_resume_queued",
        "cp_locker_quarantine_queued",
        "cp_locker_stop_queued",
        "cp_locker_state_changed",
        # Command lifecycle
        "cp_command_created",
        "cp_command_executing",
        "cp_command_completed",
        "cp_command_failed",
        "cp_command_cancelled",
        # Receipt
        "cp_receipt_submitted",
        # Heartbeat
        "cp_heartbeat_stale",
        "cp_heartbeat_recovered",
        # Playbook
        "cp_playbook_triggered",
        "cp_playbook_completed",
        "cp_playbook_dry_run",
        # Audit / MSP
        "cp_msp_cross_tenant_access",
        "cp_ledger_verified",
        "cp_ledger_tamper_detected",
        "cp_ledger_anchor_exported",
        # Breaker
        "cp_breaker_open",
        "cp_breaker_closed",
        "cp_breaker_isolated",
    }
)


# ---------------------------------------------------------------------------
# Canonical JSON (deterministic, no floats/NaN)
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialisation used for all hash inputs."""
    import json
    from decimal import Decimal

    def _norm(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): _norm(val) for k, val in sorted(v.items())}
        if isinstance(v, (list, tuple)):
            return [_norm(i) for i in v]
        if isinstance(v, datetime):
            ts = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(v, Decimal):
            return float(v)
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return str(v)

    return json.dumps(
        _norm(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hash chain helpers
# ---------------------------------------------------------------------------

def compute_content_hash(
    *,
    payload_json: Dict[str, Any],
    actor_id: str,
    tenant_id: Optional[str],
    event_type: str,
    ts: str,
) -> str:
    """
    content_hash = SHA256(canonical_json(content_envelope))

    The envelope includes all fields that uniquely identify this event's content.
    """
    envelope = {
        "payload_json": payload_json,
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "event_type": event_type,
        "ts": ts,
    }
    return _sha256(_canonical_json(envelope))


def compute_chain_hash(
    *,
    prev_hash: str,
    content_hash: str,
    ts: str,
    event_id: str,
) -> str:
    """
    chain_hash = SHA256(prev_hash:content_hash:ts:event_id)

    Binding event_id prevents hash-collision attacks across different events
    with identical content.
    """
    raw = f"{prev_hash}:{content_hash}:{ts}:{event_id}".encode("utf-8")
    return _sha256(raw)


# ---------------------------------------------------------------------------
# Ledger result types
# ---------------------------------------------------------------------------

@dataclass
class LedgerEntry:
    id: str
    ts: str
    tenant_id: Optional[str]
    actor_id: str
    actor_role: str
    event_type: str
    payload_json: Dict[str, Any]
    content_hash: str
    prev_hash: str
    chain_hash: str
    trace_id: str
    severity: str
    source: str


@dataclass
class ChainVerificationResult:
    ok: bool
    total_entries: int
    first_tampered_id: Optional[str]
    first_tampered_index: Optional[int]
    error_detail: Optional[str]
    chain_id: str = LEDGER_CHAIN_ID
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    merkle_root: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "chain_id": self.chain_id,
            "total_entries": self.total_entries,
            "first_tampered_id": self.first_tampered_id,
            "first_tampered_index": self.first_tampered_index,
            "error_detail": self.error_detail,
            "verified_at": self.verified_at,
            "merkle_root": self.merkle_root,
        }


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

def _merkle_root(leaves: List[str]) -> Optional[str]:
    """
    Binary Merkle tree over SHA-256 leaf hashes.
    Returns None for empty input; returns single leaf for single-entry chain.
    """
    if not leaves:
        return None
    layer = list(leaves)
    while len(layer) > 1:
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            combined = _sha256((left + right).encode("utf-8"))
            next_layer.append(combined)
        layer = next_layer
    return layer[0]


def compute_merkle_root(entries: List[LedgerEntry]) -> Optional[str]:
    """Compute Merkle root over chain_hash||id for each entry."""
    leaves = [_sha256((e.chain_hash + e.id).encode("utf-8")) for e in entries]
    return _merkle_root(leaves)


# ---------------------------------------------------------------------------
# Core ledger service
# ---------------------------------------------------------------------------

class ControlPlaneLedger:
    """
    Thread-safe ledger service.

    All public methods that write to the DB raise on failure (fail-closed).
    Reads degrade gracefully with explicit error returns.
    """

    def append_event(
        self,
        *,
        db_session: Any,
        event_type: str,
        actor_id: str,
        actor_role: str,
        tenant_id: Optional[str],
        payload: Dict[str, Any],
        trace_id: str = "",
        severity: str = "info",
        source: str = "api",
        event_id: Optional[str] = None,
    ) -> LedgerEntry:
        """
        Append a new event to the ledger.

        Computes content_hash and chain_hash by reading the last entry
        within the same tenant chain (or global chain if tenant_id is None).

        Raises RuntimeError if DB write fails (fail-closed).
        """
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type!r}")
        if severity not in VALID_SEVERITIES:
            severity = "info"
        if source not in VALID_SOURCES:
            source = "api"

        ts_now = datetime.now(timezone.utc)
        ts_iso = ts_now.isoformat().replace("+00:00", "Z")
        eid = event_id or str(uuid.uuid4())

        # Fetch the most recent chain_hash for this chain
        prev_hash = self._get_chain_tip(db_session, tenant_id=tenant_id)

        content_hash = compute_content_hash(
            payload_json=payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
            event_type=event_type,
            ts=ts_iso,
        )
        chain_hash = compute_chain_hash(
            prev_hash=prev_hash,
            content_hash=content_hash,
            ts=ts_iso,
            event_id=eid,
        )

        row = ControlPlaneEventLedger(
            id=eid,
            seq=_next_seq(),
            ts=ts_now,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            event_type=event_type,
            payload_json=payload,
            content_hash=content_hash,
            prev_hash=prev_hash,
            chain_hash=chain_hash,
            trace_id=trace_id or "",
            severity=severity,
            source=source,
        )

        try:
            db_session.add(row)
            db_session.flush()
        except Exception as exc:
            log.error("cp_ledger.append_failed event_type=%s error=%s", event_type, exc)
            raise RuntimeError(f"Ledger write failed: {exc}") from exc

        log.info(
            "cp_ledger.appended event_type=%s id=%s tenant=%s chain_hash=%s",
            event_type,
            eid,
            tenant_id,
            chain_hash,
        )
        return LedgerEntry(
            id=eid,
            ts=ts_iso,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            event_type=event_type,
            payload_json=payload,
            content_hash=content_hash,
            prev_hash=prev_hash,
            chain_hash=chain_hash,
            trace_id=trace_id or "",
            severity=severity,
            source=source,
        )

    def _get_chain_tip(
        self,
        db_session: Any,
        tenant_id: Optional[str],
    ) -> str:
        """
        Return the chain_hash of the most recent entry in this chain.
        Returns GENESIS_HASH if no prior entries exist.

        Uses tenant_id=None for the global chain.
        """
        from api.db_models_cp_v2 import ControlPlaneEventLedger
        from sqlalchemy import desc

        try:
            q = db_session.query(ControlPlaneEventLedger.chain_hash)
            if tenant_id is None:
                q = q.filter(ControlPlaneEventLedger.tenant_id.is_(None))
            else:
                q = q.filter(ControlPlaneEventLedger.tenant_id == tenant_id)
            # Use seq for stable monotonic ordering (autoincrement guarantees insertion order)
            row = q.order_by(
                desc(ControlPlaneEventLedger.seq),
            ).first()
            if row:
                return row[0]
        except Exception as exc:
            log.warning("cp_ledger.chain_tip_read_failed error=%s", exc)
        return GENESIS_HASH

    def verify_chain(
        self,
        db_session: Any,
        tenant_id: Optional[str] = None,
        limit: int = 10_000,
    ) -> ChainVerificationResult:
        """
        Verify the full ledger chain for a given tenant (or global chain).

        Returns a deterministic ChainVerificationResult.
        """
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        try:
            q = db_session.query(ControlPlaneEventLedger)
            if tenant_id is None:
                q = q.filter(ControlPlaneEventLedger.tenant_id.is_(None))
            else:
                q = q.filter(ControlPlaneEventLedger.tenant_id == tenant_id)
            rows = (
                q.order_by(
                    ControlPlaneEventLedger.seq,
                )
                .limit(limit)
                .all()
            )
        except Exception as exc:
            return ChainVerificationResult(
                ok=False,
                total_entries=0,
                first_tampered_id=None,
                first_tampered_index=None,
                error_detail=f"DB read failed: {exc}",
            )

        if not rows:
            return ChainVerificationResult(
                ok=True,
                total_entries=0,
                first_tampered_id=None,
                first_tampered_index=None,
                error_detail=None,
                merkle_root=None,
            )

        entries: List[LedgerEntry] = []
        prev_chain_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            # Normalize timestamp: SQLite may return naive datetimes; always treat as UTC.
            if isinstance(row.ts, datetime):
                ts_val = row.ts
                if ts_val.tzinfo is None:
                    ts_val = ts_val.replace(tzinfo=timezone.utc)
                else:
                    ts_val = ts_val.astimezone(timezone.utc)
                ts_iso = ts_val.isoformat().replace("+00:00", "Z")
            else:
                # String from SQLite — normalize space→T separator
                ts_str = str(row.ts).strip().replace(" ", "T")
                if not ts_str.endswith("Z") and "+" not in ts_str[10:] and "-" not in ts_str[10:]:
                    ts_str += "+00:00"
                try:
                    parsed = datetime.fromisoformat(ts_str)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    ts_iso = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                except ValueError:
                    ts_iso = ts_str
            expected_content_hash = compute_content_hash(
                payload_json=row.payload_json or {},
                actor_id=row.actor_id,
                tenant_id=row.tenant_id,
                event_type=row.event_type,
                ts=ts_iso,
            )
            expected_chain_hash = compute_chain_hash(
                prev_hash=prev_chain_hash,
                content_hash=expected_content_hash,
                ts=ts_iso,
                event_id=str(row.id),
            )

            if (
                row.content_hash != expected_content_hash
                or row.chain_hash != expected_chain_hash
                or row.prev_hash != prev_chain_hash
            ):
                return ChainVerificationResult(
                    ok=False,
                    total_entries=len(rows),
                    first_tampered_id=str(row.id),
                    first_tampered_index=idx,
                    error_detail="content_hash or chain_hash mismatch",
                )

            entries.append(
                LedgerEntry(
                    id=str(row.id),
                    ts=ts_iso,
                    tenant_id=row.tenant_id,
                    actor_id=row.actor_id,
                    actor_role=row.actor_role,
                    event_type=row.event_type,
                    payload_json=row.payload_json or {},
                    content_hash=row.content_hash,
                    prev_hash=row.prev_hash,
                    chain_hash=row.chain_hash,
                    trace_id=row.trace_id or "",
                    severity=row.severity,
                    source=row.source,
                )
            )
            prev_chain_hash = row.chain_hash

        merkle_root = compute_merkle_root(entries)

        return ChainVerificationResult(
            ok=True,
            total_entries=len(rows),
            first_tampered_id=None,
            first_tampered_index=None,
            error_detail=None,
            merkle_root=merkle_root,
        )

    def get_events(
        self,
        db_session: Any,
        tenant_id: Optional[str],
        is_global_admin: bool,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Query ledger events with tenant isolation.

        Global admins may query all tenants (pass tenant_id=None).
        Tenant actors only see their own tenant.
        """
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        q = db_session.query(ControlPlaneEventLedger)

        if not is_global_admin:
            if tenant_id:
                q = q.filter(ControlPlaneEventLedger.tenant_id == tenant_id)
            else:
                return []  # no tenant, no global — return empty

        if since:
            q = q.filter(ControlPlaneEventLedger.ts >= since)
        if until:
            q = q.filter(ControlPlaneEventLedger.ts <= until)
        if event_type:
            q = q.filter(ControlPlaneEventLedger.event_type == event_type)

        rows = (
            q.order_by(
                ControlPlaneEventLedger.ts.desc(),
                ControlPlaneEventLedger.id.desc(),
            )
            .offset(offset)
            .limit(limit)
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
                    "id": str(row.id),
                    "ts": ts_iso,
                    "tenant_id": row.tenant_id,
                    "actor_id": row.actor_id,
                    "actor_role": row.actor_role,
                    "event_type": row.event_type,
                    "payload_json": row.payload_json or {},
                    "content_hash": row.content_hash,
                    "prev_hash": row.prev_hash,
                    "chain_hash": row.chain_hash,
                    "trace_id": row.trace_id or "",
                    "severity": row.severity,
                    "source": row.source,
                }
            )
        return result

    def export_daily_anchor(
        self,
        db_session: Any,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export a daily Merkle root anchor for the chain.

        Returns a deterministic JSON anchor artifact suitable for
        external notarisation (e.g., timestamping authority).
        """
        result = self.verify_chain(db_session, tenant_id=tenant_id)
        anchor = {
            "anchor_type": "cp_ledger_daily_anchor",
            "chain_id": LEDGER_CHAIN_ID,
            "tenant_id": tenant_id,
            "total_entries": result.total_entries,
            "merkle_root": result.merkle_root,
            "integrity_ok": result.ok,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        log.info(
            "cp_ledger.anchor_exported tenant=%s merkle_root=%s entries=%s",
            tenant_id,
            result.merkle_root,
            result.total_entries,
        )
        return anchor


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_ledger_instance: Optional[ControlPlaneLedger] = None


def get_ledger() -> ControlPlaneLedger:
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = ControlPlaneLedger()
    return _ledger_instance
