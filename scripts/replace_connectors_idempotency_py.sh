#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="services/connectors/idempotency.py"
mkdir -p "$(dirname "$TARGET")"

echo "== Backup current file (if exists) =="
if [[ -f "$TARGET" ]]; then
  cp -a "$TARGET" "${TARGET}.bak.$(date +%Y%m%d_%H%M%S)"
fi

echo "== Write clean production-grade idempotency implementation =="
cat > "$TARGET" <<'PY'
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models import ConnectorIdempotency


@dataclass(frozen=True)
class IdempotencyReservation:
    ok: bool
    expires_at: Optional[datetime] = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sqlite_now_iso() -> str:
    """
    SQLite stores expires_at as TEXT in our bootstrap. Use a stable UTC ISO format
    that compares lexicographically correctly:
      YYYY-MM-DDTHH:MM:SS.ffffffZ
    """
    return _now_utc().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sqlite_expires_iso(ttl_hours: int) -> str:
    dt = _now_utc() + timedelta(hours=int(ttl_hours))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _dialect_name(db: Session) -> str:
    bind = db.get_bind()
    if bind is None:
        return ""
    d = getattr(bind, "dialect", None)
    return (getattr(d, "name", "") or "").lower().strip()


def reserve_idempotency_key(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str,
    ttl_hours: int = 168,
) -> bool:
    """
    Attempt to reserve a key. Returns True if reserved by this call, False if already reserved.

    Behavior:
    - First try to insert.
    - If uniqueness fails:
      - best-effort reclaim if the existing row is expired,
      - then retry insert once.
    """
    dialect = _dialect_name(db)

    if dialect == "sqlite":
        return _reserve_sqlite(
            db,
            tenant_id=tenant_id,
            connector_id=connector_id,
            action=action,
            idempotency_key=idempotency_key,
            ttl_hours=ttl_hours,
        )

    # Default to Postgres semantics (timestamptz)
    return _reserve_postgres(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action=action,
        idempotency_key=idempotency_key,
        ttl_hours=ttl_hours,
    )


def prune_expired(db: Session, *, limit: int = 5000) -> int:
    """
    Delete expired reservations. Returns number of rows deleted (best-effort).
    """
    dialect = _dialect_name(db)

    if dialect == "sqlite":
        now_iso = _sqlite_now_iso()
        stmt = (
            delete(ConnectorIdempotency)
            .where(ConnectorIdempotency.expires_at < now_iso)  # TEXT compare
        )
    else:
        stmt = delete(ConnectorIdempotency).where(ConnectorIdempotency.expires_at < _now_utc())

    # LIMIT on DELETE is not portable; keep it simple.
    res = db.execute(stmt)
    # SQLAlchemy rowcount is best-effort, but good enough for pruning telemetry.
    try:
        return int(res.rowcount or 0)
    except Exception:
        return 0


# -------------------------
# Postgres path
# -------------------------


def _reserve_postgres(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str,
    ttl_hours: int,
) -> bool:
    expires_at = _now_utc() + timedelta(hours=int(ttl_hours))

    row = ConnectorIdempotency(
        tenant_id=tenant_id,
        connector_id=connector_id,
        action=action,
        idempotency_key=idempotency_key,
        expires_at=expires_at,
    )

    db.add(row)
    try:
        db.flush()
        return True
    except IntegrityError:
        db.rollback()

    # Best-effort reclaim expired
    reclaimed = _reclaim_postgres(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action=action,
        idempotency_key=idempotency_key,
    )
    if not reclaimed:
        return False

    db.add(
        ConnectorIdempotency(
            tenant_id=tenant_id,
            connector_id=connector_id,
            action=action,
            idempotency_key=idempotency_key,
            expires_at=expires_at,
        )
    )
    try:
        db.flush()
        return True
    except IntegrityError:
        db.rollback()
        return False


def _reclaim_postgres(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str,
) -> bool:
    now = _now_utc()
    # Delete only if expired, bounded by key
    res = db.execute(
        delete(ConnectorIdempotency).where(
            ConnectorIdempotency.tenant_id == tenant_id,
            ConnectorIdempotency.connector_id == connector_id,
            ConnectorIdempotency.action == action,
            ConnectorIdempotency.idempotency_key == idempotency_key,
            ConnectorIdempotency.expires_at < now,
        )
    )
    try:
        return int(res.rowcount or 0) > 0
    except Exception:
        return False


# -------------------------
# SQLite path
# -------------------------


def _reserve_sqlite(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str,
    ttl_hours: int,
) -> bool:
    """
    SQLite-friendly reservation:
    - expires_at is stored as TEXT in stable UTC ISO.
    - we attempt an INSERT and rely on UNIQUE constraint.
    - on conflict, we attempt delete-if-expired then retry.
    """
    expires_iso = _sqlite_expires_iso(ttl_hours)

    # Use a raw INSERT OR IGNORE to avoid exception-based control flow.
    # This is the only reliable way to make “two sessions racing” deterministic-ish on SQLite.
    insert_sql = text(
        """
        INSERT OR IGNORE INTO connectors_idempotency
          (tenant_id, connector_id, action, idempotency_key, response_hash, created_at, expires_at)
        VALUES
          (:tenant_id, :connector_id, :action, :idempotency_key, NULL, CURRENT_TIMESTAMP, :expires_at)
        """
    )

    res = db.execute(
        insert_sql,
        {
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "action": action,
            "idempotency_key": idempotency_key,
            "expires_at": expires_iso,
        },
    )

    # If rowcount == 1, we inserted and won.
    if getattr(res, "rowcount", 0) == 1:
        return True

    # Conflict: best-effort reclaim if expired, then retry once.
    reclaimed = _reclaim_sqlite(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action=action,
        idempotency_key=idempotency_key,
    )
    if not reclaimed:
        return False

    res2 = db.execute(
        insert_sql,
        {
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "action": action,
            "idempotency_key": idempotency_key,
            "expires_at": expires_iso,
        },
    )
    return getattr(res2, "rowcount", 0) == 1


def _reclaim_sqlite(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str,
) -> bool:
    now_iso = _sqlite_now_iso()
    del_sql = text(
        """
        DELETE FROM connectors_idempotency
        WHERE tenant_id = :tenant_id
          AND connector_id = :connector_id
          AND action = :action
          AND idempotency_key = :idempotency_key
          AND expires_at < :now_iso
        """
    )
    res = db.execute(
        del_sql,
        {
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "action": action,
            "idempotency_key": idempotency_key,
            "now_iso": now_iso,
        },
    )
    return getattr(res, "rowcount", 0) > 0
PY

echo "== Compile check (must pass) =="
python -m py_compile "$TARGET"

echo "== Format + lint (best effort) =="
ruff format "$TARGET" >/dev/null 2>&1 || true
ruff check "$TARGET" >/dev/null 2>&1 || true

echo "== Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== Done =="