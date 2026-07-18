# api/tenant_repository.py
"""
R7 — Canonical Tenant Persistence.

TenantRepository is the Postgres-first tenant authority.  During the R7
transition window a JSON fallback is provided so existing tenants remain
visible before migrate_to_postgres.py has been run.

See docs/ai/R1_AUTHORITY_AUDIT.md for the authority audit that motivated
this module.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger("frostgate.tenant_repository")

# Valid lifecycle states (R3 will own the workflow; R7 only enumerates them).
_SUPPORTED_LIFECYCLE_STATES = {
    "active",
    "suspended",
    "archived",
    "failed",
    "validating",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TenantRow:
    tenant_id: str
    display_name: str
    lifecycle_state: str
    created_at: Any  # datetime or ISO string depending on driver
    updated_at: Any
    created_by: Optional[str]
    metadata: Dict[str, Any]
    canonical_version: int
    last_reconciled_at: Any
    archived_at: Any
    migration_source: Optional[str]
    migration_version: Optional[str]


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class TenantRepository:
    """Postgres-first tenant authority with JSON fallback."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, tenant_id: str) -> Optional[TenantRow]:
        """Return tenant from Postgres; fall back to JSON registry if absent."""
        row = self._pg_get(tenant_id)
        if row is not None:
            return row
        return self._json_get(tenant_id)

    def create(
        self,
        tenant_id: str,
        display_name: str,
        *,
        created_by: Optional[str] = None,
        migration_source: Optional[str] = None,
        migration_version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TenantRow:
        """Insert a new tenant row; raise ValueError if already exists."""
        now = _now_iso()
        meta_json = json.dumps(metadata or {})
        with self._engine.begin() as conn:
            existing = conn.execute(
                text("SELECT tenant_id FROM tenants WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            ).fetchone()
            if existing is not None:
                raise ValueError(f"Tenant already exists: {tenant_id}")

            conn.execute(
                text(
                    """
                    INSERT INTO tenants (
                        tenant_id, display_name, lifecycle_state,
                        created_at, updated_at, created_by,
                        metadata, canonical_version,
                        migration_source, migration_version
                    ) VALUES (
                        :tid, :name, 'active',
                        :now, :now, :created_by,
                        :meta, 1,
                        :msrc, :mver
                    )
                    """
                ),
                {
                    "tid": tenant_id,
                    "name": display_name,
                    "now": now,
                    "created_by": created_by,
                    "meta": meta_json,
                    "msrc": migration_source,
                    "mver": migration_version,
                },
            )
        result = self._pg_get(tenant_id)
        assert result is not None  # just inserted
        return result

    def upsert(
        self,
        tenant_id: str,
        display_name: str,
        *,
        lifecycle_state: str = "active",
        created_by: Optional[str] = None,
        migration_source: Optional[str] = None,
        migration_version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        original_created_at: Optional[str] = None,
    ) -> Tuple[TenantRow, bool]:
        """Insert or reconcile.  Returns (row, created)."""
        now = _now_iso()
        meta_json = json.dumps(metadata or {})
        with self._engine.begin() as conn:
            existing = conn.execute(
                text("SELECT tenant_id FROM tenants WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            ).fetchone()

            if existing is not None:
                # Reconcile: update tracking fields only.
                conn.execute(
                    text(
                        """
                        UPDATE tenants SET
                            last_reconciled_at = :now,
                            migration_source   = :msrc,
                            migration_version  = :mver,
                            updated_at         = :now
                        WHERE tenant_id = :tid
                        """
                    ),
                    {
                        "now": now,
                        "msrc": migration_source,
                        "mver": migration_version,
                        "tid": tenant_id,
                    },
                )
                row = self._pg_get(tenant_id)
                assert row is not None
                return row, False

            # New row: use original_created_at when available.
            created_at = original_created_at or now
            conn.execute(
                text(
                    """
                    INSERT INTO tenants (
                        tenant_id, display_name, lifecycle_state,
                        created_at, updated_at, created_by,
                        metadata, canonical_version,
                        last_reconciled_at,
                        migration_source, migration_version
                    ) VALUES (
                        :tid, :name, :state,
                        :cat, :now, :created_by,
                        :meta, 1,
                        :now,
                        :msrc, :mver
                    )
                    """
                ),
                {
                    "tid": tenant_id,
                    "name": display_name,
                    "state": lifecycle_state,
                    "cat": created_at,
                    "now": now,
                    "created_by": created_by,
                    "meta": meta_json,
                    "msrc": migration_source,
                    "mver": migration_version,
                },
            )
        row = self._pg_get(tenant_id)
        assert row is not None
        return row, True

    def list_all(self, *, include_archived: bool = False) -> List[TenantRow]:
        """Return all tenants from Postgres; optionally exclude archived."""
        if include_archived:
            states = list(_SUPPORTED_LIFECYCLE_STATES)
        else:
            states = [s for s in _SUPPORTED_LIFECYCLE_STATES if s != "archived"]

        # Use IN clause for cross-dialect compatibility (SQLite + Postgres).
        placeholders = ", ".join(f":s{i}" for i in range(len(states)))
        params: Dict[str, Any] = {f"s{i}": s for i, s in enumerate(states)}

        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    f"""
                    SELECT
                        tenant_id, display_name, lifecycle_state,
                        created_at, updated_at, created_by,
                        metadata, canonical_version,
                        last_reconciled_at, archived_at,
                        migration_source, migration_version
                    FROM tenants
                    WHERE lifecycle_state IN ({placeholders})
                    ORDER BY tenant_id
                    """
                ),
                params,
            ).fetchall()
        return [self._row_to_dataclass(r) for r in rows]

    def set_lifecycle_state(self, tenant_id: str, state: str) -> TenantRow:
        """UPDATE lifecycle_state; raise ValueError for unknown state, KeyError if not found."""
        if state not in _SUPPORTED_LIFECYCLE_STATES:
            raise ValueError(f"Unknown lifecycle state: {state!r}")
        now = _now_iso()
        archived_at = now if state == "archived" else None
        with self._engine.begin() as conn:
            result = conn.execute(
                text(
                    """
                    UPDATE tenants SET
                        lifecycle_state = :state,
                        updated_at = :now
                    WHERE tenant_id = :tid
                    """
                ),
                {"state": state, "now": now, "tid": tenant_id},
            )
            if result.rowcount == 0:
                raise KeyError(f"Tenant not found: {tenant_id}")
            if archived_at:
                conn.execute(
                    text("UPDATE tenants SET archived_at = :a WHERE tenant_id = :tid"),
                    {"a": archived_at, "tid": tenant_id},
                )
        row = self._pg_get(tenant_id)
        assert row is not None
        return row

    def credential_prefixes(self, tenant_id: str) -> List[str]:
        """Return active API key prefixes for a tenant (informational, for migration verification)."""
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT prefix FROM api_keys
                    WHERE tenant_id = :tid AND enabled IS TRUE
                    """
                ),
                {"tid": tenant_id},
            ).fetchall()
        return [r[0] for r in rows if r[0]]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _pg_get(self, tenant_id: str) -> Optional[TenantRow]:
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT
                        tenant_id, display_name, lifecycle_state,
                        created_at, updated_at, created_by,
                        metadata, canonical_version,
                        last_reconciled_at, archived_at,
                        migration_source, migration_version
                    FROM tenants
                    WHERE tenant_id = :tid
                    """
                ),
                {"tid": tenant_id},
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dataclass(row)

    def _json_get(self, tenant_id: str) -> Optional[TenantRow]:
        """Fallback: read from JSON registry during transition window."""
        try:
            from tools.tenants.registry import load_registry

            records = load_registry()
        except Exception:
            return None

        rec = records.get(tenant_id)
        if rec is None:
            return None

        return TenantRow(
            tenant_id=rec.tenant_id,
            display_name=rec.name,
            lifecycle_state=rec.status
            if rec.status in _SUPPORTED_LIFECYCLE_STATES
            else "active",
            created_at=rec.created_at,
            updated_at=rec.updated_at,
            created_by=None,
            metadata={},
            canonical_version=0,  # 0 signals JSON-sourced
            last_reconciled_at=None,
            archived_at=None,
            migration_source="json",
            migration_version=None,
        )

    @staticmethod
    def _row_to_dataclass(row: Any) -> TenantRow:
        """Map a SQL row tuple (by position) to TenantRow."""
        # metadata may come back as dict (psycopg3) or JSON string (SQLite).
        raw_meta = row[6]
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except (json.JSONDecodeError, TypeError):
                meta = {}
        elif isinstance(raw_meta, dict):
            meta = raw_meta
        else:
            meta = {}

        return TenantRow(
            tenant_id=row[0],
            display_name=row[1],
            lifecycle_state=row[2],
            created_at=row[3],
            updated_at=row[4],
            created_by=row[5],
            metadata=meta,
            canonical_version=row[7],
            last_reconciled_at=row[8],
            archived_at=row[9],
            migration_source=row[10],
            migration_version=row[11],
        )


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_tenant_repository() -> Optional[TenantRepository]:
    """Return a TenantRepository backed by the configured engine, or None on SQLite."""
    try:
        from api.db import get_engine

        engine = get_engine()
    except Exception:
        return None

    if engine.dialect.name != "postgresql":
        return None

    return TenantRepository(engine)
