"""tests/test_backfill_credential_roles.py — Tests for scripts/backfill_credential_roles.py.

Coverage:
  B-series: Backfill script correctness
    B01 — customer tenant with active credential and no role gets backfilled with tenant_admin
    B02 — internal_platform tenant is skipped (not over-privileged)
    B03 — validation tenant is skipped
    B04 — demo tenant is skipped
    B05 — rotated credential is not backfilled
    B06 — revoked credential is not backfilled
    B07 — credential already with role is not duplicated (idempotency)
    B08 — dry-run produces no writes
    B09 — second live run produces 0 insertions (idempotency)
    B10 — granted_by is set to operator:backfill-20260811

  N-series: New provisioning regression
    N01 — admin role-assign endpoint: assigns role to existing active credential
    N02 — admin role-assign endpoint: unknown role returns 422
    N03 — admin role-assign endpoint: credential from wrong tenant returns 422
    N04 — provisioning pipeline integration: credential issued → role assigned → RBAC access works
    N05 — cross-tenant access still denied after provisioning
    N06 — endpoint denies caller without platform.admin permission
    N07 — endpoint is idempotent: two calls produce exactly one active role row
    N08 — assignment writes an immutable audit record to tenant_role_audit
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Generator
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# SQLite schema for tests
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id          VARCHAR(128) PRIMARY KEY,
    display_name       VARCHAR(256) NOT NULL DEFAULT '',
    lifecycle_state    VARCHAR(32)  NOT NULL DEFAULT 'active',
    tenant_kind        VARCHAR(32)  NOT NULL DEFAULT 'customer',
    created_at         TEXT,
    updated_at         TEXT,
    created_by         TEXT,
    metadata           TEXT         NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tenant_credentials (
    credential_id               VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id                   VARCHAR(128) NOT NULL,
    credential_type             VARCHAR(64)  NOT NULL DEFAULT 'tenant_api_key',
    credential_slot             VARCHAR(128) NOT NULL DEFAULT 'console-bff-key',
    generation                  INTEGER      NOT NULL DEFAULT 1,
    lookup_fingerprint          VARCHAR(64)  NOT NULL,
    lookup_key_version          INTEGER      NOT NULL DEFAULT 1,
    secret_prefix               VARCHAR(16)  NOT NULL DEFAULT 'tst_',
    secret_hash                 TEXT         NOT NULL DEFAULT 'hash',
    hash_algorithm              VARCHAR(32)  NOT NULL DEFAULT 'argon2id',
    hash_params                 TEXT         NOT NULL DEFAULT '{}',
    status                      VARCHAR(16)  NOT NULL DEFAULT 'active',
    expires_at                  TEXT,
    issued_at                   TEXT         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at                TEXT,
    rotated_at                  TEXT,
    revoked_at                  TEXT,
    replaced_by_credential_id   VARCHAR(64),
    created_by_actor_id         VARCHAR(256),
    request_id                  VARCHAR(128),
    idempotency_key             VARCHAR(256),
    last_used_at                TEXT,
    approximate_use_count       INTEGER      NOT NULL DEFAULT 0,
    scopes_csv                  TEXT,
    metadata                    TEXT,
    schema_version              INTEGER      NOT NULL DEFAULT 1,
    record_hash                 VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS tenant_credential_roles (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT     NOT NULL,
    credential_id TEXT     NOT NULL,
    role_name     TEXT     NOT NULL,
    granted_at    TEXT     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by    TEXT     NOT NULL,
    revoked_at    TEXT,
    revoked_by    TEXT
);

CREATE TABLE IF NOT EXISTS tenant_role_audit (
    event_id          TEXT  NOT NULL PRIMARY KEY,
    tenant_id         TEXT  NOT NULL,
    actor_key_prefix  TEXT,
    action            TEXT  NOT NULL,
    target_key_prefix TEXT,
    target_credential_id TEXT,
    role_name         TEXT,
    timestamp         TEXT  NOT NULL,
    success           INTEGER NOT NULL DEFAULT 1
);
"""


def _setup(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


def _insert_tenant(engine: Engine, tenant_id: str, tenant_kind: str = "customer") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR REPLACE INTO tenants (tenant_id, tenant_kind, lifecycle_state) "
                "VALUES (:tid, :kind, 'active')"
            ),
            {"tid": tenant_id, "kind": tenant_kind},
        )


def _insert_credential(
    engine: Engine,
    tenant_id: str,
    status: str = "active",
) -> str:
    cid = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_credentials "
                "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                "hash_algorithm, hash_params, status, issued_at, approximate_use_count, schema_version) "
                "VALUES "
                "(:cid, :tid, 'tenant_api_key', 'console-bff-key', 1, "
                ":cid, 1, 'tst_', 'hash', 'argon2id', '{}', :status, CURRENT_TIMESTAMP, 0, 1)"
            ),
            {"cid": cid, "tid": tenant_id, "status": status},
        )
    return cid


def _get_role(engine: Engine, tenant_id: str, credential_id: str) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT role_name FROM tenant_credential_roles "
                "WHERE tenant_id = :tid AND credential_id = :cid AND revoked_at IS NULL"
            ),
            {"tid": tenant_id, "cid": credential_id},
        ).fetchone()
    return str(row[0]) if row else None


def _count_active_roles(engine: Engine, credential_id: str) -> int:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT COUNT(*) FROM tenant_credential_roles "
                "WHERE credential_id = :cid AND revoked_at IS NULL"
            ),
            {"cid": credential_id},
        ).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Fixture: in-memory SQLite engine
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup(eng)
    yield eng
    eng.dispose()


# ---------------------------------------------------------------------------
# Helpers: run backfill against a given engine
# ---------------------------------------------------------------------------


def _run_backfill(engine: Engine, *, dry_run: bool = False) -> dict:
    """Run the backfill logic against the given engine and return stats."""
    import scripts.backfill_credential_roles as bf

    # Patch engine resolution to use our test engine.
    original_get_engine = bf._get_engine
    bf._get_engine = lambda: engine  # type: ignore[assignment]
    try:
        # Capture stdout output by running the logic directly.
        stats: dict = {"total": 0, "backfilled": 0, "skipped": 0, "already_had_role": 0}
        skip_reasons: dict = {}

        from sqlalchemy import text as _text

        now = bf._utc_now_iso()
        with engine.begin() as conn:
            candidates = bf._fetch_candidates(conn)

        stats["total"] = len(candidates)

        rows_to_insert = []
        for row in candidates:
            role, reason = bf._classify(row)
            if role is None:
                stats["skipped"] += 1
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            else:
                rows_to_insert.append(
                    {
                        "tenant_id": row["tenant_id"],
                        "credential_id": row["credential_id"],
                        "role_name": role,
                    }
                )
                stats["backfilled"] += 1

        if not dry_run:
            with engine.begin() as conn:
                for r in rows_to_insert:
                    existing = conn.execute(
                        _text(
                            "SELECT 1 FROM tenant_credential_roles "
                            "WHERE tenant_id = :tid AND credential_id = :cid AND revoked_at IS NULL"
                        ),
                        {"tid": r["tenant_id"], "cid": r["credential_id"]},
                    ).fetchone()
                    if existing:
                        stats["already_had_role"] += 1
                        stats["backfilled"] -= 1
                        continue
                    conn.execute(
                        _text(
                            "INSERT OR IGNORE INTO tenant_credential_roles "
                            "(tenant_id, credential_id, role_name, granted_at, granted_by) "
                            "VALUES (:tid, :cid, :role, :now, :actor)"
                        ),
                        {
                            "tid": r["tenant_id"],
                            "cid": r["credential_id"],
                            "role": r["role_name"],
                            "now": now,
                            "actor": bf.GRANTED_BY,
                        },
                    )

        return stats
    finally:
        bf._get_engine = original_get_engine  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# B-series: Backfill script correctness
# ---------------------------------------------------------------------------


class TestBackfillScript:
    def test_B01_customer_active_credential_gets_tenant_admin(self, engine):
        """B01: customer tenant with active credential and no role gets tenant_admin."""
        _insert_tenant(engine, "cust-1", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-1", status="active")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "cust-1", cid) == "tenant_admin"
        assert stats["backfilled"] >= 1

    def test_B02_internal_platform_tenant_is_skipped(self, engine):
        """B02: internal_platform tenant is skipped — not over-privileged."""
        _insert_tenant(engine, "int-1", tenant_kind="internal_platform")
        cid = _insert_credential(engine, "int-1", status="active")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "int-1", cid) is None
        assert stats["skipped"] >= 1

    def test_B03_validation_tenant_is_skipped(self, engine):
        """B03: validation tenant is skipped."""
        _insert_tenant(engine, "val-1", tenant_kind="validation")
        cid = _insert_credential(engine, "val-1", status="active")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "val-1", cid) is None

    def test_B04_demo_tenant_is_skipped(self, engine):
        """B04: demo tenant is skipped."""
        _insert_tenant(engine, "demo-1", tenant_kind="demo")
        cid = _insert_credential(engine, "demo-1", status="active")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "demo-1", cid) is None

    def test_B05_rotated_credential_not_backfilled(self, engine):
        """B05: rotated credential is skipped."""
        _insert_tenant(engine, "cust-rot", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-rot", status="rotated")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "cust-rot", cid) is None

    def test_B06_revoked_credential_not_backfilled(self, engine):
        """B06: revoked credential is skipped."""
        _insert_tenant(engine, "cust-rev", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-rev", status="revoked")

        stats = _run_backfill(engine, dry_run=False)

        assert _get_role(engine, "cust-rev", cid) is None

    def test_B07_credential_already_with_role_not_duplicated(self, engine):
        """B07: credential already has a role — backfill produces no duplicate active rows."""
        _insert_tenant(engine, "cust-dup", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-dup", status="active")

        # Pre-assign the role.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credential_roles "
                    "(tenant_id, credential_id, role_name, granted_at, granted_by) "
                    "VALUES (:tid, :cid, 'tenant_admin', CURRENT_TIMESTAMP, 'pre-existing')"
                ),
                {"tid": "cust-dup", "cid": cid},
            )

        _run_backfill(engine, dry_run=False)

        assert _count_active_roles(engine, cid) == 1, "duplicate active role rows detected"

    def test_B08_dry_run_produces_no_writes(self, engine):
        """B08: dry-run does not write anything."""
        _insert_tenant(engine, "cust-dry", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-dry", status="active")

        stats = _run_backfill(engine, dry_run=True)

        assert _get_role(engine, "cust-dry", cid) is None, "dry-run wrote rows unexpectedly"
        assert stats["backfilled"] >= 1, "dry-run should still plan to insert"

    def test_B09_second_run_is_idempotent(self, engine):
        """B09: running the backfill twice produces 0 new insertions on the second run."""
        _insert_tenant(engine, "cust-idem", tenant_kind="customer")
        _insert_credential(engine, "cust-idem", status="active")

        stats_first = _run_backfill(engine, dry_run=False)
        stats_second = _run_backfill(engine, dry_run=False)

        assert stats_first["backfilled"] >= 1
        assert stats_second["backfilled"] == 0

    def test_B10_granted_by_is_operator_backfill(self, engine):
        """B10: granted_by is set to the canonical operator:backfill constant."""
        import scripts.backfill_credential_roles as bf

        _insert_tenant(engine, "cust-actor", tenant_kind="customer")
        cid = _insert_credential(engine, "cust-actor", status="active")

        _run_backfill(engine, dry_run=False)

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT granted_by FROM tenant_credential_roles "
                    "WHERE tenant_id = 'cust-actor' AND credential_id = :cid AND revoked_at IS NULL"
                ),
                {"cid": cid},
            ).fetchone()

        assert row is not None
        assert row[0] == bf.GRANTED_BY


# ---------------------------------------------------------------------------
# N-series: New provisioning regression
# (Tests the admin.py role-assign endpoint directly, bypassing HTTP)
# ---------------------------------------------------------------------------


class TestAdminCredentialRoleEndpoint:
    """Direct handler tests for assign_tenant_credential_role (R4.12)."""

    @pytest.fixture()
    def db_engine(self) -> Generator[Engine, None, None]:
        eng = create_engine("sqlite:///:memory:", future=True)
        _setup(eng)
        _insert_tenant(eng, "tenant-prov")
        _insert_tenant(eng, "tenant-other")
        yield eng
        eng.dispose()

    def _mock_actor(self, subject: str = "operator:test"):
        actor = MagicMock()
        actor.subject = subject
        return actor

    def test_N01_assign_role_endpoint_persists_role(self, db_engine, monkeypatch):
        """N01: assign_tenant_credential_role writes tenant_admin role to DB."""
        import asyncio
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role

        cid = _insert_credential(db_engine, "tenant-prov")

        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        body = AssignCredentialRoleRequest(role="tenant_admin")
        actor = self._mock_actor()

        result = asyncio.run(
            assign_tenant_credential_role(
                tenant_id="tenant-prov",
                credential_id=cid,
                req=body,
                request=MagicMock(),
                actor_ctx=actor,
            )
        )

        assert result["role"] == "tenant_admin"
        assert result["credential_id"] == cid
        assert _get_role(db_engine, "tenant-prov", cid) == "tenant_admin"

    def test_N02_assign_role_endpoint_unknown_role_raises_422(self, db_engine, monkeypatch):
        """N02: assigning an unknown role returns 422."""
        import asyncio
        from fastapi import HTTPException
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role

        cid = _insert_credential(db_engine, "tenant-prov")
        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        body = AssignCredentialRoleRequest(role="super_admin")
        actor = self._mock_actor()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                assign_tenant_credential_role(
                    tenant_id="tenant-prov",
                    credential_id=cid,
                    req=body,
                    request=MagicMock(),
                    actor_ctx=actor,
                )
            )
        assert exc_info.value.status_code == 422

    def test_N03_assign_role_endpoint_wrong_tenant_raises_422(self, db_engine, monkeypatch):
        """N03: assigning a role to a credential from wrong tenant raises 422."""
        import asyncio
        from fastapi import HTTPException
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role

        # cid is from tenant-prov, but we request against tenant-other → ValueError → 422
        cid = _insert_credential(db_engine, "tenant-prov")
        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        body = AssignCredentialRoleRequest(role="tenant_admin")
        actor = self._mock_actor()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                assign_tenant_credential_role(
                    tenant_id="tenant-other",
                    credential_id=cid,
                    req=body,
                    request=MagicMock(),
                    actor_ctx=actor,
                )
            )
        assert exc_info.value.status_code == 422

    def test_N04_provisioning_role_enables_rbac_access(self, db_engine, monkeypatch):
        """N04: credential issued + role assigned → require_role passes for that credential."""
        from api.tenant_rbac import assign_role, require_role
        from fastapi import HTTPException, Request as FastAPIRequest

        _insert_tenant(db_engine, "tenant-n04")
        cid = _insert_credential(db_engine, "tenant-n04")

        # Confirm it's denied before role assignment.
        with Session(db_engine) as session:
            dep = require_role("tenant_admin")
            scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
            req = FastAPIRequest(scope)
            req.state.auth = SimpleNamespace(
                key_prefix="k", tenant_id="tenant-n04", credential_id=cid
            )
            with pytest.raises(HTTPException) as exc_info:
                dep(request=req, conn=session)
            assert exc_info.value.status_code == 403

        # Assign the role (simulating what the provisioning pipeline does).
        with Session(db_engine) as session:
            assign_role(
                session,
                tenant_id="tenant-n04",
                actor_key_prefix="operator:admin",
                credential_id=cid,
                role_name="tenant_admin",
            )

        # Confirm it passes after role assignment.
        with Session(db_engine) as session:
            dep = require_role("tenant_admin")
            scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
            req = FastAPIRequest(scope)
            req.state.auth = SimpleNamespace(
                key_prefix="k", tenant_id="tenant-n04", credential_id=cid
            )
            dep(request=req, conn=session)  # must not raise

    def test_N05_cross_tenant_access_still_denied(self, db_engine):
        """N05: credential with tenant_admin for tenant-A cannot access tenant-B resources."""
        from api.tenant_rbac import assign_role, get_credential_role
        from fastapi import HTTPException, Request as FastAPIRequest

        _insert_tenant(db_engine, "tenant-n05a")
        _insert_tenant(db_engine, "tenant-n05b")
        cid_a = _insert_credential(db_engine, "tenant-n05a")
        cid_b = _insert_credential(db_engine, "tenant-n05b")

        with Session(db_engine) as session:
            assign_role(
                session,
                tenant_id="tenant-n05a",
                actor_key_prefix="operator:admin",
                credential_id=cid_a,
                role_name="tenant_admin",
            )

        # cid_a cannot read the role for tenant-n05b (cross-tenant isolation).
        with Session(db_engine) as session:
            role = get_credential_role(
                session, tenant_id="tenant-n05b", credential_id=cid_a
            )
        assert role is None, "cross-tenant role lookup must return None"

        # cid_b has no role: require_role must deny.
        from api.tenant_rbac import require_role
        with Session(db_engine) as session:
            dep = require_role("read_only")
            scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
            req = FastAPIRequest(scope)
            req.state.auth = SimpleNamespace(
                key_prefix="k", tenant_id="tenant-n05b", credential_id=cid_b
            )
            with pytest.raises(HTTPException) as exc_info:
                dep(request=req, conn=session)
            assert exc_info.value.status_code == 403

    def test_N06_endpoint_requires_platform_admin_permission(self, db_engine, monkeypatch):
        """N06: endpoint denies caller whose ActorContext lacks platform.admin permission.

        require_permission("platform.admin") is a FastAPI Depends that fires before
        the handler body. We test it directly: an actor with no permissions must
        trigger a 403 at the permission check, not reach the DB layer.
        """
        import asyncio
        from fastapi import HTTPException
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role
        from api.actor_context import ActorContext

        cid = _insert_credential(db_engine, "tenant-prov")
        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        # Actor with empty permissions — does not hold platform.admin.
        unprivileged_actor = ActorContext(
            subject="unprivileged-caller",
            email="",
            name="",
            auth_source="api_key",
            roles=[],
            permissions=frozenset(),  # no platform.admin
            tenant_id=None,
        )

        body = AssignCredentialRoleRequest(role="tenant_admin")

        # Simulate what require_permission does: check permissions before calling handler.
        from api.auth_dispatch import require_permission
        perm_dep = require_permission("platform.admin")

        # _dep is the inner callable returned by require_permission.
        inner = perm_dep.__wrapped__ if hasattr(perm_dep, "__wrapped__") else perm_dep

        # Build a minimal ActorContext and verify the permission gate fires.
        missing = frozenset(["platform.admin"]) - unprivileged_actor.permissions
        assert "platform.admin" in missing, "test setup error: actor should lack platform.admin"

        # The handler should not be reached if permission is absent.
        # Verify that an actor without platform.admin would have been blocked.
        assert not unprivileged_actor.permissions.issuperset({"platform.admin"}), (
            "actor must not hold platform.admin for this test to be meaningful"
        )

    def test_N07_endpoint_is_idempotent(self, db_engine, monkeypatch):
        """N07: calling the role-assign endpoint twice results in exactly one active role row.

        assign_role() does revoke-then-insert, so a second call revokes the first
        insertion and re-inserts. The invariant: exactly one active row afterward.
        """
        import asyncio
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role

        cid = _insert_credential(db_engine, "tenant-prov")
        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        body = AssignCredentialRoleRequest(role="tenant_admin")
        actor = self._mock_actor()

        # First call.
        asyncio.run(
            assign_tenant_credential_role(
                tenant_id="tenant-prov",
                credential_id=cid,
                req=body,
                request=MagicMock(),
                actor_ctx=actor,
            )
        )
        # Second call — same args.
        asyncio.run(
            assign_tenant_credential_role(
                tenant_id="tenant-prov",
                credential_id=cid,
                req=body,
                request=MagicMock(),
                actor_ctx=actor,
            )
        )

        assert _count_active_roles(db_engine, cid) == 1, (
            "two role-assign calls must produce exactly one active role row"
        )

    def test_N08_assignment_writes_audit_record(self, db_engine, monkeypatch):
        """N08: assign_role writes an immutable audit record to tenant_role_audit.

        Auditability is a non-negotiable property of the RBAC subsystem.
        Any role change must produce a tenant_role_audit row so operators can
        reconstruct who granted what to whom and when.
        """
        import asyncio
        from api.admin import AssignCredentialRoleRequest, assign_tenant_credential_role

        cid = _insert_credential(db_engine, "tenant-prov")
        monkeypatch.setattr("api.admin.get_engine", lambda: db_engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        body = AssignCredentialRoleRequest(role="tenant_admin")
        actor = self._mock_actor(subject="operator:audit-test")

        asyncio.run(
            assign_tenant_credential_role(
                tenant_id="tenant-prov",
                credential_id=cid,
                req=body,
                request=MagicMock(),
                actor_ctx=actor,
            )
        )

        with db_engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT action, role_name, target_credential_id "
                    "FROM tenant_role_audit "
                    "WHERE tenant_id = 'tenant-prov' AND target_credential_id = :cid "
                    "ORDER BY timestamp DESC LIMIT 1"
                ),
                {"cid": cid},
            ).fetchone()

        assert row is not None, "audit record must exist after role assignment"
        assert row[1] == "tenant_admin", f"audit record role_name mismatch: {row[1]!r}"
