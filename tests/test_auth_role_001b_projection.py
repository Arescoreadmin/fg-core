"""AUTH-ROLE-001B: Identity projection outbox tests.

Test series:
  A — Migration structure
  B — Enqueue helper (projection_outbox.py)
  C — Worker: success, stale-write, failure / backoff
  D — Auth0ManagementClient.update_user_app_metadata + get_user_app_metadata
  E — Invariants: no credentials stored, provider filter
"""

from __future__ import annotations

import json
import pathlib
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as SASession

from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
)
from admin_gateway.identity.projection_outbox import enqueue_projection
from admin_gateway.identity.projection_worker import run_projection_pass

# ---------------------------------------------------------------------------
# Constants and paths
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MIGRATION_0184 = (
    _REPO_ROOT / "migrations" / "postgres" / "0184_identity_projection_outbox.sql"
)

TENANT = "tenant-test"
PROVIDER = "auth0"
SUBJECT = "auth0|user-abc123"
PRINCIPAL_ID = str(uuid.uuid4())
MEMBERSHIP_ID = str(uuid.uuid4())

# ---------------------------------------------------------------------------
# SQLite schema for testing (mirrors the postgres migration, SQLite-compatible)
# ---------------------------------------------------------------------------

_OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS identity_projection_outbox (
    id                  TEXT    PRIMARY KEY,
    principal_id        TEXT    NOT NULL,
    membership_id       TEXT    NOT NULL,
    tenant_id           TEXT    NOT NULL,
    provider            TEXT    NOT NULL,
    provider_subject    TEXT    NOT NULL,
    roles               TEXT    NOT NULL,
    projection_revision INTEGER NOT NULL,
    status              TEXT    NOT NULL DEFAULT 'pending',
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    last_error_code     TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    processed_at        TEXT
)
"""


def _make_engine():
    engine = create_engine("sqlite:///:memory:", echo=False)
    with engine.begin() as conn:
        conn.execute(text(_OUTBOX_SCHEMA))
    return engine


@pytest.fixture()
def engine():
    return _make_engine()


@pytest.fixture()
def db(engine):
    """Yield a SQLAlchemy Session backed by the in-memory SQLite engine."""
    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_auth0_client() -> Auth0ManagementClient:
    from admin_gateway.identity.auth0_config import Auth0Config

    config = Auth0Config(
        domain="example.us.auth0.com",
        audience="https://api.example.com/",
        client_id="test-client",
        client_secret="test-secret",
        mgmt_audience="https://example.us.auth0.com/api/v2/",
        mgmt_client_id="mgmt-client",
        mgmt_client_secret="mgmt-secret",
        callback_url="https://app.example.com/callback",
        logout_return_url="https://app.example.com/",
        org_login_required=True,
        allowed_connection_strategies=(),
    )
    return Auth0ManagementClient(config=config)


def _count_rows(db: SASession, status: str | None = None) -> int:
    if status:
        row = db.execute(
            text("SELECT COUNT(*) FROM identity_projection_outbox WHERE status = :s"),
            {"s": status},
        ).fetchone()
    else:
        row = db.execute(
            text("SELECT COUNT(*) FROM identity_projection_outbox")
        ).fetchone()
    return int(row[0]) if row else 0  # type: ignore[index]


def _fetch_one(db: SASession) -> Any:
    return db.execute(
        text("SELECT * FROM identity_projection_outbox LIMIT 1")
    ).fetchone()


# ---------------------------------------------------------------------------
# A — Migration structure
# ---------------------------------------------------------------------------


def test_A1_migration_0184_file_exists() -> None:
    assert _MIGRATION_0184.exists(), (
        f"AUTH-ROLE-001B migration missing at expected path: {_MIGRATION_0184}"
    )


def test_A2_migration_filename_convention() -> None:
    assert _MIGRATION_0184.name == "0184_identity_projection_outbox.sql"


def test_A3_migration_contains_rls_statements() -> None:
    content = _MIGRATION_0184.read_text()
    assert "ENABLE ROW LEVEL SECURITY" in content
    assert "FORCE ROW LEVEL SECURITY" in content
    assert "identity_projection_outbox_tenant_isolation" in content


def test_A4_migration_has_status_check_constraint() -> None:
    content = _MIGRATION_0184.read_text()
    for status in ("pending", "processing", "done", "failed"):
        assert status in content


def test_A5_migration_no_credentials_stored() -> None:
    content = _MIGRATION_0184.read_text()
    for forbidden in ("access_token", "client_secret", "id_token", "refresh_token"):
        assert forbidden not in content.lower(), (
            f"Migration must not reference credential field: {forbidden}"
        )


def test_A6_migration_defines_worker_index() -> None:
    content = _MIGRATION_0184.read_text()
    assert "ix_identity_projection_outbox_pending" in content


# ---------------------------------------------------------------------------
# B — Enqueue helper
# ---------------------------------------------------------------------------


def test_B1_enqueue_inserts_row_with_correct_fields(db: SASession) -> None:
    enqueue_projection(
        db,
        membership_id=MEMBERSHIP_ID,
        principal_id=PRINCIPAL_ID,
        tenant_id=TENANT,
        provider=PROVIDER,
        provider_subject=SUBJECT,
        roles=["admin"],
        projection_revision=7,
    )
    db.flush()

    assert _count_rows(db) == 1
    row = _fetch_one(db)
    assert row is not None
    assert str(row.principal_id) == PRINCIPAL_ID
    assert row.membership_id == MEMBERSHIP_ID
    assert row.tenant_id == TENANT
    assert row.provider == PROVIDER
    assert row.provider_subject == SUBJECT
    roles = json.loads(row.roles) if isinstance(row.roles, str) else row.roles
    assert roles == ["admin"]
    assert int(row.projection_revision) == 7
    assert row.status == "pending"
    assert int(row.attempt_count) == 0


def test_B2_enqueue_multiple_revisions_inserts_separate_rows(db: SASession) -> None:
    for rev in (1, 2, 3):
        enqueue_projection(
            db,
            membership_id=MEMBERSHIP_ID,
            principal_id=PRINCIPAL_ID,
            tenant_id=TENANT,
            provider=PROVIDER,
            provider_subject=SUBJECT,
            roles=["user"],
            projection_revision=rev,
        )
    db.flush()
    assert _count_rows(db) == 3


def test_B3_enqueue_roles_list_is_serialized(db: SASession) -> None:
    enqueue_projection(
        db,
        membership_id=MEMBERSHIP_ID,
        principal_id=PRINCIPAL_ID,
        tenant_id=TENANT,
        provider=PROVIDER,
        provider_subject=SUBJECT,
        roles=["admin", "viewer"],
        projection_revision=1,
    )
    db.flush()
    row = _fetch_one(db)
    parsed = json.loads(row.roles) if isinstance(row.roles, str) else row.roles
    assert parsed == ["admin", "viewer"]


def test_B4_enqueue_empty_roles(db: SASession) -> None:
    enqueue_projection(
        db,
        membership_id=MEMBERSHIP_ID,
        principal_id=PRINCIPAL_ID,
        tenant_id=TENANT,
        provider=PROVIDER,
        provider_subject=SUBJECT,
        roles=[],
        projection_revision=1,
    )
    db.flush()
    row = _fetch_one(db)
    parsed = json.loads(row.roles) if isinstance(row.roles, str) else row.roles
    assert parsed == []


# ---------------------------------------------------------------------------
# C — Worker
# ---------------------------------------------------------------------------


def _seed_row(
    db: SASession,
    *,
    status: str = "pending",
    projection_revision: int = 5,
    attempt_count: int = 0,
    next_attempt_at: str = "2000-01-01T00:00:00",
    roles: list[str] | None = None,
) -> str:
    row_id = str(uuid.uuid4())
    db.execute(
        text(
            """
            INSERT INTO identity_projection_outbox
                (id, principal_id, membership_id, tenant_id, provider,
                 provider_subject, roles, projection_revision, status,
                 attempt_count, next_attempt_at)
            VALUES
                (:id, :pid, :mid, :tid, :prov, :sub, :roles, :rev,
                 :status, :ac, :naa)
            """
        ),
        {
            "id": row_id,
            "pid": PRINCIPAL_ID,
            "mid": MEMBERSHIP_ID,
            "tid": TENANT,
            "prov": PROVIDER,
            "sub": SUBJECT,
            "roles": json.dumps(roles or ["admin"]),
            "rev": projection_revision,
            "status": status,
            "ac": attempt_count,
            "naa": next_attempt_at,
        },
    )
    return row_id


def _make_mock_client(*, existing_revision: int | None = None) -> MagicMock:
    client = MagicMock(spec=Auth0ManagementClient)
    client.hash_subject = Auth0ManagementClient.hash_subject
    existing_meta: dict[str, Any] = {}
    if existing_revision is not None:
        existing_meta = {"projection_revision": existing_revision}
    client.get_user_app_metadata.return_value = existing_meta
    client.update_user_app_metadata.return_value = None
    return client


def test_C1_success_marks_done(db: SASession) -> None:
    _seed_row(db, projection_revision=5)
    db.flush()

    client = _make_mock_client(existing_revision=None)
    processed = run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    assert processed == 1
    row = _fetch_one(db)
    assert row.status == "done"
    assert row.processed_at is not None
    client.update_user_app_metadata.assert_called_once_with(
        SUBJECT,
        principal_id=PRINCIPAL_ID,
        roles=["admin"],
        projection_revision=5,
    )


def test_C2_stale_revision_skips_write_marks_done(db: SASession) -> None:
    """Incoming revision <= existing revision → skip write, mark done."""
    _seed_row(db, projection_revision=3)
    db.flush()

    client = _make_mock_client(existing_revision=10)
    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "done"
    client.update_user_app_metadata.assert_not_called()


def test_C3_duplicate_revision_same_as_existing_skips(db: SASession) -> None:
    """Incoming revision == existing revision → treat as done, no double-apply."""
    _seed_row(db, projection_revision=5)
    db.flush()

    client = _make_mock_client(existing_revision=5)
    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "done"
    client.update_user_app_metadata.assert_not_called()


def test_C4_failure_leaves_retryable(db: SASession) -> None:
    """Auth0 API failure → row stays pending with incremented attempt_count."""
    _seed_row(db, projection_revision=5, attempt_count=0)
    db.flush()

    client = _make_mock_client(existing_revision=None)
    client.update_user_app_metadata.side_effect = Auth0ManagementError(
        "MGMT_PATCH_FAILED:503", 503
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "pending"
    assert row.last_error_code is not None
    assert "MGMT_PATCH_FAILED" in row.last_error_code


def test_C5_failure_sets_last_error_code(db: SASession) -> None:
    _seed_row(db, projection_revision=5)
    db.flush()

    client = _make_mock_client()
    client.update_user_app_metadata.side_effect = Auth0ManagementError(
        "CONNECTION_TIMEOUT", 0
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.last_error_code == "CONNECTION_TIMEOUT"


def test_C6_newer_revision_overwrites_older(db: SASession) -> None:
    """Incoming revision > existing → write is applied."""
    _seed_row(db, projection_revision=10)
    db.flush()

    client = _make_mock_client(existing_revision=3)
    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "done"
    client.update_user_app_metadata.assert_called_once()


def test_C7_backoff_schedule_is_increasing() -> None:
    delays = []
    for attempt in range(4):
        from admin_gateway.identity.projection_worker import _BACKOFF_SECONDS

        delays.append(_BACKOFF_SECONDS[min(attempt, len(_BACKOFF_SECONDS) - 1)])
    # Each backoff step must be >= the previous
    for i in range(1, len(delays)):
        assert delays[i] >= delays[i - 1]


def test_C8_empty_outbox_returns_zero(db: SASession) -> None:
    client = _make_mock_client()
    result = run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)
    assert result == 0


# ---------------------------------------------------------------------------
# D — Auth0ManagementClient.update_user_app_metadata
# ---------------------------------------------------------------------------


def test_D1_update_user_app_metadata_patches_correct_fields() -> None:
    import httpx

    client = _make_auth0_client()
    client._token = "test-token"  # skip token acquisition

    captured: list[Any] = []

    def _fake_patch(url, *, headers, json, timeout):
        captured.append({"url": url, "json": json, "headers": headers})
        response = MagicMock()
        response.status_code = 200
        response.content = b'{"updated": true}'
        response.json.return_value = {"updated": True}
        return response

    with patch.object(httpx, "patch", _fake_patch):
        client.update_user_app_metadata(
            "auth0|user-xyz",
            principal_id=PRINCIPAL_ID,
            roles=["admin"],
            projection_revision=42,
        )

    assert len(captured) == 1
    payload = captured[0]["json"]
    meta = payload["app_metadata"]
    assert meta["principal_id"] == PRINCIPAL_ID
    assert meta["roles"] == ["admin"]
    assert meta["projection_revision"] == 42


def test_D2_update_user_app_metadata_retries_on_401() -> None:
    import httpx

    client = _make_auth0_client()
    client._token = "expired-token"

    call_count = 0

    def _fake_patch(url, *, headers, json, timeout):
        nonlocal call_count
        call_count += 1
        response = MagicMock()
        if call_count == 1:
            response.status_code = 401
            response.content = b""
        else:
            response.status_code = 200
            response.content = b'{"ok": true}'
            response.json.return_value = {"ok": True}
        return response

    def _fake_post(url, *, json, timeout):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"access_token": "new-token"}
        return response

    with (
        patch.object(httpx, "patch", _fake_patch),
        patch.object(httpx, "post", _fake_post),
    ):
        client.update_user_app_metadata(
            "auth0|user-xyz",
            principal_id=PRINCIPAL_ID,
            roles=["user"],
            projection_revision=1,
        )

    assert call_count == 2  # one 401 + one success


def test_D3_update_user_app_metadata_raises_on_non_200() -> None:
    import httpx

    client = _make_auth0_client()
    client._token = "test-token"

    def _fake_patch(url, *, headers, json, timeout):
        response = MagicMock()
        response.status_code = 500
        response.content = b"Internal error"
        return response

    with patch.object(httpx, "patch", _fake_patch):
        with pytest.raises(Auth0ManagementError) as exc_info:
            client.update_user_app_metadata(
                "auth0|user-xyz",
                principal_id=PRINCIPAL_ID,
                roles=["admin"],
                projection_revision=1,
            )
    assert "500" in exc_info.value.code


def test_D4_get_user_app_metadata_returns_dict() -> None:
    import httpx

    client = _make_auth0_client()
    client._token = "test-token"

    meta = {"principal_id": PRINCIPAL_ID, "roles": ["admin"], "projection_revision": 3}

    def _fake_get(url, *, headers, params, timeout):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"app_metadata": meta}
        return response

    with patch.object(httpx, "get", _fake_get):
        result = client.get_user_app_metadata("auth0|user-xyz")

    assert result == meta


def test_D5_get_user_app_metadata_returns_empty_on_404() -> None:
    import httpx

    client = _make_auth0_client()
    client._token = "test-token"

    def _fake_get(url, *, headers, params, timeout):
        response = MagicMock()
        response.status_code = 404
        response.json.return_value = {}
        return response

    with patch.object(httpx, "get", _fake_get):
        result = client.get_user_app_metadata("auth0|nonexistent")

    assert result == {}


# ---------------------------------------------------------------------------
# E — Invariants
# ---------------------------------------------------------------------------


def test_E1_outbox_row_contains_no_credential_fields(db: SASession) -> None:
    """Verify that the outbox schema has no credential columns."""
    enqueue_projection(
        db,
        membership_id=MEMBERSHIP_ID,
        principal_id=PRINCIPAL_ID,
        tenant_id=TENANT,
        provider=PROVIDER,
        provider_subject=SUBJECT,
        roles=["admin"],
        projection_revision=1,
    )
    db.flush()

    row = _fetch_one(db)
    row_dict = dict(zip(row._fields, row))  # type: ignore[attr-defined]
    forbidden_fields = {
        "access_token",
        "client_secret",
        "id_token",
        "refresh_token",
        "token",
        "password",
        "credential",
    }
    for field in row_dict:
        assert field.lower() not in forbidden_fields, (
            f"Forbidden credential field found in outbox row: {field}"
        )


def test_E2_projection_revision_equals_membership_version() -> None:
    """Verify the worker uses projection_revision, not a separate sequence."""
    from admin_gateway.identity.projection_worker import _SELECT_PENDING_SQL

    # The query must select projection_revision (not a separate counter)
    assert "projection_revision" in str(_SELECT_PENDING_SQL)


def test_E3_migration_rls_table_registered_in_db_migrations() -> None:
    """Verify identity_projection_outbox is in assert_tenant_rls expected tables."""
    db_migrations_path = _REPO_ROOT / "api" / "db_migrations.py"
    content = db_migrations_path.read_text()
    assert "identity_projection_outbox" in content
