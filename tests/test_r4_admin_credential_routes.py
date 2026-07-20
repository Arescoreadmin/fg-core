# tests/test_r4_admin_credential_routes.py
"""
R4.6 — Admin credential route handler tests.

Calls the FastAPI handler functions directly (bypassing the HTTP/auth stack)
to verify business logic, error mapping, and response shape.

Skipped if FastAPI is not installed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

fastapi = pytest.importorskip("fastapi")

from argon2 import PasswordHasher  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402

import api.credential_authority as ca  # noqa: E402
from api.admin import (  # noqa: E402
    IssueCredentialRequest,
    RotateCredentialRequest,
    RevokeCredentialRequest,
    get_tenant_credential,
    issue_tenant_credential,
    list_tenant_credential_events,
    list_tenant_credentials,
    revoke_tenant_credential,
    rotate_tenant_credential,
)
from api.credential_authority import issue_credential  # noqa: E402

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id          VARCHAR(128) PRIMARY KEY,
    display_name       VARCHAR(256) NOT NULL DEFAULT '',
    lifecycle_state    VARCHAR(32)  NOT NULL DEFAULT 'active',
    created_at         TEXT,
    updated_at         TEXT,
    created_by         TEXT,
    metadata           TEXT         NOT NULL DEFAULT '{}',
    canonical_version  INTEGER      NOT NULL DEFAULT 1,
    last_reconciled_at TEXT,
    archived_at        TEXT,
    migration_source   TEXT,
    migration_version  TEXT
);

CREATE TABLE IF NOT EXISTS credential_slots (
    tenant_id           VARCHAR(128) NOT NULL,
    credential_type     VARCHAR(64)  NOT NULL,
    credential_slot     VARCHAR(128) NOT NULL,
    current_generation  INTEGER      NOT NULL DEFAULT 0,
    rotation_policy     VARCHAR(32)  NOT NULL DEFAULT 'immediate',
    max_overlap_count   INTEGER      NOT NULL DEFAULT 1,
    created_at          TEXT,
    updated_at          TEXT,
    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);

CREATE TABLE IF NOT EXISTS tenant_credential_events (
    event_id          VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id         VARCHAR(128) NOT NULL,
    credential_id     VARCHAR(64),
    credential_type   VARCHAR(64),
    credential_slot   VARCHAR(128),
    generation        INTEGER,
    event_type        VARCHAR(64)  NOT NULL,
    actor_id          VARCHAR(256),
    request_id        VARCHAR(128),
    occurred_at       TEXT         NOT NULL,
    outcome           VARCHAR(16)  NOT NULL DEFAULT 'success',
    failure_reason    TEXT,
    metadata          TEXT,
    schema_version    INTEGER      NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tenant_credentials (
    credential_id               VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id                   VARCHAR(128) NOT NULL,
    credential_type             VARCHAR(64)  NOT NULL,
    credential_slot             VARCHAR(128) NOT NULL,
    generation                  INTEGER      NOT NULL DEFAULT 1,
    lookup_fingerprint          VARCHAR(64)  NOT NULL,
    lookup_key_version          INTEGER      NOT NULL DEFAULT 1,
    secret_prefix               VARCHAR(16)  NOT NULL,
    secret_hash                 TEXT         NOT NULL,
    hash_algorithm              VARCHAR(32)  NOT NULL DEFAULT 'argon2id',
    hash_params                 TEXT         NOT NULL,
    status                      VARCHAR(16)  NOT NULL DEFAULT 'active',
    expires_at                  TEXT,
    issued_at                   TEXT         NOT NULL,
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
    record_hash                 VARCHAR(64),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_tc_slot_generation
    ON tenant_credentials (tenant_id, credential_type, credential_slot, generation);
CREATE INDEX IF NOT EXISTS ix_tc_lookup_fingerprint
    ON tenant_credentials (lookup_fingerprint);
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "r4.6-test-pepper")


@pytest.fixture()
def engine() -> Engine:
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with e.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
        conn.execute(
            text("INSERT INTO tenants (tenant_id, display_name) VALUES (:tid, :name)"),
            {"tid": "tenant-alpha", "name": "Alpha"},
        )
    return e


def _mock_request() -> MagicMock:
    return MagicMock()


def _mock_actor() -> MagicMock:
    actor = MagicMock()
    actor.subject = "test-actor"
    return actor


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# A — Issue
# ---------------------------------------------------------------------------


class TestA_Issue:
    def test_issue_returns_dict_with_secret(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        result = _run(
            issue_tenant_credential(
                tenant_id="tenant-alpha",
                req=IssueCredentialRequest(
                    credential_slot="prod", credential_type="tenant_api_key"
                ),
                request=_mock_request(),
                actor_ctx=_mock_actor(),
            )
        )
        assert result["status"] == "active"
        assert result["plaintext_secret"] is not None
        assert result["plaintext_secret"].startswith("fgk.")

    def test_issue_unknown_tenant_raises_404(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        with pytest.raises(HTTPException) as exc:
            _run(
                issue_tenant_credential(
                    tenant_id="ghost",
                    req=IssueCredentialRequest(
                        credential_slot="prod", credential_type="tenant_api_key"
                    ),
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
        assert exc.value.status_code == 404

    def test_issue_bad_type_raises_400(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        with pytest.raises(HTTPException) as exc:
            _run(
                issue_tenant_credential(
                    tenant_id="tenant-alpha",
                    req=IssueCredentialRequest(
                        credential_slot="prod", credential_type="bad_type"
                    ),
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
        assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# B — List
# ---------------------------------------------------------------------------


class TestB_List:
    def test_list_returns_credentials(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            list_tenant_credentials(
                tenant_id="tenant-alpha",
                request=_mock_request(),
                actor_ctx=_mock_actor(),
                credential_type=None,
                status=None,
                limit=50,
            )
        )
        assert len(result["credentials"]) == 1
        assert result["credentials"][0]["credential_slot"] == "prod"

    def test_list_empty_for_no_credentials(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        result = _run(
            list_tenant_credentials(
                tenant_id="tenant-alpha",
                request=_mock_request(),
                actor_ctx=_mock_actor(),
                credential_type=None,
                status=None,
                limit=50,
            )
        )
        assert result["credentials"] == []


# ---------------------------------------------------------------------------
# C — Get
# ---------------------------------------------------------------------------


class TestC_Get:
    def test_get_returns_credential(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issued = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            get_tenant_credential(
                tenant_id="tenant-alpha",
                credential_id=issued.record.credential_id,
                request=_mock_request(),
                actor_ctx=_mock_actor(),
            )
        )
        assert result["credential_id"] == issued.record.credential_id
        assert result["status"] == "active"

    def test_get_unknown_raises_404(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        with pytest.raises(HTTPException) as exc:
            _run(
                get_tenant_credential(
                    tenant_id="tenant-alpha",
                    credential_id="00000000-0000-0000-0000-000000000000",
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
        assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# D — Rotate
# ---------------------------------------------------------------------------


class TestD_Rotate:
    def test_rotate_returns_generation_2(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issued = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            rotate_tenant_credential(
                tenant_id="tenant-alpha",
                credential_id=issued.record.credential_id,
                req=RotateCredentialRequest(),
                request=_mock_request(),
                actor_ctx=_mock_actor(),
            )
        )
        assert result["generation"] == 2
        assert result["plaintext_secret"] is not None

    def test_rotate_unknown_raises_404(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        with pytest.raises(HTTPException) as exc:
            _run(
                rotate_tenant_credential(
                    tenant_id="tenant-alpha",
                    credential_id="00000000-0000-0000-0000-000000000000",
                    req=RotateCredentialRequest(),
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
        assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# E — Revoke
# ---------------------------------------------------------------------------


class TestE_Revoke:
    def test_revoke_returns_revoked_status(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issued = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            revoke_tenant_credential(
                tenant_id="tenant-alpha",
                credential_id=issued.record.credential_id,
                req=RevokeCredentialRequest(reason="test cleanup"),
                request=_mock_request(),
                actor_ctx=_mock_actor(),
            )
        )
        assert result["status"] == "revoked"

    def test_revoke_idempotent(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issued = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        for _ in range(2):
            result = _run(
                revoke_tenant_credential(
                    tenant_id="tenant-alpha",
                    credential_id=issued.record.credential_id,
                    req=RevokeCredentialRequest(reason="test"),
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
            assert result["status"] == "revoked"

    def test_revoke_unknown_raises_404(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        with pytest.raises(HTTPException) as exc:
            _run(
                revoke_tenant_credential(
                    tenant_id="tenant-alpha",
                    credential_id="00000000-0000-0000-0000-000000000000",
                    req=RevokeCredentialRequest(reason="test"),
                    request=_mock_request(),
                    actor_ctx=_mock_actor(),
                )
            )
        assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# F — Credential events
# ---------------------------------------------------------------------------


class TestF_CredentialEvents:
    def test_events_after_issue(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            list_tenant_credential_events(
                tenant_id="tenant-alpha",
                request=_mock_request(),
                actor_ctx=_mock_actor(),
                credential_id=None,
                event_type=None,
                limit=100,
            )
        )
        assert len(result["events"]) == 1
        assert result["events"][0]["event_type"] == "issued"

    def test_events_filter_by_event_type(self, engine, monkeypatch) -> None:
        monkeypatch.setattr("api.admin.get_engine", lambda: engine)
        monkeypatch.setattr("api.admin.bind_tenant_id", lambda *a, **kw: None)

        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        result = _run(
            list_tenant_credential_events(
                tenant_id="tenant-alpha",
                request=_mock_request(),
                actor_ctx=_mock_actor(),
                credential_id=None,
                event_type="issued",
                limit=100,
            )
        )
        assert all(e["event_type"] == "issued" for e in result["events"])


# ---------------------------------------------------------------------------
# G — BUG-001 absence check
# ---------------------------------------------------------------------------


class TestG_BugOneAbsent:
    def test_duplicate_rotate_key_handler_removed(self) -> None:
        """The no-tenant-enforcement rotate_key handler must not exist in api.admin."""
        import api.admin as admin_mod

        assert not hasattr(admin_mod, "rotate_key"), (
            "BUG-001: duplicate rotate_key (no tenant enforcement) must be removed"
        )
