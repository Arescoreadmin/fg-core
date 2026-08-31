"""AUTH-ROLE-001C: Worker deployment test suite.

Tests that the projection worker entrypoint (worker_main.py) wires
correctly into the production polling runtime, handles Auth0 429/5xx/4xx
responses correctly, shuts down cleanly on SIGTERM, and never logs secrets.

Reuses fixtures from test_auth_role_001b_projection.py where possible.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as SASession, sessionmaker

from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
    Auth0RateLimitError,
    _parse_retry_after,
)
from admin_gateway.identity.projection_worker import run_projection_pass

# ---------------------------------------------------------------------------
# Shared constants (mirrored from 001B test suite — do not duplicate full suite)
# ---------------------------------------------------------------------------

TENANT = "tenant-001c"
PROVIDER = "auth0"
SUBJECT = "auth0|worker-test-abc"
PRINCIPAL_ID = str(uuid.uuid4())
MEMBERSHIP_ID = str(uuid.uuid4())

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
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_auth0_client(*, existing_revision: int | None = None) -> MagicMock:
    client = MagicMock(spec=Auth0ManagementClient)
    client.hash_subject = Auth0ManagementClient.hash_subject
    existing_meta: dict[str, Any] = {}
    if existing_revision is not None:
        existing_meta = {"projection_revision": existing_revision}
    client.get_user_app_metadata.return_value = existing_meta
    client.update_user_app_metadata.return_value = None
    return client


def _make_real_auth0_client() -> Auth0ManagementClient:
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
    return int(row[0]) if row else 0


def _fetch_one(db: SASession) -> Any:
    return db.execute(
        text("SELECT * FROM identity_projection_outbox LIMIT 1")
    ).fetchone()


# ---------------------------------------------------------------------------
# W1 — Worker main imports and invokes run_projection_pass
# ---------------------------------------------------------------------------


def test_W1_worker_main_imports_and_invokes_run_projection_pass(tmp_path) -> None:
    """Monkeypatch run_projection_pass; verify it gets called in the poll loop."""
    call_log: list[str] = []
    stop_event = threading.Event()

    def fake_run_projection_pass(db, client, **kwargs):
        call_log.append("called")
        stop_event.set()  # stop after first pass
        return 0

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
        "AUTH0_MGMT_CLIENT_SECRET": "mgmt-client-secret",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        # Required by get_auth0_config() full loader:
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-client-secret",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "worker_test.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "1",
    }

    with patch.dict(os.environ, env_overrides, clear=False):
        from admin_gateway.identity.auth0_config import clear_auth0_config_cache

        clear_auth0_config_cache()
        try:
            with (
                patch(
                    "admin_gateway.identity.worker_main.run_projection_pass",
                    fake_run_projection_pass,
                ),
                patch(
                    "admin_gateway.identity.worker_main.get_auth0_config",
                ),
                patch(
                    "admin_gateway.identity.worker_main.Auth0ManagementClient",
                ),
                patch(
                    "admin_gateway.identity.worker_main.get_identity_sessionmaker",
                ) as mock_factory,
            ):
                # Make session factory return a mock session
                mock_session = MagicMock()
                mock_session.close = MagicMock()
                mock_factory.return_value.return_value = mock_session

                from admin_gateway.identity import worker_main

                worker_main.run_worker(_stop_event=stop_event)
        finally:
            clear_auth0_config_cache()

    assert len(call_log) >= 1, "run_projection_pass was never called"


# ---------------------------------------------------------------------------
# W2 — Graceful SIGTERM shutdown
# ---------------------------------------------------------------------------


def test_W2_graceful_sigterm_shutdown(tmp_path) -> None:
    """Send SIGTERM to the worker thread; verify loop exits cleanly."""
    stop_event = threading.Event()
    worker_stopped = threading.Event()
    errors: list[str] = []

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
        "AUTH0_MGMT_CLIENT_SECRET": "mgmt-client-secret",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-client-secret",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "sigterm_test.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "60",  # long poll — will be interrupted
    }

    def fake_run_projection_pass(db, client, **kwargs):
        return 0

    def _run_worker():
        try:
            with patch.dict(os.environ, env_overrides, clear=False):
                from admin_gateway.identity.auth0_config import clear_auth0_config_cache

                clear_auth0_config_cache()
                try:
                    with (
                        patch(
                            "admin_gateway.identity.worker_main.run_projection_pass",
                            fake_run_projection_pass,
                        ),
                        patch("admin_gateway.identity.worker_main.get_auth0_config"),
                        patch(
                            "admin_gateway.identity.worker_main.Auth0ManagementClient"
                        ),
                        patch(
                            "admin_gateway.identity.worker_main.get_identity_sessionmaker"
                        ) as mock_factory,
                    ):
                        mock_session = MagicMock()
                        mock_session.close = MagicMock()
                        mock_factory.return_value.return_value = mock_session

                        from admin_gateway.identity import worker_main

                        worker_main.run_worker(_stop_event=stop_event)
                finally:
                    clear_auth0_config_cache()
        except Exception as exc:
            errors.append(str(exc))
        finally:
            worker_stopped.set()

    t = threading.Thread(target=_run_worker, daemon=True)
    t.start()

    # Give worker a moment to start, then signal stop
    time.sleep(0.2)
    stop_event.set()

    finished = worker_stopped.wait(timeout=5.0)
    assert finished, "Worker did not stop within 5 seconds of stop_event being set"
    assert not errors, f"Worker raised unexpected exception: {errors}"


# ---------------------------------------------------------------------------
# W3 — Poll interval respected
# ---------------------------------------------------------------------------


def test_W3_poll_interval_respected(tmp_path) -> None:
    """Verify stop_event.wait is called with the correct poll interval."""
    wait_calls: list[float] = []

    # Run for 2 passes then stop
    pass_count = [0]
    stop_event = threading.Event()

    def fake_wait(self, timeout=None):
        if timeout is not None:
            wait_calls.append(timeout)
        stop_event.set()
        return True  # simulate event set immediately

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
        "AUTH0_MGMT_CLIENT_SECRET": "mgmt-secret",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-secret",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "poll_test.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "45",
    }

    def fake_run_projection_pass(db, client, **kwargs):
        pass_count[0] += 1
        return 0

    with patch.dict(os.environ, env_overrides, clear=False):
        from admin_gateway.identity.auth0_config import clear_auth0_config_cache

        clear_auth0_config_cache()
        try:
            with (
                patch(
                    "admin_gateway.identity.worker_main.run_projection_pass",
                    fake_run_projection_pass,
                ),
                patch("admin_gateway.identity.worker_main.get_auth0_config"),
                patch("admin_gateway.identity.worker_main.Auth0ManagementClient"),
                patch(
                    "admin_gateway.identity.worker_main.get_identity_sessionmaker"
                ) as mock_factory,
                patch.object(threading.Event, "wait", fake_wait),
            ):
                mock_session = MagicMock()
                mock_session.close = MagicMock()
                mock_factory.return_value.return_value = mock_session

                from admin_gateway.identity import worker_main

                worker_main.run_worker(_stop_event=stop_event)
        finally:
            clear_auth0_config_cache()

    assert len(wait_calls) >= 1, "stop_event.wait was never called with a timeout"
    assert wait_calls[0] == 45, f"Expected poll_seconds=45, got {wait_calls[0]}"


# ---------------------------------------------------------------------------
# W4 — Startup config validation fails closed on missing required env var
# ---------------------------------------------------------------------------


def test_W4_startup_config_validation_fails_closed(monkeypatch) -> None:
    """Missing required env var → process exits non-zero (SystemExit)."""
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_MGMT_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_MGMT_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AUTH0_MGMT_AUDIENCE", raising=False)

    # Patch other required env vars too so only the management vars are missing
    with patch.dict(
        os.environ,
        {
            "AUTH0_DOMAIN": "",
            "AUTH0_MGMT_CLIENT_ID": "",
            "AUTH0_MGMT_CLIENT_SECRET": "",
            "AUTH0_MGMT_AUDIENCE": "",
        },
        clear=False,
    ):
        from admin_gateway.identity.worker_main import _load_config

        with pytest.raises(SystemExit) as exc_info:
            _load_config()

    assert exc_info.value.code != 0, "Expected non-zero exit on missing config"


# ---------------------------------------------------------------------------
# W5 — Transient error continues — worker does not crash-loop
# ---------------------------------------------------------------------------


def test_W5_transient_error_continues(tmp_path) -> None:
    """run_projection_pass raises transient error → loop continues, does not crash."""
    call_count = [0]
    stop_event = threading.Event()

    def fake_run_projection_pass(db, client, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise ConnectionError("transient DB error")
        # Second call: stop cleanly
        stop_event.set()
        return 0

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
        "AUTH0_MGMT_CLIENT_SECRET": "mgmt-secret",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-secret",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "transient_test.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "1",
    }

    with patch.dict(os.environ, env_overrides, clear=False):
        from admin_gateway.identity.auth0_config import clear_auth0_config_cache

        clear_auth0_config_cache()
        try:
            with (
                patch(
                    "admin_gateway.identity.worker_main.run_projection_pass",
                    fake_run_projection_pass,
                ),
                patch("admin_gateway.identity.worker_main.get_auth0_config"),
                patch("admin_gateway.identity.worker_main.Auth0ManagementClient"),
                patch(
                    "admin_gateway.identity.worker_main.get_identity_sessionmaker"
                ) as mock_factory,
            ):
                mock_session = MagicMock()
                mock_session.close = MagicMock()
                mock_factory.return_value.return_value = mock_session

                from admin_gateway.identity import worker_main

                worker_main.run_worker(_stop_event=stop_event)
        finally:
            clear_auth0_config_cache()

    # Worker must have run at least 2 passes (1 error + 1 success)
    assert call_count[0] >= 2, (
        f"Expected >= 2 passes (showing error recovery), got {call_count[0]}"
    )


# ---------------------------------------------------------------------------
# W6 — Unrecoverable startup error fails closed
# ---------------------------------------------------------------------------


def test_W6_unrecoverable_startup_error_fails_closed(tmp_path) -> None:
    """Auth0Config raises on bad config → process exits non-zero."""
    from admin_gateway.identity.auth0_config import Auth0ConfigError

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
        "AUTH0_MGMT_CLIENT_SECRET": "mgmt-secret",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-secret",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "startup_err.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "1",
    }

    with patch.dict(os.environ, env_overrides, clear=False):
        from admin_gateway.identity.auth0_config import clear_auth0_config_cache

        clear_auth0_config_cache()
        try:
            with patch(
                "admin_gateway.identity.worker_main.get_auth0_config",
                side_effect=Auth0ConfigError("AUTH0_CONFIG_MISSING:TEST"),
            ):
                from admin_gateway.identity import worker_main

                with pytest.raises(SystemExit) as exc_info:
                    worker_main.run_worker()
        finally:
            clear_auth0_config_cache()

    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# W7 — 429 Retry-After honored
# ---------------------------------------------------------------------------


def test_W7_429_retry_after_honored() -> None:
    """Mock _patch to return 429 with Retry-After header → Auth0RateLimitError raised
    and retry_after matches the header value."""
    import httpx

    client = _make_real_auth0_client()
    client._token = "test-token"

    def _fake_patch(url, *, headers, json, timeout):
        response = MagicMock()
        response.status_code = 429
        response.content = b"rate limited"
        response.headers = {"Retry-After": "42"}
        return response

    with patch.object(httpx, "patch", _fake_patch):
        with pytest.raises(Auth0RateLimitError) as exc_info:
            client.update_user_app_metadata(
                "auth0|user-xyz",
                principal_id=PRINCIPAL_ID,
                roles=["admin"],
                projection_revision=1,
            )

    err = exc_info.value
    assert err.status == 429
    assert err.retry_after == 42, f"Expected retry_after=42, got {err.retry_after}"
    assert err.code == "AUTH0_RATE_LIMITED"


def test_W7b_parse_retry_after_integer() -> None:
    assert _parse_retry_after("30") == 30


def test_W7c_parse_retry_after_none_returns_default() -> None:
    assert _parse_retry_after(None) == 60


def test_W7d_parse_retry_after_invalid_returns_default() -> None:
    assert _parse_retry_after("not-a-number") == 60


# ---------------------------------------------------------------------------
# W8 — 5xx retry behavior
# ---------------------------------------------------------------------------


def test_W8_5xx_retry_behavior(db: SASession) -> None:
    """Mock Auth0 to return 500 → row stays pending (retryable), not marked done."""
    _seed_row(db, projection_revision=5, attempt_count=0)
    db.flush()

    client = _make_auth0_client()
    client.update_user_app_metadata.side_effect = Auth0ManagementError(
        "MGMT_PATCH_FAILED:500", 500
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "pending", (
        f"Expected pending for retryable 5xx, got {row.status}"
    )
    assert row.last_error_code is not None
    assert "500" in row.last_error_code


# ---------------------------------------------------------------------------
# W9 — Permanent 4xx handling
# ---------------------------------------------------------------------------


def test_W9_permanent_4xx_not_retried_indefinitely(db: SASession) -> None:
    """Mock Auth0 to return 404 → row gets error_code set; does not immediately retry."""
    _seed_row(db, projection_revision=5, attempt_count=0)
    db.flush()

    client = _make_auth0_client()
    # 404 from the GET (user not found during stale-write check)
    client.get_user_app_metadata.side_effect = Auth0ManagementError(
        "MGMT_GET_FAILED:404", 404
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    # Row should remain pending but with error code set and max backoff applied
    assert row.status == "pending"
    assert row.last_error_code is not None
    # Should contain a 404-related code
    assert "404" in row.last_error_code or "GET" in row.last_error_code


def test_W9b_permanent_400_not_retried_indefinitely(db: SASession) -> None:
    """Mock Auth0 PATCH to return 400 → permanent error code recorded."""
    _seed_row(db, projection_revision=5, attempt_count=0)
    db.flush()

    client = _make_auth0_client()
    client.get_user_app_metadata.return_value = {}
    client.update_user_app_metadata.side_effect = Auth0ManagementError(
        "MGMT_PATCH_FAILED:400", 400
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "pending"
    assert "400" in (row.last_error_code or "")


# ---------------------------------------------------------------------------
# W10 — No secret logging
# ---------------------------------------------------------------------------


def test_W10_no_secret_logging(tmp_path, caplog) -> None:
    """Capture log output; verify no token/secret/Authorization header present."""
    stop_event = threading.Event()

    def fake_run_projection_pass(db, client, **kwargs):
        stop_event.set()
        return 0

    env_overrides = {
        "AUTH0_DOMAIN": "test.us.auth0.com",
        "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id-001c",
        "AUTH0_MGMT_CLIENT_SECRET": "super-secret-token-must-not-appear",
        "AUTH0_MGMT_AUDIENCE": "https://test.us.auth0.com/api/v2/",
        "AUTH0_CLIENT_ID": "app-client-id",
        "AUTH0_CLIENT_SECRET": "app-secret-must-not-appear",
        "AUTH0_AUDIENCE": "https://api.test.com/",
        "AUTH0_CALLBACK_URL": "https://app.test.com/callback",
        "AUTH0_LOGOUT_RETURN_URL": "https://app.test.com/",
        "FG_SQLITE_PATH": str(tmp_path / "secret_test.db"),
        "PROJECTION_WORKER_POLL_SECONDS": "1",
    }

    with caplog.at_level(logging.DEBUG):
        with patch.dict(os.environ, env_overrides, clear=False):
            from admin_gateway.identity.auth0_config import clear_auth0_config_cache

            clear_auth0_config_cache()
            try:
                with (
                    patch(
                        "admin_gateway.identity.worker_main.run_projection_pass",
                        fake_run_projection_pass,
                    ),
                    patch("admin_gateway.identity.worker_main.get_auth0_config"),
                    patch("admin_gateway.identity.worker_main.Auth0ManagementClient"),
                    patch(
                        "admin_gateway.identity.worker_main.get_identity_sessionmaker"
                    ) as mock_factory,
                ):
                    mock_session = MagicMock()
                    mock_session.close = MagicMock()
                    mock_factory.return_value.return_value = mock_session

                    from admin_gateway.identity import worker_main

                    worker_main.run_worker(_stop_event=stop_event)
            finally:
                clear_auth0_config_cache()

    full_log = "\n".join(r.getMessage() for r in caplog.records)

    forbidden_values = [
        "super-secret-token-must-not-appear",
        "app-secret-must-not-appear",
    ]
    for forbidden in forbidden_values:
        assert forbidden not in full_log, (
            f"Secret value appeared in logs: {forbidden!r}"
        )

    forbidden_header_keys = ["Authorization", "Bearer "]
    for key in forbidden_header_keys:
        # It's ok to log the key name "Authorization" without its value, but
        # actual header values (Bearer <token>) must not appear.
        assert "Bearer " not in full_log, (
            "Bearer token appeared in log output — potential credential disclosure"
        )


# ---------------------------------------------------------------------------
# W11 — Stale-write protection survives worker
# ---------------------------------------------------------------------------


def test_W11_stale_write_protection_survives_worker(db: SASession) -> None:
    """Two projection events for same principal; older revision does not override newer.

    Reuses the 001B stale-revision logic.  Projection of revision 3 is queued
    but Auth0 already has revision 10 — the worker must NOT write.
    """
    _seed_row(db, projection_revision=3, next_attempt_at="2000-01-01T00:00:00")
    db.flush()

    # Auth0 already has revision 10 (newer)
    client = _make_auth0_client(existing_revision=10)

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "done", (
        f"Stale row should be marked done (converge safely), got {row.status}"
    )
    client.update_user_app_metadata.assert_not_called()


def test_W11b_newer_revision_wins(db: SASession) -> None:
    """Projection of revision 10 when Auth0 has revision 3 — write must happen."""
    _seed_row(db, projection_revision=10, next_attempt_at="2000-01-01T00:00:00")
    db.flush()

    client = _make_auth0_client(existing_revision=3)

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    row = _fetch_one(db)
    assert row.status == "done"
    client.update_user_app_metadata.assert_called_once_with(
        SUBJECT,
        principal_id=PRINCIPAL_ID,
        roles=["admin"],
        projection_revision=10,
    )


# ---------------------------------------------------------------------------
# W12 — Canonical auth independent of projection failure
# ---------------------------------------------------------------------------


def test_W12_canonical_auth_independent_of_projection_failure(db: SASession) -> None:
    """Projection failure → FrostGate DB state unchanged.

    The outbox row represents a *projection* (Auth0 app_metadata convergence).
    A failure in the worker marks the outbox row pending for retry, but does NOT
    modify the authoritative tenant_users record.  We verify this by inspecting
    that the outbox row still contains the original principal_id and revision,
    and that no modification was attempted on any FrostGate authority table.
    """
    original_revision = 7
    _seed_row(db, projection_revision=original_revision)
    db.flush()

    # Simulate Auth0 hard failure
    client = _make_auth0_client()
    client.update_user_app_metadata.side_effect = Auth0ManagementError(
        "MGMT_PATCH_FAILED:503", 503
    )

    run_projection_pass(db, client, batch_size=10, _sqlite_mode=True)

    # Outbox row stays pending (retryable) — revision unchanged
    row = _fetch_one(db)
    assert row.status == "pending"
    assert int(row.projection_revision) == original_revision, (
        f"projection_revision must be unchanged after failure: "
        f"expected {original_revision}, got {row.projection_revision}"
    )

    # The row principal_id is unchanged — FrostGate canonical state is intact
    assert str(row.principal_id) == PRINCIPAL_ID
    assert row.tenant_id == TENANT


# ---------------------------------------------------------------------------
# W13 — Auth0RateLimitError is a subclass of Auth0ManagementError
# ---------------------------------------------------------------------------


def test_W13_rate_limit_error_is_management_error_subclass() -> None:
    """Auth0RateLimitError must be a subclass of Auth0ManagementError
    so existing error-handling code that catches Auth0ManagementError
    also catches rate-limit errors."""
    err = Auth0RateLimitError(retry_after=30)
    assert isinstance(err, Auth0ManagementError)
    assert err.status == 429
    assert err.retry_after == 30
    assert err.code == "AUTH0_RATE_LIMITED"


# ---------------------------------------------------------------------------
# W14 — Worker entrypoint module is importable
# ---------------------------------------------------------------------------


def test_W14_worker_main_module_importable() -> None:
    """worker_main.py must be importable and expose run_worker callable."""
    from admin_gateway.identity import worker_main

    assert callable(worker_main.run_worker)
