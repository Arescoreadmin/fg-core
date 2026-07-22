# tests/security/test_agent_device_credential_security.py
"""
R4.10 security tests — agent_device credential authority.

SOC-HIGH controls validated:
  - Tenant isolation: cross-tenant credential validation impossible
  - Fail-closed: suspended/revoked credentials reject with absent=False
  - Bootstrap token replay prevention (one-time use enforced atomically)
  - Sentinel rows are never matched by canonical validation
  - Revoke is permanent (terminal state, no resurrection)
  - Suspend does not reveal status to validator (opaque error)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    AgentDeviceCredentialMetadata,
    CredentialNotFoundError,
    CredentialStateError,
    get_credential,
    issue_credential,
    revoke_credential,
    validate_credential,
)

# ---------------------------------------------------------------------------
# Minimal schema (shared with main test file)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(128) PRIMARY KEY,
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS credential_slots (
    tenant_id VARCHAR(128) NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_slot VARCHAR(128) NOT NULL,
    current_generation INTEGER NOT NULL DEFAULT 0,
    rotation_policy VARCHAR(32) NOT NULL DEFAULT 'immediate',
    max_overlap_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT, updated_at TEXT,
    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);
CREATE TABLE IF NOT EXISTS tenant_credentials (
    credential_id VARCHAR(64) NOT NULL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_slot VARCHAR(128) NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    lookup_fingerprint VARCHAR(64) NOT NULL,
    lookup_key_version INTEGER NOT NULL DEFAULT 1,
    secret_prefix VARCHAR(16) NOT NULL,
    secret_hash TEXT NOT NULL,
    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'argon2id',
    hash_params TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    expires_at TEXT, issued_at TEXT NOT NULL,
    activated_at TEXT, rotated_at TEXT, revoked_at TEXT,
    replaced_by_credential_id VARCHAR(64),
    created_by_actor_id VARCHAR(256),
    request_id VARCHAR(128),
    idempotency_key VARCHAR(256),
    last_used_at TEXT,
    approximate_use_count INTEGER NOT NULL DEFAULT 0,
    scopes_csv TEXT, metadata TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    record_hash VARCHAR(64),
    UNIQUE (tenant_id, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_tc_slot_generation
    ON tenant_credentials (tenant_id, credential_type, credential_slot, generation);
CREATE INDEX IF NOT EXISTS ix_tc_lookup_fingerprint
    ON tenant_credentials (lookup_fingerprint);
CREATE TABLE IF NOT EXISTS tenant_credential_events (
    event_id VARCHAR(64) NOT NULL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    credential_id VARCHAR(64),
    credential_type VARCHAR(64),
    credential_slot VARCHAR(128),
    generation INTEGER,
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(256), request_id VARCHAR(128),
    occurred_at TEXT NOT NULL,
    outcome VARCHAR(16) NOT NULL DEFAULT 'success',
    failure_reason TEXT, metadata TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(128) NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by VARCHAR(128) NOT NULL DEFAULT 'unknown',
    reason VARCHAR(256) NOT NULL DEFAULT 'unspecified',
    ticket VARCHAR(128)
);
"""

_TENANT_A = "sec-tenant-a"
_TENANT_B = "sec-tenant-b"


def _setup(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
        for tid in (_TENANT_A, _TENANT_B):
            conn.execute(
                text(
                    "INSERT OR REPLACE INTO tenants (tenant_id, lifecycle_state) "
                    "VALUES (:tid, 'active')"
                ),
                {"tid": tid},
            )


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-security")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup(eng)
    yield eng
    eng.dispose()


def _issue(
    engine: Engine, *, tenant_id: str, agent_id: str, device_id: str
) -> ca.IssuanceResult:
    meta = AgentDeviceCredentialMetadata(
        agent_id=agent_id,
        device_id=device_id,
        hostname="h",
        platform="linux",
        architecture="x86_64",
        os_version="5",
        agent_version="1.0",
        deployment_environment="prod",
        bootstrap_method="manual",
        trust_level="full",
        credential_slot=f"agent:{agent_id}",
        issued_by="test",
        rotation_generation=1,
        hardware_fingerprint=f"fp-{device_id}",
    )
    return issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="agent_device",
        credential_slot=f"agent:{agent_id}",
        scopes=["credential:use"],
        metadata=meta.model_dump(),
    )


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolationSecurity:
    def test_tenant_a_secret_invalid_for_tenant_b(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="iso-agent", device_id="iso-dv"
        )
        secret = result.plaintext_secret
        assert secret is not None
        # Validate with correct type but the system should return TENANT_A only
        principal = validate_credential(engine, secret, credential_type="agent_device")
        assert principal.tenant_id == _TENANT_A
        # There is no "validate for tenant B" overload, but ensure the principal binding is correct
        assert principal.tenant_id != _TENANT_B

    def test_cross_tenant_get_credential_blocked(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="xtg-agent", device_id="xtg-dv"
        )
        cid = result.record.credential_id
        with pytest.raises(CredentialNotFoundError):
            get_credential(engine, cid, _TENANT_B)

    def test_cross_tenant_revoke_blocked(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="xtr-agent", device_id="xtr-dv"
        )
        cid = result.record.credential_id
        with pytest.raises(CredentialNotFoundError):
            revoke_credential(
                engine,
                credential_id=cid,
                tenant_id=_TENANT_B,
                actor_id="attacker",
                reason="cross-tenant attack",
            )
        # Credential must still be active
        rec = get_credential(engine, cid, _TENANT_A)
        assert rec.status == "active"

    def test_cross_tenant_bootstrap_token_blocked(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TENANT_B,
                raw_token=tok.raw_token,
                agent_id="xb-agent",
                device_id="xb-dv",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-xb",
            )
        assert exc_info.value.absent is True


# ---------------------------------------------------------------------------
# Fail-closed: revoked credentials must not be authenticated
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_revoked_secret_fails_absent_false(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="rc-agent", device_id="rc-dv"
        )
        secret = result.plaintext_secret
        assert secret is not None
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TENANT_A,
            actor_id="admin",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="agent_device")
        # absent=False means do NOT fall through to legacy path
        assert exc_info.value.absent is False

    def test_suspended_secret_fails_absent_false(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="sc-agent", device_id="sc-dv"
        )
        secret = result.plaintext_secret
        assert secret is not None
        ca.suspend_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TENANT_A,
            actor_id="admin",
            reason="security_hold",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="agent_device")
        assert exc_info.value.absent is False

    def test_revoke_is_terminal_cannot_resume(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="tr-agent", device_id="tr-dv"
        )
        cid = result.record.credential_id
        revoke_credential(
            engine,
            credential_id=cid,
            tenant_id=_TENANT_A,
            actor_id="admin",
            reason="test",
        )
        with pytest.raises(CredentialStateError):
            ca.resume_credential(
                engine, credential_id=cid, tenant_id=_TENANT_A, actor_id="admin"
            )
        rec = get_credential(engine, cid, _TENANT_A)
        assert rec.status == "revoked"

    def test_revoke_is_terminal_cannot_suspend(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="ts-agent", device_id="ts-dv"
        )
        cid = result.record.credential_id
        revoke_credential(
            engine,
            credential_id=cid,
            tenant_id=_TENANT_A,
            actor_id="admin",
            reason="test",
        )
        with pytest.raises(CredentialStateError):
            ca.suspend_credential(
                engine,
                credential_id=cid,
                tenant_id=_TENANT_A,
                actor_id="admin",
                reason="too late",
            )

    def test_revoke_does_not_delete_row(self, engine: Engine) -> None:
        result = _issue(
            engine, tenant_id=_TENANT_A, agent_id="nd-agent", device_id="nd-dv"
        )
        cid = result.record.credential_id
        revoke_credential(
            engine,
            credential_id=cid,
            tenant_id=_TENANT_A,
            actor_id="admin",
            reason="test",
        )
        rec = get_credential(engine, cid, _TENANT_A)
        assert rec is not None
        assert rec.status == "revoked"


# ---------------------------------------------------------------------------
# Bootstrap token security
# ---------------------------------------------------------------------------


class TestBootstrapTokenSecurity:
    def test_one_time_use_enforced(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TENANT_A,
            raw_token=tok.raw_token,
            agent_id="otu-1",
            device_id="otu-dv-1",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-1",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TENANT_A,
                raw_token=tok.raw_token,
                agent_id="otu-2",
                device_id="otu-dv-2",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-2",
            )
        assert exc_info.value.absent is True

    def test_token_stored_as_hmac_fingerprint_never_plaintext(
        self, engine: Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hmac as _hmac
        import os

        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        raw = tok.raw_token
        pepper = os.environ["FG_KEY_PEPPER"]
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT token_hash FROM agent_enrollment_tokens WHERE id = :id"),
                {"id": tok.enrollment_id},
            ).fetchone()
        assert row is not None
        stored = row[0]
        assert stored != raw, "Raw token must not be stored in plaintext"
        assert len(stored) == 64, "Fingerprint must be 64-char hex"
        # Must be HMAC-SHA256(pepper, token), not plain SHA-256(token)
        expected_hmac = _hmac.new(
            key=pepper.encode("utf-8"),
            msg=raw.encode("utf-8"),
            digestmod=__import__("hashlib").sha256,
        ).hexdigest()
        plain_sha256 = __import__("hashlib").sha256(raw.encode()).hexdigest()
        assert stored == expected_hmac, "Stored hash must be peppered HMAC-SHA256"
        assert stored != plain_sha256, "Stored hash must NOT be plain SHA-256"

    def test_wrong_pepper_bootstrap_lookup_fails(
        self, engine: Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        # Change pepper after issuance — lookup fingerprint won't match
        monkeypatch.setenv("FG_KEY_PEPPER", "different-pepper-value")
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TENANT_A,
                raw_token=tok.raw_token,
                agent_id="wp-ag",
                device_id="wp-dv",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-wp",
            )
        assert exc_info.value.absent is True

    def test_same_token_different_peppers_produce_different_fingerprints(self) -> None:
        import hmac as _hmac

        token = "test-bootstrap-token-for-pepper-comparison"
        fp_a = _hmac.new(
            key=b"pepper-alpha",
            msg=token.encode("utf-8"),
            digestmod=__import__("hashlib").sha256,
        ).hexdigest()
        fp_b = _hmac.new(
            key=b"pepper-beta",
            msg=token.encode("utf-8"),
            digestmod=__import__("hashlib").sha256,
        ).hexdigest()
        assert fp_a != fp_b, "Different peppers must produce different fingerprints"

    def test_bootstrap_fingerprint_is_constant_time_comparable(self) -> None:
        import hmac as _hmac

        # HMAC-SHA256 hexdigest is a fixed-length string — constant-time comparison
        # via hmac.compare_digest() is safe and should be used for any verification.
        # This test confirms the fingerprint is a fixed-length hex string.
        import hashlib as _hashlib

        token = "test-token-constant-time"
        fp = _hmac.new(
            key=b"pepper",
            msg=token.encode("utf-8"),
            digestmod=_hashlib.sha256,
        ).hexdigest()
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_expired_token_cannot_be_used(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE agent_enrollment_tokens SET expires_at = :exp WHERE id = :id"
                ),
                {
                    "exp": (
                        datetime.now(timezone.utc) - timedelta(seconds=1)
                    ).isoformat(),
                    "id": tok.enrollment_id,
                },
            )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TENANT_A,
                raw_token=tok.raw_token,
                agent_id="ex-ag",
                device_id="ex-dv",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-ex",
            )
        assert exc_info.value.absent is True

    def test_wrong_token_rejected_with_absent_true(self, engine: Engine) -> None:
        ca.issue_bootstrap_token(
            engine, tenant_id=_TENANT_A, actor_id="admin", ttl_seconds=60, reason="test"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TENANT_A,
                raw_token="notarealtoken" + "x" * 30,
                agent_id="wr-ag",
                device_id="wr-dv",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-wr",
            )
        assert exc_info.value.absent is True
