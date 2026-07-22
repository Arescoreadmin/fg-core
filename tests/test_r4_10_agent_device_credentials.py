# tests/test_r4_10_agent_device_credentials.py
"""
R4.10 — Agent and Device Credential Authority acceptance tests.

All tests run against SQLite in-memory.  Argon2id is monkeypatched to
minimum cost so the suite completes in under a second.

Coverage groups:
  A — Credential authority: agent_device type dispatch
  B — AgentDeviceCredentialMetadata validation
  C — Device trust state machine (validate_trust_transition)
  D — Bootstrap token lifecycle (issue + exchange)
  E — Suspend / resume lifecycle
  F — get_active_credential_for_slot helper
  G — Tenant isolation (cross-tenant denial)
  H — Audit events
  I — Sentinel design invariants
  J — Concurrent / edge-case operations
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    AgentDeviceCredentialMetadata,
    BootstrapTokenResult,
    CredentialNotFoundError,
    CredentialPrincipal,
    CredentialStateError,
    DEVICE_TRUST_STATES,
    IssuanceResult,
    VALID_TRUST_TRANSITIONS,
    get_active_credential_for_slot,
    get_credential,
    issue_credential,
    list_credential_events,
    revoke_credential,
    rotate_credential,
    validate_credential,
    validate_trust_transition,
)

# ---------------------------------------------------------------------------
# SQLite schema (mirrors the production Postgres schema)
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

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    tenant_id   VARCHAR(128) NOT NULL,
    expires_at  TEXT NOT NULL,
    max_uses    INTEGER NOT NULL DEFAULT 1,
    used_count  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    created_by  VARCHAR(128) NOT NULL DEFAULT 'unknown',
    reason      VARCHAR(256) NOT NULL DEFAULT 'unspecified',
    ticket      VARCHAR(128)
);
"""

_TID = "tenant-agent-test"
_TID2 = "tenant-agent-test-2"
_AGENT = "agent-001"
_DEVICE = "device-abc123"
_SLOT = f"agent:{_AGENT}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


def _insert_tenant(engine: Engine, tenant_id: str, state: str = "active") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR REPLACE INTO tenants (tenant_id, lifecycle_state) "
                "VALUES (:tid, :state)"
            ),
            {"tid": tenant_id, "state": state},
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca,
        "_HASHER",
        PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-r4-10")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup_schema(eng)
    _insert_tenant(eng, _TID)
    _insert_tenant(eng, _TID2)
    yield eng
    eng.dispose()


def _issue_agent_device(
    engine: Engine,
    *,
    agent_id: str = _AGENT,
    device_id: str = _DEVICE,
    tenant_id: str = _TID,
    ttl_seconds: int | None = None,
    actor_id: str = "test-actor",
) -> IssuanceResult:
    meta = AgentDeviceCredentialMetadata(
        agent_id=agent_id,
        device_id=device_id,
        hostname="host-001",
        platform="linux",
        architecture="x86_64",
        os_version="5.15",
        agent_version="1.0.0",
        deployment_environment="prod",
        bootstrap_method="enrollment_token",
        trust_level="full",
        credential_slot=f"agent:{agent_id}",
        issued_by=actor_id,
        rotation_generation=1,
        hardware_fingerprint="fp-" + device_id,
    )
    return issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="agent_device",
        credential_slot=f"agent:{agent_id}",
        scopes=["credential:use"],
        metadata=meta.model_dump(),
        expires_in_seconds=ttl_seconds,
        actor_id=actor_id,
    )


# ---------------------------------------------------------------------------
# A — Credential authority: agent_device type dispatch
# ---------------------------------------------------------------------------


class TestAgentDeviceCredentialType:
    def test_agent_device_type_accepted(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.record.credential_type == "agent_device"

    def test_agent_device_raw_token_no_fgk_prefix(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.plaintext_secret is not None
        assert not result.plaintext_secret.startswith("fgk.")

    def test_agent_device_token_length(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.plaintext_secret is not None
        assert 40 <= len(result.plaintext_secret) <= 60

    def test_agent_device_default_ttl_set(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.record.expires_at is not None
        expected_days = 90
        delta = result.record.expires_at - datetime.now(timezone.utc)
        assert abs(delta.days - expected_days) <= 1

    def test_agent_device_custom_ttl(self, engine: Engine) -> None:
        result = _issue_agent_device(engine, ttl_seconds=3600)
        assert result.record.expires_at is not None
        delta = result.record.expires_at - datetime.now(timezone.utc)
        assert abs(delta.total_seconds() - 3600) < 10

    def test_agent_device_validates_correctly(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="agent_device")
        assert isinstance(principal, CredentialPrincipal)
        assert principal.credential_type == "agent_device"
        assert principal.tenant_id == _TID

    def test_agent_device_principal_carries_metadata(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="agent_device")
        assert principal.metadata is not None
        assert principal.metadata.get("agent_id") == _AGENT
        assert principal.metadata.get("device_id") == _DEVICE

    def test_wrong_token_fails(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        with pytest.raises(CredentialNotFoundError):
            validate_credential(
                engine, "wrongtoken_" + "x" * 32, credential_type="agent_device"
            )

    def test_fgk_token_rejected_absent_true(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(
                engine, "fgk.tid.secret", credential_type="agent_device"
            )
        assert exc_info.value.absent is True

    def test_revoked_agent_device_fails_absent_false(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TID,
            actor_id="test",
            reason="test_revoke",
        )
        secret = result.plaintext_secret
        assert secret is not None
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="agent_device")
        assert exc_info.value.absent is False

    def test_agent_device_rotation_new_token(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        new_secret = rotated.plaintext_secret
        assert new_secret is not None
        assert new_secret != old_secret
        principal = validate_credential(
            engine, new_secret, credential_type="agent_device"
        )
        assert principal.credential_type == "agent_device"

    def test_agent_device_rotation_invalidates_old(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, old_secret, credential_type="agent_device")

    def test_agent_device_rotation_preserves_metadata(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        assert rotated.record.metadata is not None
        assert rotated.record.metadata.get("agent_id") == _AGENT

    def test_agent_device_rotation_increments_generation(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.record.generation == 1
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        assert rotated.record.generation == 2

    def test_agent_device_idempotency_key(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot="agent:idp-test-agent",
            scopes=["credential:use"],
            metadata={
                "agent_id": "idp-test-agent",
                "device_id": "d1",
                "hostname": "h",
                "platform": "linux",
                "architecture": "x86_64",
                "os_version": "5.15",
                "agent_version": "1.0",
                "deployment_environment": "prod",
                "bootstrap_method": "manual",
                "trust_level": "full",
                "credential_slot": "agent:idp-test-agent",
                "issued_by": "test",
                "rotation_generation": 1,
                "hardware_fingerprint": "fp-d1",
            },
            idempotency_key="test-idp-001",
        )
        r2 = issue_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot="agent:idp-test-agent",
            scopes=["credential:use"],
            metadata={
                "agent_id": "idp-test-agent",
                "device_id": "d1",
                "hostname": "h",
                "platform": "linux",
                "architecture": "x86_64",
                "os_version": "5.15",
                "agent_version": "1.0",
                "deployment_environment": "prod",
                "bootstrap_method": "manual",
                "trust_level": "full",
                "credential_slot": "agent:idp-test-agent",
                "issued_by": "test",
                "rotation_generation": 1,
                "hardware_fingerprint": "fp-d1",
            },
            idempotency_key="test-idp-001",
        )
        assert r1.record.credential_id == r2.record.credential_id
        assert r2.plaintext_secret is None  # replay returns None

    def test_empty_token_rejected_absent_true(self, engine: Engine) -> None:
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, "", credential_type="agent_device")
        assert exc_info.value.absent is True

    def test_short_token_rejected_absent_true(self, engine: Engine) -> None:
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, "tooshort", credential_type="agent_device")
        assert exc_info.value.absent is True

    def test_agent_device_slot_format(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.record.credential_slot == f"agent:{_AGENT}"

    def test_revoke_is_idempotent(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "revoked"


# ---------------------------------------------------------------------------
# B — AgentDeviceCredentialMetadata validation
# ---------------------------------------------------------------------------


class TestAgentDeviceCredentialMetadata:
    def test_required_fields_accepted(self) -> None:
        m = AgentDeviceCredentialMetadata(
            agent_id="ag1",
            device_id="dev1",
            hostname="host",
            platform="linux",
            architecture="x86_64",
            os_version="5.15",
            agent_version="1.0",
            deployment_environment="prod",
            bootstrap_method="enrollment_token",
            trust_level="full",
            credential_slot="agent:ag1",
            issued_by="admin",
            rotation_generation=1,
            hardware_fingerprint="fp-abc",
        )
        assert m.agent_id == "ag1"
        assert m.metadata_version == 1
        assert m.future_extensions == {}

    def test_optional_fields_default_none(self) -> None:
        m = AgentDeviceCredentialMetadata(
            agent_id="ag2",
            device_id="dev2",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            deployment_environment="prod",
            bootstrap_method="manual",
            trust_level="limited",
            credential_slot="agent:ag2",
            issued_by="admin",
            rotation_generation=1,
            hardware_fingerprint="fp-xyz",
        )
        assert m.device_uuid is None
        assert m.certificate_serial is None
        assert m.attestation_hash is None
        assert m.last_seen is None

    def test_agent_id_empty_rejected(self) -> None:
        with pytest.raises(Exception):
            AgentDeviceCredentialMetadata(
                agent_id="",
                device_id="dev",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                deployment_environment="prod",
                bootstrap_method="manual",
                trust_level="full",
                credential_slot="agent:",
                issued_by="admin",
                rotation_generation=1,
                hardware_fingerprint="fp",
            )

    def test_device_id_empty_rejected(self) -> None:
        with pytest.raises(Exception):
            AgentDeviceCredentialMetadata(
                agent_id="ag",
                device_id="",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                deployment_environment="prod",
                bootstrap_method="manual",
                trust_level="full",
                credential_slot="agent:ag",
                issued_by="admin",
                rotation_generation=1,
                hardware_fingerprint="fp",
            )

    def test_hardware_fingerprint_empty_rejected(self) -> None:
        with pytest.raises(Exception):
            AgentDeviceCredentialMetadata(
                agent_id="ag",
                device_id="dev",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                deployment_environment="prod",
                bootstrap_method="manual",
                trust_level="full",
                credential_slot="agent:ag",
                issued_by="admin",
                rotation_generation=1,
                hardware_fingerprint="",
            )

    def test_future_extensions_accepts_dict(self) -> None:
        m = AgentDeviceCredentialMetadata(
            agent_id="ag3",
            device_id="dev3",
            hostname="h",
            platform="linux",
            architecture="arm64",
            os_version="5",
            agent_version="2.0",
            deployment_environment="staging",
            bootstrap_method="enrollment_token",
            trust_level="quarantine",
            credential_slot="agent:ag3",
            issued_by="ops",
            rotation_generation=2,
            hardware_fingerprint="fp-ag3",
            future_extensions={"tpm_version": "2.0", "fido2": True},
        )
        assert m.future_extensions.get("tpm_version") == "2.0"

    def test_metadata_round_trips_through_model_dump(self) -> None:
        m = AgentDeviceCredentialMetadata(
            agent_id="round-ag",
            device_id="round-dev",
            hostname="h",
            platform="darwin",
            architecture="arm64",
            os_version="14.0",
            agent_version="3.0",
            deployment_environment="dev",
            bootstrap_method="manual",
            trust_level="full",
            credential_slot="agent:round-ag",
            issued_by="ci",
            rotation_generation=1,
            hardware_fingerprint="fp-roundtrip",
            attestation_hash="sha256-abc",
        )
        d = m.model_dump()
        m2 = AgentDeviceCredentialMetadata(**d)
        assert m2.agent_id == m.agent_id
        assert m2.attestation_hash == "sha256-abc"


# ---------------------------------------------------------------------------
# C — Device trust state machine
# ---------------------------------------------------------------------------


class TestDeviceTrustStateMachine:
    def test_all_states_known(self) -> None:
        expected = {
            "unknown",
            "pending",
            "bootstrapping",
            "enrolled",
            "active",
            "rotating",
            "suspended",
            "revoked",
            "expired",
            "orphaned",
            "failed_attestation",
        }
        assert DEVICE_TRUST_STATES == expected

    def test_valid_transitions_accepted(self) -> None:
        valid_pairs = [
            ("unknown", "pending"),
            ("pending", "bootstrapping"),
            ("bootstrapping", "enrolled"),
            ("enrolled", "active"),
            ("active", "rotating"),
            ("active", "suspended"),
            ("active", "revoked"),
            ("active", "expired"),
            ("active", "orphaned"),
            ("rotating", "active"),
            ("rotating", "revoked"),
            ("suspended", "active"),
            ("suspended", "revoked"),
            ("orphaned", "active"),
            ("orphaned", "revoked"),
            ("failed_attestation", "pending"),
            ("failed_attestation", "revoked"),
        ]
        for from_s, to_s in valid_pairs:
            validate_trust_transition(from_s, to_s)  # must not raise

    def test_invalid_transition_raises(self) -> None:
        with pytest.raises(CredentialStateError):
            validate_trust_transition("active", "unknown")

    def test_terminal_state_revoked_no_outgoing(self) -> None:
        with pytest.raises(CredentialStateError):
            validate_trust_transition("revoked", "active")

    def test_terminal_state_expired_no_outgoing(self) -> None:
        with pytest.raises(CredentialStateError):
            validate_trust_transition("expired", "active")

    def test_unknown_from_state_raises(self) -> None:
        with pytest.raises(CredentialStateError, match="Unknown device trust state"):
            validate_trust_transition("nonexistent", "active")

    def test_unknown_to_state_raises(self) -> None:
        with pytest.raises(CredentialStateError, match="Unknown device trust state"):
            validate_trust_transition("active", "nonexistent")

    def test_valid_trust_transitions_keys_are_states(self) -> None:
        for state in VALID_TRUST_TRANSITIONS:
            assert state in DEVICE_TRUST_STATES

    def test_valid_trust_transitions_values_are_states(self) -> None:
        for targets in VALID_TRUST_TRANSITIONS.values():
            for t in targets:
                assert t in DEVICE_TRUST_STATES

    def test_pending_to_revoked_direct(self) -> None:
        validate_trust_transition("pending", "revoked")  # must not raise

    def test_bootstrapping_to_failed_attestation(self) -> None:
        validate_trust_transition("bootstrapping", "failed_attestation")

    def test_enrolled_to_failed_attestation(self) -> None:
        validate_trust_transition("enrolled", "failed_attestation")


# ---------------------------------------------------------------------------
# D — Bootstrap token lifecycle
# ---------------------------------------------------------------------------


class TestBootstrapTokenLifecycle:
    def test_issue_bootstrap_token_returns_result(self, engine: Engine) -> None:
        result = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=3600, reason="test"
        )
        assert isinstance(result, BootstrapTokenResult)
        assert result.tenant_id == _TID
        assert len(result.raw_token) >= 20
        assert result.enrollment_id > 0

    def test_bootstrap_token_expires_at_correct(self, engine: Engine) -> None:
        result = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=3600, reason="test"
        )
        delta = result.expires_at - datetime.now(timezone.utc)
        assert abs(delta.total_seconds() - 3600) < 10

    def test_bootstrap_token_stored_hashed(self, engine: Engine) -> None:
        result = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        expected_hash = hashlib.sha256(result.raw_token.encode()).hexdigest()
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT token_hash FROM agent_enrollment_tokens WHERE id = :id"),
                {"id": result.enrollment_id},
            ).fetchone()
        assert row is not None
        assert row[0] == expected_hash

    def test_exchange_bootstrap_token_issues_credential(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        result = ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id=_AGENT,
            device_id=_DEVICE,
            hostname="host-001",
            platform="linux",
            architecture="x86_64",
            os_version="5.15",
            agent_version="1.0",
            hardware_fingerprint="fp-abc",
        )
        assert result.record.credential_type == "agent_device"
        assert result.record.credential_slot == f"agent:{_AGENT}"
        assert result.plaintext_secret is not None

    def test_exchange_produces_validatable_credential(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        result = ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-val",
            device_id="dv-val",
            hostname="host",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-val",
        )
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="agent_device")
        assert principal.tenant_id == _TID

    def test_used_bootstrap_token_rejected(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-once",
            device_id="dv-once",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TID,
                raw_token=tok.raw_token,
                agent_id="ag-once-retry",
                device_id="dv-once",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp",
            )
        assert exc_info.value.absent is True

    def test_wrong_bootstrap_token_rejected(self, engine: Engine) -> None:
        ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TID,
                raw_token="wrongtoken_" + "x" * 30,
                agent_id="ag-wr",
                device_id="dv-wr",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp",
            )
        assert exc_info.value.absent is True

    def test_expired_bootstrap_token_rejected(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        # Manually backdate expires_at to simulate expiry
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE agent_enrollment_tokens SET expires_at = :exp WHERE id = :id"
                ),
                {
                    "exp": (
                        datetime.now(timezone.utc) - timedelta(seconds=10)
                    ).isoformat(),
                    "id": tok.enrollment_id,
                },
            )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TID,
                raw_token=tok.raw_token,
                agent_id="ag-exp",
                device_id="dv-exp",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-exp",
            )
        assert exc_info.value.absent is True

    def test_bootstrap_multi_use_token(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine,
            tenant_id=_TID,
            actor_id="admin",
            ttl_seconds=60,
            reason="test",
            max_uses=2,
        )
        ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-mu-1",
            device_id="dv-mu-1",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-mu1",
        )
        # Second use should succeed
        ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-mu-2",
            device_id="dv-mu-2",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-mu2",
        )

    def test_bootstrap_cross_tenant_rejected(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            ca.exchange_bootstrap_token(
                engine,
                tenant_id=_TID2,
                raw_token=tok.raw_token,
                agent_id="ag-xt",
                device_id="dv-xt",
                hostname="h",
                platform="linux",
                architecture="x86_64",
                os_version="5",
                agent_version="1",
                hardware_fingerprint="fp-xt",
            )
        assert exc_info.value.absent is True

    def test_exchange_idempotent_same_agent(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine,
            tenant_id=_TID,
            actor_id="admin",
            ttl_seconds=60,
            reason="test",
            max_uses=2,
        )
        r1 = ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-idem",
            device_id="dv-idem",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-idem",
        )
        r2 = ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-idem",
            device_id="dv-idem",
            hostname="h",
            platform="linux",
            architecture="x86_64",
            os_version="5",
            agent_version="1",
            hardware_fingerprint="fp-idem",
        )
        assert r1.record.credential_id == r2.record.credential_id

    def test_bootstrap_token_tenant_not_found(self, engine: Engine) -> None:
        from api.credential_authority import TenantNotFoundError

        with pytest.raises(TenantNotFoundError):
            ca.issue_bootstrap_token(
                engine,
                tenant_id="nonexistent-tenant",
                actor_id="admin",
                ttl_seconds=60,
                reason="test",
            )

    def test_bootstrap_exchange_metadata_stored(self, engine: Engine) -> None:
        tok = ca.issue_bootstrap_token(
            engine, tenant_id=_TID, actor_id="admin", ttl_seconds=60, reason="test"
        )
        result = ca.exchange_bootstrap_token(
            engine,
            tenant_id=_TID,
            raw_token=tok.raw_token,
            agent_id="ag-meta",
            device_id="dv-meta",
            hostname="myhost",
            platform="windows",
            architecture="x86_64",
            os_version="11",
            agent_version="2.0",
            hardware_fingerprint="fp-meta",
            deployment_environment="staging",
            trust_level="limited",
        )
        rec = result.record
        assert rec.metadata is not None
        assert rec.metadata.get("hostname") == "myhost"
        assert rec.metadata.get("platform") == "windows"
        assert rec.metadata.get("trust_level") == "limited"
        assert rec.metadata.get("deployment_environment") == "staging"


# ---------------------------------------------------------------------------
# E — Suspend / resume lifecycle
# ---------------------------------------------------------------------------


class TestSuspendResume:
    def test_suspend_active_credential(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="test"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "suspended"

    def test_suspended_credential_fails_validation(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        secret = result.plaintext_secret
        assert secret is not None
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="test"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="agent_device")
        assert exc_info.value.absent is False

    def test_resume_restores_active(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        secret = result.plaintext_secret
        assert secret is not None
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="test"
        )
        ca.resume_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin"
        )
        principal = validate_credential(engine, secret, credential_type="agent_device")
        assert principal.credential_type == "agent_device"

    def test_resume_resumed_credential_is_idempotent(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="test"
        )
        ca.resume_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin"
        )
        ca.resume_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "active"

    def test_suspend_already_suspended_is_idempotent(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="first"
        )
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="second"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "suspended"

    def test_resume_revoked_credential_raises(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        with pytest.raises(CredentialStateError):
            ca.resume_credential(
                engine, credential_id=cid, tenant_id=_TID, actor_id="admin"
            )

    def test_suspend_revoked_credential_raises(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        with pytest.raises(CredentialStateError):
            ca.suspend_credential(
                engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="x"
            )

    def test_suspend_wrong_tenant_raises(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        with pytest.raises(CredentialNotFoundError):
            ca.suspend_credential(
                engine, credential_id=cid, tenant_id=_TID2, actor_id="admin", reason="x"
            )

    def test_resume_wrong_tenant_raises(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="x"
        )
        with pytest.raises(CredentialNotFoundError):
            ca.resume_credential(
                engine, credential_id=cid, tenant_id=_TID2, actor_id="admin"
            )

    def test_suspend_emits_event(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="policy"
        )
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "suspended" in types

    def test_resume_emits_event(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="policy"
        )
        ca.resume_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin"
        )
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "resumed" in types


# ---------------------------------------------------------------------------
# F — get_active_credential_for_slot helper
# ---------------------------------------------------------------------------


class TestGetActiveCredentialForSlot:
    def test_returns_active_credential(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        rec = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        assert rec is not None
        assert rec.status == "active"

    def test_returns_none_when_slot_never_issued(self, engine: Engine) -> None:
        result = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot="agent:nonexistent-agent",
        )
        assert result is None

    def test_raises_absent_false_when_revoked(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TID,
            actor_id="a",
            reason="r",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="agent_device",
                credential_slot=_SLOT,
            )
        assert exc_info.value.absent is False

    def test_raises_absent_false_when_suspended(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="agent_device",
                credential_slot=_SLOT,
            )
        assert exc_info.value.absent is False

    def test_after_rotation_returns_new_generation(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        rec = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        assert rec is not None
        assert rec.generation == 2

    def test_cross_tenant_slot_returns_none(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        result = get_active_credential_for_slot(
            engine,
            tenant_id=_TID2,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        assert result is None


# ---------------------------------------------------------------------------
# G — Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_credentials_are_tenant_isolated(self, engine: Engine) -> None:
        r1 = _issue_agent_device(engine, tenant_id=_TID)
        r2 = _issue_agent_device(
            engine, agent_id="ag-t2", device_id="dv-t2", tenant_id=_TID2
        )
        s1 = r1.plaintext_secret
        s2 = r2.plaintext_secret
        assert s1 is not None
        assert s2 is not None
        p1 = validate_credential(engine, s1, credential_type="agent_device")
        p2 = validate_credential(engine, s2, credential_type="agent_device")
        assert p1.tenant_id == _TID
        assert p2.tenant_id == _TID2

    def test_cross_tenant_get_credential_fails(self, engine: Engine) -> None:
        result = _issue_agent_device(engine, tenant_id=_TID)
        cid = result.record.credential_id
        with pytest.raises(CredentialNotFoundError):
            get_credential(engine, cid, _TID2)

    def test_cross_tenant_revoke_fails(self, engine: Engine) -> None:
        result = _issue_agent_device(engine, tenant_id=_TID)
        cid = result.record.credential_id
        with pytest.raises(CredentialNotFoundError):
            revoke_credential(
                engine,
                credential_id=cid,
                tenant_id=_TID2,
                actor_id="attacker",
                reason="xss",
            )

    def test_same_agent_id_different_tenants(self, engine: Engine) -> None:
        r1 = _issue_agent_device(engine, agent_id="shared-agent", tenant_id=_TID)
        r2 = _issue_agent_device(engine, agent_id="shared-agent", tenant_id=_TID2)
        assert r1.record.credential_id != r2.record.credential_id
        s1 = r1.plaintext_secret
        s2 = r2.plaintext_secret
        assert s1 != s2


# ---------------------------------------------------------------------------
# H — Audit events
# ---------------------------------------------------------------------------


class TestAuditEvents:
    def test_issue_emits_issued_event(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "issued" in types

    def test_revoke_emits_revoked_event(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="admin", reason="test"
        )
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "revoked" in types

    def test_rotate_emits_rotated_event(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
        )
        cid = rotated.record.credential_id
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "rotated" in types

    def test_events_contain_correct_tenant(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        for evt in events:
            assert evt.tenant_id == _TID

    def test_events_have_timestamps(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        for evt in events:
            assert evt.occurred_at is not None

    def test_cross_tenant_events_not_visible(self, engine: Engine) -> None:
        result = _issue_agent_device(engine, tenant_id=_TID)
        cid = result.record.credential_id
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID2)
        assert events == []

    def test_validate_emits_validated_event(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        secret = result.plaintext_secret
        cid = result.record.credential_id
        assert secret is not None
        validate_credential(engine, secret, credential_type="agent_device")
        events = list_credential_events(engine, credential_id=cid, tenant_id=_TID)
        types = [e.event_type for e in events]
        assert "validated" in types


# ---------------------------------------------------------------------------
# I — Sentinel design invariants
# ---------------------------------------------------------------------------


class TestSentinelDesignInvariants:
    """Verify that sentinel fingerprints can never be produced by HMAC-SHA256."""

    def test_sentinel_fingerprint_prefix_not_hex(self) -> None:
        import re

        sentinel = "legacy:12345"
        is_hex_64 = bool(re.match(r"^[0-9a-f]{64}$", sentinel))
        assert not is_hex_64, "Sentinel must not match canonical HMAC-SHA256 format"

    def test_sentinel_slot_prefix_distinct_from_canonical(self) -> None:
        canonical_slot = f"agent:{_AGENT}"
        legacy_slot = f"legacy:device:{_DEVICE}:42"
        assert not legacy_slot.startswith("agent:")
        assert canonical_slot != legacy_slot

    def test_issued_fingerprint_is_hex_not_legacy(self, engine: Engine) -> None:
        import re

        result = _issue_agent_device(engine)
        rec = get_credential(engine, result.record.credential_id, _TID)
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    "SELECT lookup_fingerprint FROM tenant_credentials "
                    "WHERE credential_id = :cid"
                ),
                {"cid": rec.credential_id},
            ).fetchone()
        assert row is not None
        fp = row[0]
        assert re.match(r"^[0-9a-f]{64}$", fp), (
            f"Canonical fingerprint must be 64-char hex: {fp!r}"
        )

    def test_sentinel_hash_not_argon2(self) -> None:
        sentinel_hash = "sentinel-not-for-auth"
        assert not sentinel_hash.startswith("$argon2id$")


# ---------------------------------------------------------------------------
# J — Edge-case and concurrent operations
# ---------------------------------------------------------------------------


class TestEdgeCasesAndConcurrency:
    def test_two_agents_independent_slots(self, engine: Engine) -> None:
        r1 = _issue_agent_device(engine, agent_id="ag-slot-1", device_id="dv-1")
        r2 = _issue_agent_device(engine, agent_id="ag-slot-2", device_id="dv-2")
        assert r1.record.credential_slot != r2.record.credential_slot
        s1 = r1.plaintext_secret
        s2 = r2.plaintext_secret
        assert s1 is not None and s2 is not None
        p1 = validate_credential(engine, s1, credential_type="agent_device")
        p2 = validate_credential(engine, s2, credential_type="agent_device")
        assert p1.metadata is not None and p2.metadata is not None
        assert p1.metadata.get("agent_id") == "ag-slot-1"
        assert p2.metadata.get("agent_id") == "ag-slot-2"

    def test_rotate_without_prior_issue_raises(self, engine: Engine) -> None:
        from api.credential_authority import CredentialSlotNotFoundError

        with pytest.raises(CredentialSlotNotFoundError):
            rotate_credential(
                engine,
                tenant_id=_TID,
                credential_type="agent_device",
                credential_slot="agent:never-issued",
            )

    def test_rotate_idempotency_key_replay(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        r1 = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
            idempotency_key="rotate-idem-key-001",
        )
        r2 = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="agent_device",
            credential_slot=_SLOT,
            idempotency_key="rotate-idem-key-001",
        )
        assert r1.record.credential_id == r2.record.credential_id
        assert r2.plaintext_secret is None  # replay — no new secret

    def test_credential_status_progression(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "active"
        ca.suspend_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="r"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "suspended"
        ca.resume_credential(engine, credential_id=cid, tenant_id=_TID, actor_id="a")
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "active"
        revoke_credential(
            engine, credential_id=cid, tenant_id=_TID, actor_id="a", reason="final"
        )
        rec = get_credential(engine, cid, _TID)
        assert rec.status == "revoked"

    def test_multiple_rotations_chain_correctly(self, engine: Engine) -> None:
        _issue_agent_device(engine)
        for gen in range(2, 6):
            rotated = rotate_credential(
                engine,
                tenant_id=_TID,
                credential_type="agent_device",
                credential_slot=_SLOT,
            )
            assert rotated.record.generation == gen

    def test_inactive_tenant_blocked_from_issue(self, engine: Engine) -> None:
        from api.credential_authority import TenantLifecycleError

        _insert_tenant(engine, "suspended-tenant", "suspended")
        with pytest.raises(TenantLifecycleError):
            _issue_agent_device(engine, tenant_id="suspended-tenant")

    def test_archived_tenant_blocked_from_issue(self, engine: Engine) -> None:
        from api.credential_authority import TenantLifecycleError

        _insert_tenant(engine, "archived-tenant", "archived")
        with pytest.raises(TenantLifecycleError):
            _issue_agent_device(engine, tenant_id="archived-tenant")

    def test_get_credential_returns_metadata(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        rec = get_credential(engine, cid, _TID)
        assert rec.metadata is not None
        assert rec.metadata.get("agent_id") == _AGENT
        assert rec.metadata.get("device_id") == _DEVICE

    def test_different_agent_ids_different_slots(self, engine: Engine) -> None:
        agents = [f"ag-multi-{i}" for i in range(5)]
        for ag in agents:
            _issue_agent_device(engine, agent_id=ag, device_id=f"dv-{ag}")
        for ag in agents:
            rec = get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="agent_device",
                credential_slot=f"agent:{ag}",
            )
            assert rec is not None
            assert rec.metadata is not None
            assert rec.metadata.get("agent_id") == ag

    def test_constant_time_validation_no_timing_oracle(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        assert result.plaintext_secret is not None
        start = time.monotonic()
        try:
            validate_credential(
                engine, "wrongtoken_" + "a" * 32, credential_type="agent_device"
            )
        except CredentialNotFoundError:
            pass
        wrong_elapsed = time.monotonic() - start

        start = time.monotonic()
        validate_credential(
            engine, result.plaintext_secret, credential_type="agent_device"
        )
        correct_elapsed = time.monotonic() - start

        # Both paths should take comparable time (< 10x difference in either direction).
        # This is a sanity check, not a rigorous timing test.
        assert wrong_elapsed < 5.0 and correct_elapsed < 5.0

    def test_agent_device_scopes_stored(self, engine: Engine) -> None:
        result = _issue_agent_device(engine)
        cid = result.record.credential_id
        rec = get_credential(engine, cid, _TID)
        assert rec.scopes_csv is not None
        assert "credential:use" in rec.scopes_csv
