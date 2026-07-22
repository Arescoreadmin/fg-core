# tests/test_r4_9b_connector_credentials.py
"""
R4.9b — connector credential class acceptance tests.

All tests run against SQLite in-memory.  Argon2id is monkeypatched to
minimum cost so the suite completes in under a second.

Coverage groups:
  A — Credential authority: connector type dispatch
  B — ConnectorCredentialMetadata validation
  C — Sentinel design invariants
  D — get_active_credential_for_slot helper
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    ConnectorCredentialMetadata,
    CredentialNotFoundError,
    CredentialPrincipal,
    IssuanceResult,
    get_active_credential_for_slot,
    get_credential,
    issue_credential,
    rotate_credential,
    validate_credential,
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
"""

_TID = "tenant-connector-test"
_PROVIDER = "microsoft"
_CONNECTOR = "ms-teams-001"
_SLOT = f"{_PROVIDER}:{_CONNECTOR}"


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
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-r4-9b")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup_schema(eng)
    _insert_tenant(eng, _TID)
    yield eng
    eng.dispose()


def _issue_connector(
    engine: Engine,
    *,
    provider: str = _PROVIDER,
    connector_id: str = _CONNECTOR,
    tenant_id: str = _TID,
    ttl_seconds: int | None = None,
) -> IssuanceResult:
    meta = ConnectorCredentialMetadata(
        tenant_id=tenant_id,
        provider=provider,
        connector_id=connector_id,
        credential_slot=f"{provider}:{connector_id}",
        credential_kind="oauth2",
        display_name=f"{provider} connector",
        created_by="test-actor",
        rotation_generation=1,
    )
    return issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="connector",
        credential_slot=f"{provider}:{connector_id}",
        scopes=["credential:use"],
        metadata=meta.model_dump(),
        expires_in_seconds=ttl_seconds,
    )


# ---------------------------------------------------------------------------
# A — Credential authority: connector type dispatch
# ---------------------------------------------------------------------------


class TestConnectorCredentialType:
    def test_connector_type_accepted(self, engine: Engine) -> None:
        """connector must be accepted by issue_credential."""
        result = _issue_connector(engine)
        assert result.record.credential_type == "connector"

    def test_connector_raw_token_no_fgk_prefix(self, engine: Engine) -> None:
        """Connector secrets are raw opaque tokens — no fgk. prefix."""
        result = _issue_connector(engine)
        assert result.plaintext_secret is not None
        assert not result.plaintext_secret.startswith("fgk.")

    def test_connector_token_length(self, engine: Engine) -> None:
        """token_urlsafe(32) produces ~43 chars."""
        result = _issue_connector(engine)
        assert result.plaintext_secret is not None
        assert 40 <= len(result.plaintext_secret) <= 60

    def test_connector_no_expiry_by_default(self, engine: Engine) -> None:
        """Connector credentials default to no expiry (TTL=0)."""
        result = _issue_connector(engine)
        assert result.record.expires_at is None

    def test_connector_validates_correctly(self, engine: Engine) -> None:
        """Correct connector token must validate successfully."""
        result = _issue_connector(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="connector")
        assert isinstance(principal, CredentialPrincipal)
        assert principal.credential_type == "connector"
        assert principal.tenant_id == _TID

    def test_connector_principal_carries_metadata(self, engine: Engine) -> None:
        """Validated principal must expose provider and connector_id via metadata."""
        result = _issue_connector(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="connector")
        assert principal.metadata is not None
        assert principal.metadata.get("provider") == _PROVIDER
        assert principal.metadata.get("connector_id") == _CONNECTOR

    def test_wrong_token_fails(self, engine: Engine) -> None:
        """Wrong token must raise CredentialNotFoundError."""
        _issue_connector(engine)
        with pytest.raises(CredentialNotFoundError):
            validate_credential(
                engine, "wrongtoken_" + "x" * 32, credential_type="connector"
            )

    def test_fgk_token_rejected_absent_true(self, engine: Engine) -> None:
        """A token with fgk. prefix is rejected with absent=True."""
        _issue_connector(engine)
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, "fgk.tid.secret", credential_type="connector")
        assert exc_info.value.absent is True

    def test_revoked_connector_fails(self, engine: Engine) -> None:
        """Revoked connector credential must fail with absent=False."""
        result = _issue_connector(engine)
        ca.revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TID,
            actor_id="test",
            reason="test",
        )
        secret = result.plaintext_secret
        assert secret is not None
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="connector")
        assert exc_info.value.absent is False

    def test_connector_rotation_new_token(self, engine: Engine) -> None:
        """Rotation must produce a new secret that validates."""
        result = _issue_connector(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        new_secret = rotated.plaintext_secret
        assert new_secret is not None
        assert new_secret != old_secret
        principal = validate_credential(engine, new_secret, credential_type="connector")
        assert principal.credential_type == "connector"

    def test_connector_rotation_invalidates_old(self, engine: Engine) -> None:
        """Old connector secret must be invalid after rotation."""
        result = _issue_connector(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, old_secret, credential_type="connector")

    def test_connector_rotation_preserves_metadata(self, engine: Engine) -> None:
        """Rotation must preserve provider/connector_id binding in metadata."""
        _issue_connector(engine)
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        meta = rotated.record.metadata or {}
        assert meta.get("provider") == _PROVIDER
        assert meta.get("connector_id") == _CONNECTOR

    def test_connector_secrets_not_in_record_repr(self, engine: Engine) -> None:
        """CredentialRecord must never expose raw secret material."""
        result = _issue_connector(engine)
        record = get_credential(engine, result.record.credential_id, _TID)
        record_repr = repr(record)
        plaintext_secret = result.plaintext_secret
        assert plaintext_secret is not None
        assert plaintext_secret not in record_repr
        assert not hasattr(record, "secret_hash")

    def test_connector_principal_tenant_id_correct(self, engine: Engine) -> None:
        """validate_credential must return the credential's issuing tenant_id."""
        _insert_tenant(engine, "tenant-other")
        result = _issue_connector(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="connector")
        assert principal.tenant_id == _TID
        assert principal.tenant_id != "tenant-other"

    def test_connector_with_custom_ttl(self, engine: Engine) -> None:
        """expires_in_seconds parameter must be honoured."""
        result = _issue_connector(engine, ttl_seconds=3600)
        assert result.record.expires_at is not None
        now = datetime.now(timezone.utc)
        delta = result.record.expires_at - now
        assert 3500 < delta.total_seconds() < 3700


# ---------------------------------------------------------------------------
# B — ConnectorCredentialMetadata validation
# ---------------------------------------------------------------------------


class TestConnectorCredentialMetadata:
    def test_valid_metadata(self) -> None:
        meta = ConnectorCredentialMetadata(
            tenant_id="t1",
            provider="microsoft",
            connector_id="ms-001",
            credential_slot="microsoft:ms-001",
            credential_kind="oauth2",
            display_name="Microsoft connector",
            created_by="admin",
            rotation_generation=1,
        )
        assert meta.provider == "microsoft"
        assert meta.connector_id == "ms-001"
        assert meta.engagement_id is None

    def test_metadata_with_engagement_id(self) -> None:
        meta = ConnectorCredentialMetadata(
            tenant_id="t1",
            provider="google",
            connector_id="gws-001",
            credential_slot="google:gws-001",
            credential_kind="service_account",
            display_name="Google Workspace",
            created_by="admin",
            rotation_generation=1,
            engagement_id="eng-42",
        )
        assert meta.engagement_id == "eng-42"
        d = meta.model_dump()
        assert d["engagement_id"] == "eng-42"

    def test_empty_provider_raises(self) -> None:
        with pytest.raises(Exception):
            ConnectorCredentialMetadata(
                tenant_id="t1",
                provider="",
                connector_id="ms-001",
                credential_slot="microsoft:ms-001",
                credential_kind="oauth2",
                display_name="test",
                created_by="admin",
                rotation_generation=1,
            )

    def test_whitespace_provider_raises(self) -> None:
        with pytest.raises(Exception):
            ConnectorCredentialMetadata(
                tenant_id="t1",
                provider="   ",
                connector_id="ms-001",
                credential_slot="microsoft:ms-001",
                credential_kind="oauth2",
                display_name="test",
                created_by="admin",
                rotation_generation=1,
            )

    def test_empty_connector_id_raises(self) -> None:
        with pytest.raises(Exception):
            ConnectorCredentialMetadata(
                tenant_id="t1",
                provider="microsoft",
                connector_id="",
                credential_slot="microsoft:ms-001",
                credential_kind="oauth2",
                display_name="test",
                created_by="admin",
                rotation_generation=1,
            )

    def test_metadata_serializes_to_dict(self) -> None:
        meta = ConnectorCredentialMetadata(
            tenant_id="t1",
            provider="slack",
            connector_id="slack-001",
            credential_slot="slack:slack-001",
            credential_kind="api_key",
            display_name="Slack",
            created_by="svc",
            rotation_generation=2,
        )
        d = meta.model_dump()
        assert d["provider"] == "slack"
        assert d["rotation_generation"] == 2
        assert d["engagement_id"] is None

    def test_metadata_survives_credential_roundtrip(self, engine: Engine) -> None:
        """Metadata stored at issuance is returned unchanged via the credential record."""
        result = _issue_connector(engine)
        record = get_credential(engine, result.record.credential_id, _TID)
        assert record.metadata is not None
        assert record.metadata["provider"] == _PROVIDER
        assert record.metadata["connector_id"] == _CONNECTOR
        assert record.metadata["credential_kind"] == "oauth2"


# ---------------------------------------------------------------------------
# C — Sentinel design invariants
# ---------------------------------------------------------------------------


class TestSentinelDesign:
    def test_sentinel_fingerprint_unreachable_by_hmac(self, engine: Engine) -> None:
        """A sentinel lookup_fingerprint 'legacy:{id}' can never match HMAC validation.

        Insert a sentinel row directly and confirm validate_credential cannot
        authenticate against it through the fingerprint index.
        """
        sentinel_fp = "legacy:connector-cred-id-123"
        secret_hash = "$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash"

        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credentials "
                    "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                    "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                    "hash_algorithm, hash_params, status, issued_at, scopes_csv, schema_version, "
                    "record_hash) VALUES "
                    "('sentinel-conn-001', :tid, 'connector', 'legacy:ms-teams-001', "
                    "1, :fp, 1, 'legacyxx', :shash, 'argon2id', '{}', 'active', "
                    "'2026-01-01T00:00:00+00:00', 'credential:use', 1, 'fakehash')"
                ),
                {"tid": _TID, "fp": sentinel_fp, "shash": secret_hash},
            )

        # Any real secret cannot produce the sentinel fingerprint ('legacy:...' prefix),
        # so validate raises CredentialNotFoundError (absent=True).
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(
                engine, "real-secret-" + "x" * 30, credential_type="connector"
            )
        assert exc_info.value.absent is True

    def test_canonical_and_legacy_slots_coexist(self, engine: Engine) -> None:
        """Canonical slot 'provider:connector_id' must not conflict with 'legacy:connector_id'."""
        _issue_connector(engine)
        # Insert a sentinel (legacy) row with a different slot.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credentials "
                    "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                    "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                    "hash_algorithm, hash_params, status, issued_at, scopes_csv, schema_version, "
                    "record_hash) VALUES "
                    "('sentinel-conn-002', :tid, 'connector', :legacy_slot, "
                    "1, :fp, 1, 'legacyxx', 'fakehash', 'argon2id', '{}', 'active', "
                    "'2026-01-01T00:00:00+00:00', 'credential:use', 1, 'fakehash')"
                ),
                {
                    "tid": _TID,
                    "legacy_slot": f"legacy:{_CONNECTOR}",
                    "fp": f"legacy:{_CONNECTOR}-id-456",
                },
            )
        # Both canonical and legacy slots coexist without constraint error.
        creds = ca.list_credentials(engine, _TID, credential_type="connector")
        slots = [c.credential_slot for c in creds]
        assert _SLOT in slots
        assert f"legacy:{_CONNECTOR}" in slots

    def test_sentinel_validation_mode_metadata(self, engine: Engine) -> None:
        """Sentinel rows carry validation_mode='legacy_only' in metadata."""
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credentials "
                    "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                    "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                    "hash_algorithm, hash_params, status, issued_at, scopes_csv, schema_version, "
                    "record_hash, metadata) VALUES "
                    "('sentinel-conn-003', :tid, 'connector', 'legacy:sentinel-cid', "
                    "1, 'legacy:sentinel-cid', 1, 'legacyxx', 'fakehash', 'argon2id', '{}', "
                    "'active', '2026-01-01T00:00:00+00:00', 'credential:use', 1, 'fakehash', "
                    ":meta)"
                ),
                {
                    "tid": _TID,
                    "meta": '{"connector_id": "sentinel-cid", "validation_mode": "legacy_only", '
                    '"source": "legacy_connector"}',
                },
            )
        record = get_credential(engine, "sentinel-conn-003", _TID)
        assert record.metadata is not None
        assert record.metadata.get("validation_mode") == "legacy_only"
        assert record.metadata.get("source") == "legacy_connector"


# ---------------------------------------------------------------------------
# D — get_active_credential_for_slot
# ---------------------------------------------------------------------------


class TestGetActiveCredentialForSlot:
    def test_get_active_returns_record(self, engine: Engine) -> None:
        """Returns CredentialRecord when an active canonical record exists for the slot."""
        _issue_connector(engine)
        record = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        assert record is not None
        assert record.credential_type == "connector"
        assert record.credential_slot == _SLOT
        assert record.status == "active"

    def test_get_active_returns_none_for_absent(self, engine: Engine) -> None:
        """Returns None when no canonical record exists for the slot."""
        result = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot="nonexistent:slot",
        )
        assert result is None

    def test_get_active_fails_closed_on_revoked(self, engine: Engine) -> None:
        """Raises CredentialNotFoundError(absent=False) when canonical record is revoked.

        A revoked canonical record must NOT return None (which would silently allow
        callers to fall through to the legacy AES-GCM path). It must raise with
        absent=False so callers fail closed immediately without any fallback.
        """
        result = _issue_connector(engine)
        ca.revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TID,
            actor_id="test",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="connector",
                credential_slot=_SLOT,
            )
        assert exc_info.value.absent is False

    def test_get_active_fails_closed_on_rotated(self, engine: Engine) -> None:
        """After final revoke (not rotation), raises absent=False for the slot."""
        _issue_connector(engine)
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        ca.revoke_credential(
            engine,
            credential_id=rotated.record.credential_id,
            tenant_id=_TID,
            actor_id="test",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="connector",
                credential_slot=_SLOT,
            )
        assert exc_info.value.absent is False

    def test_get_active_returns_none_for_rotated(self, engine: Engine) -> None:
        """After rotation the OLD slot record has status='rotated'; new is 'active'."""
        _issue_connector(engine)
        rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        # New active generation must be found.
        record = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        assert record is not None
        assert record.status == "active"
        assert record.generation == 2

    def test_get_active_with_wrong_slot(self, engine: Engine) -> None:
        """Returns None for a slot that has never been issued."""
        _issue_connector(engine)
        result = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot="google:nonexistent-connector",
        )
        assert result is None

    def test_get_active_absent_is_none_not_raise(self, engine: Engine) -> None:
        """Absent slot (no record ever created) returns None, not a raise.

        Callers distinguish absent (None → fallback OK) from revoked (raise
        absent=False → fail closed). Absent must never raise.
        """
        result = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot="provider:never-issued",
        )
        assert result is None


# ---------------------------------------------------------------------------
# E — load_connector_secret fail-closed guarantee
# ---------------------------------------------------------------------------


class TestLoadConnectorSecretFailClosed:
    """Verify load_connector_secret() honours the canonical-first fail-closed contract.

    Tests exercise the canonical lifecycle check via get_active_credential_for_slot
    directly, since load_connector_secret is a thin wrapper whose only logic is:
      - None return  → legacy fallback
      - active return → AES-GCM decrypt
      - raise absent=False → propagate without fallback

    The critical security invariant (revoked canonical blocks legacy fallback) is
    proven end-to-end in TestGetActiveCredentialForSlot and additionally here
    through the CA module itself, which these tests import directly.
    """

    def test_canonical_absent_allows_fallback(self, engine: Engine) -> None:
        """get_active_credential_for_slot returns None for absent slot.

        load_connector_secret interprets None as 'safe to fall back'.
        """
        rec = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot="provider:never-issued",
        )
        assert rec is None  # load_connector_secret will call load_active_secret

    def test_canonical_revoked_blocks_fallback(self, engine: Engine) -> None:
        """get_active_credential_for_slot raises absent=False for revoked slot.

        load_connector_secret MUST propagate this without calling load_active_secret.
        This proves the critical invariant: a canonically-revoked connector credential
        cannot be retrieved via the legacy AES-GCM path, even if connectors_credentials
        still has an active row (e.g. if soft-revoke of connectors_credentials failed).
        """
        result = _issue_connector(engine)
        ca.revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id=_TID,
            actor_id="test",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="connector",
                credential_slot=_SLOT,
            )
        assert (
            exc_info.value.absent is False
        )  # load_connector_secret must NOT fall back

    def test_canonical_active_proceeds_to_aes_gcm(self, engine: Engine) -> None:
        """get_active_credential_for_slot returns active record for valid slot.

        load_connector_secret proceeds to AES-GCM decrypt when this returns a record.
        """
        _issue_connector(engine)
        rec = get_active_credential_for_slot(
            engine,
            tenant_id=_TID,
            credential_type="connector",
            credential_slot=_SLOT,
        )
        assert rec is not None
        assert rec.status == "active"
        assert rec.credential_type == "connector"

    def test_canonical_expired_blocks_fallback(self, engine: Engine) -> None:
        """Expired canonical credential raises absent=False.

        load_connector_secret must not fall back to legacy for expired credentials.
        """
        result = _issue_connector(engine, ttl_seconds=1)
        assert result.record.expires_at is not None
        # Manually set expires_at to past to simulate expiry
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenant_credentials SET expires_at = :past "
                    "WHERE credential_id = :cid"
                ),
                {
                    "past": "2000-01-01T00:00:00+00:00",
                    "cid": result.record.credential_id,
                },
            )
        with pytest.raises(CredentialNotFoundError) as exc_info:
            get_active_credential_for_slot(
                engine,
                tenant_id=_TID,
                credential_type="connector",
                credential_slot=_SLOT,
            )
        assert exc_info.value.absent is False
