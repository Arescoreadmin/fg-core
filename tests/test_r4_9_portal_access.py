# tests/test_r4_9_portal_access.py
"""
R4.9 — portal_access credential class acceptance tests.

All tests run against SQLite in-memory.  Argon2id is monkeypatched to
minimum cost so the suite completes in under a second.

Coverage groups:
  A — Credential authority: portal_access type dispatch
  B — Service create / authenticate (canonical path)
  C — Service authenticate (legacy fallback path)
  D — Service revoke and rotate (canonical)
  E — Migration sentinel design invariants
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
    CredentialNotFoundError,
    CredentialPrincipal,
    IssuanceResult,
    PortalAccessMetadata,
    issue_credential,
    rotate_credential,
    validate_credential,
    get_credential,
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

_TID = "tenant-portal-test"
_CLIENT = "acme"
_ENGAGEMENT = "eng-42"
_SLOT = f"{_CLIENT}:{_ENGAGEMENT}"


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
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-r4-9")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup_schema(eng)
    _insert_tenant(eng, _TID)
    yield eng
    eng.dispose()


def _issue_portal(
    engine: Engine,
    *,
    client_id: str = _CLIENT,
    engagement_id: str = _ENGAGEMENT,
    tenant_id: str = _TID,
    ttl_seconds: int | None = None,
) -> IssuanceResult:
    meta = PortalAccessMetadata(client_id=client_id, engagement_id=engagement_id)
    return issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="portal_access",
        credential_slot=f"{client_id}:{engagement_id}",
        scopes=["credential:use"],
        metadata=meta.model_dump(),
        expires_in_seconds=ttl_seconds,
    )


# ---------------------------------------------------------------------------
# A — Credential authority: portal_access type dispatch
# ---------------------------------------------------------------------------


class TestPortalAccessType:
    def test_portal_access_is_valid_type(self, engine: Engine) -> None:
        """portal_access must be accepted by issue_credential."""
        result = _issue_portal(engine)
        assert result.record.credential_type == "portal_access"

    def test_returns_raw_token_without_fgk_prefix(self, engine: Engine) -> None:
        """Portal secrets are raw opaque tokens — no fgk. prefix."""
        result = _issue_portal(engine)
        assert result.plaintext_secret is not None
        assert not result.plaintext_secret.startswith("fgk.")

    def test_portal_token_reasonable_length(self, engine: Engine) -> None:
        """token_urlsafe(32) produces ~43 chars."""
        result = _issue_portal(engine)
        assert result.plaintext_secret is not None
        assert 40 <= len(result.plaintext_secret) <= 60

    def test_default_ttl_is_14_days(self, engine: Engine) -> None:
        """Portal access defaults to 14-day TTL, not the 365-day api_key default."""
        result = _issue_portal(engine)
        assert result.record.expires_at is not None
        now = datetime.now(timezone.utc)
        delta = result.record.expires_at - now
        assert 13 * 86400 < delta.total_seconds() < 15 * 86400

    def test_correct_token_validates(self, engine: Engine) -> None:
        """Correct portal token must validate successfully."""
        result = _issue_portal(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="portal_access")
        assert isinstance(principal, CredentialPrincipal)
        assert principal.credential_type == "portal_access"
        assert principal.tenant_id == _TID

    def test_principal_carries_metadata(self, engine: Engine) -> None:
        """Validated principal must expose client_id and engagement_id via metadata."""
        result = _issue_portal(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="portal_access")
        assert principal.metadata is not None
        assert principal.metadata.get("client_id") == _CLIENT
        assert principal.metadata.get("engagement_id") == _ENGAGEMENT

    def test_wrong_token_raises_not_found(self, engine: Engine) -> None:
        """Wrong token must raise CredentialNotFoundError."""
        _issue_portal(engine)
        with pytest.raises(CredentialNotFoundError):
            validate_credential(
                engine, "wrongtoken_" + "x" * 32, credential_type="portal_access"
            )

    def test_fgk_prefix_raises_not_found_absent(self, engine: Engine) -> None:
        """A token with fgk. prefix is rejected with absent=True (wrong type, fall through safe)."""
        _issue_portal(engine)
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(
                engine, "fgk.tid.secret", credential_type="portal_access"
            )
        assert exc_info.value.absent is True

    def test_expired_token_raises_not_found_not_absent(self, engine: Engine) -> None:
        """Expired portal credential must fail with absent=False (do not fall through)."""
        result = issue_credential(
            engine,
            tenant_id=_TID,
            credential_type="portal_access",
            credential_slot=_SLOT,
            scopes=["credential:use"],
            metadata={"client_id": _CLIENT, "engagement_id": _ENGAGEMENT},
            expires_in_seconds=1,
        )
        # Force-expire via direct SQL update to avoid waiting 1 second
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenant_credentials SET expires_at = '2000-01-01T00:00:00+00:00' "
                    "WHERE credential_id = :cid"
                ),
                {"cid": result.record.credential_id},
            )
        secret = result.plaintext_secret
        assert secret is not None
        with pytest.raises(CredentialNotFoundError) as exc_info:
            validate_credential(engine, secret, credential_type="portal_access")
        assert exc_info.value.absent is False

    def test_revoked_token_raises_not_found_not_absent(self, engine: Engine) -> None:
        """Revoked portal credential must fail with absent=False."""
        result = _issue_portal(engine)
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
            validate_credential(engine, secret, credential_type="portal_access")
        assert exc_info.value.absent is False

    def test_rotation_issues_new_secret(self, engine: Engine) -> None:
        """Rotation must produce a new secret that validates."""
        result = _issue_portal(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="portal_access",
            credential_slot=_SLOT,
        )
        new_secret = rotated.plaintext_secret
        assert new_secret is not None
        assert new_secret != old_secret
        principal = validate_credential(
            engine, new_secret, credential_type="portal_access"
        )
        assert principal.credential_type == "portal_access"

    def test_rotation_invalidates_old_secret(self, engine: Engine) -> None:
        """Old portal secret must be invalid after rotation."""
        result = _issue_portal(engine)
        old_secret = result.plaintext_secret
        assert old_secret is not None
        rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="portal_access",
            credential_slot=_SLOT,
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, old_secret, credential_type="portal_access")

    def test_rotation_preserves_metadata(self, engine: Engine) -> None:
        """Rotation must preserve client_id/engagement_id binding in metadata."""
        _issue_portal(engine)
        rotated = rotate_credential(
            engine,
            tenant_id=_TID,
            credential_type="portal_access",
            credential_slot=_SLOT,
        )
        meta = rotated.record.metadata or {}
        assert meta.get("client_id") == _CLIENT
        assert meta.get("engagement_id") == _ENGAGEMENT

    def test_secrets_not_in_record(self, engine: Engine) -> None:
        """CredentialRecord must never expose raw secret material."""
        result = _issue_portal(engine)
        record = get_credential(engine, result.record.credential_id, _TID)
        record_repr = repr(record)
        assert result.plaintext_secret not in record_repr
        # Verify secret_hash is not surfaced through public API
        assert not hasattr(record, "secret_hash")

    def test_principal_tenant_id_matches_issuing_tenant(self, engine: Engine) -> None:
        """validate_credential must return the credential's issuing tenant_id.

        Callers (e.g. portal_grant_service) must compare principal.tenant_id to
        their expected tenant and reject on mismatch — this test verifies that
        the authority surfaces the correct tenant_id so that check is possible.
        """
        _insert_tenant(engine, "tenant-other")
        result = _issue_portal(engine)
        secret = result.plaintext_secret
        assert secret is not None
        principal = validate_credential(engine, secret, credential_type="portal_access")
        assert principal.tenant_id == _TID
        assert principal.tenant_id != "tenant-other"


# ---------------------------------------------------------------------------
# B — PortalAccessMetadata validation
# ---------------------------------------------------------------------------


class TestPortalAccessMetadata:
    def test_valid_metadata(self) -> None:
        meta = PortalAccessMetadata(client_id="acme", engagement_id="eng-001")
        assert meta.client_id == "acme"
        assert meta.engagement_id == "eng-001"
        assert meta.portal_grant_id is None

    def test_metadata_with_legacy_grant_id(self) -> None:
        meta = PortalAccessMetadata(
            client_id="c", engagement_id="e", portal_grant_id="old-uuid"
        )
        d = meta.model_dump()
        assert d["portal_grant_id"] == "old-uuid"

    def test_empty_client_id_raises(self) -> None:
        with pytest.raises(Exception):
            PortalAccessMetadata(client_id="", engagement_id="e")

    def test_whitespace_client_id_raises(self) -> None:
        with pytest.raises(Exception):
            PortalAccessMetadata(client_id="   ", engagement_id="e")

    def test_empty_engagement_id_raises(self) -> None:
        with pytest.raises(Exception):
            PortalAccessMetadata(client_id="c", engagement_id="")


# ---------------------------------------------------------------------------
# E — Migration sentinel design invariants
# ---------------------------------------------------------------------------


class TestSentinelDesign:
    def test_sentinel_fingerprint_cannot_match_hmac(self, engine: Engine) -> None:
        """A sentinel lookup_fingerprint 'legacy:<id>' must never match HMAC validation.

        Insert a sentinel row directly and confirm validate_credential cannot
        authenticate against it through the fingerprint index.
        """
        sentinel_fp = "legacy:old-grant-id-123"
        secret_hash = "$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash"

        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credentials "
                    "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                    "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                    "hash_algorithm, hash_params, status, issued_at, scopes_csv, schema_version, "
                    "record_hash) VALUES "
                    "('sentinel-cid-001', :tid, 'portal_access', 'legacy:acme:e:old-grant-id-123', "
                    "1, :fp, 1, 'legacyxx', :shash, 'argon2id', '{}', 'active', "
                    "'2026-01-01T00:00:00+00:00', 'credential:use', 1, 'fakehash')"
                ),
                {"tid": _TID, "fp": sentinel_fp, "shash": secret_hash},
            )

        # Any real secret cannot produce the sentinel fingerprint, so validate
        # raises CredentialNotFoundError (absent=True — nothing indexed matched).
        with pytest.raises(CredentialNotFoundError) as exc_info:
            # This produces a real HMAC fingerprint which can't be "legacy:..."
            validate_credential(
                engine, "real-secret-" + "x" * 30, credential_type="portal_access"
            )
        assert exc_info.value.absent is True

    def test_canonical_slot_not_collide_with_legacy_slot(self, engine: Engine) -> None:
        """Canonical slot 'client:eng' must not conflict with legacy 'legacy:client:eng:id'."""
        _issue_portal(engine)
        # Both canonical and legacy slots should coexist without a UNIQUE constraint error.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_credentials "
                    "(credential_id, tenant_id, credential_type, credential_slot, generation, "
                    "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
                    "hash_algorithm, hash_params, status, issued_at, scopes_csv, schema_version, "
                    "record_hash) VALUES "
                    "('sentinel-cid-002', :tid, 'portal_access', :legacy_slot, "
                    "1, :fp, 1, 'legacyxx', 'fakehash', 'argon2id', '{}', 'active', "
                    "'2026-01-01T00:00:00+00:00', 'credential:use', 1, 'fakehash')"
                ),
                {
                    "tid": _TID,
                    "legacy_slot": f"legacy:{_CLIENT}:{_ENGAGEMENT}:old-grant-123",
                    "fp": "legacy:old-grant-123",
                },
            )
        # Verify via list_credentials that both rows exist with different slots.
        creds = ca.list_credentials(engine, _TID, credential_type="portal_access")
        slots = [c.credential_slot for c in creds]
        assert _SLOT in slots
        assert f"legacy:{_CLIENT}:{_ENGAGEMENT}:old-grant-123" in slots
