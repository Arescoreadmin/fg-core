# tests/test_r4_credential_authority.py
"""
R4.3 — Credential Authority tests.

Uses SQLite in-memory database.  Argon2id parameters are set to the minimum
allowed values via monkeypatch so the suite runs in under a second without
compromising code-path coverage.
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
    CredentialConflictError,
    CredentialNotFoundError,
    CredentialPrincipal,
    CredentialRecord,
    CredentialSlotNotFoundError,
    CredentialStateError,
    CredentialTypeError,
    IssuanceResult,
    TenantLifecycleError,
    TenantNotFoundError,
    expire_credentials,
    get_credential,
    get_credential_history,
    issue_credential,
    list_credentials,
    revoke_credential,
    rotate_credential,
    validate_credential,
)

# ---------------------------------------------------------------------------
# SQLite schema
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
"""


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
    """Replace module-level hasher with minimum-cost parameters for test speed."""
    monkeypatch.setattr(
        ca,
        "_HASHER",
        PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-value-for-r4-tests")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup_schema(eng)
    _insert_tenant(eng, "tenant-alpha")
    _insert_tenant(eng, "tenant-beta")
    yield eng
    eng.dispose()


# ---------------------------------------------------------------------------
# A — Models and errors
# ---------------------------------------------------------------------------


class TestA_Models:
    def test_credential_principal_repr_safe(self) -> None:
        p = CredentialPrincipal(
            tenant_id="t1",
            credential_id="c1",
            credential_type="tenant_api_key",
            credential_slot="prod",
            generation=1,
            scopes=frozenset({"credential:use"}),
            issued_at=datetime.now(timezone.utc),
        )
        assert "t1" in repr(p)
        assert "c1" in repr(p)

    def test_credential_record_repr_does_not_expose_hash(self) -> None:
        r = CredentialRecord(
            credential_id="c1",
            tenant_id="t1",
            credential_type="tenant_api_key",
            credential_slot="prod",
            generation=1,
            status="active",
            expires_at=None,
            issued_at=datetime.now(timezone.utc),
            activated_at=None,
            rotated_at=None,
            revoked_at=None,
            replaced_by_credential_id=None,
            created_by_actor_id=None,
            request_id=None,
            idempotency_key=None,
            last_used_at=None,
            approximate_use_count=0,
            scopes_csv="credential:use",
            schema_version=1,
            record_hash=None,
        )
        r_repr = repr(r)
        assert "secret" not in r_repr.lower()
        assert "hash" not in r_repr.lower()

    def test_issuance_result_repr_hides_secret(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="repr-test",
        )
        r_repr = repr(result)
        assert result.plaintext_secret not in r_repr
        assert "<present>" in r_repr

    def test_error_hierarchy(self) -> None:
        assert issubclass(CredentialNotFoundError, KeyError)
        assert issubclass(CredentialTypeError, ValueError)
        assert issubclass(TenantLifecycleError, PermissionError)
        assert issubclass(TenantNotFoundError, KeyError)
        assert issubclass(CredentialConflictError, RuntimeError)


# ---------------------------------------------------------------------------
# B — Hash helpers
# ---------------------------------------------------------------------------


class TestB_HashHelpers:
    def test_lookup_fingerprint_is_deterministic(self) -> None:
        fp1 = ca._compute_lookup_fingerprint("mysecret", "mypepper")
        fp2 = ca._compute_lookup_fingerprint("mysecret", "mypepper")
        assert fp1 == fp2

    def test_lookup_fingerprint_differs_by_secret(self) -> None:
        fp1 = ca._compute_lookup_fingerprint("secret-a", "pepper")
        fp2 = ca._compute_lookup_fingerprint("secret-b", "pepper")
        assert fp1 != fp2

    def test_lookup_fingerprint_differs_by_pepper(self) -> None:
        fp1 = ca._compute_lookup_fingerprint("secret", "pepper-a")
        fp2 = ca._compute_lookup_fingerprint("secret", "pepper-b")
        assert fp1 != fp2

    def test_record_hash_deterministic(self) -> None:
        kwargs = dict(
            credential_id="c1",
            tenant_id="t1",
            credential_type="tenant_api_key",
            credential_slot="prod",
            generation=1,
            issued_at="2026-01-01T00:00:00+00:00",
        )
        assert ca._compute_record_hash(**kwargs) == ca._compute_record_hash(**kwargs)

    def test_record_hash_differs_on_any_field_change(self) -> None:
        base = dict(
            credential_id="c1",
            tenant_id="t1",
            credential_type="tenant_api_key",
            credential_slot="prod",
            generation=1,
            issued_at="2026-01-01T00:00:00+00:00",
        )
        h_base = ca._compute_record_hash(**base)
        assert ca._compute_record_hash(**{**base, "generation": 2}) != h_base
        assert ca._compute_record_hash(**{**base, "tenant_id": "t2"}) != h_base
        assert (
            ca._compute_record_hash(**{**base, "credential_slot": "staging"}) != h_base
        )

    def test_generated_key_has_fgk_prefix(self, engine: Engine) -> None:
        raw_key, _, _, _ = ca._generate_key("t1", None)
        assert raw_key.startswith("fgk.")
        assert raw_key.count(".") >= 2

    def test_generated_keys_are_unique(self, engine: Engine) -> None:
        keys = {ca._generate_key("t1", None)[0] for _ in range(20)}
        assert len(keys) == 20

    def test_parse_key_extracts_tenant_hint(self) -> None:
        raw_key, _, _, _ = ca._generate_key("tenant-alpha", None)
        hint, _ = ca._parse_key(raw_key)
        assert hint == "tenant-alpha"

    def test_parse_key_rejects_malformed(self) -> None:
        with pytest.raises(CredentialNotFoundError):
            ca._parse_key("not-a-valid-key")
        with pytest.raises(CredentialNotFoundError):
            ca._parse_key("bad.two")
        with pytest.raises(CredentialNotFoundError):
            ca._parse_key("wrong.prefix.here.secret")


# ---------------------------------------------------------------------------
# C — Issuance
# ---------------------------------------------------------------------------


class TestC_Issuance:
    def test_issue_returns_plaintext_once(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        assert result.plaintext_secret is not None
        assert result.plaintext_secret.startswith("fgk.")

    def test_plaintext_not_stored_in_record(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        secret = result.plaintext_secret
        assert secret is not None
        # Read raw row from DB and confirm secret is absent
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT secret_hash, lookup_fingerprint, secret_prefix "
                    "FROM tenant_credentials WHERE credential_id = :cid"
                ),
                {"cid": result.record.credential_id},
            ).fetchone()
        assert secret not in (row[0], row[1], row[2])
        assert "$argon2" in row[0]  # PHC format stored, not plaintext

    def test_record_fields_populated(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            actor_id="actor-1",
        )
        rec = result.record
        assert rec.status == "active"
        assert rec.tenant_id == "tenant-alpha"
        assert rec.credential_type == "tenant_api_key"
        assert rec.credential_slot == "prod"
        assert rec.generation == 1
        assert rec.issued_at is not None
        assert rec.schema_version == 1
        assert rec.record_hash is not None
        assert rec.created_by_actor_id == "actor-1"

    def test_idempotency_replay_returns_no_plaintext(self, engine: Engine) -> None:
        first = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="idem-1",
        )
        second = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="idem-1",
        )
        assert second.plaintext_secret is None
        assert second.record.credential_id == first.record.credential_id

    def test_idempotency_keys_do_not_collide_across_tenants(
        self, engine: Engine
    ) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="shared-key",
        )
        r2 = issue_credential(
            engine,
            tenant_id="tenant-beta",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="shared-key",
        )
        # Different credential IDs — they are independent issuances.
        assert r1.record.credential_id != r2.record.credential_id
        assert r1.plaintext_secret is not None
        assert r2.plaintext_secret is not None

    def test_invalid_credential_type_rejected(self, engine: Engine) -> None:
        with pytest.raises(CredentialTypeError):
            issue_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="unknown_type",
                credential_slot="prod",
            )

    def test_unknown_tenant_fails_closed(self, engine: Engine) -> None:
        with pytest.raises(TenantNotFoundError):
            issue_credential(
                engine,
                tenant_id="does-not-exist",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )

    def test_generation_increments_per_slot(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-a",
        )
        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-b",
        )
        assert r1.record.generation == 1
        assert r2.record.generation == 1  # separate slot, resets

    def test_scopes_csv_defaults_to_credential_use(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        assert result.record.scopes_csv == "credential:use"

    def test_custom_expiry_recorded(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            expires_in_seconds=3600,
        )
        assert result.record.expires_at is not None

    def test_occupied_slot_rejects_second_issue(self, engine: Engine) -> None:
        """issue_credential on an occupied slot must raise, not silently add a second active row."""
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="occupied",
        )
        with pytest.raises(CredentialStateError):
            issue_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="occupied",
            )

    def test_issue_on_different_slot_succeeds(self, engine: Engine) -> None:
        """Slot guard is scoped: issuing on a new slot must succeed even if another slot is occupied."""
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-one",
        )
        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-two",
        )
        assert r2.record.credential_slot == "slot-two"
        assert r2.record.generation == 1


# ---------------------------------------------------------------------------
# D — Validation
# ---------------------------------------------------------------------------


class TestD_Validation:
    def _issue(self, engine: Engine, slot: str = "prod", **kw) -> IssuanceResult:
        return issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot=slot,
            **kw,
        )

    def test_correct_secret_accepted(self, engine: Engine) -> None:
        result = self._issue(engine)
        principal = validate_credential(engine, result.plaintext_secret)
        assert isinstance(principal, CredentialPrincipal)
        assert principal.tenant_id == "tenant-alpha"
        assert principal.credential_id == result.record.credential_id

    def test_principal_fields_populated(self, engine: Engine) -> None:
        result = self._issue(engine)
        p = validate_credential(engine, result.plaintext_secret)
        assert p.credential_type == "tenant_api_key"
        assert p.credential_slot == "prod"
        assert p.generation == 1
        assert "credential:use" in p.scopes
        assert p.authentication_method == "api_key"
        assert p.issued_at is not None

    def test_wrong_secret_rejected(self, engine: Engine) -> None:
        self._issue(engine)
        raw, _, _, _ = ca._generate_key("tenant-alpha", None)
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, raw)

    def test_malformed_key_rejected(self, engine: Engine) -> None:
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, "not-a-credential")

    def test_expired_credential_rejected_at_validation_time(
        self, engine: Engine
    ) -> None:
        result = self._issue(engine, expires_in_seconds=-1)
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, result.plaintext_secret)

    def test_revoked_credential_rejected(self, engine: Engine) -> None:
        result = self._issue(engine)
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, result.plaintext_secret)

    def test_rotated_credential_rejected(self, engine: Engine) -> None:
        result = self._issue(engine)
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, result.plaintext_secret)

    def test_validation_returns_principal_not_row(self, engine: Engine) -> None:
        result = self._issue(engine)
        principal = validate_credential(engine, result.plaintext_secret)
        assert not hasattr(principal, "secret_hash")
        assert not hasattr(principal, "lookup_fingerprint")
        assert not hasattr(principal, "hash_params")


# ---------------------------------------------------------------------------
# E — Rotation
# ---------------------------------------------------------------------------


class TestE_Rotation:
    def test_rotation_issues_new_generation(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        assert r2.record.generation == r1.record.generation + 1
        assert r2.plaintext_secret is not None
        assert r2.plaintext_secret != r1.plaintext_secret

    def test_old_secret_fails_after_rotation(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, r1.plaintext_secret)

    def test_new_secret_works_after_rotation(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        p = validate_credential(engine, r2.plaintext_secret)
        assert p.generation == 2

    def test_rotation_links_replaced_by_credential_id(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        old_rec = get_credential(engine, r1.record.credential_id, "tenant-alpha")
        assert old_rec.status == "rotated"
        assert old_rec.replaced_by_credential_id == r2.record.credential_id
        assert old_rec.rotated_at is not None

    def test_idempotency_replay_on_rotation_returns_no_plaintext(
        self, engine: Engine
    ) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="rotate-1",
        )
        replay = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="rotate-1",
        )
        assert replay.plaintext_secret is None
        assert replay.record.credential_id == r2.record.credential_id

    def test_rotation_on_empty_slot_raises(self, engine: Engine) -> None:
        with pytest.raises(CredentialSlotNotFoundError):
            rotate_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="never-issued",
            )

    def test_rotation_of_revoked_generation_raises(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="revoked-slot",
        )
        revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="test",
        )
        with pytest.raises(CredentialStateError):
            rotate_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="revoked-slot",
            )

    def test_rotation_of_expired_generation_raises(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="expired-slot",
            expires_in_seconds=-1,
        )
        expire_credentials(engine, tenant_id="tenant-alpha")
        with pytest.raises(CredentialStateError):
            rotate_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="expired-slot",
            )

    def test_rotation_chain_recorded_in_history(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="chain",
        )
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="chain",
        )
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="chain",
        )
        history = get_credential_history(engine, "tenant-alpha", "chain")
        assert len(history) == 3
        assert history[0].generation == 3
        assert history[1].generation == 2
        assert history[2].generation == 1

    def test_concurrent_rotation_conflict_via_conditional_update(
        self, engine: Engine
    ) -> None:
        """Simulate a lost conditional UPDATE (rowcount=0) — raises CredentialConflictError.

        The real race: Thread A reads current_gen=1, Thread B also reads current_gen=1,
        Thread B wins and advances the slot to current_gen=2.  Thread A's conditional
        UPDATE (WHERE current_generation = 1) now returns rowcount=0.

        We can't interrupt rotate_credential mid-flight in a single-threaded test, so
        we call _advance_slot_generation directly with a stale expected_generation.
        """
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="concurrent",
        )
        # Slot is now at current_generation=1.  Simulate Thread B winning by
        # advancing it to 2 without going through rotate_credential.
        now_iso = datetime.now(timezone.utc).isoformat()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE credential_slots SET current_generation = 2 "
                    "WHERE tenant_id = 'tenant-alpha' "
                    "  AND credential_type = 'tenant_api_key' "
                    "  AND credential_slot = 'concurrent'"
                )
            )
        # Thread A tries to advance from 1→2 but current_generation is now 2 → rowcount=0.
        with engine.begin() as conn:
            with pytest.raises(CredentialConflictError):
                ca._advance_slot_generation(
                    conn,
                    tenant_id="tenant-alpha",
                    credential_type="tenant_api_key",
                    credential_slot="concurrent",
                    expected_generation=1,
                    new_generation=2,
                    now_iso=now_iso,
                )


# ---------------------------------------------------------------------------
# F — Revocation
# ---------------------------------------------------------------------------


class TestF_Revocation:
    def _issue(self, engine: Engine, slot: str = "prod") -> IssuanceResult:
        return issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot=slot,
        )

    def test_revoke_marks_status_revoked(self, engine: Engine) -> None:
        r = self._issue(engine)
        rec = revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="policy",
        )
        assert rec.status == "revoked"
        assert rec.revoked_at is not None

    def test_revoke_is_idempotent(self, engine: Engine) -> None:
        r = self._issue(engine)
        rec1 = revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="first",
        )
        rec2 = revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="second",
        )
        assert rec1.revoked_at == rec2.revoked_at

    def test_revoked_credential_stays_revoked(self, engine: Engine) -> None:
        r = self._issue(engine)
        revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="test",
        )
        rec = get_credential(engine, r.record.credential_id, "tenant-alpha")
        assert rec.status == "revoked"

    def test_revoke_wrong_tenant_raises(self, engine: Engine) -> None:
        r = self._issue(engine)
        with pytest.raises(CredentialNotFoundError):
            revoke_credential(
                engine,
                credential_id=r.record.credential_id,
                tenant_id="tenant-beta",
                actor_id="op",
                reason="test",
            )

    def test_revoke_rotated_credential_raises(self, engine: Engine) -> None:
        self._issue(engine)
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        old_id = get_credential_history(engine, "tenant-alpha", "prod")[1].credential_id
        with pytest.raises(CredentialStateError):
            revoke_credential(
                engine,
                credential_id=old_id,
                tenant_id="tenant-alpha",
                actor_id="op",
                reason="test",
            )

    def test_revoke_nonexistent_raises(self, engine: Engine) -> None:
        with pytest.raises(CredentialNotFoundError):
            revoke_credential(
                engine,
                credential_id="00000000-0000-0000-0000-000000000000",
                tenant_id="tenant-alpha",
                actor_id="op",
                reason="test",
            )


# ---------------------------------------------------------------------------
# G — Expiration
# ---------------------------------------------------------------------------


class TestG_Expiration:
    def test_lazy_expiration_at_validation_time(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="exp-test",
            expires_in_seconds=-1,
        )
        # Row status is still 'active'; expires_at is in the past.
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials WHERE credential_id = :cid"
                ),
                {"cid": r.record.credential_id},
            ).fetchone()
        assert row[0] == "active"
        # Validation rejects it immediately without waiting for the sweep.
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, r.plaintext_secret)

    def test_expiration_sweep_updates_status(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="exp-sweep",
            expires_in_seconds=-1,
        )
        count = expire_credentials(engine, tenant_id="tenant-alpha")
        assert count >= 1

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials "
                    "WHERE tenant_id = 'tenant-alpha' AND credential_slot = 'exp-sweep'"
                )
            ).fetchone()
        assert row[0] == "expired"

    def test_expiration_sweep_is_idempotent(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="exp-idem",
            expires_in_seconds=-1,
        )
        c1 = expire_credentials(engine, tenant_id="tenant-alpha")
        c2 = expire_credentials(engine, tenant_id="tenant-alpha")
        assert c1 >= 1
        assert c2 == 0  # already expired; nothing to sweep

    def test_non_expired_credentials_not_swept(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="live-cred",
            expires_in_seconds=86400,
        )
        count = expire_credentials(engine, tenant_id="tenant-alpha")
        assert count == 0

    def test_sweep_scoped_to_tenant(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="exp-a",
            expires_in_seconds=-1,
        )
        issue_credential(
            engine,
            tenant_id="tenant-beta",
            credential_type="tenant_api_key",
            credential_slot="exp-b",
            expires_in_seconds=-1,
        )
        count = expire_credentials(engine, tenant_id="tenant-alpha")
        assert count == 1

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials "
                    "WHERE tenant_id = 'tenant-beta' AND credential_slot = 'exp-b'"
                )
            ).fetchone()
        assert row[0] == "active"  # tenant-beta not swept


# ---------------------------------------------------------------------------
# H — Read-side
# ---------------------------------------------------------------------------


class TestH_ReadSide:
    def test_get_credential_returns_record(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        rec = get_credential(engine, r.record.credential_id, "tenant-alpha")
        assert rec.credential_id == r.record.credential_id

    def test_get_credential_wrong_tenant_raises(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        with pytest.raises(CredentialNotFoundError):
            get_credential(engine, r.record.credential_id, "tenant-beta")

    def test_list_credentials_returns_newest_first(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-1",
        )
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-2",
        )
        records = list_credentials(engine, "tenant-alpha")
        assert len(records) == 2
        assert records[0].issued_at >= records[1].issued_at

    def test_list_credentials_status_filter(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="active-slot",
        )
        revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="test",
        )
        active = list_credentials(engine, "tenant-alpha", status="active")
        revoked = list_credentials(engine, "tenant-alpha", status="revoked")
        assert all(c.status == "active" for c in active)
        assert any(c.status == "revoked" for c in revoked)

    def test_list_credentials_excludes_other_tenants(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        records = list_credentials(engine, "tenant-beta")
        assert len(records) == 0

    def test_get_credential_history_newest_generation_first(
        self, engine: Engine
    ) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="hist",
        )
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="hist",
        )
        history = get_credential_history(engine, "tenant-alpha", "hist")
        assert history[0].generation > history[1].generation

    def test_get_credential_history_empty_slot(self, engine: Engine) -> None:
        history = get_credential_history(engine, "tenant-alpha", "no-such-slot")
        assert history == []


# ---------------------------------------------------------------------------
# I — Tenant lifecycle enforcement
# ---------------------------------------------------------------------------


class TestI_LifecycleEnforcement:
    @pytest.mark.parametrize("state", ["suspended", "archived", "deleted"])
    def test_issue_blocked_for_non_active_tenant(
        self, engine: Engine, state: str
    ) -> None:
        _insert_tenant(engine, f"tenant-{state}", state=state)
        with pytest.raises(TenantLifecycleError):
            issue_credential(
                engine,
                tenant_id=f"tenant-{state}",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )

    @pytest.mark.parametrize("state", ["suspended", "archived", "deleted"])
    def test_validate_blocked_for_non_active_tenant(
        self, engine: Engine, state: str
    ) -> None:
        # Issue while active, then switch state.
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="lifecycle-test",
        )
        _insert_tenant(engine, "tenant-alpha", state=state)
        with pytest.raises((TenantLifecycleError, CredentialNotFoundError)):
            validate_credential(engine, r.plaintext_secret)

    def test_revoke_allowed_for_suspended_tenant(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="sus-revoke",
        )
        _insert_tenant(engine, "tenant-alpha", state="suspended")
        rec = revoke_credential(
            engine,
            credential_id=r.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="suspension cleanup",
        )
        assert rec.status == "revoked"

    def test_unknown_tenant_fails_closed_on_issue(self, engine: Engine) -> None:
        with pytest.raises(TenantNotFoundError):
            issue_credential(
                engine,
                tenant_id="ghost-tenant",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )


# ---------------------------------------------------------------------------
# J — Plaintext security invariants
# ---------------------------------------------------------------------------


class TestJ_PlaintextSecurity:
    def test_plaintext_not_in_issuance_result_repr(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="sec-test",
        )
        assert r.plaintext_secret is not None
        assert r.plaintext_secret not in repr(r)

    def test_plaintext_not_in_credential_record_repr(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="sec-test2",
        )
        assert r.plaintext_secret is not None
        assert r.plaintext_secret not in repr(r.record)

    def test_idempotency_replay_never_exposes_original_plaintext(
        self, engine: Engine
    ) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="idem-sec",
            idempotency_key="once",
        )
        for _ in range(5):
            replay = issue_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="idem-sec",
                idempotency_key="once",
            )
            assert replay.plaintext_secret is None

    def test_principal_contains_no_secret_material(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="principal-check",
        )
        principal = validate_credential(engine, r.plaintext_secret)
        principal_dict = vars(principal)
        for key, val in principal_dict.items():
            if isinstance(val, str):
                assert r.plaintext_secret not in val, f"Secret leaked into {key}"
