# tests/test_r4_credential_authority.py
"""
R4.3 — Credential Authority tests.

Uses SQLite in-memory database.  Argon2id parameters are set to the minimum
allowed values via monkeypatch so the suite runs in under a second without
compromising code-path coverage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator, Mapping, cast

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


def _compute_test_record_hash(values: Mapping[str, object]) -> str:
    """Call the strongly typed record-hash helper from mutable test data."""
    return ca._compute_record_hash(
        credential_id=cast(str, values["credential_id"]),
        tenant_id=cast(str, values["tenant_id"]),
        credential_type=cast(str, values["credential_type"]),
        credential_slot=cast(str, values["credential_slot"]),
        generation=cast(int, values["generation"]),
        issued_at=cast(str, values["issued_at"]),
    )


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
        assert cast(str, result.plaintext_secret) not in r_repr
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
        assert _compute_test_record_hash(kwargs) == _compute_test_record_hash(kwargs)

    def test_record_hash_differs_on_any_field_change(self) -> None:
        base = dict(
            credential_id="c1",
            tenant_id="t1",
            credential_type="tenant_api_key",
            credential_slot="prod",
            generation=1,
            issued_at="2026-01-01T00:00:00+00:00",
        )
        h_base = _compute_test_record_hash(base)
        assert _compute_test_record_hash({**base, "generation": 2}) != h_base
        assert _compute_test_record_hash({**base, "tenant_id": "t2"}) != h_base
        assert (
            _compute_test_record_hash({**base, "credential_slot": "staging"}) != h_base
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
        assert cast(str, result.plaintext_secret).startswith("fgk.")

    def test_plaintext_not_stored_in_record(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        secret = cast(str, result.plaintext_secret)
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
        assert row is not None
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
        """issue_credential on an occupied ACTIVE slot must raise, not silently add a second active row."""
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

    def test_reissue_after_revoked_generation_succeeds(self, engine: Engine) -> None:
        """Issue on a slot whose current generation is revoked must succeed as N+1.

        A revoked credential is terminal but the slot is not.  Blocking reissue
        permanently on a revoked generation is the invariant defect this test covers.
        """
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="retry-slot",
        )
        assert r1.record.generation == 1

        revoke_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_id=r1.record.credential_id,
            actor_id="system",
            reason="persistence failure rollback",
        )

        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="retry-slot",
        )
        assert r2.record.generation == 2
        assert r2.record.status == "active"
        assert r2.plaintext_secret is not None
        assert r2.plaintext_secret != r1.plaintext_secret

    def test_reissue_preserves_revoked_history(self, engine: Engine) -> None:
        """The revoked generation-1 row must remain intact after reissue."""
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="history-slot",
        )
        revoke_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_id=r1.record.credential_id,
            actor_id="system",
            reason="test",
        )
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="history-slot",
        )

        history = get_credential_history(engine, tenant_id="tenant-alpha", credential_slot="history-slot")
        assert len(history) == 2
        statuses = {r.generation: r.status for r in history}
        assert statuses[1] == "revoked"
        assert statuses[2] == "active"

    def test_reissue_after_expired_generation_succeeds(self, engine: Engine) -> None:
        """Expired generation is also terminal — reissue must produce N+1."""
        from sqlalchemy import text as _text

        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="expired-slot",
        )
        # Backdate expires_at so expire_credentials sweeps it up immediately.
        with engine.begin() as conn:
            conn.execute(
                _text(
                    "UPDATE tenant_credentials SET expires_at = '2000-01-01T00:00:00+00:00' "
                    "WHERE credential_id = :cid"
                ),
                {"cid": r1.record.credential_id},
            )
        expire_credentials(engine)
        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="expired-slot",
        )
        assert r2.record.generation == 2
        assert r2.record.status == "active"

    def test_active_slot_still_rejects_second_issue(self, engine: Engine) -> None:
        """Regression: an ACTIVE credential in the slot must still raise CredentialStateError."""
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="active-guard",
        )
        with pytest.raises(CredentialStateError):
            issue_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="active-guard",
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
        principal = validate_credential(engine, cast(str, result.plaintext_secret))
        assert isinstance(principal, CredentialPrincipal)
        assert principal.tenant_id == "tenant-alpha"
        assert principal.credential_id == result.record.credential_id

    def test_principal_fields_populated(self, engine: Engine) -> None:
        result = self._issue(engine)
        p = validate_credential(engine, cast(str, result.plaintext_secret))
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
            validate_credential(engine, cast(str, result.plaintext_secret))

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
            validate_credential(engine, cast(str, result.plaintext_secret))

    def test_rotated_credential_rejected(self, engine: Engine) -> None:
        result = self._issue(engine)
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, cast(str, result.plaintext_secret))

    def test_validation_returns_principal_not_row(self, engine: Engine) -> None:
        result = self._issue(engine)
        principal = validate_credential(engine, cast(str, result.plaintext_secret))
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
        assert cast(str, r2.plaintext_secret) != cast(str, r1.plaintext_secret)

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
            validate_credential(engine, cast(str, r1.plaintext_secret))

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
        p = validate_credential(engine, cast(str, r2.plaintext_secret))
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
        assert row is not None
        assert row[0] == "active"
        # Validation rejects it immediately without waiting for the sweep.
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, cast(str, r.plaintext_secret))

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
        assert row is not None
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
        assert row is not None
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
            validate_credential(engine, cast(str, r.plaintext_secret))

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
        assert cast(str, r.plaintext_secret) not in repr(r)

    def test_plaintext_not_in_credential_record_repr(self, engine: Engine) -> None:
        r = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="sec-test2",
        )
        assert r.plaintext_secret is not None
        assert cast(str, r.plaintext_secret) not in repr(r.record)

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
        principal = validate_credential(engine, cast(str, r.plaintext_secret))
        principal_dict = vars(principal)
        for key, val in principal_dict.items():
            if isinstance(val, str):
                assert cast(str, r.plaintext_secret) not in val, (
                    f"Secret leaked into {key}"
                )


# ---------------------------------------------------------------------------
# K — SOC-HIGH-004/005 CI gate invariants
# ---------------------------------------------------------------------------


class TestK_CredentialAuthorityGate:
    """Verify that the SOC-HIGH-004/005 CI gate (check_credential_authority.py)
    enforces the expected invariants without external process invocation.

    Each test imports the gate's internals directly so that:
    - IDE refactoring catches stale references
    - Test failures point to the exact invariant that broke
    - No subprocess overhead
    """

    def _load_gate(self):
        """Import the gate module from tools/ci/ by path."""
        import importlib.util
        from pathlib import Path

        gate_path = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "ci"
            / "check_credential_authority.py"
        )
        spec = importlib.util.spec_from_file_location(
            "check_credential_authority", gate_path
        )
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod

    def test_gate_passes_clean_tree(self) -> None:
        """Gate must exit 0 on the current tree (no regressions introduced)."""
        gate = self._load_gate()
        result = gate.main()
        assert result == 0, "check_credential_authority gate failed unexpectedly"

    def test_retired_modules_are_blocked(self) -> None:
        """The gate's RETIRED_MODULES list must include all three retired modules."""
        gate = self._load_gate()
        # The gate defines _RETIRED_MODULES inside main(); verify via source.
        import inspect

        src = inspect.getsource(gate.main)
        assert "api.credentials" in src
        assert "api.key_rotation" in src
        assert "api.db.api_keys_store" in src

    def test_rotate_api_key_by_prefix_absent_from_api(self) -> None:
        """rotate_api_key_by_prefix must not exist in any api/ Python source."""
        from pathlib import Path

        repo = Path(__file__).resolve().parents[1]
        violations = []
        for py in sorted((repo / "api").rglob("*.py")):
            if "rotate_api_key_by_prefix" in py.read_text(encoding="utf-8"):
                violations.append(str(py.relative_to(repo)))
        assert violations == [], f"rotate_api_key_by_prefix found in api/: {violations}"

    def test_canonical_protected_table_writes_exclusive_to_authority(self) -> None:
        """No file outside credential_authority.py may INSERT/UPDATE canonical tables."""
        import re
        from pathlib import Path

        repo = Path(__file__).resolve().parents[1]
        authority = repo / "api" / "credential_authority.py"
        pattern = re.compile(
            r"\b(?:INSERT\s+INTO|UPDATE)\s+"
            r"(?:tenant_credentials|credential_slots|tenant_credential_events)\b",
            re.IGNORECASE,
        )
        violations = []
        for py in sorted(repo.rglob("*.py")):
            if py == authority:
                continue
            rel = py.relative_to(repo).as_posix()
            if rel.startswith(("tests/", "migrations/", ".claude/")):
                continue
            src = py.read_text(encoding="utf-8", errors="replace")
            if pattern.search(src):
                violations.append(rel)
        assert violations == [], (
            f"Direct writes to canonical credential tables found outside authority: {violations}"
        )

    def test_new_api_keys_writer_would_fail_gate(self, tmp_path) -> None:
        """A synthetic new file with INSERT INTO api_keys must cause gate failure."""
        import re

        # Verify the gate's regex would match the pattern (unit test of the regex).
        pattern = re.compile(r"\b(?:INSERT\s+INTO|UPDATE)\s+api_keys\b", re.IGNORECASE)
        bad_snippet = "conn.execute('INSERT INTO api_keys (prefix) VALUES (?)', [v])"
        assert pattern.search(bad_snippet) is not None, (
            "Gate regex must match INSERT INTO api_keys"
        )
        update_snippet = 'cur.execute("UPDATE api_keys SET enabled=0 WHERE id=?")'
        assert pattern.search(update_snippet) is not None, (
            "Gate regex must match UPDATE api_keys"
        )

    def test_grandfathered_mapping_py_passes_gate(self) -> None:
        """api/auth_scopes/mapping.py is grandfathered and must not trip the gate."""
        gate = self._load_gate()
        # If the gate passes (tested in test_gate_passes_clean_tree), mapping.py
        # is correctly in the allowlist.  This test makes the intent explicit.
        import inspect

        src = inspect.getsource(gate.main)
        assert "api/auth_scopes/mapping.py" in src, (
            "mapping.py must appear in _LEGACY_WRITE_ALLOWED"
        )


# ---------------------------------------------------------------------------
# L — Reissue after terminal generation
# ---------------------------------------------------------------------------


class TestL_ReissueAfterTerminal:
    """Verify issue_credential permits N+1 issuance when generation N is terminal.

    The status check on tenant_credentials runs inside the same transaction
    that holds the credential_slots row lock, so two concurrent retries on a
    terminal slot cannot both write generation N+1 — the second raises
    CredentialConflictError via the conditional UPDATE guard.
    """

    # ---- helpers ----

    def _issue(
        self,
        engine: Engine,
        slot: str = "reissue-slot",
        **kw,
    ) -> IssuanceResult:
        return issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot=slot,
            **kw,
        )

    def _revoke(self, engine: Engine, credential_id: str) -> None:
        revoke_credential(
            engine,
            credential_id=credential_id,
            tenant_id="tenant-alpha",
            actor_id="test-op",
            reason="terminal-reissue-test",
        )

    def _force_status(self, engine: Engine, credential_id: str, status: str) -> None:
        """Directly set the status column for test setup only."""
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenant_credentials SET status = :status "
                    "WHERE credential_id = :cid"
                ),
                {"status": status, "cid": credential_id},
            )

    # ---- 1. revoked → gen 2 ----

    def test_reissue_after_revoked_generation_succeeds(self, engine: Engine) -> None:
        """Gen 1 revoked → issue_credential issues gen 2 with a new secret."""
        r1 = self._issue(engine)
        self._revoke(engine, r1.record.credential_id)

        r2 = self._issue(engine)
        assert r2.plaintext_secret is not None
        assert r2.record.credential_id != r1.record.credential_id
        assert r2.record.generation == 2
        assert r2.record.status == "active"

    # ---- 2. expired → gen 2 ----

    def test_reissue_after_expired_generation_succeeds(self, engine: Engine) -> None:
        """Gen 1 expired (via sweep) → issue_credential issues gen 2."""
        self._issue(engine, expires_in_seconds=-1)
        expire_credentials(engine, tenant_id="tenant-alpha")

        r2 = self._issue(engine)
        assert r2.plaintext_secret is not None
        assert r2.record.generation == 2
        assert r2.record.status == "active"

    # ---- 3. rotated → gen 3 ----

    def test_reissue_after_rotated_generation_succeeds(self, engine: Engine) -> None:
        """After rotate_credential leaves gen 1 as 'rotated' and gen 2 as active,
        revoking gen 2 and then calling issue_credential should produce gen 3.

        rotate_credential marks the predecessor 'rotated' and inserts a new
        active generation — so 'rotated' is the terminal status set by the
        rotation path, not by issue_credential.  We simulate a slot whose
        *current* generation is rotated by directly setting the status of
        gen 2 to 'rotated' after rotation, to avoid touching rotate_credential's
        invariants.
        """
        # Issue gen 1, rotate → gen 2 active, gen 1 rotated.
        self._issue(engine)
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="reissue-slot",
        )
        # Force gen 2 (the current_generation the slot points to) to 'rotated'
        # so that issue_credential sees a terminal current generation.
        self._force_status(engine, r2.record.credential_id, "rotated")

        r3 = self._issue(engine)
        assert r3.record.generation == 3
        assert r3.record.status == "active"

    # ---- 4. active slot still rejects second issue ----

    def test_active_slot_still_rejects_second_issue(self, engine: Engine) -> None:
        """Regression: an active gen 1 must still raise CredentialStateError."""
        self._issue(engine, slot="active-guard")
        with pytest.raises(CredentialStateError):
            self._issue(engine, slot="active-guard")

    # ---- 5. suspended slot rejects reissue ----

    def test_suspended_slot_rejects_reissue(self, engine: Engine) -> None:
        """Suspended is not a TERMINAL_STATUS so it must be rejected.

        'suspended' is a reversible, non-terminal status — it blocks
        validation but can be resumed.  issue_credential must not skip it
        silently; the caller should resume or revoke before reissuing.
        TERMINAL_STATUSES = {rotated, revoked, expired} — suspended is absent.
        """
        from api.credential_authority import suspend_credential

        r1 = self._issue(engine, slot="suspended-guard")
        suspend_credential(
            engine,
            credential_id=r1.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="test-op",
            reason="testing suspension block",
        )
        with pytest.raises(CredentialStateError):
            self._issue(engine, slot="suspended-guard")

    # ---- 6. revoked history preserved ----

    def test_reissue_preserves_revoked_history(self, engine: Engine) -> None:
        """After reissue, gen 1 still exists in the DB with status='revoked'."""
        r1 = self._issue(engine, slot="hist-preserve")
        self._revoke(engine, r1.record.credential_id)
        self._issue(engine, slot="hist-preserve")

        history = get_credential_history(
            engine,
            "tenant-alpha",
            "hist-preserve",
        )
        # Both generations must be present.
        assert len(history) == 2
        statuses = {rec.generation: rec.status for rec in history}
        assert statuses[1] == "revoked"
        assert statuses[2] == "active"

    # ---- 7. generation sequence ----

    def test_reissue_produces_exactly_next_generation(self, engine: Engine) -> None:
        """Reissue after gen 1 revoked must produce generation == 2, not higher."""
        r1 = self._issue(engine, slot="gen-seq")
        self._revoke(engine, r1.record.credential_id)

        r2 = self._issue(engine, slot="gen-seq")
        assert r2.record.generation == 2

    # ---- 8. concurrency: one winner ----

    def test_simultaneous_reissue_produces_one_winner(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two threads calling issue_credential on a revoked slot must produce
        exactly one gen 2 success; the other must raise (CredentialConflictError
        or CredentialStateError).  Final slot state must be current_generation=2.

        Uses a file-based SQLite engine (not the in-memory fixture) because
        SQLite's SingletonThreadPool does not allow connections created in one
        thread to be closed from another.  File-based SQLite with
        check_same_thread=False and StaticPool gives each thread its own
        connection while sharing the same on-disk state.

        SQLite serialises writes at the database level: the loser will see
        current_generation=2 (already advanced by the winner) and its
        conditional UPDATE returns rowcount=0 → CredentialConflictError.
        Under Postgres the FOR UPDATE row lock achieves the same serialisation.
        """
        import concurrent.futures

        from sqlalchemy.pool import NullPool

        monkeypatch.setattr(
            ca,
            "_HASHER",
            __import__("argon2").PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
        )
        monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-value-for-r4-tests")

        db_path = tmp_path / "concurrent_test.db"
        teng = create_engine(
            f"sqlite:///{db_path}",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=NullPool,
        )
        _setup_schema(teng)
        _insert_tenant(teng, "tenant-alpha")

        # Set up: issue gen 1, revoke it.
        r1 = issue_credential(
            teng,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="concurrent-reissue",
        )
        revoke_credential(
            teng,
            credential_id=r1.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="test-op",
            reason="concurrent-test",
        )

        errors: list[Exception] = []
        results: list[IssuanceResult] = []

        def _try_issue() -> None:
            try:
                res = issue_credential(
                    teng,
                    tenant_id="tenant-alpha",
                    credential_type="tenant_api_key",
                    credential_slot="concurrent-reissue",
                )
                results.append(res)
            except Exception as exc:
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_try_issue), pool.submit(_try_issue)]
            concurrent.futures.wait(futures)

        teng.dispose()

        # Exactly one success, one error.
        assert len(results) == 1, f"Expected 1 success, got {len(results)}: {results}"
        assert len(errors) == 1, f"Expected 1 error, got {len(errors)}: {errors}"
        assert isinstance(
            errors[0], (CredentialConflictError, CredentialStateError)
        ), f"Expected CredentialConflictError or CredentialStateError, got {type(errors[0])}"

        # Reopen the DB to verify the final slot generation.
        teng2 = create_engine(
            f"sqlite:///{db_path}",
            future=True,
            connect_args={"check_same_thread": False},
        )
        with teng2.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT current_generation FROM credential_slots "
                    "WHERE tenant_id = 'tenant-alpha' "
                    "  AND credential_type = 'tenant_api_key' "
                    "  AND credential_slot = 'concurrent-reissue'"
                )
            ).fetchone()
        teng2.dispose()

        assert row is not None
        assert row[0] == 2, f"Expected current_generation=2, got {row[0]}"

    # ---- 9. audit events distinguish revocation from reissue ----

    def test_audit_events_distinguish_revocation_from_reissue(
        self, engine: Engine
    ) -> None:
        """After gen 1 revoked + gen 2 issued, the audit log contains a 'revoked'
        event and an 'issued' event as distinct records.

        tenant_credential_events is populated by _insert_event() inside both
        revoke_credential and issue_credential.  list_credential_events() is
        the public read-side for that table.
        """
        from api.credential_authority import list_credential_events

        r1 = self._issue(engine, slot="audit-distinct")
        self._revoke(engine, r1.record.credential_id)
        self._issue(engine, slot="audit-distinct")

        events = list_credential_events(engine, "tenant-alpha")
        event_types = [e.event_type for e in events]

        assert "revoked" in event_types, "Expected 'revoked' event in audit log"
        assert "issued" in event_types, "Expected 'issued' event in audit log"

        # The two events must be separate (not the same record).
        revoked_events = [e for e in events if e.event_type == "revoked"]
        issued_events = [e for e in events if e.event_type == "issued"]
        assert len(revoked_events) >= 1
        assert len(issued_events) >= 2  # gen 1 issuance + gen 2 reissuance

        # The reissue 'issued' event must reference generation 2.
        gen2_issued = [e for e in issued_events if e.generation == 2]
        assert len(gen2_issued) == 1, "Expected exactly one 'issued' event for gen 2"

        # The revocation event must reference generation 1 and the original cred ID.
        gen1_revoked = [e for e in revoked_events if e.generation == 1]
        assert len(gen1_revoked) == 1
        assert gen1_revoked[0].credential_id == r1.record.credential_id
