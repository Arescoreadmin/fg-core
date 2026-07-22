"""
Task 12.2 — Per-Tenant Usage Attribution With Query/Export Support

Tests proving:
1)  Usage records are attributed to the trusted tenant
2)  Missing trusted tenant fails closed (structured error)
3)  Missing customer identity fails closed (structured error)
4)  Invalid units are rejected (zero, negative, bool, float, string)
5)  Idempotency prevents double-counting
6)  Same idempotency_key under different tenant does not collide
7)  query_usage returns ONLY trusted tenant records
8)  export_usage returns ONLY trusted tenant records
9)  Cross-tenant query does not leak foreign records
10) Metadata is detached from caller mutation
11) export_usage is deterministic
12) export_usage rejects invalid format
13) Errors are structured and non-leaky
14) Credentials integration uses validated tenant context
"""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from api.usage_attribution import (
    ERR_CUSTOMER_REQUIRED,
    ERR_EXPORT_INVALID_FORMAT,
    ERR_INVALID_UNITS,
    ERR_TENANT_REQUIRED,
    _reset_store,
    export_usage,
    query_usage,
    record_usage,
)


# ---------------------------------------------------------------------------
# Fixture: isolate in-memory store for each test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_store():
    """Reset in-memory usage store before each test."""
    _reset_store()
    yield
    _reset_store()


# ---------------------------------------------------------------------------
# 1) test_usage_records_are_attributed_to_trusted_tenant
# ---------------------------------------------------------------------------


def test_usage_records_are_attributed_to_trusted_tenant():
    """Record carries the trusted tenant_id and customer_id supplied at write."""
    result = record_usage(
        trusted_tenant_id="tenant-a",
        customer_id="cred-abc",
        action="rag_query",
        units=1,
        source="api.rag",
        idempotency_key="ikey-001",
    )
    assert result.created is True
    r = result.record
    assert r.tenant_id == "tenant-a"
    assert r.customer_id == "cred-abc"
    assert r.action == "rag_query"
    assert r.units == 1
    assert r.source == "api.rag"
    assert r.status == "recorded"
    assert r.usage_id  # non-empty


# ---------------------------------------------------------------------------
# 2) test_usage_rejects_missing_trusted_tenant
# ---------------------------------------------------------------------------


def test_usage_rejects_missing_trusted_tenant():
    """Missing or empty trusted_tenant_id must raise USAGE_TENANT_REQUIRED."""
    for bad in (None, "", "  "):
        with pytest.raises(HTTPException) as exc:
            record_usage(trusted_tenant_id=bad, customer_id="cred", action="op")
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_TENANT_REQUIRED


# ---------------------------------------------------------------------------
# 3) test_usage_rejects_missing_customer_identity
# ---------------------------------------------------------------------------


def test_usage_rejects_missing_customer_identity():
    """Missing or empty customer_id must raise USAGE_CUSTOMER_REQUIRED."""
    for bad in (None, "", "  "):
        with pytest.raises(HTTPException) as exc:
            record_usage(trusted_tenant_id="tenant-a", customer_id=bad, action="op")
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_CUSTOMER_REQUIRED


# ---------------------------------------------------------------------------
# 4) test_usage_rejects_invalid_units
# ---------------------------------------------------------------------------


def test_usage_rejects_invalid_units():
    """Zero, negative, boolean, float, and string units must all be rejected."""
    for bad_units in (0, -1, -100, True, False, 1.5, "2", None):
        with pytest.raises(HTTPException) as exc:
            record_usage(
                trusted_tenant_id="tenant-a",
                customer_id="cred",
                action="op",
                units=bad_units,
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_INVALID_UNITS


# ---------------------------------------------------------------------------
# 5) test_usage_idempotency_prevents_double_counting
# ---------------------------------------------------------------------------


def test_usage_idempotency_prevents_double_counting():
    """Same (tenant, idempotency_key) written twice must not double-count."""
    r1 = record_usage(
        trusted_tenant_id="tenant-a",
        customer_id="cred-x",
        action="decision",
        units=5,
        idempotency_key="event-42",
    )
    r2 = record_usage(
        trusted_tenant_id="tenant-a",
        customer_id="cred-x",
        action="decision",
        units=5,
        idempotency_key="event-42",
    )
    assert r1.created is True
    assert r2.created is False
    assert r1.record.usage_id == r2.record.usage_id

    # Only one record in store
    records = query_usage("tenant-a")
    assert len(records) == 1
    assert records[0].units == 5  # not 10


# ---------------------------------------------------------------------------
# 6) test_usage_same_idempotency_key_different_tenant_does_not_collide
# ---------------------------------------------------------------------------


def test_usage_same_idempotency_key_different_tenant_does_not_collide():
    """Same idempotency_key under different tenants must produce distinct usage_ids."""
    r_a = record_usage(
        trusted_tenant_id="tenant-a",
        customer_id="cred-1",
        action="op",
        idempotency_key="shared-key",
    )
    r_b = record_usage(
        trusted_tenant_id="tenant-b",
        customer_id="cred-2",
        action="op",
        idempotency_key="shared-key",
    )
    assert r_a.created is True
    assert r_b.created is True
    assert r_a.record.usage_id != r_b.record.usage_id

    # Each tenant sees only their own record
    records_a = query_usage("tenant-a")
    records_b = query_usage("tenant-b")
    assert len(records_a) == 1
    assert len(records_b) == 1
    assert records_a[0].tenant_id == "tenant-a"
    assert records_b[0].tenant_id == "tenant-b"


# ---------------------------------------------------------------------------
# 7) test_usage_query_returns_only_trusted_tenant_records
# ---------------------------------------------------------------------------


def test_usage_query_returns_only_trusted_tenant_records():
    """query_usage must filter strictly to the supplied trusted_tenant_id."""
    record_usage("tenant-a", "cred-1", "op", idempotency_key="k1")
    record_usage("tenant-a", "cred-2", "op", idempotency_key="k2")
    record_usage("tenant-b", "cred-3", "op", idempotency_key="k3")

    results = query_usage("tenant-a")
    assert len(results) == 2
    assert all(r.tenant_id == "tenant-a" for r in results)


# ---------------------------------------------------------------------------
# 8) test_usage_export_returns_only_trusted_tenant_records
# ---------------------------------------------------------------------------


def test_usage_export_returns_only_trusted_tenant_records():
    """export_usage JSON output must contain only records for the trusted tenant."""
    record_usage("tenant-a", "cred-1", "op", idempotency_key="e1")
    record_usage("tenant-b", "cred-9", "op", idempotency_key="e2")

    raw = export_usage("tenant-a", fmt="json")
    rows = json.loads(raw)
    assert all(row["tenant_id"] == "tenant-a" for row in rows)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 9) test_usage_cross_tenant_query_does_not_leak_foreign_records
# ---------------------------------------------------------------------------


def test_usage_cross_tenant_query_does_not_leak_foreign_records():
    """query_usage for an unknown/different tenant returns empty list, not error."""
    record_usage("tenant-z", "cred-z", "op", idempotency_key="z1")

    results = query_usage("tenant-other")
    assert results == []


# ---------------------------------------------------------------------------
# 10) test_usage_metadata_is_detached_from_caller_mutation
# ---------------------------------------------------------------------------


def test_usage_metadata_is_detached_from_caller_mutation():
    """Mutating the caller's metadata dict after write must not alter stored record."""
    meta = {"key": "value"}
    result = record_usage(
        trusted_tenant_id="tenant-a",
        customer_id="cred-1",
        action="op",
        idempotency_key="m1",
        metadata=meta,
    )
    # Mutate the original dict
    meta["key"] = "MUTATED"
    meta["extra"] = "injected"

    stored = query_usage("tenant-a")[0]
    assert stored.metadata["key"] == "value"
    assert "extra" not in stored.metadata

    # Also verify read-time copy (metadata on record is the frozen copy)
    assert result.record.metadata["key"] == "value"


# ---------------------------------------------------------------------------
# 11) test_usage_export_is_deterministic
# ---------------------------------------------------------------------------


def test_usage_export_is_deterministic():
    """Exporting the same records twice must produce byte-identical output."""
    now = 1000000
    record_usage("tenant-a", "cred-1", "op-b", idempotency_key="d1", now=now)
    record_usage("tenant-a", "cred-2", "op-a", idempotency_key="d2", now=now + 1)

    out1 = export_usage("tenant-a", fmt="json")
    out2 = export_usage("tenant-a", fmt="json")
    assert out1 == out2

    # CSV also deterministic
    csv1 = export_usage("tenant-a", fmt="csv")
    csv2 = export_usage("tenant-a", fmt="csv")
    assert csv1 == csv2

    # Records are ordered by (created_at, usage_id) — op-b (now) before op-a (now+1)
    rows = json.loads(out1)
    assert rows[0]["action"] == "op-b"
    assert rows[1]["action"] == "op-a"


# ---------------------------------------------------------------------------
# 12) test_usage_export_rejects_invalid_format
# ---------------------------------------------------------------------------


def test_usage_export_rejects_invalid_format():
    """Unsupported export format must raise USAGE_EXPORT_INVALID_FORMAT."""
    record_usage("tenant-a", "cred-1", "op", idempotency_key="f1")
    for bad_fmt in ("xml", "parquet", "", "JSON", "CSV"):
        with pytest.raises(HTTPException) as exc:
            export_usage("tenant-a", fmt=bad_fmt)
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_EXPORT_INVALID_FORMAT


# ---------------------------------------------------------------------------
# 13) test_usage_errors_are_structured_and_non_leaky
# ---------------------------------------------------------------------------


def test_usage_errors_are_structured_and_non_leaky():
    """All error payloads must be dicts with stable code/message fields.
    No tenant, customer, or secret values leak into error messages.
    """
    secret_tenant = "ultra-secret-tenant-id"
    secret_cred = "ultra-secret-cred-id"

    # Missing tenant error
    with pytest.raises(HTTPException) as exc:
        record_usage(trusted_tenant_id="", customer_id=secret_cred, action="op")
    detail = exc.value.detail
    assert isinstance(detail, dict)
    assert "code" in detail and "message" in detail
    assert secret_cred not in str(detail)

    # Missing customer error
    with pytest.raises(HTTPException) as exc2:
        record_usage(trusted_tenant_id=secret_tenant, customer_id="", action="op")
    detail2 = exc2.value.detail
    assert isinstance(detail2, dict)
    assert secret_tenant not in str(detail2)

    # Export format error must not expose tenant
    record_usage(secret_tenant, secret_cred, "op", idempotency_key="e1")
    with pytest.raises(HTTPException) as exc3:
        export_usage(secret_tenant, fmt="xml")
    assert secret_tenant not in str(exc3.value.detail)
    assert secret_cred not in str(exc3.value.detail)


# ---------------------------------------------------------------------------
# 14) test_usage_credentials_integration_uses_validated_tenant_context
# ---------------------------------------------------------------------------


def test_usage_credentials_integration_uses_validated_tenant_context(
    monkeypatch,
):
    """Usage attributed via credential validation must carry the credential's tenant.

    Simulates the call chain:
    1) issue_credential(engine, ...) → IssuanceResult with plaintext_secret
    2) validate_credential(engine, raw_key) → CredentialPrincipal.tenant_id
    3) record_usage(trusted_tenant_id=authenticated_tenant_id, ...)

    Uses an in-memory SQLite engine with the canonical credential schema so
    there is no filesystem state and no dependency on api.credentials (retired).
    """
    import api.credential_authority as ca
    from argon2 import PasswordHasher
    from sqlalchemy import create_engine, text

    from api.credential_authority import issue_credential, validate_credential

    # Minimum-cost hasher so the test runs fast.
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper-cred-usage-ws1")

    # Build a minimal in-memory schema — same DDL as test_r4_credential_authority.py.
    engine = create_engine("sqlite:///:memory:", future=True)
    schema = """
    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id        VARCHAR(128) PRIMARY KEY,
        display_name     VARCHAR(256) NOT NULL DEFAULT '',
        lifecycle_state  VARCHAR(32)  NOT NULL DEFAULT 'active',
        created_at       TEXT, updated_at TEXT, created_by TEXT,
        metadata         TEXT NOT NULL DEFAULT '{}',
        canonical_version INTEGER NOT NULL DEFAULT 1,
        last_reconciled_at TEXT, archived_at TEXT,
        migration_source TEXT, migration_version TEXT
    );
    CREATE TABLE IF NOT EXISTS credential_slots (
        tenant_id          VARCHAR(128) NOT NULL,
        credential_type    VARCHAR(64)  NOT NULL,
        credential_slot    VARCHAR(128) NOT NULL,
        current_generation INTEGER      NOT NULL DEFAULT 0,
        rotation_policy    VARCHAR(32)  NOT NULL DEFAULT 'immediate',
        max_overlap_count  INTEGER      NOT NULL DEFAULT 1,
        created_at TEXT, updated_at TEXT,
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
        expires_at TEXT, issued_at TEXT NOT NULL, activated_at TEXT,
        rotated_at TEXT, revoked_at TEXT, replaced_by_credential_id VARCHAR(64),
        created_by_actor_id VARCHAR(256), request_id VARCHAR(128),
        idempotency_key VARCHAR(256), last_used_at TEXT,
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
        event_id      VARCHAR(64)  NOT NULL PRIMARY KEY,
        tenant_id     VARCHAR(128) NOT NULL,
        credential_id VARCHAR(64), credential_type VARCHAR(64),
        credential_slot VARCHAR(128), generation INTEGER,
        event_type    VARCHAR(64)  NOT NULL,
        actor_id      VARCHAR(256), request_id VARCHAR(128),
        occurred_at   TEXT NOT NULL,
        outcome       VARCHAR(16)  NOT NULL DEFAULT 'success',
        failure_reason TEXT, metadata TEXT,
        schema_version INTEGER NOT NULL DEFAULT 1
    )
    """
    with engine.begin() as conn:
        for stmt in schema.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, lifecycle_state) VALUES (:tid, 'active')"
            ),
            {"tid": "tenant-cred-usage"},
        )

    # Issue a credential via the canonical authority.
    result_issue = issue_credential(
        engine,
        tenant_id="tenant-cred-usage",
        credential_type="tenant_api_key",
        credential_slot="default",
    )
    assert result_issue.plaintext_secret is not None
    raw_key = result_issue.plaintext_secret

    # Validate via the canonical authority — returns a CredentialPrincipal.
    principal = validate_credential(engine, raw_key)
    authenticated_tenant = principal.tenant_id
    assert authenticated_tenant == "tenant-cred-usage"

    # trusted_tenant_id comes from validated credential context, not user payload.
    result = record_usage(
        trusted_tenant_id=authenticated_tenant,
        customer_id=result_issue.record.credential_id[:16],
        action="rag_query",
        units=2,
        source="api.rag",
        idempotency_key="cred-integration-001",
    )
    assert result.created is True
    assert result.record.tenant_id == "tenant-cred-usage"
    assert result.record.units == 2

    # query confirms attribution
    records = query_usage("tenant-cred-usage")
    assert len(records) == 1
    assert records[0].tenant_id == "tenant-cred-usage"

    engine.dispose()
