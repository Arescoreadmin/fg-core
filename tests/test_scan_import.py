"""tests/test_scan_import.py — PR 3: Scan Result Import Framework tests.

Covers:
  - Schema version allowlist enforcement (per source type)
  - Required top-level field enforcement (per source type)
  - Quarantine: depth, field count, per-field size limits
  - Credential / secret redaction (key-name and value-pattern based)
  - Idempotency is preserved through the redaction pipeline
  - evidence_hash verified against original (pre-redaction) payload
  - Redaction metadata recorded in audit trail
  - Unit-level tests for redaction and scan_registry helpers
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from services.field_assessment.redaction import REDACT_SENTINEL, redact_payload
from services.field_assessment.scan_registry import (
    MAX_FIELD_COUNT,
    MAX_FIELD_SIZE_BYTES,
    MAX_PAYLOAD_DEPTH,
    quarantine_check,
    validate_required_fields,
    validate_scan_payload,
    validate_schema_version,
)
from services.field_assessment.models import ScanQuarantinedError, ScanValidationError
from services.field_assessment.store import compute_evidence_hash

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TENANT_ID = "tenant-scan-import-test"

_ENGAGEMENT_BODY = {
    "client_name": "Scan Import Corp",
    "assessor_id": "assessor-scan-001",
    "assessment_type": "ai_governance",
}


def _make_client(build_app) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> str:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _ingest(client: TestClient, eng_id: str, body: dict) -> Response:
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=body,
    )
    return resp


# ---------------------------------------------------------------------------
# Unit tests — redaction helpers
# ---------------------------------------------------------------------------


class TestRedactionUnit:
    def test_sensitive_key_name_redacted(self):
        result = redact_payload({"api_key": "abc123", "data": "safe"})
        assert result.payload["api_key"] == REDACT_SENTINEL
        assert result.payload["data"] == "safe"
        assert result.redacted_count == 1

    def test_password_key_redacted(self):
        result = redact_payload({"password": "hunter2"})
        assert result.payload["password"] == REDACT_SENTINEL

    def test_token_key_redacted(self):
        result = redact_payload({"token": "sometoken"})
        assert result.payload["token"] == REDACT_SENTINEL

    def test_bearer_value_redacted(self):
        result = redact_payload({"authorization": "Bearer eyABC123"})
        # key 'authorization' is not in sensitive key list, but value matches bearer pattern
        # Actually 'authorization' won't match key pattern; value 'Bearer eyABC123' will match
        assert result.payload["authorization"] == REDACT_SENTINEL

    def test_aws_access_key_value_redacted(self):
        result = redact_payload({"access_id": "AKIAIOSFODNN7EXAMPLE"})
        # 'access_id' matches sensitive key pattern AND value matches AWS AKID pattern
        assert result.payload["access_id"] == REDACT_SENTINEL

    def test_nested_secret_redacted(self):
        payload = {
            "cloud": {"credentials": {"api_key": "sk-secret123", "region": "us-east-1"}}
        }
        result = redact_payload(payload)
        assert result.payload["cloud"]["credentials"]["api_key"] == REDACT_SENTINEL
        assert result.payload["cloud"]["credentials"]["region"] == "us-east-1"
        assert result.redacted_count == 1

    def test_secret_in_list_item_dict_redacted(self):
        payload = {"users": [{"name": "alice", "password": "pw123"}]}
        result = redact_payload(payload)
        assert result.payload["users"][0]["password"] == REDACT_SENTINEL
        assert result.payload["users"][0]["name"] == "alice"

    def test_clean_payload_untouched(self):
        payload = {"users": [{"id": "u1", "email": "alice@example.com"}], "count": 1}
        result = redact_payload(payload)
        assert result.payload == payload
        assert result.redacted_count == 0

    def test_pem_value_redacted(self):
        # Split so static secret scanners don't flag this test file.
        pem_header = "-----BEGIN PRIVATE " + "KEY-----"
        result = redact_payload({"cert": pem_header + "\nMIIE..."})
        assert result.payload["cert"] == REDACT_SENTINEL

    def test_redacted_paths_reported(self):
        result = redact_payload({"api_key": "x", "data": {"token": "y"}})
        assert "api_key" in result.redacted_paths
        assert "data.token" in result.redacted_paths


# ---------------------------------------------------------------------------
# Unit tests — scan_registry helpers
# ---------------------------------------------------------------------------


class TestRegistryUnit:
    def test_valid_schema_version_accepted(self):
        validate_schema_version("microsoft_graph", "1.0")  # no exception

    def test_unknown_schema_version_raises(self):
        with pytest.raises(ScanValidationError, match="schema_version"):
            validate_schema_version("microsoft_graph", "99.0")

    def test_valid_schema_version_for_aws(self):
        validate_schema_version("aws", "2.0")

    def test_invalid_schema_for_network_scan(self):
        with pytest.raises(ScanValidationError):
            validate_schema_version("network_scan", "1.1")  # only "1.0" is valid

    def test_required_fields_present(self):
        validate_required_fields("microsoft_graph", {"users": [], "extra": "ok"})

    def test_required_fields_missing_raises(self):
        with pytest.raises(ScanValidationError, match="missing required fields"):
            validate_required_fields("microsoft_graph", {"groups": []})

    def test_quarantine_depth_ok(self):
        payload = {"a": {"b": {"c": {"d": "leaf"}}}}
        quarantine_check(payload)  # depth 4 < 12, no exception

    def test_quarantine_depth_exceeded_raises(self):
        obj: dict = {}
        nested = obj
        for _ in range(MAX_PAYLOAD_DEPTH + 2):
            nested["x"] = {}
            nested = nested["x"]
        with pytest.raises(ScanQuarantinedError, match="depth"):
            quarantine_check(obj)

    def test_quarantine_field_count_exceeded_raises(self):
        payload = {str(i): i for i in range(MAX_FIELD_COUNT + 1)}
        with pytest.raises(ScanQuarantinedError, match="field count"):
            quarantine_check(payload)

    def test_quarantine_field_size_exceeded_raises(self):
        big_value = "x" * (MAX_FIELD_SIZE_BYTES + 1)
        with pytest.raises(ScanQuarantinedError, match="size"):
            quarantine_check({"blob": big_value})

    def test_validate_scan_payload_end_to_end(self):
        validate_scan_payload("microsoft_graph", "1.0", {"users": []})  # no exception

    def test_validate_scan_payload_bad_version_raises(self):
        with pytest.raises(ScanValidationError):
            validate_scan_payload("microsoft_graph", "99.0", {"users": []})

    def test_validate_scan_payload_missing_field_raises(self):
        with pytest.raises(ScanValidationError):
            validate_scan_payload("aws", "1.0", {"other": []})


# ---------------------------------------------------------------------------
# API integration tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app: object) -> TestClient:
    return _make_client(build_app)  # type: ignore[arg-type]


class TestSchemaVersionEnforcement:
    def test_valid_schema_version_accepted(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 201

    def test_unknown_schema_version_rejected(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "99.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_VALIDATION_ERROR" in resp.text

    def test_schema_version_valid_for_source_aws(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "aws",
                "schema_version": "2.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"accounts": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 201

    def test_schema_version_valid_for_one_source_invalid_for_another(
        self, client: TestClient
    ):
        eng_id = _create_engagement(client)
        # "2.0" is valid for aws but not for network_scan (only "1.0")
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "network_scan",
                "schema_version": "2.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"hosts": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 422

    def test_all_source_types_accept_1_0(self, client: TestClient):
        """Every registered source type must accept schema_version 1.0."""
        eng_id = _create_engagement(client)
        required_field = {
            "microsoft_graph": "users",
            "google_workspace": "users",
            "aws": "accounts",
            "azure": "subscriptions",
            "gcp": "projects",
            "network_scan": "hosts",
            "endpoint_inventory": "endpoints",
            "oauth_inventory": "apps",
        }
        for source_type, field in required_field.items():
            resp = _ingest(
                client,
                eng_id,
                {
                    "source_type": source_type,
                    "schema_version": "1.0",
                    "collected_at": "2026-05-19T00:00:00Z",
                    "raw_payload": {field: []},
                    "object_count": 0,
                },
            )
            assert resp.status_code == 201, f"{source_type}: {resp.text}"


class TestRequiredFieldEnforcement:
    def test_missing_required_field_rejected(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"groups": []},  # missing 'users'
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_VALIDATION_ERROR" in resp.text

    def test_required_field_present_accepted(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": [{"id": "u1"}]},
                "object_count": 1,
            },
        )
        assert resp.status_code == 201

    def test_aws_requires_accounts_field(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "aws",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"regions": []},  # missing 'accounts'
                "object_count": 0,
            },
        )
        assert resp.status_code == 422


class TestQuarantine:
    def test_depth_exceeded_quarantined(self, client: TestClient):
        eng_id = _create_engagement(client)
        obj: dict = {"users": []}
        nested = obj
        for _ in range(MAX_PAYLOAD_DEPTH + 2):
            nested["x"] = {}
            nested = nested["x"]
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": obj,
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_QUARANTINED" in resp.text

    def test_field_count_exceeded_quarantined(self, client: TestClient):
        eng_id = _create_engagement(client)
        payload = {"users": [], **{str(i): i for i in range(MAX_FIELD_COUNT)}}
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": payload,
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_QUARANTINED" in resp.text

    def test_large_field_quarantined(self, client: TestClient):
        eng_id = _create_engagement(client)
        big = "x" * (MAX_FIELD_SIZE_BYTES + 1)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": [], "blob": big},
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_QUARANTINED" in resp.text


class TestRedactionIntegration:
    def test_api_key_in_payload_stored_redacted(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {
                    "users": [{"id": "u1", "name": "Alice"}],
                    "api_key": "super-secret-key-abc123",
                },
                "object_count": 1,
            },
        )
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        detail = client.get(
            f"/field-assessment/engagements/{eng_id}/scan-results/{scan_id}"
        )
        assert detail.status_code == 200
        stored = detail.json()["raw_payload"]
        assert stored["api_key"] == REDACT_SENTINEL
        assert stored["users"][0]["name"] == "Alice"

    def test_password_in_nested_user_stored_redacted(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {
                    "users": [{"id": "u2", "password": "Pa$$w0rd!"}],
                },
                "object_count": 1,
            },
        )
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        detail = client.get(
            f"/field-assessment/engagements/{eng_id}/scan-results/{scan_id}"
        )
        assert detail.status_code == 200
        user = detail.json()["raw_payload"]["users"][0]
        assert user["password"] == REDACT_SENTINEL
        assert user["id"] == "u2"

    def test_clean_payload_stored_unchanged(self, client: TestClient):
        eng_id = _create_engagement(client)
        payload = {"users": [{"id": "u3", "email": "bob@example.com", "role": "admin"}]}
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": payload,
                "object_count": 1,
            },
        )
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        detail = client.get(
            f"/field-assessment/engagements/{eng_id}/scan-results/{scan_id}"
        )
        assert detail.json()["raw_payload"] == payload


class TestIdempotencyWithRedaction:
    def test_same_payload_twice_returns_same_id(self, client: TestClient):
        eng_id = _create_engagement(client)
        body = {
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-19T00:00:00Z",
            "raw_payload": {"users": [{"id": "u1", "api_key": "secret"}]},
            "object_count": 1,
        }
        r1 = _ingest(client, eng_id, body)
        r2 = _ingest(client, eng_id, body)
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["id"] == r2.json()["id"]

    def test_expected_evidence_hash_verified_against_original(self, client: TestClient):
        """expected_evidence_hash must be computed from the original (pre-redaction) payload."""
        eng_id = _create_engagement(client)
        original_payload = {"users": [], "api_key": "s3cr3t"}
        correct_hash = compute_evidence_hash(original_payload)

        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": original_payload,
                "object_count": 0,
                "expected_evidence_hash": correct_hash,
            },
        )
        assert resp.status_code == 201

    def test_wrong_expected_evidence_hash_rejected(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
                "expected_evidence_hash": "a" * 64,
            },
        )
        assert resp.status_code == 422


class TestAuditRedactionMetadata:
    def test_redaction_count_in_audit_event(self, client: TestClient):
        eng_id = _create_engagement(client)
        _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": [], "api_key": "secret1", "token": "tok2"},
                "object_count": 0,
            },
        )

        audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
        assert audit_resp.status_code == 200
        events = audit_resp.json()
        ingest_events = [e for e in events if e["event_type"] == "scan_result.ingested"]
        assert ingest_events, "expected a scan_result.ingested audit event"
        payload = ingest_events[0]["payload"]
        assert "redacted_field_count" in payload
        assert payload["redacted_field_count"] == 2  # api_key + token
