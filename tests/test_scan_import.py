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
  - Extended secret value patterns (GitHub PAT, Vault, Databricks, Stripe, MongoDB URI)
  - access_token / compound-key redaction (Bug 1 fix: no word-boundary anchors)
  - JSON-in-JSON recursive redaction (nested serialised payloads)
  - False-positive guard: hex SHA-256 hashes are NOT redacted
  - Field-type validation (wrong type rejected with 422)
  - Per-source quarantine thresholds (AWS: 8K, endpoint_inventory: 10K)
  - _field_count() counts list items (Bug 2 fix)
  - Quarantine store audit trail (rejected scans emit audit events)
  - Deprecation notice infrastructure (no notice for current schema versions)
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
        with pytest.raises(ScanValidationError, match="missing required field"):
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

    def test_redacted_paths_in_audit_event(self, client: TestClient):
        eng_id = _create_engagement(client)
        _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": [], "api_key": "secret1"},
                "object_count": 0,
            },
        )

        audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
        events = audit_resp.json()
        ingest_events = [e for e in events if e["event_type"] == "scan_result.ingested"]
        payload = ingest_events[0]["payload"]
        assert "redacted_paths" in payload
        assert "api_key" in payload["redacted_paths"]


# ---------------------------------------------------------------------------
# New gap coverage: Bug fixes, extended patterns, per-source thresholds, etc.
# ---------------------------------------------------------------------------


class TestCompoundKeyRedaction:
    """Bug 1 fix: removing \b word-boundary anchors catches compound keys."""

    def test_access_token_key_redacted(self):
        result = redact_payload({"access_token": "tok-abc123"})
        assert result.payload["access_token"] == REDACT_SENTINEL

    def test_api_token_key_redacted(self):
        result = redact_payload({"api_token": "tok-abc123"})
        assert result.payload["api_token"] == REDACT_SENTINEL

    def test_private_key_id_key_redacted(self):
        result = redact_payload({"private_key_id": "key-id-123"})
        assert result.payload["private_key_id"] == REDACT_SENTINEL

    def test_service_account_key_redacted(self):
        result = redact_payload({"service_account_key": "sa-key-value"})
        assert result.payload["service_account_key"] == REDACT_SENTINEL

    def test_connection_string_key_redacted(self):
        result = redact_payload({"connection_string": "Server=db;Password=pw"})
        assert result.payload["connection_string"] == REDACT_SENTINEL


class TestFalsePositiveGuard:
    """Base64-padded blob pattern must NOT trigger on hex SHA-256 hashes."""

    def test_sha256_hex_hash_not_redacted(self):
        sha = "a" * 64  # 64 hex chars, no +/= — not a base64 blob
        result = redact_payload({"evidence_hash": sha})
        # evidence_hash does not match _SENSITIVE_KEY_RE
        # and the value is hex-only (no + / =) so base64 pattern won't match
        assert result.payload["evidence_hash"] == sha
        assert result.redacted_count == 0

    def test_short_safe_string_not_redacted(self):
        result = redact_payload({"status": "active"})
        assert result.payload["status"] == "active"
        assert result.redacted_count == 0

    def test_email_not_redacted(self):
        result = redact_payload({"email": "alice@example.com"})
        assert result.payload["email"] == "alice@example.com"
        assert result.redacted_count == 0


class TestExtendedSecretPatterns:
    """Value-level patterns: GitHub PAT, Vault, Databricks, Stripe, MongoDB URI."""

    def test_github_pat_redacted(self):
        pat = "ghp_" + "A" * 36
        result = redact_payload({"header": pat})
        assert result.payload["header"] == REDACT_SENTINEL

    def test_github_oauth_token_redacted(self):
        tok = "gho_" + "A" * 36
        result = redact_payload({"header": tok})
        assert result.payload["header"] == REDACT_SENTINEL

    def test_stripe_live_key_redacted(self):
        key = "sk_live_" + "A" * 24
        result = redact_payload({"payment_key": key})
        assert result.payload["payment_key"] == REDACT_SENTINEL

    def test_databricks_token_redacted(self):
        tok = "dapi" + "a" * 32
        result = redact_payload({"db_token": tok})
        assert result.payload["db_token"] == REDACT_SENTINEL

    def test_vault_token_redacted(self):
        tok = "s." + "A" * 20
        result = redact_payload({"vault_token": tok})
        assert result.payload["vault_token"] == REDACT_SENTINEL

    def test_mongodb_uri_redacted(self):
        uri = "mongodb://admin:s3cr3t@cluster.mongodb.net/db"
        result = redact_payload({"db_uri": uri})
        assert result.payload["db_uri"] == REDACT_SENTINEL

    def test_aws_sts_token_redacted(self):
        tok = "ASIA" + "A" * 16
        result = redact_payload({"session_token": tok})
        assert result.payload["session_token"] == REDACT_SENTINEL

    def test_anthropic_key_redacted(self):
        key = "sk-ant-" + "A" * 40
        result = redact_payload({"llm_key": key})
        assert result.payload["llm_key"] == REDACT_SENTINEL


class TestJsonInJsonRedaction:
    """JSON-in-JSON: string values containing serialised JSON are also walked."""

    def test_json_string_with_api_key_redacted(self):
        import json

        inner = json.dumps({"api_key": "inner-secret", "safe_field": "keep"})
        result = redact_payload({"config_blob": inner})
        parsed_back = json.loads(result.payload["config_blob"])
        assert parsed_back["api_key"] == REDACT_SENTINEL
        assert parsed_back["safe_field"] == "keep"
        assert result.redacted_count == 1

    def test_clean_json_string_not_modified(self):
        import json

        inner = json.dumps({"host": "db.example.com", "port": 5432})
        result = redact_payload({"config_blob": inner})
        assert result.payload["config_blob"] == inner
        assert result.redacted_count == 0

    def test_non_json_string_not_modified(self):
        result = redact_payload({"description": "This is just a plain string."})
        assert result.payload["description"] == "This is just a plain string."


class TestFieldTypeValidation:
    """Wrong-type required fields are rejected with ScanValidationError."""

    def test_required_field_wrong_type_raises(self):
        with pytest.raises(ScanValidationError, match="must be list"):
            validate_required_fields("microsoft_graph", {"users": "not-a-list"})

    def test_required_field_correct_type_accepted(self):
        validate_required_fields("microsoft_graph", {"users": []})  # no exception

    def test_aws_accounts_wrong_type_raises(self):
        with pytest.raises(ScanValidationError, match="must be list"):
            validate_required_fields("aws", {"accounts": {"key": "value"}})


class TestFieldTypeValidationIntegration:
    def test_wrong_type_rejected_via_api(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": "not-a-list"},  # wrong type
                "object_count": 0,
            },
        )
        assert resp.status_code == 422
        assert "SCAN_VALIDATION_ERROR" in resp.text


class TestPerSourceQuarantineThresholds:
    """Per-source quarantine overrides: AWS allows 8K fields, endpoint_inventory 10K."""

    def test_aws_allows_large_payload(self):
        # 2001 fields — exceeds global 2K threshold but under AWS override of 8K
        payload = {"accounts": [{str(i): i for i in range(2_001)}]}
        quarantine_check(payload, source_type="aws")  # no exception

    def test_microsoft_graph_still_quarantined_at_global_limit(self):
        payload = {str(i): i for i in range(MAX_FIELD_COUNT + 1)}
        with pytest.raises(ScanQuarantinedError, match="field count"):
            quarantine_check(payload, source_type="microsoft_graph")

    def test_endpoint_inventory_allows_large_payload(self):
        # 5001 fields — under endpoint_inventory override of 10K
        payload = {"endpoints": [{str(i): i for i in range(5_001)}]}
        quarantine_check(payload, source_type="endpoint_inventory")  # no exception

    def test_aws_still_quarantined_above_its_override(self):
        payload = {str(i): i for i in range(8_001)}
        with pytest.raises(ScanQuarantinedError, match="field count"):
            quarantine_check(payload, source_type="aws")


class TestFieldCountBugFix:
    """Bug 2 fix: _field_count() must count list items, not just dict keys."""

    def test_list_items_counted(self):
        from services.field_assessment.scan_registry import _field_count

        # A list of 5 scalars: len([...]) = 5, no nested dicts
        assert _field_count([1, 2, 3, 4, 5]) == 5

    def test_flat_array_triggers_quarantine(self):
        # A flat list of 2001 scalars must trip the field count limit
        payload = {"users": list(range(MAX_FIELD_COUNT + 1))}
        with pytest.raises(ScanQuarantinedError, match="field count"):
            quarantine_check(payload)

    def test_nested_dict_count(self):
        from services.field_assessment.scan_registry import _field_count

        # {"a": {"b": 1}} — 2 dict keys + 0 leaf = 2; depth separate from count
        assert _field_count({"a": {"b": 1}}) == 2

    def test_mixed_list_dict_count(self):
        from services.field_assessment.scan_registry import _field_count

        # {"items": [{"x": 1}]} — 1 key (items) + 1 list item + 1 key (x) = 3
        assert _field_count({"items": [{"x": 1}]}) == 3


class TestQuarantineAuditTrail:
    """Quarantine rejections must produce a scan_result.quarantined audit event."""

    def test_quarantined_scan_emits_audit_event(self, client: TestClient):
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

        audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
        assert audit_resp.status_code == 200
        events = audit_resp.json()
        quarantine_events = [
            e for e in events if e["event_type"] == "scan_result.quarantined"
        ]
        assert quarantine_events, "expected a scan_result.quarantined audit event"
        q_payload = quarantine_events[0]["payload"]
        assert "quarantine_detail" in q_payload

    def test_validation_error_emits_audit_event(self, client: TestClient):
        eng_id = _create_engagement(client)
        resp = _ingest(
            client,
            eng_id,
            {
                "source_type": "microsoft_graph",
                "schema_version": "99.0",  # invalid schema version
                "collected_at": "2026-05-19T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 422

        audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
        events = audit_resp.json()
        quarantine_events = [
            e for e in events if e["event_type"] == "scan_result.quarantined"
        ]
        assert quarantine_events, (
            "expected a scan_result.quarantined audit event for validation failure"
        )


class TestDeprecationNoticeInfrastructure:
    """Deprecation notices: current versions return None; infrastructure is in place."""

    def test_current_version_has_no_deprecation_notice(self):
        # All current versions should return None (no deprecation)
        notice = validate_schema_version("microsoft_graph", "2.0")
        assert notice is None

    def test_all_registered_current_versions_are_not_deprecated(self):
        from services.field_assessment.scan_registry import (
            SUPPORTED_SCHEMA_VERSIONS,
            DEPRECATED_SCHEMA_VERSIONS,
        )

        for source_type, versions in SUPPORTED_SCHEMA_VERSIONS.items():
            deprecated_for_source = DEPRECATED_SCHEMA_VERSIONS.get(source_type, {})
            non_deprecated = versions - set(deprecated_for_source.keys())
            for v in non_deprecated:
                notice = validate_schema_version(source_type, v)
                assert notice is None, (
                    f"{source_type}@{v} unexpectedly has a deprecation notice"
                )
