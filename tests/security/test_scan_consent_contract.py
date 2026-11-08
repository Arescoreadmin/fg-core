"""Contract security tests for customer scan consent routes.

L14-SCAN-AUTH-HARDENING-001.  Verifies the COMMITTED OpenAPI contract (not just
runtime code) cannot be used to forge customer approval: no identity, tenant or
status fields are accepted from request bodies, and unknown fields are rejected.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = [
    ROOT / "contracts" / "core" / "openapi.json",
    ROOT / "schemas" / "api" / "openapi.json",
]

_PREFIX = "/field-assessment/engagements/{engagement_id}"
ROUTES = {
    ("post", f"{_PREFIX}/customer-authorizations"): "CustomerAuthorizationRequestBody",
    ("get", f"{_PREFIX}/customer-authorizations"): None,
    ("get", f"{_PREFIX}/customer-authorizations/{{receipt_id}}"): None,
    (
        "post",
        f"{_PREFIX}/customer-authorizations/{{receipt_id}}/approve",
    ): "CustomerAuthorizationDecisionBody",
    (
        "post",
        f"{_PREFIX}/customer-authorizations/{{receipt_id}}/reject",
    ): "CustomerAuthorizationReasonBody",
    (
        "post",
        f"{_PREFIX}/customer-authorizations/{{receipt_id}}/revoke",
    ): "CustomerAuthorizationReasonBody",
    ("get", f"{_PREFIX}/scan-authorizations/effective-status"): None,
    ("post", "/field-assessment/emergency-stop/{stop_id}/clear"): None,
}

# Fields that, if accepted from a client, would let a caller forge consent.
FORGEABLE = {
    "tenant_id",
    "approver_subject",
    "approved_by",
    "approver_email",
    "approver_authority_basis",
    "approver_auth_source",
    "status",
    "approved_at",
    "payload_digest",
    "attestation_kid",
    "attestation_value",
    "proof_level",
    "requested_by_subject",
}


@pytest.fixture(params=CONTRACTS, ids=lambda p: p.parent.name)
def spec(request) -> dict:
    return json.loads(request.param.read_text())


def _schema(spec: dict, name: str) -> dict:
    return spec["components"]["schemas"][name]


def test_all_consent_routes_in_contract(spec):
    for method, path in ROUTES:
        assert method in spec["paths"].get(path, {}), f"{method.upper()} {path} missing"


def test_request_bodies_match_expected_models(spec):
    for (method, path), model in ROUTES.items():
        op = spec["paths"][path][method]
        body = op.get("requestBody", {}).get("content", {}).get("application/json", {})
        ref = body.get("schema", {}).get("$ref")
        if model is None:
            assert ref is None, f"{path} unexpectedly accepts a body"
        else:
            assert ref == f"#/components/schemas/{model}"


@pytest.mark.parametrize(
    "model",
    sorted({m for m in ROUTES.values() if m}),
)
def test_bodies_reject_unknown_fields_and_forgeable_identity(spec, model):
    sch = _schema(spec, model)
    assert sch.get("additionalProperties") is False, f"{model} must forbid extra fields"
    leaked = FORGEABLE & set(sch.get("properties", {}))
    assert not leaked, f"{model} accepts forgeable fields: {sorted(leaked)}"


def test_approval_body_is_only_statement_acknowledgement(spec):
    sch = _schema(spec, "CustomerAuthorizationDecisionBody")
    assert set(sch["properties"]) == {"acknowledge_consent_statement_version"}
    assert sch["required"] == ["acknowledge_consent_statement_version"]


def test_path_parameters_are_only_identifiers(spec):
    for method, path in ROUTES:
        op = spec["paths"][path][method]
        names = {
            p["name"]
            for p in op.get("parameters", [])
            if p.get("in") in ("query", "path")
        }
        assert not (names & {"tenant_id", "approver_subject", "principal_id"}), path
