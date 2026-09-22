from __future__ import annotations

import copy
import hashlib

import pytest

from services.cgin.key_management.trust_evidence import (
    DIMENSIONS,
    EvidenceState,
    CeremonyStateMachine,
    canonical_manifest_bytes,
    fingerprint_manifest,
    validate_manifest,
)


def manifest() -> dict:
    roles = []
    for role, suffix in (
        ("customer-zero-identity", "identity"),
        ("customer-zero-acceptance", "acceptance"),
        ("customer-zero-approval", "approval"),
    ):
        public = f"public-{suffix}"
        roles.append(
            {
                "trust_role": role,
                "issuer": "vault-hcp",
                "auth_role_id": f"auth-{suffix}",
                "policy_id": f"policy-{suffix}",
                "policy_fingerprint": hashlib.sha256(
                    f"policy-{suffix}".encode()
                ).hexdigest(),
                "key_id": f"key-{suffix}",
                "key_version": 1,
                "algorithm": "ed25519",
                "exportable": False,
                "deletion_allowed": False,
                "public_key": public,
                "public_key_fingerprint": hashlib.sha256(public.encode()).hexdigest(),
                "anchor_status": "active",
                "audit_evidence_ref": f"audit-{suffix}",
                "public_anchor": {
                    "trust_role": role,
                    "key_id": f"key-{suffix}",
                    "key_version": 1,
                    "public_key_fingerprint": hashlib.sha256(
                        public.encode()
                    ).hexdigest(),
                },
            }
        )
    return {
        "schema_version": "1.0",
        "work_item": "CUSTOMER-ZERO-TRUST-001",
        "ceremony_id": "ceremony-001",
        "environment": "hcp-vault-dedicated",
        "generated_at": "2026-09-22T12:00:00Z",
        "source_sha": "a" * 64,
        "tested_sha": "a" * 64,
        "deployed_sha": "a" * 64,
        "vault_deployment": {"identity": "hcp-vault-001", "region": "us-east"},
        "trust_roles": roles,
        "dimensions": {dimension: "PASS" for dimension in DIMENSIONS},
        "recovery_evidence_ref": "recovery-001",
    }


def test_fingerprint_is_deterministic_and_excludes_self():
    value = manifest()
    first = fingerprint_manifest(value)
    value["evidence_fingerprint"] = "different"
    assert fingerprint_manifest(value) == first
    assert hashlib.sha256(canonical_manifest_bytes(value)).hexdigest() == first


def test_reordering_roles_preserves_fingerprint():
    value = manifest()
    reordered = copy.deepcopy(value)
    reordered["trust_roles"] = list(reversed(reordered["trust_roles"]))
    assert fingerprint_manifest(value) == fingerprint_manifest(reordered)


def test_material_mutation_changes_fingerprint():
    value = manifest()
    original = fingerprint_manifest(value)
    value["vault_deployment"]["region"] = "eu-west"
    assert fingerprint_manifest(value) != original


def test_complete_manifest_passes():
    result = validate_manifest(manifest())
    assert result.state is EvidenceState.PASS
    assert all(value is EvidenceState.PASS for value in result.dimensions.values())


@pytest.mark.parametrize(
    "field,value",
    [
        ("algorithm", "rsa"),
        ("exportable", True),
        ("deletion_allowed", True),
        ("key_version", 0),
    ],
)
def test_unsafe_key_configuration_fails(field, value):
    value_manifest = manifest()
    value_manifest["trust_roles"][0][field] = value
    assert validate_manifest(value_manifest).state is EvidenceState.FAIL


def test_exactly_three_roles_and_duplicate_ids_fail():
    value = manifest()
    value["trust_roles"] = value["trust_roles"][:2]
    assert validate_manifest(value).state is EvidenceState.FAIL
    value = manifest()
    value["trust_roles"][1]["key_id"] = value["trust_roles"][0]["key_id"]
    assert validate_manifest(value).state is EvidenceState.FAIL


def test_anchor_mismatch_fails():
    value = manifest()
    value["trust_roles"][0]["public_anchor"]["key_version"] = 2
    assert validate_manifest(value).state is EvidenceState.FAIL


def test_missing_anchor_or_audit_is_not_proven():
    value = manifest()
    value["trust_roles"][0].pop("public_anchor")
    result = validate_manifest(value)
    assert result.state is EvidenceState.NOT_PROVEN
    value = manifest()
    value["trust_roles"][0].pop("audit_evidence_ref")
    assert (
        validate_manifest(value).dimensions["IDENTITY_AUTHORITY"]
        is EvidenceState.NOT_PROVEN
    )


def test_missing_deployed_sha_and_recovery_are_not_proven():
    value = manifest()
    value.pop("deployed_sha")
    value.pop("recovery_evidence_ref")
    result = validate_manifest(value)
    assert result.state is EvidenceState.NOT_PROVEN
    assert result.dimensions["DEPLOYMENT_IDENTITY"] is EvidenceState.NOT_PROVEN


def test_source_or_deployed_mismatch_fails():
    value = manifest()
    value["tested_sha"] = "b" * 64
    assert validate_manifest(value).dimensions["SOURCE_IDENTITY"] is EvidenceState.FAIL
    value = manifest()
    value["deployed_sha"] = "b" * 64
    assert (
        validate_manifest(value).dimensions["DEPLOYMENT_IDENTITY"] is EvidenceState.FAIL
    )


@pytest.mark.parametrize(
    "field",
    [
        "token",
        "secret_id",
        "private_key",
        "authorization",
        "bearer",
        "recovery_key",
        "unseal",
    ],
)
def test_secret_bearing_fields_are_rejected(field):
    value = manifest()
    value["unsafe"] = {field: "do-not-store"}
    assert validate_manifest(value).state is EvidenceState.FAIL


def test_public_key_is_allowed():
    value = manifest()
    value["public_key"] = "public-material"
    assert validate_manifest(value).state is EvidenceState.PASS


def test_unknown_schema_or_work_item_fails():
    value = manifest()
    value["schema_version"] = "9.0"
    assert validate_manifest(value).state is EvidenceState.FAIL
    value = manifest()
    value["work_item"] = "OTHER"
    assert validate_manifest(value).state is EvidenceState.FAIL


def test_unknown_dimension_fails_closed():
    value = manifest()
    value["dimensions"]["UNKNOWN"] = "PASS"
    assert validate_manifest(value).state is EvidenceState.FAIL


def test_missing_dimensions_are_not_proven_and_empty_cannot_pass():
    value = manifest()
    value.pop("dimensions")
    result = validate_manifest(value)
    assert result.state is EvidenceState.NOT_PROVEN
    assert validate_manifest({}).state is EvidenceState.FAIL


def test_state_machine_rejects_skipping_and_requires_evidence():
    machine = CeremonyStateMachine()
    with pytest.raises(ValueError, match="skip"):
        machine.advance("KEYS_VERIFIED", manifest())
    assert machine.advance("VAULT_IDENTIFIED", manifest()) == "VAULT_IDENTIFIED"
    with pytest.raises(ValueError, match="required evidence"):
        machine.advance("AUTH_CONFIGURED", {**manifest(), "dimensions": {}})


def test_replay_validation_is_network_free_and_stable():
    value = manifest()
    first = validate_manifest(value).as_dict()
    second = validate_manifest(copy.deepcopy(value)).as_dict()
    assert first == second
