"""Offline validator for non-secret Customer-Zero Vault provisioning evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from services.canonical import canonical_json_bytes

SCHEMA_VERSION = "1.0"
WORK_ITEM = "CUSTOMER-ZERO-TRUST-001"
ROLES = ("customer-zero-identity", "customer-zero-acceptance", "customer-zero-approval")
DIMENSIONS = (
    "SOURCE_IDENTITY",
    "DEPLOYMENT_IDENTITY",
    "VAULT_DEPLOYMENT",
    "VAULT_AUTHENTICATION",
    "ROLE_SEPARATION",
    "IDENTITY_AUTHORITY",
    "ACCEPTANCE_AUTHORITY",
    "APPROVAL_AUTHORITY",
    "KEY_CONFIGURATION",
    "PUBLIC_ANCHORS",
    "AUDITABILITY",
    "ROTATION_HISTORY",
    "FAILURE_BEHAVIOR",
    "RECOVERY",
    "SECRET_BOUNDARY",
)
STATE_ORDER = (
    "NOT_STARTED",
    "VAULT_IDENTIFIED",
    "AUTH_CONFIGURED",
    "KEYS_VERIFIED",
    "POLICIES_VERIFIED",
    "ANCHORS_ENROLLED",
    "NEGATIVE_TESTS_VERIFIED",
    "ROTATION_VERIFIED",
    "FAILURE_TESTS_VERIFIED",
    "RECOVERY_VERIFIED",
    "EVIDENCE_COMPLETE",
)
_SECRET_FIELDS = re.compile(
    r"(?:token|secret[_-]?id|private[_-]?key|authorization|bearer|recovery[_-]?key|unseal)",
    re.I,
)
_SHA = re.compile(r"^[0-9a-f]{64}$")


class EvidenceState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_PROVEN = "NOT_PROVEN"


@dataclass(frozen=True)
class ValidationResult:
    state: EvidenceState
    dimensions: dict[str, EvidenceState]
    reasons: tuple[str, ...]
    fingerprint: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "dimensions": {k: v.value for k, v in self.dimensions.items()},
            "reasons": list(self.reasons),
            "evidence_fingerprint": self.fingerprint,
        }


def _contains_secret_field(value: Any, path: str = "$") -> str | None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _SECRET_FIELDS.search(key_text):
                return f"secret-bearing field rejected: {path}.{key_text}"
            found = _contains_secret_field(child, f"{path}.{key_text}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _contains_secret_field(child, f"{path}[{index}]")
            if found:
                return found
    return None


_UNORDERED_LIST_FIELDS = {
    "trust_roles",
    "public_anchors",
    "audit_evidence",
    "rotation_history",
    "failure_evidence",
}


def _without_fingerprint(manifest: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        key: value for key, value in manifest.items() if key != "evidence_fingerprint"
    }
    for field_name in _UNORDERED_LIST_FIELDS:
        values = result.get(field_name)
        if isinstance(values, list) and all(
            isinstance(item, Mapping) for item in values
        ):
            result[field_name] = sorted(
                values, key=lambda item: canonical_json_bytes(item)
            )
    return result


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(_without_fingerprint(manifest))


def fingerprint_manifest(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _state(value: Any) -> EvidenceState | None:
    try:
        return EvidenceState(value)
    except (TypeError, ValueError):
        return None


def _aggregate(states: Mapping[str, EvidenceState]) -> EvidenceState:
    if any(value is EvidenceState.FAIL for value in states.values()):
        return EvidenceState.FAIL
    if any(value is EvidenceState.NOT_PROVEN for value in states.values()):
        return EvidenceState.NOT_PROVEN
    return EvidenceState.PASS


def _role_reasons(manifest: Mapping[str, Any]) -> tuple[list[str], EvidenceState]:
    reasons: list[str] = []
    result = EvidenceState.PASS
    roles = manifest.get("trust_roles")
    if not isinstance(roles, list) or len(roles) != 3:
        return ["exactly three trust roles are required"], EvidenceState.FAIL
    seen: set[str] = set()
    key_ids: set[str] = set()
    auth_ids: set[str] = set()
    policy_fingerprints: set[str] = set()
    for record in roles:
        if not isinstance(record, dict):
            reasons.append("malformed trust-role record")
            result = EvidenceState.FAIL
            continue
        role = record.get("trust_role")
        if role not in ROLES or role in seen:
            reasons.append("unknown or duplicate trust role")
            result = EvidenceState.FAIL
            continue
        seen.add(role)
        required = (
            "issuer",
            "auth_role_id",
            "policy_id",
            "policy_fingerprint",
            "key_id",
            "key_version",
            "algorithm",
            "exportable",
            "deletion_allowed",
            "public_key",
            "public_key_fingerprint",
            "anchor_status",
        )
        missing = [
            field
            for field in required
            if field not in record or record[field] in (None, "")
        ]
        if missing:
            reasons.append(f"{role} missing evidence: {','.join(missing)}")
            if result is EvidenceState.PASS:
                result = EvidenceState.NOT_PROVEN
        if record.get("algorithm") not in (None, "ed25519"):
            reasons.append(f"{role} uses unsupported algorithm")
            result = EvidenceState.FAIL
        if record.get("exportable") is True or record.get("deletion_allowed") is True:
            reasons.append(f"{role} has unsafe key configuration")
            result = EvidenceState.FAIL
        if (
            not isinstance(record.get("key_version"), int)
            or record.get("key_version", 0) <= 0
        ):
            reasons.append(f"{role} has invalid key version")
            result = EvidenceState.FAIL
        if role in seen and record.get("key_id"):
            if record["key_id"] in key_ids:
                reasons.append("duplicate Transit key ID")
                result = EvidenceState.FAIL
            key_ids.add(record["key_id"])
            if record.get("auth_role_id") in auth_ids:
                reasons.append("duplicate runtime auth identity")
                result = EvidenceState.FAIL
            auth_ids.add(str(record.get("auth_role_id")))
            if record.get("policy_fingerprint") in policy_fingerprints:
                reasons.append("duplicate policy fingerprint")
                result = EvidenceState.FAIL
            policy_fingerprints.add(str(record.get("policy_fingerprint")))
        anchor = record.get("public_anchor")
        if not isinstance(anchor, dict):
            reasons.append(f"{role} public anchor evidence missing")
            if result is EvidenceState.PASS:
                result = EvidenceState.NOT_PROVEN
        elif (
            anchor.get("trust_role") != role
            or anchor.get("key_id") != record.get("key_id")
            or anchor.get("key_version") != record.get("key_version")
        ):
            reasons.append(f"{role} anchor binding mismatch")
            result = EvidenceState.FAIL
        elif anchor.get("public_key_fingerprint") != record.get(
            "public_key_fingerprint"
        ):
            reasons.append(f"{role} anchor fingerprint mismatch")
            result = EvidenceState.FAIL
    if seen != set(ROLES):
        reasons.append("all three canonical trust roles are required")
        result = EvidenceState.FAIL
    return reasons, result


def validate_manifest(manifest: Mapping[str, Any]) -> ValidationResult:
    if not isinstance(manifest, Mapping):
        return ValidationResult(
            EvidenceState.FAIL, {}, ("manifest must be an object",), ""
        )
    secret_reason = _contains_secret_field(manifest)
    fp = fingerprint_manifest(manifest)
    if secret_reason:
        return ValidationResult(EvidenceState.FAIL, {}, (secret_reason,), fp)
    reasons: list[str] = []
    dimensions: dict[str, EvidenceState] = {}
    if manifest.get("schema_version") != SCHEMA_VERSION:
        return ValidationResult(EvidenceState.FAIL, {}, ("unknown schema version",), fp)
    if manifest.get("work_item") != WORK_ITEM:
        return ValidationResult(EvidenceState.FAIL, {}, ("wrong work item",), fp)
    for field in (
        "ceremony_id",
        "environment",
        "generated_at",
        "source_sha",
        "tested_sha",
        "vault_deployment",
    ):
        if not manifest.get(field):
            reasons.append(f"missing {field}")
    if not isinstance(manifest.get("source_sha"), str) or not _SHA.fullmatch(
        str(manifest.get("source_sha", ""))
    ):
        reasons.append("invalid source SHA")
        dimensions["SOURCE_IDENTITY"] = EvidenceState.FAIL
    elif manifest.get("tested_sha") != manifest.get("source_sha"):
        dimensions["SOURCE_IDENTITY"] = (
            EvidenceState.FAIL
            if manifest.get("tested_sha")
            else EvidenceState.NOT_PROVEN
        )
        reasons.append(
            "tested SHA does not match source SHA"
            if manifest.get("tested_sha")
            else "tested SHA unavailable"
        )
    else:
        dimensions["SOURCE_IDENTITY"] = EvidenceState.PASS
    dimensions["DEPLOYMENT_IDENTITY"] = (
        EvidenceState.PASS if manifest.get("deployed_sha") else EvidenceState.NOT_PROVEN
    )
    role_reasons, role_state = _role_reasons(manifest)
    reasons.extend(role_reasons)
    dimensions["ROLE_SEPARATION"] = role_state
    dimensions["KEY_CONFIGURATION"] = role_state
    dimensions["PUBLIC_ANCHORS"] = role_state
    role_dimension_map = {
        "IDENTITY_AUTHORITY": "identity",
        "ACCEPTANCE_AUTHORITY": "acceptance",
        "APPROVAL_AUTHORITY": "approval",
    }
    for dimension, key in role_dimension_map.items():
        dimensions[dimension] = (
            EvidenceState.PASS
            if any(
                isinstance(r, dict)
                and r.get("trust_role") == f"customer-zero-{key}"
                and r.get("audit_evidence_ref")
                for r in manifest.get("trust_roles", [])
            )
            else EvidenceState.NOT_PROVEN
        )
    raw_dimensions = manifest.get("dimensions")
    if isinstance(raw_dimensions, Mapping):
        unknown_dimensions = set(raw_dimensions) - set(DIMENSIONS)
        if unknown_dimensions:
            reasons.append("unknown evidence dimension")
            dimensions["ROLE_SEPARATION"] = EvidenceState.FAIL
    if not isinstance(raw_dimensions, Mapping):
        reasons.append("dimension evidence missing")
        raw_dimensions = {}
    for dimension in DIMENSIONS:
        if dimension in dimensions:
            continue
        value = _state(raw_dimensions.get(dimension))
        if value is None:
            dimensions[dimension] = EvidenceState.NOT_PROVEN
            reasons.append(f"{dimension} evidence unavailable")
        else:
            dimensions[dimension] = value
    if manifest.get("deployed_sha") and manifest.get("deployed_sha") != manifest.get(
        "tested_sha"
    ):
        dimensions["DEPLOYMENT_IDENTITY"] = EvidenceState.FAIL
        reasons.append("deployed SHA does not match tested SHA")
    if dimensions.get("RECOVERY") is EvidenceState.PASS and not manifest.get(
        "recovery_evidence_ref"
    ):
        dimensions["RECOVERY"] = EvidenceState.NOT_PROVEN
        reasons.append("recovery evidence reference missing")
    overall = _aggregate(dimensions)
    return ValidationResult(overall, dimensions, tuple(sorted(set(reasons))), fp)


class CeremonyStateMachine:
    def __init__(self) -> None:
        self.state = "NOT_STARTED"

    def advance(self, target: str, manifest: Mapping[str, Any]) -> str:
        if (
            target not in STATE_ORDER
            or STATE_ORDER.index(target) != STATE_ORDER.index(self.state) + 1
        ):
            raise ValueError("ceremony state cannot skip required evidence")
        result = validate_manifest(manifest)
        required = {
            "VAULT_IDENTIFIED": ("VAULT_DEPLOYMENT",),
            "AUTH_CONFIGURED": ("VAULT_AUTHENTICATION",),
            "KEYS_VERIFIED": ("KEY_CONFIGURATION",),
            "POLICIES_VERIFIED": ("ROLE_SEPARATION",),
            "ANCHORS_ENROLLED": ("PUBLIC_ANCHORS",),
            "NEGATIVE_TESTS_VERIFIED": ("FAILURE_BEHAVIOR",),
            "ROTATION_VERIFIED": ("ROTATION_HISTORY",),
            "FAILURE_TESTS_VERIFIED": ("FAILURE_BEHAVIOR",),
            "RECOVERY_VERIFIED": ("RECOVERY",),
            "EVIDENCE_COMPLETE": DIMENSIONS,
        }[target]
        if any(result.dimensions.get(d) is not EvidenceState.PASS for d in required):
            raise ValueError("required evidence does not pass")
        self.state = target
        return self.state


def load_manifest(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("manifest must be a JSON object")
    return value
