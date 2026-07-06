#!/usr/bin/env python3
"""Governance Digital Twin foundation gate for PR 18.8.1."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVICE_DIR = ROOT / "services" / "governance_digital_twin"
DOC_PATH = ROOT / "docs" / "GOVERNANCE_DIGITAL_TWIN_18_8_1.md"
CONSTITUTION_PATH = ROOT / "docs" / "GOVERNANCE_DIGITAL_TWIN_CONSTITUTION.md"
PR_FIX_LOG = ROOT / "docs" / "ai" / "PR_FIX_LOG.md"
TEST_FILE = ROOT / "tests" / "test_governance_digital_twin.py"
CI_TEST_FILE = ROOT / "tests" / "tools" / "test_governance_digital_twin_ci.py"

REQUIRED_FILES = [
    SERVICE_DIR / "__init__.py",
    SERVICE_DIR / "models.py",
    SERVICE_DIR / "builder.py",
    SERVICE_DIR / "fingerprint.py",
    SERVICE_DIR / "exporter.py",
    SERVICE_DIR / "baseline.py",
    SERVICE_DIR / "redaction.py",
    SERVICE_DIR / "immutability.py",
    SERVICE_DIR / "relationship_registry.py",
    SERVICE_DIR / "manifest.py",
    SERVICE_DIR / "validator.py",
    SERVICE_DIR / "contract.py",
    SERVICE_DIR / "mcim.py",
    SERVICE_DIR / "mcim_registration.py",
]
FORBIDDEN_KEYS = [
    "secret",
    "token",
    "password",
    "api_key",
    "auth_header",
    "authorization",
    "raw_prompt",
    "raw_vector",
    "embedding",
    "provider_payload",
    "private_key",
    "session",
    "cookie",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    for path in REQUIRED_FILES:
        if not path.exists():
            failures.append(f"missing required file: {path.relative_to(ROOT)}")

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    models_text = _read(SERVICE_DIR / "models.py")
    builder_text = _read(SERVICE_DIR / "builder.py")
    fingerprint_text = _read(SERVICE_DIR / "fingerprint.py")
    exporter_text = _read(SERVICE_DIR / "exporter.py")
    redaction_text = _read(SERVICE_DIR / "redaction.py")
    baseline_text = _read(SERVICE_DIR / "baseline.py")
    manifest_text = _read(SERVICE_DIR / "manifest.py")
    validator_text = _read(SERVICE_DIR / "validator.py")
    contract_text = _read(SERVICE_DIR / "contract.py")
    immutability_text = _read(SERVICE_DIR / "immutability.py")
    relationship_registry_text = _read(SERVICE_DIR / "relationship_registry.py")
    mcim_text = _read(SERVICE_DIR / "mcim.py")
    mcim_registration_text = _read(SERVICE_DIR / "mcim_registration.py")
    init_text = _read(SERVICE_DIR / "__init__.py")
    doc_text = _read(DOC_PATH) if DOC_PATH.exists() else ""
    constitution_text = _read(CONSTITUTION_PATH) if CONSTITUTION_PATH.exists() else ""
    fix_log_text = _read(PR_FIX_LOG) if PR_FIX_LOG.exists() else ""

    for required_name in (
        "GovernanceDigitalTwinSnapshot",
        "GovernanceDigitalTwinEntity",
        "GovernanceDigitalTwinRelationship",
        "GovernanceDigitalTwinBaseline",
        "GovernanceDigitalTwinManifest",
        "GovernanceDigitalTwinValidationReport",
        "GovernanceDigitalTwinTwinIdentity",
    ):
        if required_name not in models_text:
            failures.append(f"models.py missing {required_name}")

    helper_text = (
        builder_text
        + fingerprint_text
        + exporter_text
        + baseline_text
        + redaction_text
        + manifest_text
        + validator_text
        + contract_text
    )
    for required_name in (
        "build_governance_digital_twin_snapshot",
        "compute_snapshot_fingerprint",
        "compute_entity_hash",
        "compute_relationship_hash",
        "export_replay_safe_snapshot",
        "create_comparison_baseline",
        "redact_forbidden_fields",
        "build_snapshot_manifest",
        "validate_governance_digital_twin_snapshot",
        "GovernanceDigitalTwinServiceContract",
    ):
        if required_name not in helper_text:
            failures.append(f"missing required helper: {required_name}")

    for required_field in (
        "parent_snapshot_id",
        "previous_fingerprint",
        "generation",
        "lineage_id",
        "graph_schema_version",
        "builder_version",
        "confidence_provenance",
        "provenance",
        "state_extensions",
        "future_references",
        "highest_severity",
        "canonical_snapshot_id",
    ):
        if required_field not in models_text:
            failures.append(
                f"models.py missing field or contract text: {required_field}"
            )

    if (
        "canonical_json_bytes" not in fingerprint_text
        or "hashlib.sha256" not in fingerprint_text
    ):
        failures.append("fingerprint.py must use SHA-256 over canonical JSON")
    if (
        "GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN" not in fingerprint_text
        or "FG_GOVERNANCE_DIGITAL_TWIN_V1" not in models_text
    ):
        failures.append("fingerprint.py must include explicit fingerprint domain separation")

    if "sorted(" not in builder_text or ".order_by(" not in builder_text:
        failures.append("builder.py must enforce deterministic sorting")
    if "GOVERNANCE_DIGITAL_TWIN_BUILDER_VERSION" not in builder_text:
        failures.append("builder.py must pin builder version into snapshot state")
    if "canonical_identity_seed" not in builder_text or "_canonical_identity_ref" not in builder_text:
        failures.append("builder.py must derive canonical entity ids from stable identity seeds")
    if "validate_governance_digital_twin_snapshot" not in builder_text:
        failures.append("builder.py must call validator")
    if "build_snapshot_manifest" not in builder_text:
        failures.append("builder.py must build deterministic manifest")

    if (
        "redact_forbidden_fields" not in exporter_text
        or "assert_no_forbidden_fields" not in exporter_text
    ):
        failures.append("exporter.py must enforce replay-safe redaction")
    if "manifest" not in exporter_text:
        failures.append("exporter.py must project the snapshot manifest")
    if "deep_freeze" not in exporter_text or "return deep_freeze(redacted)" not in exporter_text:
        failures.append("exporter.py must return deeply immutable replay-safe exports")

    for forbidden in FORBIDDEN_KEYS:
        if (
            f'"{forbidden}"' not in redaction_text
            and f"'{forbidden}'" not in redaction_text
        ):
            failures.append(
                f"redaction.py missing forbidden key enforcement for {forbidden}"
            )

    if any(
        token in (fingerprint_text + builder_text)
        for token in ["random.", "uuid.uuid4", "utc_iso8601_z_now()", "datetime.now("]
    ):
        failures.append(
            "fingerprinting path must not use random or wall-clock generation"
        )

    if any(
        token in exporter_text
        for token in ["provider_payload", "raw_prompt", "raw_vector"]
    ):
        failures.append(
            "exporter.py must not expose raw prompt/vector/provider payload fields"
        )

    if "FrozenDict" not in immutability_text or "deep_freeze" not in immutability_text:
        failures.append("immutability.py must define FrozenDict and deep_freeze")
    if "RELATIONSHIP_REGISTRY" not in relationship_registry_text or "max_targets_per_source" not in relationship_registry_text:
        failures.append("relationship_registry.py must define the extensible relationship registry")
    if "GovernanceDigitalTwinValidationSeverity" not in validator_text or "highest_severity" not in validator_text:
        failures.append("validator.py must expose structured severity findings")

    if "source of truth" not in mcim_text.lower() or "MCIM_COMPONENT_REGISTRY" not in mcim_text:
        failures.append("mcim.py must consume MCIM registration as the source of truth")
    if "MCIM_REGISTRATION_SOURCE" not in mcim_registration_text or "MCIM-18.8.1-GDT" not in mcim_registration_text:
        failures.append("mcim_registration.py must define Governance Digital Twin MCIM registrations")

    if not TEST_FILE.exists():
        failures.append("tests/test_governance_digital_twin.py missing")
    if not CI_TEST_FILE.exists():
        failures.append("tests/tools/test_governance_digital_twin_ci.py missing")
    if not DOC_PATH.exists():
        failures.append("docs/GOVERNANCE_DIGITAL_TWIN_18_8_1.md missing")
    if not CONSTITUTION_PATH.exists():
        failures.append("docs/GOVERNANCE_DIGITAL_TWIN_CONSTITUTION.md missing")

    if (
        "Constitution" not in doc_text
        or "State is built first, validated second, fingerprinted third" not in doc_text
    ):
        failures.append("architecture doc missing constitution/build-order rule")
    if (
        "No Fabrication" not in constitution_text
        or "Nothing computes governance state outside" not in constitution_text
    ):
        failures.append("constitution doc missing permanent law")

    if "18.8.1" not in fix_log_text or "Governance Digital Twin" not in fix_log_text:
        failures.append("docs/ai/PR_FIX_LOG.md missing PR 18.8.1 entry")

    api_route_file = ROOT / "api" / "governance_digital_twin.py"
    if api_route_file.exists():
        main_text = _read(ROOT / "api" / "main.py")
        if "governance_digital_twin" not in main_text:
            failures.append(
                "api route file exists but is not registered in api/main.py"
            )

    if (
        "GovernanceDigitalTwinSnapshot" not in init_text
        or "validate_governance_digital_twin_snapshot" not in init_text
    ):
        failures.append(
            "__init__.py must re-export the snapshot and validator interfaces"
        )

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    print("PASS — Governance Digital Twin foundation check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
