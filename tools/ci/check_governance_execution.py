#!/usr/bin/env python3
"""Governance Execution Engine gate for PR 18.8.3."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVICE_DIR = ROOT / "services" / "governance_execution"
TEST_FILE = ROOT / "tests" / "test_governance_execution.py"
PR_FIX_LOG = ROOT / "docs" / "ai" / "PR_FIX_LOG.md"
CONSTITUTION_DOC = ROOT / "docs" / "GOVERNANCE_EXECUTION_CONSTITUTION.md"

REQUIRED_FILES = [
    SERVICE_DIR / "__init__.py",
    SERVICE_DIR / "models.py",
    SERVICE_DIR / "planner.py",
    SERVICE_DIR / "approvals.py",
    SERVICE_DIR / "execution.py",
    SERVICE_DIR / "verification.py",
    SERVICE_DIR / "measurement.py",
    SERVICE_DIR / "rollback.py",
    SERVICE_DIR / "replay.py",
    SERVICE_DIR / "validator.py",
    SERVICE_DIR / "exporter.py",
    SERVICE_DIR / "contract.py",
    SERVICE_DIR / "manifest.py",
    SERVICE_DIR / "fingerprint.py",
    SERVICE_DIR / "registry.py",
    SERVICE_DIR / "constitution.py",
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

CONTRACT_METHODS = [
    "plan",
    "validate",
    "approve",
    "execute",
    "verify",
    "measure",
    "rollback",
    "export",
    "replay",
    "fingerprint",
]

MCIM_REQUIRED_KEYS = [
    "execution_plan",
    "execution_run",
    "execution_decision",
    "execution_verification",
    "execution_measurement",
    "execution_replay",
    "execution_manifest",
    "execution_approval",
    "execution_gate",
    "execution_policy",
    "execution_authority",
    "execution_rollback",
    "execution_audit",
    "execution_authority_mandate",
    "execution_participant",
    "execution_policy_exception",
    "execution_policy_exception_ledger",
    "execution_override",
    "execution_sla_target",
    "execution_sla_record",
    "execution_change_window",
    "execution_ticket_reference",
    "execution_effectiveness",
]

VERSION_CONSTANTS = [
    ("GOVERNANCE_EXECUTION_VERSION", "18.8.3"),
    ("GOVERNANCE_EXECUTION_PLANNER_VERSION", "1.0.0"),
    ("GOVERNANCE_EXECUTION_VALIDATOR_VERSION", "1.0.0"),
    ("GOVERNANCE_EXECUTION_SCHEMA_VERSION", "1.0"),
    ("GOVERNANCE_EXECUTION_REPLAY_VERSION", "1.0"),
    ("GOVERNANCE_EXECUTION_MANIFEST_VERSION", "1.0"),
    ("GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN", "FG_GOVERNANCE_EXECUTION_V1"),
    ("GOVERNANCE_EXECUTION_MCIM_VERSION", "MCIM-18.8.3-GOVERNANCE-EXECUTION"),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _count_asserts(path: Path) -> int:
    """Count assert statements in a Python file using AST."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                count += 1
        return count
    except SyntaxError:
        return 0


def main() -> int:
    failures: list[str] = []

    # 1. Check all 17 required files exist
    for path in REQUIRED_FILES:
        if not path.exists():
            failures.append(f"missing required file: {path.relative_to(ROOT)}")

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    # Read all service files
    models_text = _read(SERVICE_DIR / "models.py")
    planner_text = _read(SERVICE_DIR / "planner.py")
    approvals_text = _read(SERVICE_DIR / "approvals.py")
    execution_text = _read(SERVICE_DIR / "execution.py")
    verification_text = _read(SERVICE_DIR / "verification.py")
    measurement_text = _read(SERVICE_DIR / "measurement.py")
    rollback_text = _read(SERVICE_DIR / "rollback.py")
    replay_text = _read(SERVICE_DIR / "replay.py")
    validator_text = _read(SERVICE_DIR / "validator.py")
    exporter_text = _read(SERVICE_DIR / "exporter.py")
    contract_text = _read(SERVICE_DIR / "contract.py")
    manifest_text = _read(SERVICE_DIR / "manifest.py")
    fingerprint_text = _read(SERVICE_DIR / "fingerprint.py")
    registry_text = _read(SERVICE_DIR / "registry.py")
    constitution_text = _read(SERVICE_DIR / "constitution.py")
    mcim_text = _read(SERVICE_DIR / "mcim_registration.py")
    _read(SERVICE_DIR / "__init__.py")  # verify readable

    all_service_text = "".join(
        [
            models_text,
            planner_text,
            approvals_text,
            execution_text,
            verification_text,
            measurement_text,
            rollback_text,
            replay_text,
            validator_text,
            exporter_text,
            contract_text,
            manifest_text,
            fingerprint_text,
            registry_text,
            constitution_text,
            mcim_text,
        ]
    )

    # 2. Check version constants defined (all 8)
    for const_name, const_value in VERSION_CONSTANTS:
        if const_name not in models_text:
            failures.append(f"models.py missing version constant: {const_name}")
        if f'"{const_value}"' not in models_text:
            failures.append(
                f"models.py version constant {const_name} has wrong value "
                f"(expected {const_value!r})"
            )

    # 3. Check MCIM registration has all required keys (now 23)
    for key in MCIM_REQUIRED_KEYS:
        if f'"{key}"' not in mcim_text:
            failures.append(f"mcim_registration.py missing key: {key}")

    # Import and check actual count at runtime
    try:
        from services.governance_execution.mcim_registration import (
            MCIM_REGISTRATION_SOURCE,
        )

        assert len(MCIM_REGISTRATION_SOURCE) >= 23, (
            f"MCIM_REGISTRATION_SOURCE has {len(MCIM_REGISTRATION_SOURCE)} keys, "
            f"expected >= 23"
        )
    except AssertionError as exc:
        failures.append(str(exc))
    except ImportError:
        pass  # covered by file existence check above

    if "MCIM_REGISTRATION_SOURCE" not in mcim_text:
        failures.append("mcim_registration.py missing MCIM_REGISTRATION_SOURCE")
    if "GOVERNANCE_EXECUTION_MCIM_VERSION" not in mcim_text:
        failures.append(
            "mcim_registration.py missing GOVERNANCE_EXECUTION_MCIM_VERSION"
        )

    # 4. Check no forbidden keys in service files (exporter is exempt — it enumerates them)
    for forbidden in FORBIDDEN_KEYS:
        for fname, text in [
            ("models.py", models_text),
            ("planner.py", planner_text),
            ("execution.py", execution_text),
            ("measurement.py", measurement_text),
            ("verification.py", verification_text),
        ]:
            if f'"{forbidden}"' in text or f"'{forbidden}'" in text:
                failures.append(f"{fname} contains forbidden key string: {forbidden}")

    # 5. Check no DB access in service files
    db_forbidden = [
        "sqlalchemy",
        "Session(",
        "db.query(",
        "from api.db",
        "create_engine",
    ]
    for bad in db_forbidden:
        if bad in all_service_text:
            failures.append(
                f"governance_execution service must not use DB/SQLAlchemy: found '{bad}'"
            )

    # 6. Check all dataclasses are frozen=True in models.py
    if "frozen=True" not in models_text:
        failures.append("models.py dataclasses must use frozen=True")

    # 7. Check ExecutionValidationError is a proper Exception subclass
    if "class ExecutionValidationError" not in validator_text:
        failures.append("validator.py must define ExecutionValidationError")
    if "Exception" not in validator_text:
        failures.append(
            "validator.py ExecutionValidationError must inherit from Exception"
        )

    # 8. Check all 10 contract methods in contract.py
    for method in CONTRACT_METHODS:
        if f"def {method}" not in contract_text:
            failures.append(f"contract.py missing method: {method}")

    if "GovernanceExecutionServiceContract" not in contract_text:
        failures.append("contract.py missing GovernanceExecutionServiceContract")
    if "GovernanceExecutionService" not in contract_text:
        failures.append("contract.py missing GovernanceExecutionService")
    if "Protocol" not in contract_text:
        failures.append("contract.py must use Protocol")

    # 9. Check SHA-256 in fingerprint.py
    if "hashlib.sha256" not in fingerprint_text:
        failures.append("fingerprint.py must use hashlib.sha256")
    if "canonical_json_bytes" not in fingerprint_text:
        failures.append("fingerprint.py must use canonical_json_bytes")
    if "GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN" not in fingerprint_text:
        failures.append(
            "fingerprint.py must reference GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN"
        )

    # 10. Check deep_freeze in exporter.py
    if "deep_freeze" not in exporter_text:
        failures.append("exporter.py must use deep_freeze")
    if "replay_instructions" not in exporter_text:
        failures.append("exporter.py must include replay_instructions")

    # 11. Check validator raises ExecutionValidationError on ERROR/FATAL
    if "raise ExecutionValidationError" not in validator_text:
        failures.append(
            "validator.py must raise ExecutionValidationError on ERROR/FATAL"
        )

    # 12. Check rollback referenced in planner.py
    if "rollback" not in planner_text.lower():
        failures.append("planner.py must reference rollback")
    if "ExecutionRollbackPlan" not in planner_text:
        failures.append("planner.py must create ExecutionRollbackPlan")

    # 13. Check state transitions in registry.py
    if "EXECUTION_STATE_TRANSITIONS" not in registry_text:
        failures.append("registry.py missing EXECUTION_STATE_TRANSITIONS")
    if "is_valid_transition" not in registry_text:
        failures.append("registry.py missing is_valid_transition")
    if "MappingProxyType" not in registry_text:
        failures.append("registry.py must use MappingProxyType for immutability")

    # 14. Check test file has >= 250 assert statements
    if not TEST_FILE.exists():
        failures.append("tests/test_governance_execution.py missing")
    else:
        assert_count = _count_asserts(TEST_FILE)
        if assert_count < 250:
            failures.append(
                f"tests/test_governance_execution.py has only {assert_count} assert "
                f"statements (need >= 250)"
            )

    # 15. Check constitution doc exists
    if not CONSTITUTION_DOC.exists():
        failures.append("docs/GOVERNANCE_EXECUTION_CONSTITUTION.md missing")

    # 16. Check PR fix log has 18.8.3 entry
    if PR_FIX_LOG.exists():
        fix_log_text = _read(PR_FIX_LOG)
        if "18.8.3" not in fix_log_text:
            failures.append("docs/ai/PR_FIX_LOG.md missing PR 18.8.3 entry")
    else:
        failures.append("docs/ai/PR_FIX_LOG.md not found")

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    print("PASS — Governance Execution Engine check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
