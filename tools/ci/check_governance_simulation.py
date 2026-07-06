#!/usr/bin/env python3
"""Governance Simulation Engine gate for PR 18.8.2."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVICE_DIR = ROOT / "services" / "governance_simulation"
TEST_FILE = ROOT / "tests" / "test_governance_simulation.py"
PR_FIX_LOG = ROOT / "docs" / "ai" / "PR_FIX_LOG.md"

REQUIRED_FILES = [
    SERVICE_DIR / "__init__.py",
    SERVICE_DIR / "models.py",
    SERVICE_DIR / "overlay.py",
    SERVICE_DIR / "scenario.py",
    SERVICE_DIR / "simulator.py",
    SERVICE_DIR / "diff.py",
    SERVICE_DIR / "impact.py",
    SERVICE_DIR / "validator.py",
    SERVICE_DIR / "replay.py",
    SERVICE_DIR / "exporter.py",
    SERVICE_DIR / "contract.py",
    SERVICE_DIR / "fingerprint.py",
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
    "build_scenario",
    "validate",
    "simulate",
    "diff",
    "impact",
    "fingerprint",
    "export",
    "replay",
]

MCIM_REQUIRED_KEYS = [
    "scenario",
    "overlay",
    "impact_report",
    "diff_report",
    "replay_package",
    "simulation_manifest",
    "simulation_validator",
    "simulation_fingerprint",
    "simulation_category",
]

VERSION_CONSTANTS = [
    ("GOVERNANCE_SIMULATION_VERSION", "18.8.2"),
    ("GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION", "1.0"),
    ("GOVERNANCE_SIMULATION_SIMULATOR_VERSION", "1.0.0"),
    ("GOVERNANCE_SIMULATION_REPLAY_VERSION", "1.0"),
    ("GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN", "FG_GOVERNANCE_SIMULATION_V1"),
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

    # 1. Check all required files exist
    for path in REQUIRED_FILES:
        if not path.exists():
            failures.append(f"missing required file: {path.relative_to(ROOT)}")

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    # Read all service files
    models_text = _read(SERVICE_DIR / "models.py")
    overlay_text = _read(SERVICE_DIR / "overlay.py")
    scenario_text = _read(SERVICE_DIR / "scenario.py")
    simulator_text = _read(SERVICE_DIR / "simulator.py")
    diff_text = _read(SERVICE_DIR / "diff.py")
    impact_text = _read(SERVICE_DIR / "impact.py")
    validator_text = _read(SERVICE_DIR / "validator.py")
    replay_text = _read(SERVICE_DIR / "replay.py")
    exporter_text = _read(SERVICE_DIR / "exporter.py")
    contract_text = _read(SERVICE_DIR / "contract.py")
    fingerprint_text = _read(SERVICE_DIR / "fingerprint.py")
    mcim_text = _read(SERVICE_DIR / "mcim_registration.py")
    init_text = _read(SERVICE_DIR / "__init__.py")

    all_service_text = (
        models_text
        + overlay_text
        + scenario_text
        + simulator_text
        + diff_text
        + impact_text
        + validator_text
        + replay_text
        + exporter_text
        + contract_text
        + fingerprint_text
        + mcim_text
    )

    # 2. Check version constants in models.py
    for const_name, const_value in VERSION_CONSTANTS:
        if const_name not in models_text:
            failures.append(f"models.py missing version constant: {const_name}")
        if f'"{const_value}"' not in models_text:
            failures.append(
                f"models.py version constant {const_name} has wrong value (expected {const_value!r})"
            )

    # 3. Check MCIM registration has all 9 keys
    for key in MCIM_REQUIRED_KEYS:
        if f'"{key}"' not in mcim_text:
            failures.append(f"mcim_registration.py missing key: {key}")

    if "MCIM_REGISTRATION_SOURCE" not in mcim_text:
        failures.append("mcim_registration.py missing MCIM_REGISTRATION_SOURCE")
    if "GOVERNANCE_SIMULATION_MCIM_VERSION" not in mcim_text:
        failures.append(
            "mcim_registration.py missing GOVERNANCE_SIMULATION_MCIM_VERSION"
        )

    # 4. Check no forbidden keys in service files
    for forbidden in FORBIDDEN_KEYS:
        for fname, text in [
            ("models.py", models_text),
            ("simulator.py", simulator_text),
            ("impact.py", impact_text),
            ("overlay.py", overlay_text),
        ]:
            # Only flag if it appears as a dict key literal (not in comments)
            if f'"{forbidden}"' in text or f"'{forbidden}'" in text:
                # Exporter is allowed to enumerate forbidden keys for scrubbing
                if fname == "exporter.py":
                    continue
                failures.append(f"{fname} contains forbidden key string: {forbidden}")

    # 5. Check SimulationValidationError is defined and is an Exception
    if "class SimulationValidationError" not in validator_text:
        failures.append("validator.py must define SimulationValidationError")
    if "Exception" not in validator_text:
        failures.append(
            "validator.py SimulationValidationError must inherit from Exception"
        )

    # 6. Check contract.py has all 8 method names
    for method in CONTRACT_METHODS:
        if f"def {method}" not in contract_text:
            failures.append(f"contract.py missing method: {method}")

    # 7. Check GovernanceSimulationService and Protocol in contract
    if "GovernanceSimulationServiceContract" not in contract_text:
        failures.append("contract.py missing GovernanceSimulationServiceContract")
    if "GovernanceSimulationService" not in contract_text:
        failures.append("contract.py missing GovernanceSimulationService")
    if "Protocol" not in contract_text:
        failures.append("contract.py must use Protocol")

    # 8. Check fingerprint.py uses SHA-256
    if "hashlib.sha256" not in fingerprint_text:
        failures.append("fingerprint.py must use hashlib.sha256")
    if "canonical_json_bytes" not in fingerprint_text:
        failures.append("fingerprint.py must use canonical_json_bytes")
    if "GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN" not in fingerprint_text:
        failures.append(
            "fingerprint.py must reference GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN"
        )

    # 9. Check exporter uses deep_freeze
    if "deep_freeze" not in exporter_text:
        failures.append("exporter.py must use deep_freeze")
    if "replay_instructions" not in exporter_text:
        failures.append("exporter.py must include replay_instructions")

    # 10. Check validator fails closed (raises SimulationValidationError)
    if "raise SimulationValidationError" not in validator_text:
        failures.append(
            "validator.py must raise SimulationValidationError on ERROR/FATAL"
        )
    if "SimulationValidationSeverity" not in validator_text:
        failures.append("validator.py must use SimulationValidationSeverity")

    # 11. Check simulator calls validate_simulation
    if "validate_simulation" not in simulator_text:
        failures.append("simulator.py must call validate_simulation")

    # 12. Check no DB access in service files
    db_forbidden = [
        "sqlalchemy",
        "Session(",
        "db.query(",
        "from api.db",
        "from services.governance_digital_twin.builder",
    ]
    for bad in db_forbidden:
        if bad in all_service_text:
            failures.append(
                f"governance_simulation service must not use DB/SQLAlchemy: found '{bad}'"
            )

    # 13. Check frozen dataclasses in models
    if "frozen=True" not in models_text:
        failures.append("models.py dataclasses must use frozen=True")

    # 14. Check __init__.py exports key symbols
    required_exports = [
        "SimulationValidationError",
        "GovernanceSimulationService",
        "build_scenario",
        "simulate",
        "validate_simulation",
    ]
    for sym in required_exports:
        if sym not in init_text:
            failures.append(f"__init__.py missing export: {sym}")

    # 15. Check test file has >= 200 assert statements
    if not TEST_FILE.exists():
        failures.append("tests/test_governance_simulation.py missing")
    else:
        assert_count = _count_asserts(TEST_FILE)
        if assert_count < 200:
            failures.append(
                f"tests/test_governance_simulation.py has only {assert_count} assert "
                f"statements (need >= 200)"
            )

    # 16. Check PR fix log has 18.8.2 entry
    if PR_FIX_LOG.exists():
        fix_log_text = _read(PR_FIX_LOG)
        if "18.8.2" not in fix_log_text:
            failures.append("docs/ai/PR_FIX_LOG.md missing PR 18.8.2 entry")
    else:
        failures.append("docs/ai/PR_FIX_LOG.md not found")

    if failures:
        for failure in failures:
            print(f"FAIL - {failure}")
        return 1

    print("PASS — Governance Simulation Engine check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
