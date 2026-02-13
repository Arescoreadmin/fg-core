"""
Deterministic Simulation Validator for FrostGate Core.

Runs a fixed set of simulation inputs through the decision engine,
produces artifacts, and detects output drift.

Golden outputs are versioned. If output changes without a version bump,
validation fails.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger

# State directory for artifacts
STATE_DIR = Path(
    os.getenv("FG_STATE_DIR", str(Path(__file__).resolve().parents[2] / "state"))
)
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Artifacts directory
ARTIFACTS_DIR = STATE_DIR / "sim_validator"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Golden outputs file
GOLDEN_FILE = Path(__file__).resolve().parent / "golden_outputs.json"

# Version for the current golden outputs
GOLDEN_VERSION = "1.0.0"


def sha256_hex(data: str | bytes) -> str:
    """Compute SHA-256 hash of data."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Produce deterministic JSON representation."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


@dataclass
class SimulationInput:
    """Fixed simulation input for testing the decision engine."""

    name: str
    tenant_id: str
    source: str
    event_type: str
    payload: dict[str, Any]
    persona: Optional[str] = None
    classification: Optional[str] = None
    expected_threat_level: Optional[str] = None
    expected_rules: list[str] = field(default_factory=list)


@dataclass
class SimulationOutput:
    """Output from running a simulation through the decision engine."""

    name: str
    input_hash: str
    threat_level: str
    rules_triggered: list[str]
    mitigations: list[dict[str, Any]]
    anomaly_score: float
    score: int
    roe_applied: bool
    disruption_limited: bool
    output_hash: str


@dataclass
class ValidationResult:
    """Result of validating simulation outputs against golden outputs."""

    passed: bool
    version: str
    timestamp: str
    total_simulations: int
    passed_count: int
    failed_count: int
    drift_detected: bool
    failures: list[dict[str, Any]] = field(default_factory=list)


# Fixed set of simulation inputs - deterministic across runs
SIMULATION_INPUTS: list[SimulationInput] = [
    SimulationInput(
        name="baseline_no_threat",
        tenant_id="t_sim_001",
        source="sim_validator",
        event_type="http_request",
        payload={
            "path": "/api/health",
            "method": "GET",
            "src_ip": "192.168.1.100",
            "status_code": 200,
        },
        expected_threat_level="none",
        expected_rules=["rule:default_allow"],
    ),
    SimulationInput(
        name="auth_bruteforce_5_attempts",
        tenant_id="t_sim_001",
        source="sim_validator",
        event_type="auth",
        payload={
            "src_ip": "10.0.0.50",
            "failed_auths": 5,
            "username": "admin",
        },
        expected_threat_level="high",
        expected_rules=["rule:ssh_bruteforce"],
    ),
    SimulationInput(
        name="auth_bruteforce_10_attempts",
        tenant_id="t_sim_001",
        source="sim_validator",
        event_type="auth.bruteforce",
        payload={
            "src_ip": "10.0.0.51",
            "failed_auths": 10,
            "username": "root",
        },
        expected_threat_level="high",
        expected_rules=["rule:ssh_bruteforce"],
    ),
    SimulationInput(
        name="auth_below_threshold",
        tenant_id="t_sim_001",
        source="sim_validator",
        event_type="auth",
        payload={
            "src_ip": "10.0.0.52",
            "failed_auths": 3,
            "username": "user1",
        },
        expected_threat_level="none",
        expected_rules=["rule:default_allow"],
    ),
    SimulationInput(
        name="guardian_secret_classification",
        tenant_id="t_sim_002",
        source="sim_validator",
        event_type="auth",
        payload={
            "src_ip": "10.0.0.60",
            "failed_auths": 5,
            "username": "classified_user",
        },
        persona="guardian",
        classification="SECRET",
        expected_threat_level="high",
        expected_rules=["rule:ssh_bruteforce"],
    ),
    SimulationInput(
        name="sentinel_unclassified",
        tenant_id="t_sim_002",
        source="sim_validator",
        event_type="auth",
        payload={
            "src_ip": "10.0.0.61",
            "failed_auths": 7,
            "username": "sentinel_user",
        },
        persona="sentinel",
        classification="UNCLASSIFIED",
        expected_threat_level="high",
        expected_rules=["rule:ssh_bruteforce"],
    ),
    SimulationInput(
        name="unknown_event_type",
        tenant_id="t_sim_003",
        source="sim_validator",
        event_type="custom_event",
        payload={
            "action": "data_export",
            "size_mb": 100,
        },
        expected_threat_level="none",
        expected_rules=["rule:default_allow"],
    ),
    SimulationInput(
        name="no_ip_in_bruteforce",
        tenant_id="t_sim_003",
        source="sim_validator",
        event_type="auth",
        payload={
            "failed_auths": 10,
            "username": "no_ip_user",
            # No src_ip - should not trigger block_ip
        },
        expected_threat_level="none",  # No IP means rule doesn't fire
        expected_rules=["rule:default_allow"],
    ),
]


def compute_input_hash(sim_input: SimulationInput) -> str:
    """Compute deterministic hash of simulation input."""
    data = {
        "name": sim_input.name,
        "tenant_id": sim_input.tenant_id,
        "source": sim_input.source,
        "event_type": sim_input.event_type,
        "payload": sim_input.payload,
        "persona": sim_input.persona,
        "classification": sim_input.classification,
    }
    return sha256_hex(canonical_json(data))


def compute_output_hash(output: dict[str, Any]) -> str:
    """Compute deterministic hash of simulation output (excluding timestamps)."""
    # Only hash the deterministic fields
    data = {
        "threat_level": output.get("threat_level"),
        "rules_triggered": sorted(output.get("rules_triggered", [])),
        "mitigations": output.get("mitigations", []),
        "anomaly_score": output.get("anomaly_score"),
        "score": output.get("score"),
        "roe_applied": output.get("roe_applied"),
        "disruption_limited": output.get("disruption_limited"),
    }
    return sha256_hex(canonical_json(data))


def run_simulation(sim_input: SimulationInput) -> SimulationOutput:
    """
    Run a single simulation through the decision engine.

    Uses the same evaluation logic as the /defend endpoint.
    """
    from api.defend import evaluate, _apply_doctrine
    from api.schemas import TelemetryInput

    # Create TelemetryInput
    telemetry = TelemetryInput(
        tenant_id=sim_input.tenant_id,
        source=sim_input.source,
        event_type=sim_input.event_type,
        payload=sim_input.payload,
    )

    # Run evaluation
    threat_level, rules_triggered, mitigations, anomaly_score, score = evaluate(
        telemetry
    )

    # Apply doctrine if specified
    roe_applied = False
    disruption_limited = False

    if sim_input.persona or sim_input.classification:
        mitigations, tie_d = _apply_doctrine(
            sim_input.persona,
            sim_input.classification,
            mitigations,
        )
        roe_applied = tie_d.roe_applied
        disruption_limited = tie_d.disruption_limited

    # Convert mitigations to dicts
    mitigation_dicts = [
        {
            "action": m.action,
            "target": m.target,
            "reason": m.reason,
            "confidence": m.confidence,
        }
        for m in mitigations
    ]

    # Compute hashes
    input_hash = compute_input_hash(sim_input)
    output_data = {
        "threat_level": threat_level,
        "rules_triggered": rules_triggered,
        "mitigations": mitigation_dicts,
        "anomaly_score": anomaly_score,
        "score": score,
        "roe_applied": roe_applied,
        "disruption_limited": disruption_limited,
    }
    output_hash = compute_output_hash(output_data)

    return SimulationOutput(
        name=sim_input.name,
        input_hash=input_hash,
        threat_level=threat_level,
        rules_triggered=list(rules_triggered),
        mitigations=mitigation_dicts,
        anomaly_score=anomaly_score,
        score=score,
        roe_applied=roe_applied,
        disruption_limited=disruption_limited,
        output_hash=output_hash,
    )


def load_golden_outputs() -> dict[str, Any]:
    """Load golden outputs from file."""
    if GOLDEN_FILE.exists():
        try:
            return json.loads(GOLDEN_FILE.read_text())
        except Exception as e:
            logger.warning(f"Failed to load golden outputs: {e}")
    return {"version": GOLDEN_VERSION, "outputs": {}}


def save_golden_outputs(outputs: dict[str, SimulationOutput], version: str) -> None:
    """Save golden outputs to file."""
    data = {
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "outputs": {
            name: {
                "input_hash": out.input_hash,
                "threat_level": out.threat_level,
                "rules_triggered": out.rules_triggered,
                "mitigations": out.mitigations,
                "anomaly_score": out.anomaly_score,
                "score": out.score,
                "roe_applied": out.roe_applied,
                "disruption_limited": out.disruption_limited,
                "output_hash": out.output_hash,
            }
            for name, out in outputs.items()
        },
    }
    GOLDEN_FILE.write_text(json.dumps(data, indent=2))
    logger.info(f"Saved golden outputs v{version} to {GOLDEN_FILE}")


def validate_output(
    sim_input: SimulationInput,
    output: SimulationOutput,
    golden: dict[str, Any],
) -> tuple[bool, list[str]]:
    """
    Validate simulation output against golden output.

    Returns (passed, list of error messages).
    """
    errors = []

    # Check expected threat level (from input spec)
    if sim_input.expected_threat_level:
        if output.threat_level != sim_input.expected_threat_level:
            errors.append(
                f"Threat level mismatch: expected {sim_input.expected_threat_level}, "
                f"got {output.threat_level}"
            )

    # Check expected rules (from input spec)
    if sim_input.expected_rules:
        expected_set = set(sim_input.expected_rules)
        actual_set = set(output.rules_triggered)
        if expected_set != actual_set:
            errors.append(
                f"Rules mismatch: expected {sorted(expected_set)}, "
                f"got {sorted(actual_set)}"
            )

    # Check against golden output (drift detection)
    if golden and output.name in golden.get("outputs", {}):
        golden_out = golden["outputs"][output.name]
        if golden_out.get("output_hash") != output.output_hash:
            errors.append(
                f"Output drift detected: hash changed from {golden_out.get('output_hash')} "
                f"to {output.output_hash}"
            )

    return len(errors) == 0, errors


def save_artifacts(
    inputs: list[SimulationInput],
    outputs: dict[str, SimulationOutput],
    result: ValidationResult,
) -> Path:
    """
    Save validation artifacts to disk.

    Returns path to artifacts directory.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ARTIFACTS_DIR / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save input snapshot
    input_snapshot = {
        "version": GOLDEN_VERSION,
        "timestamp": timestamp,
        "inputs": [
            {
                "name": inp.name,
                "tenant_id": inp.tenant_id,
                "source": inp.source,
                "event_type": inp.event_type,
                "payload": inp.payload,
                "persona": inp.persona,
                "classification": inp.classification,
                "expected_threat_level": inp.expected_threat_level,
                "expected_rules": inp.expected_rules,
            }
            for inp in inputs
        ],
    }
    (run_dir / "input_snapshot.json").write_text(json.dumps(input_snapshot, indent=2))

    # Save output snapshot
    output_snapshot = {
        "version": GOLDEN_VERSION,
        "timestamp": timestamp,
        "outputs": {
            name: {
                "input_hash": out.input_hash,
                "threat_level": out.threat_level,
                "rules_triggered": out.rules_triggered,
                "mitigations": out.mitigations,
                "anomaly_score": out.anomaly_score,
                "score": out.score,
                "roe_applied": out.roe_applied,
                "disruption_limited": out.disruption_limited,
                "output_hash": out.output_hash,
            }
            for name, out in outputs.items()
        },
    }
    (run_dir / "output_snapshot.json").write_text(json.dumps(output_snapshot, indent=2))

    # Save validation result
    result_data = {
        "passed": result.passed,
        "version": result.version,
        "timestamp": result.timestamp,
        "total_simulations": result.total_simulations,
        "passed_count": result.passed_count,
        "failed_count": result.failed_count,
        "drift_detected": result.drift_detected,
        "failures": result.failures,
    }
    (run_dir / "validation_result.json").write_text(json.dumps(result_data, indent=2))

    # Save summary
    verdict = "PASS" if result.passed else "FAIL"
    summary = f"""Simulation Validation Summary
============================
Version: {result.version}
Timestamp: {result.timestamp}
Verdict: {verdict}

Results:
  Total: {result.total_simulations}
  Passed: {result.passed_count}
  Failed: {result.failed_count}
  Drift Detected: {result.drift_detected}
"""
    if result.failures:
        summary += "\nFailures:\n"
        for f in result.failures:
            summary += f"  - {f['name']}: {f['errors']}\n"

    (run_dir / "summary.txt").write_text(summary)

    logger.info(f"Saved artifacts to {run_dir}")
    return run_dir


def run_all_simulations(
    inputs: list[SimulationInput] | None = None,
) -> dict[str, SimulationOutput]:
    """Run all simulation inputs and return outputs."""
    inputs = inputs or SIMULATION_INPUTS
    outputs = {}

    for sim_input in inputs:
        try:
            output = run_simulation(sim_input)
            outputs[sim_input.name] = output
            logger.debug(f"Simulation '{sim_input.name}': {output.threat_level}")
        except Exception as e:
            logger.error(f"Simulation '{sim_input.name}' failed: {e}")
            raise

    return outputs


def validate_all(
    inputs: list[SimulationInput] | None = None,
    golden: dict[str, Any] | None = None,
    fail_on_drift: bool = True,
) -> ValidationResult:
    """
    Run all simulations and validate against golden outputs.

    Args:
        inputs: Simulation inputs (defaults to SIMULATION_INPUTS)
        golden: Golden outputs (defaults to loading from file)
        fail_on_drift: If True, drift causes validation failure

    Returns:
        ValidationResult with pass/fail and details
    """
    inputs = inputs or SIMULATION_INPUTS
    golden = golden if golden is not None else load_golden_outputs()

    timestamp = datetime.now(timezone.utc).isoformat()
    outputs = run_all_simulations(inputs)

    failures = []
    drift_detected = False

    for sim_input in inputs:
        output = outputs.get(sim_input.name)
        if not output:
            failures.append(
                {
                    "name": sim_input.name,
                    "errors": ["No output produced"],
                }
            )
            continue

        passed, errors = validate_output(sim_input, output, golden)
        if not passed:
            failures.append(
                {
                    "name": sim_input.name,
                    "errors": errors,
                }
            )
            if any("drift" in e.lower() for e in errors):
                drift_detected = True

    passed_count = len(inputs) - len(failures)
    overall_passed = len(failures) == 0 or (drift_detected and not fail_on_drift)

    return ValidationResult(
        passed=overall_passed,
        version=GOLDEN_VERSION,
        timestamp=timestamp,
        total_simulations=len(inputs),
        passed_count=passed_count,
        failed_count=len(failures),
        drift_detected=drift_detected,
        failures=failures,
    )


async def job(
    update_golden: bool = False,
    fail_on_drift: bool = True,
) -> dict[str, Any]:
    """
    Simulation validator job.

    Args:
        update_golden: If True, update golden outputs instead of validating
        fail_on_drift: If True, fail when outputs drift from golden

    Returns:
        Job result dict
    """
    logger.info(
        f"sim_validator.job: starting with {len(SIMULATION_INPUTS)} simulations"
    )

    if update_golden:
        # Update mode: run simulations and save as new golden outputs
        outputs = run_all_simulations()
        save_golden_outputs(outputs, GOLDEN_VERSION)
        return {
            "status": "ok",
            "mode": "update_golden",
            "version": GOLDEN_VERSION,
            "simulation_count": len(outputs),
        }

    # Validation mode
    result = validate_all(fail_on_drift=fail_on_drift)

    # Save artifacts
    outputs = run_all_simulations()
    artifacts_dir = save_artifacts(SIMULATION_INPUTS, outputs, result)

    status = {
        "status": "ok" if result.passed else "failed",
        "mode": "validate",
        "version": result.version,
        "timestamp": result.timestamp,
        "total_simulations": result.total_simulations,
        "passed": result.passed_count,
        "failed": result.failed_count,
        "drift_detected": result.drift_detected,
        "artifacts_dir": str(artifacts_dir),
    }

    if not result.passed:
        status["failures"] = result.failures
        logger.warning(
            f"sim_validator.job: validation FAILED - {result.failed_count} failures"
        )
    else:
        logger.info(
            f"sim_validator.job: validation PASSED - {result.passed_count}/{result.total_simulations}"
        )

    return status


# Export for external use
__all__ = [
    "GOLDEN_VERSION",
    "SIMULATION_INPUTS",
    "SimulationInput",
    "SimulationOutput",
    "ValidationResult",
    "run_simulation",
    "run_all_simulations",
    "validate_all",
    "load_golden_outputs",
    "save_golden_outputs",
    "job",
]
