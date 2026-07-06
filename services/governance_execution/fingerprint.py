"""SHA-256 fingerprinting for Governance Execution Engine objects."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

from services.canonical import canonical_json_bytes
from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
    ExecutionApproval,
    ExecutionAuditRecord,
    ExecutionDecisionLedger,
    ExecutionMeasurement,
    ExecutionPlan,
    ExecutionRun,
    ExecutionStep,
    ExecutionVerification,
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_step_hash(step: ExecutionStep) -> str:
    """Compute SHA-256 hash of an ExecutionStep."""
    payload = dataclasses.asdict(step)
    return _sha256_hex(canonical_json_bytes(payload))


def compute_approval_hash(approval: ExecutionApproval) -> str:
    """Compute SHA-256 hash of an ExecutionApproval."""
    payload = dataclasses.asdict(approval)
    return _sha256_hex(canonical_json_bytes(payload))


def compute_verification_hash(verification: ExecutionVerification) -> str:
    """Compute SHA-256 hash of an ExecutionVerification."""
    payload = dataclasses.asdict(verification)
    return _sha256_hex(canonical_json_bytes(payload))


def compute_measurement_hash(measurement: ExecutionMeasurement) -> str:
    """Compute SHA-256 hash of an ExecutionMeasurement."""
    payload = dataclasses.asdict(measurement)
    return _sha256_hex(canonical_json_bytes(payload))


def compute_audit_fingerprint(record: ExecutionAuditRecord) -> str:
    """Compute SHA-256 fingerprint of an ExecutionAuditRecord."""
    payload = dataclasses.asdict(record)
    return _sha256_hex(canonical_json_bytes(payload))


def compute_plan_fingerprint(plan: ExecutionPlan) -> str:
    """Compute SHA-256 fingerprint over stable plan fields."""
    step_hashes = sorted(compute_step_hash(s) for s in plan.steps)
    payload: dict[str, Any] = {
        "domain": GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
        "plan_id": plan.plan_id,
        "tenant_id": plan.tenant_id,
        "simulation_id": plan.simulation_id,
        "simulation_fingerprint": plan.simulation_fingerprint,
        "digital_twin_fingerprint": plan.digital_twin_fingerprint,
        "plan_name": plan.plan_name,
        "category": plan.category,
        "step_hashes": step_hashes,
        "planner_version": plan.planner_version,
        "schema_version": plan.schema_version,
    }
    return _sha256_hex(canonical_json_bytes(payload))


def compute_run_fingerprint(run: ExecutionRun) -> str:
    """Compute SHA-256 fingerprint over stable run fields."""
    approval_hashes = sorted(compute_approval_hash(a) for a in run.approvals)
    payload: dict[str, Any] = {
        "domain": GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
        "run_id": run.run_id,
        "plan_id": run.plan_id,
        "tenant_id": run.tenant_id,
        "simulation_id": run.simulation_id,
        "simulation_fingerprint": run.simulation_fingerprint,
        "started_at": run.started_at,
        "approval_hashes": approval_hashes,
    }
    return _sha256_hex(canonical_json_bytes(payload))


def compute_ledger_hash(ledger: ExecutionDecisionLedger) -> str:
    """Compute SHA-256 hash over sorted record fingerprints."""
    record_fingerprints = sorted(r.fingerprint for r in ledger.records)
    payload: dict[str, Any] = {
        "domain": GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
        "ledger_id": ledger.ledger_id,
        "plan_id": ledger.plan_id,
        "tenant_id": ledger.tenant_id,
        "record_fingerprints": record_fingerprints,
    }
    return _sha256_hex(canonical_json_bytes(payload))


def compute_execution_fingerprint(
    plan: ExecutionPlan,
    run: ExecutionRun,
    verifications: tuple[ExecutionVerification, ...],
    measurements: tuple[ExecutionMeasurement, ...],
    builder_version: str,
    schema_version: str,
) -> str:
    """Master execution fingerprint over plan, run, verifications, and measurements."""
    verification_hashes = sorted(compute_verification_hash(v) for v in verifications)
    measurement_hashes = sorted(compute_measurement_hash(m) for m in measurements)
    payload: dict[str, Any] = {
        "domain": GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
        "plan_fingerprint": plan.plan_fingerprint,
        "run_fingerprint": run.run_fingerprint,
        "verification_hashes": verification_hashes,
        "measurement_hashes": measurement_hashes,
        "builder_version": builder_version,
        "schema_version": schema_version,
    }
    return _sha256_hex(canonical_json_bytes(payload))


def compute_replay_fingerprint(
    package_id: str,
    plan_id: str,
    run_id: str,
    execution_fingerprint: str,
    tenant_id: str,
) -> str:
    """Compute SHA-256 fingerprint for a replay package."""
    payload: dict[str, Any] = {
        "domain": GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
        "package_id": package_id,
        "plan_id": plan_id,
        "run_id": run_id,
        "execution_fingerprint": execution_fingerprint,
        "tenant_id": tenant_id,
    }
    return _sha256_hex(canonical_json_bytes(payload))
