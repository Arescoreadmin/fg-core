"""SHA-256 fingerprinting for governance simulation objects."""

from __future__ import annotations

import hashlib
from dataclasses import asdict

from services.canonical import canonical_json_bytes
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN,
    ExecutiveComparison,
    GraphDiff,
    ImpactReport,
    ScenarioOverlay,
)


def compute_overlay_hash(overlay: ScenarioOverlay) -> str:
    """Deterministic hash over overlay identity and operations."""
    ops = [asdict(op) for op in overlay.operations]
    payload = {
        "overlay_id": overlay.overlay_id,
        "scenario_id": overlay.scenario_id,
        "source_snapshot_id": overlay.source_snapshot_id,
        "source_snapshot_fingerprint": overlay.source_snapshot_fingerprint,
        "tenant_id": overlay.tenant_id,
        "operations": ops,
        "created_at": overlay.created_at,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_diff_hash(diff: GraphDiff) -> str:
    """Deterministic hash over sorted diff entries."""
    entries = sorted(
        (asdict(entry) for entry in diff.entries),
        key=lambda e: e["diff_id"],
    )
    payload = {
        "diff_id": diff.diff_id,
        "scenario_id": diff.scenario_id,
        "source_snapshot_id": diff.source_snapshot_id,
        "entries": entries,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_impact_hash(impact_report: ImpactReport) -> str:
    """Deterministic hash over sorted impact entries."""
    entries = sorted(
        (asdict(entry) for entry in impact_report.entries),
        key=lambda e: e["impact_id"],
    )
    payload = {
        "report_id": impact_report.report_id,
        "scenario_id": impact_report.scenario_id,
        "source_snapshot_id": impact_report.source_snapshot_id,
        "entries": entries,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_comparison_hash(comparison: ExecutiveComparison) -> str:
    """Deterministic hash over sorted comparison rows."""
    rows = sorted(
        (asdict(row) for row in comparison.rows),
        key=lambda r: r["object_id"],
    )
    payload = {
        "comparison_id": comparison.comparison_id,
        "scenario_id": comparison.scenario_id,
        "rows": rows,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_scenario_fingerprint(
    scenario_version: str,
    overlay: ScenarioOverlay,
    diff: GraphDiff,
    impact_report: ImpactReport,
    builder_version: str,
    graph_schema_version: str,
    simulation_version: str,
) -> str:
    """Master fingerprint for a simulation scenario — covers all derived hashes."""
    payload = {
        "domain": GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN,
        "scenario_version": scenario_version,
        "overlay_hash": overlay.overlay_hash,
        "diff_hash": diff.diff_hash,
        "impact_hash": impact_report.report_hash,
        "builder_version": builder_version,
        "graph_schema_version": graph_schema_version,
        "simulation_version": simulation_version,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_replay_fingerprint(
    package_id: str,
    scenario_id: str,
    overlay_hash: str,
    diff_hash: str,
    impact_hash: str,
    tenant_id: str,
) -> str:
    """Fingerprint for a ReplayPackage — covers all constituent hashes."""
    payload = {
        "domain": GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN,
        "package_id": package_id,
        "scenario_id": scenario_id,
        "overlay_hash": overlay_hash,
        "diff_hash": diff_hash,
        "impact_hash": impact_hash,
        "tenant_id": tenant_id,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
