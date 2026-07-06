"""Governance Simulation Engine — public exports."""

from __future__ import annotations

from services.governance_simulation.contract import (
    GovernanceSimulationService,
    GovernanceSimulationServiceContract,
)
from services.governance_simulation.diff import compute_graph_diff
from services.governance_simulation.exporter import export_replay_package
from services.governance_simulation.fingerprint import (
    compute_comparison_hash,
    compute_diff_hash,
    compute_impact_hash,
    compute_overlay_hash,
    compute_replay_fingerprint,
    compute_scenario_fingerprint,
)
from services.governance_simulation.impact import analyze_impact
from services.governance_simulation.mcim_registration import (
    GOVERNANCE_SIMULATION_MCIM_VERSION,
    MCIM_REGISTRATION_SOURCE,
)
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN,
    GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
    GOVERNANCE_SIMULATION_REPLAY_VERSION,
    GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
    GOVERNANCE_SIMULATION_VERSION,
    SCENARIO_CATEGORY_REGISTRY,
    SCENARIO_TEMPLATE_REGISTRY,
    ExecutiveComparison,
    ExecutiveComparisonRow,
    GraphDiff,
    GraphDiffEntry,
    ImpactChain,
    ImpactChainNode,
    ImpactConfidence,
    ImpactDomain,
    ImpactEntry,
    ImpactReport,
    OverlayOperationType,
    ReplayPackage,
    ScenarioCategory,
    ScenarioOverlay,
    ScenarioOverlayOperation,
    SimulationHorizon,
    SimulationManifest,
    SimulationResult,
    SimulationRun,
    SimulationScenario,
    SimulationValidationFinding,
    SimulationValidationReport,
    SimulationValidationSeverity,
)
from services.governance_simulation.overlay import OverlayError, apply_overlay, compose_overlays
from services.governance_simulation.replay import build_replay_package
from services.governance_simulation.scenario import build_scenario
from services.governance_simulation.simulator import run_simulation, simulate
from services.governance_simulation.validator import (
    SimulationValidationError,
    validate_simulation,
)

__all__ = [
    # Version constants
    "GOVERNANCE_SIMULATION_VERSION",
    "GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION",
    "GOVERNANCE_SIMULATION_SIMULATOR_VERSION",
    "GOVERNANCE_SIMULATION_REPLAY_VERSION",
    "GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN",
    "GOVERNANCE_SIMULATION_MCIM_VERSION",
    "SCENARIO_CATEGORY_REGISTRY",
    "SCENARIO_TEMPLATE_REGISTRY",
    "MCIM_REGISTRATION_SOURCE",
    # Enums
    "ScenarioCategory",
    "SimulationHorizon",
    "OverlayOperationType",
    "SimulationValidationSeverity",
    "ImpactDomain",
    "ImpactConfidence",
    # Dataclasses
    "ScenarioOverlayOperation",
    "ScenarioOverlay",
    "SimulationScenario",
    "GraphDiffEntry",
    "GraphDiff",
    "ImpactEntry",
    "ImpactChainNode",
    "ImpactChain",
    "ImpactReport",
    "ExecutiveComparisonRow",
    "ExecutiveComparison",
    "SimulationValidationFinding",
    "SimulationValidationReport",
    "SimulationManifest",
    "ReplayPackage",
    "SimulationResult",
    "SimulationRun",
    # Errors
    "SimulationValidationError",
    "OverlayError",
    # Functions
    "apply_overlay",
    "compose_overlays",
    "build_scenario",
    "simulate",
    "run_simulation",
    "compute_graph_diff",
    "analyze_impact",
    "validate_simulation",
    "build_replay_package",
    "export_replay_package",
    "compute_scenario_fingerprint",
    "compute_overlay_hash",
    "compute_diff_hash",
    "compute_impact_hash",
    "compute_comparison_hash",
    "compute_replay_fingerprint",
    # Service
    "GovernanceSimulationServiceContract",
    "GovernanceSimulationService",
]
