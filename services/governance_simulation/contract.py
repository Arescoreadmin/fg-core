"""Service contract for Governance Simulation Engine."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from services.governance_digital_twin.models import GovernanceDigitalTwinSnapshot
from services.governance_simulation.diff import compute_graph_diff
from services.governance_simulation.exporter import export_replay_package
from services.governance_simulation.fingerprint import compute_scenario_fingerprint
from services.governance_simulation.impact import analyze_impact
from services.governance_simulation.models import (
    ExecutiveComparison,
    GraphDiff,
    ImpactReport,
    ReplayPackage,
    ScenarioOverlay,
    SimulationResult,
    SimulationRun,
    SimulationScenario,
    SimulationValidationReport,
)
from services.governance_simulation.scenario import build_scenario
from services.governance_simulation.simulator import run_simulation, simulate
from services.governance_simulation.validator import validate_simulation


class GovernanceSimulationServiceContract(Protocol):
    """Protocol defining the Governance Simulation Service interface."""

    def build_scenario(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        scenario_name: str,
        category: str,
        operations: list[dict[str, Any]],
        *,
        created_from: str,
    ) -> SimulationScenario: ...

    def validate(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        overlay: ScenarioOverlay,
        diff: GraphDiff,
        impact_report: ImpactReport,
    ) -> SimulationValidationReport: ...

    def simulate(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        scenario: SimulationScenario,
    ) -> SimulationResult: ...

    def diff(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        derived_entities: tuple,
        derived_relationships: tuple,
        scenario_id: str,
    ) -> GraphDiff: ...

    def impact(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        diff: GraphDiff,
        scenario_id: str,
    ) -> ImpactReport: ...

    def fingerprint(
        self,
        scenario_version: str,
        overlay: ScenarioOverlay,
        diff: GraphDiff,
        impact_report: ImpactReport,
        builder_version: str,
        graph_schema_version: str,
        simulation_version: str,
    ) -> str: ...

    def export(self, package: ReplayPackage) -> Mapping[str, Any]: ...

    def replay(self, package: ReplayPackage) -> SimulationResult: ...

    def run(self, snapshot: GovernanceDigitalTwinSnapshot, scenario: SimulationScenario) -> SimulationRun: ...


class GovernanceSimulationService:
    """Concrete implementation of GovernanceSimulationServiceContract.

    Delegates to module-level pure functions — no DB access.
    """

    def build_scenario(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        scenario_name: str,
        category: str,
        operations: list[dict[str, Any]],
        *,
        created_from: str = "system:governance_simulation",
    ) -> SimulationScenario:
        return build_scenario(
            snapshot,
            scenario_name,
            category,
            operations,
            created_from=created_from,
        )

    def validate(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        overlay: ScenarioOverlay,
        diff: GraphDiff,
        impact_report: ImpactReport,
    ) -> SimulationValidationReport:
        return validate_simulation(snapshot, overlay, diff, impact_report)

    def simulate(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        scenario: SimulationScenario,
    ) -> SimulationResult:
        return simulate(snapshot, scenario)

    def diff(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        derived_entities: tuple,
        derived_relationships: tuple,
        scenario_id: str,
    ) -> GraphDiff:
        return compute_graph_diff(
            snapshot, derived_entities, derived_relationships, scenario_id
        )

    def impact(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        diff: GraphDiff,
        scenario_id: str,
    ) -> ImpactReport:
        return analyze_impact(snapshot, diff, scenario_id)

    def fingerprint(
        self,
        scenario_version: str,
        overlay: ScenarioOverlay,
        diff: GraphDiff,
        impact_report: ImpactReport,
        builder_version: str = "",
        graph_schema_version: str = "",
        simulation_version: str = "",
    ) -> str:
        return compute_scenario_fingerprint(
            scenario_version=scenario_version,
            overlay=overlay,
            diff=diff,
            impact_report=impact_report,
            builder_version=builder_version,
            graph_schema_version=graph_schema_version,
            simulation_version=simulation_version,
        )

    def export(self, package: ReplayPackage) -> Mapping[str, Any]:
        return export_replay_package(package)

    def replay(self, package: ReplayPackage) -> SimulationResult:
        """Re-run simulation using embedded scenario — must produce identical output."""
        # The replay is done by re-calling simulate with the snapshot embedded in the package.
        # Since we don't have the snapshot object in the package (it's not stored by design),
        # replay is documented as requiring the original snapshot.
        # Here we re-simulate using the scenario — this is the contract method signature.
        # In practice, callers must provide the snapshot; we raise NotImplementedError
        # if replay is called without context.
        raise NotImplementedError(
            "replay() requires the original GovernanceDigitalTwinSnapshot. "
            "Call simulate(snapshot, package.scenario) directly to regenerate identical output."
        )

    def run(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        scenario: SimulationScenario,
    ) -> SimulationRun:
        return run_simulation(snapshot, scenario)

    def replay_with_snapshot(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        package: ReplayPackage,
    ) -> SimulationResult:
        """Re-run simulation from a ReplayPackage and the original snapshot.

        The result fingerprint MUST match package.fingerprint.
        """
        return simulate(snapshot, package.scenario)
