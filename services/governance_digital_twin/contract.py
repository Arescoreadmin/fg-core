"""Internal service contract for Governance Digital Twin access.

Permanent architectural rule: governance state is computed inside the Governance Digital
Twin service boundary before any presentation layer derives views from it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from sqlalchemy.orm import Session

from services.governance_digital_twin.baseline import create_comparison_baseline
from services.governance_digital_twin.builder import (
    build_governance_digital_twin_snapshot,
)
from services.governance_digital_twin.exporter import export_replay_safe_snapshot
from services.governance_digital_twin.fingerprint import compute_snapshot_fingerprint
from services.governance_digital_twin.models import (
    GovernanceDigitalTwinBaseline,
    GovernanceDigitalTwinSnapshot,
    GovernanceDigitalTwinSnapshotCategory,
    GovernanceDigitalTwinValidationReport,
)
from services.governance_digital_twin.validator import (
    validate_governance_digital_twin_snapshot,
)


class GovernanceDigitalTwinServiceContract(Protocol):
    def build(
        self,
        db: Session,
        tenant_id: str,
        *,
        baseline_ref: str | None = None,
        redaction_profile: str = "replay_safe",
        parent_snapshot_id: str | None = None,
        previous_fingerprint: str | None = None,
        generation: int | None = None,
        lineage_id: str | None = None,
        snapshot_category: GovernanceDigitalTwinSnapshotCategory
        | str = GovernanceDigitalTwinSnapshotCategory.operational.value,
        created_by: str = "system:governance_digital_twin_builder",
        twin_id: str | None = None,
        memory_reference: str | None = None,
        memory_sequence: int | None = None,
        timeline_anchor: str | None = None,
    ) -> GovernanceDigitalTwinSnapshot: ...

    def validate(
        self, snapshot: GovernanceDigitalTwinSnapshot
    ) -> GovernanceDigitalTwinValidationReport: ...

    def fingerprint(self, snapshot: GovernanceDigitalTwinSnapshot) -> str: ...

    def export(
        self, snapshot: GovernanceDigitalTwinSnapshot
    ) -> Mapping[str, object]: ...

    def baseline(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        label: str,
        created_by: str,
        purpose: str,
    ) -> GovernanceDigitalTwinBaseline: ...


class GovernanceDigitalTwinService:
    def build(
        self,
        db: Session,
        tenant_id: str,
        *,
        baseline_ref: str | None = None,
        redaction_profile: str = "replay_safe",
        parent_snapshot_id: str | None = None,
        previous_fingerprint: str | None = None,
        generation: int | None = None,
        lineage_id: str | None = None,
        snapshot_category: GovernanceDigitalTwinSnapshotCategory
        | str = GovernanceDigitalTwinSnapshotCategory.operational.value,
        created_by: str = "system:governance_digital_twin_builder",
        twin_id: str | None = None,
        memory_reference: str | None = None,
        memory_sequence: int | None = None,
        timeline_anchor: str | None = None,
    ) -> GovernanceDigitalTwinSnapshot:
        return build_governance_digital_twin_snapshot(
            db,
            tenant_id,
            baseline_ref=baseline_ref,
            redaction_profile=redaction_profile,
            parent_snapshot_id=parent_snapshot_id,
            previous_fingerprint=previous_fingerprint,
            generation=generation,
            lineage_id=lineage_id,
            snapshot_category=snapshot_category,
            created_by=created_by,
            twin_id=twin_id,
            memory_reference=memory_reference,
            memory_sequence=memory_sequence,
            timeline_anchor=timeline_anchor,
        )

    def validate(
        self, snapshot: GovernanceDigitalTwinSnapshot
    ) -> GovernanceDigitalTwinValidationReport:
        return validate_governance_digital_twin_snapshot(snapshot)

    def fingerprint(self, snapshot: GovernanceDigitalTwinSnapshot) -> str:
        return compute_snapshot_fingerprint(snapshot)

    def export(self, snapshot: GovernanceDigitalTwinSnapshot) -> Mapping[str, object]:
        return export_replay_safe_snapshot(snapshot)

    def baseline(
        self,
        snapshot: GovernanceDigitalTwinSnapshot,
        label: str,
        created_by: str,
        purpose: str,
    ) -> GovernanceDigitalTwinBaseline:
        return create_comparison_baseline(
            snapshot, label=label, created_by=created_by, purpose=purpose
        )
