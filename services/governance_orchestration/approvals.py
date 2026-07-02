"""Multi-stage approval engine for governance orchestration."""

from __future__ import annotations

from typing import Any, Optional

from services.governance_orchestration.models import (
    ACTIVE_APPROVAL_STATES,
    ApprovalState,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationApprovalError,
    GovernanceOrchestrationNotFound,
)


_VALID_DECISIONS = {"APPROVE", "REJECT", "DELEGATE"}


class ApprovalChain:
    """Coordinates a multi-stage approval chain against approval records."""

    def __init__(self, stages: list[dict[str, Any]]):
        if not isinstance(stages, list) or not stages:
            raise GovernanceOrchestrationApprovalError(
                "ApprovalChain requires at least one stage"
            )
        for idx, stage in enumerate(stages):
            if not isinstance(stage, dict):
                raise GovernanceOrchestrationApprovalError(
                    f"stage {idx} must be a dict"
                )
            if "stage" not in stage:
                raise GovernanceOrchestrationApprovalError(
                    f"stage {idx} missing 'stage' key"
                )
            quorum = stage.get("quorum", 1)
            if not isinstance(quorum, int) or quorum < 1:
                raise GovernanceOrchestrationApprovalError(
                    f"stage {idx} quorum must be int >= 1"
                )
        self._stages = list(stages)

    @property
    def stages(self) -> list[dict[str, Any]]:
        return list(self._stages)

    def advance(
        self,
        db: Any,
        tenant_id: str,
        workflow_id: str,
        approval_id: str,
        decision: str,
        actor_id: str,
    ) -> dict[str, Any]:
        if decision not in _VALID_DECISIONS:
            raise GovernanceOrchestrationApprovalError(
                f"decision must be one of {sorted(_VALID_DECISIONS)}"
            )
        repo = GovernanceOrchestrationRepository(db, tenant_id)
        row = repo.get_approval(approval_id)
        if row is None or row.workflow_id != workflow_id:
            raise GovernanceOrchestrationNotFound(
                f"Approval {approval_id!r} not found for workflow {workflow_id!r}"
            )
        current_state = ApprovalState(row.approval_state)
        if current_state not in ACTIVE_APPROVAL_STATES:
            raise GovernanceOrchestrationApprovalError(
                f"Approval {approval_id!r} not active (state={current_state.value})"
            )
        if decision == "APPROVE":
            row.approval_state = ApprovalState.APPROVED.value
            row.decision = "APPROVE"
        elif decision == "REJECT":
            row.approval_state = ApprovalState.REJECTED.value
            row.decision = "REJECT"
        else:  # DELEGATE
            row.approval_state = ApprovalState.DELEGATED.value
            row.decision = "DELEGATE"
            row.delegated_to = actor_id
        repo.update_approval(row)
        return {
            "id": row.id,
            "workflow_id": row.workflow_id,
            "stage": row.stage,
            "approval_state": row.approval_state,
            "decision": row.decision,
            "delegated_to": row.delegated_to,
        }

    def get_pending_stage(
        self, db: Any, tenant_id: str, workflow_id: str
    ) -> Optional[dict[str, Any]]:
        """Return the earliest pending stage config, or None if all complete."""
        repo = GovernanceOrchestrationRepository(db, tenant_id)
        approvals = repo.list_approvals(workflow_id=workflow_id)
        # Group by stage number
        by_stage: dict[int, list[Any]] = {}
        for a in approvals:
            by_stage.setdefault(a.stage, []).append(a)
        for stage_config in sorted(self._stages, key=lambda s: s.get("stage", 0)):
            stage_num = stage_config.get("stage")
            approvals_for_stage = by_stage.get(stage_num, [])
            if not self.check_quorum(
                [self._approval_to_dict(a) for a in approvals_for_stage],
                stage_config,
            ):
                return dict(stage_config)
        return None

    def is_complete(self, db: Any, tenant_id: str, workflow_id: str) -> bool:
        return self.get_pending_stage(db, tenant_id, workflow_id) is None

    def check_quorum(
        self, approvals: list[dict[str, Any]], stage: dict[str, Any]
    ) -> bool:
        quorum = int(stage.get("quorum", 1))
        approved = sum(
            1
            for a in approvals
            if a.get("approval_state") == ApprovalState.APPROVED.value
        )
        return approved >= quorum

    @staticmethod
    def _approval_to_dict(row: Any) -> dict[str, Any]:
        return {
            "id": row.id,
            "workflow_id": row.workflow_id,
            "stage": row.stage,
            "approval_state": row.approval_state,
            "actor_id": row.actor_id,
        }
