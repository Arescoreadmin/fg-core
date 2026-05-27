"""
progress.py

PlaybookProgress computation layer for the FrostGate Field Assessment engine.

Accepts a pre-built ExecutionState (from readiness.build_execution_state) and
enriches each NextAction with:
  - blocking: bool — true when the action closes a currently-blocked gate
  - action_type: str — semantic category derived from required_input_type
  - deep_link: str | None — console tab URL for direct navigation

Also computes the aggregate completion_pct and blocking_count for the
progress bar in GuidedExecutionPanel.

This is a pure computation module — no database I/O, no HTTP, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.field_assessment.readiness import ExecutionState

# ─── Constants ────────────────────────────────────────────────────────────────

# Maps required_input_type → semantic action category shown in the UI.
_ACTION_TYPE_MAP: dict[str, str] = {
    "scan_result": "scan_import",
    "evidence_link": "evidence_upload",
    "document_analysis": "document_review",
    "field_observation": "observation",
    "report_qa_approval": "report_approval",
}

# Maps target_ui_section → console tab query param value.
_TAB_MAP: dict[str, str] = {
    "scans": "scans",
    "evidence": "evidence",
    "documents": "documents",
    "observations": "observations",
    "interviews": "interviews",
    "report": "reports",
}

# Console workspace path template — the `tab` param activates the matching tab.
_DEEP_LINK_TEMPLATE = "/field-assessment/{engagement_id}?tab={tab}"


# ─── Output types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlaybookNextAction:
    """A next-best action enriched with blocking status, type, and deep link."""

    action_id: str
    priority: int
    title: str
    instruction: str
    why_it_matters: str
    closes_gate_ids: list[str]
    required_input_type: str
    target_ui_section: str
    expected_evidence: list[str]
    safe_for_junior_assessor: bool
    severity: str
    blocking: bool
    action_type: str
    deep_link: str | None


@dataclass(frozen=True)
class PlaybookProgress:
    """Aggregate progress view for the GuidedExecutionPanel."""

    engagement_id: str
    current_status: str
    completion_pct: float
    blocking_count: int
    actions: list[PlaybookNextAction] = field(default_factory=list)
    generated_at: str = ""


# ─── Computation ──────────────────────────────────────────────────────────────


def compute_next_actions(
    execution_state: "ExecutionState",
    *,
    engagement_id: str,
    current_status: str,
) -> PlaybookProgress:
    """Enrich ExecutionState.next_actions and compute aggregate progress.

    Pure function — safe to call on any thread without holding a DB session.

    Args:
        execution_state: Pre-built state from readiness.build_execution_state.
        engagement_id: Used to construct deep_link URLs.
        current_status: Engagement status string (e.g. "setup", "in_progress").

    Returns:
        PlaybookProgress with enriched actions and computed completion_pct.
    """
    blocked_gate_ids: set[str] = {
        gate.gate_id
        for gate in execution_state.gates
        if gate.status == "blocked"
    }

    enriched: list[PlaybookNextAction] = []
    for action in execution_state.next_actions:
        closes = set(action.closes_gate_ids)
        blocking = bool(closes & blocked_gate_ids)
        action_type = _ACTION_TYPE_MAP.get(action.required_input_type, action.required_input_type)
        tab = _TAB_MAP.get(action.target_ui_section, action.target_ui_section)
        deep_link = _DEEP_LINK_TEMPLATE.format(
            engagement_id=engagement_id,
            tab=tab,
        )
        enriched.append(
            PlaybookNextAction(
                action_id=action.action_id,
                priority=action.priority,
                title=action.title,
                instruction=action.instruction,
                why_it_matters=action.why_it_matters,
                closes_gate_ids=list(action.closes_gate_ids),
                required_input_type=action.required_input_type,
                target_ui_section=action.target_ui_section,
                expected_evidence=list(action.expected_evidence),
                safe_for_junior_assessor=action.safe_for_junior_assessor,
                severity=action.severity,
                blocking=blocking,
                action_type=action_type,
                deep_link=deep_link,
            )
        )

    total_gates = max(
        1,
        execution_state.completed_gate_count
        + execution_state.blocking_gate_count
        + execution_state.warning_gate_count,
    )
    completion_pct = round(
        execution_state.completed_gate_count / total_gates * 100, 1
    )
    blocking_count = sum(1 for a in enriched if a.blocking)

    return PlaybookProgress(
        engagement_id=engagement_id,
        current_status=current_status,
        completion_pct=completion_pct,
        blocking_count=blocking_count,
        actions=enriched,
        generated_at=execution_state.generated_at,
    )
