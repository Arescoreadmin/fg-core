"""Graph root-cause correlation for regressed/escalated drift findings.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Deferred from PR 5.5, implemented in PR 6.

Given a finding and a drift window [baseline_collected_at, current_collected_at],
queries the governance topology graph for edges that:
  1. Connect to the node representing this finding (finding node in the graph), OR
  2. Were derived within the drift window (new relationships that emerged as the
     finding appeared/regressed).

These edges are returned as RootCauseCandidate records for the caller to surface.
The engine itself (compute_drift) stays graph-agnostic; correlation is computed
on-demand by the API route, not inline in the drift computation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import GovernanceGraphEdge, GovernanceGraphNode

log = logging.getLogger("frostgate.connectors.drift.correlation")


@dataclass(frozen=True)
class RootCauseCandidate:
    edge_id: str
    edge_type: str
    source_node_id: str
    target_node_id: str
    rationale: str


def find_root_cause_candidates(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    baseline_collected_at: str,
    current_collected_at: str,
    limit: int = 20,
) -> list[RootCauseCandidate]:
    """Return graph edges that correlate with a finding in the drift window.

    1. Finds the GovernanceGraphNode whose entity_id matches the finding_id.
    2. Queries edges connecting to/from that node, filtered to those derived
       within the [baseline_collected_at, current_collected_at] window.
    3. Also includes edges derived in the window that reference the same
       engagement/tenant even without a direct node match (broader context).

    Returns empty list when the finding has no node in the graph or no edges
    appear in the window — callers must handle the empty case gracefully.
    """
    # Step 1: find the node for this finding
    node = db.execute(
        select(GovernanceGraphNode).where(
            GovernanceGraphNode.tenant_id == tenant_id,
            GovernanceGraphNode.entity_id == finding_id,
        )
    ).scalar_one_or_none()

    candidates: list[RootCauseCandidate] = []

    if node is not None:
        # Step 2: edges touching this node derived in the drift window
        edge_rows = (
            db.execute(
                select(GovernanceGraphEdge)
                .where(
                    GovernanceGraphEdge.tenant_id == tenant_id,
                    GovernanceGraphEdge.derived_at >= baseline_collected_at,
                    GovernanceGraphEdge.derived_at <= current_collected_at,
                    or_(
                        GovernanceGraphEdge.source_node_id == node.node_id,
                        GovernanceGraphEdge.target_node_id == node.node_id,
                    ),
                )
                .limit(limit)
            )
            .scalars()
            .all()
        )

        for edge in edge_rows:
            direction = "outbound" if edge.source_node_id == node.node_id else "inbound"
            candidates.append(
                RootCauseCandidate(
                    edge_id=edge.edge_id,
                    edge_type=edge.edge_type,
                    source_node_id=edge.source_node_id,
                    target_node_id=edge.target_node_id,
                    rationale=(
                        f"{direction} edge of type {edge.edge_type!r} derived "
                        f"in drift window [{baseline_collected_at}, "
                        f"{current_collected_at}]"
                    ),
                )
            )

    if len(candidates) < limit:
        # Step 3: broader context — edges derived in window where source_ref
        # contains the finding_id (e.g. source_ref="finding:{finding_id}")
        broad_rows = (
            db.execute(
                select(GovernanceGraphEdge)
                .where(
                    GovernanceGraphEdge.tenant_id == tenant_id,
                    GovernanceGraphEdge.derived_at >= baseline_collected_at,
                    GovernanceGraphEdge.derived_at <= current_collected_at,
                    GovernanceGraphEdge.source_ref.contains(finding_id),
                )
                .limit(limit - len(candidates))
            )
            .scalars()
            .all()
        )
        seen_ids = {c.edge_id for c in candidates}
        for edge in broad_rows:
            if edge.edge_id in seen_ids:
                continue
            candidates.append(
                RootCauseCandidate(
                    edge_id=edge.edge_id,
                    edge_type=edge.edge_type,
                    source_node_id=edge.source_node_id,
                    target_node_id=edge.target_node_id,
                    rationale=(
                        f"edge source_ref references finding in drift window "
                        f"[{baseline_collected_at}, {current_collected_at}]"
                    ),
                )
            )

    return candidates
