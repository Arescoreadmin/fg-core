"""Governance Asset Registry — relationship graph traversal.

blast_radius: given an asset, BFS-traverse all downstream dependents up to
max_depth hops.  Returns a structured impact report: affected asset IDs
grouped by hop distance, relationship types, and data classifications
found along the traversal path.

This is the "what breaks if this asset is compromised or decommissioned?"
query — a single API call that produces machine-readable blast radius data
for security review, vendor offboarding, and incident response.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_assets import GaAsset, GaAssetRelationship


def blast_radius(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    max_depth: int = 3,
) -> dict[str, Any]:
    """BFS from asset_id following all outbound relationship edges.

    Returns:
      {
        origin_asset_id: str,
        max_depth: int,
        hops: [
          {hop: int, asset_id: str, asset_type: str, name: str,
           relationship_type: str, data_classification: str,
           via_asset_id: str}
        ],
        affected_asset_count: int,
        unique_asset_types: [...],
        highest_data_classification: str,
        summary: str,
      }
    """
    visited: set[str] = {asset_id}
    hops: list[dict[str, Any]] = []

    # queue entries: (current_asset_id, hop_depth, via_asset_id, rel_type, data_cls)
    queue: deque[tuple[str, int, str, str, str]] = deque()
    queue.append((asset_id, 0, "", "", "unknown"))

    data_cls_severity = {
        "phi": 7, "pii": 6, "financial": 5, "confidential": 4,
        "internal": 3, "unknown": 2, "public": 1,
    }
    highest_cls = "unknown"

    while queue:
        current_id, depth, via_id, rel_type, data_cls = queue.popleft()
        if depth >= max_depth:
            continue

        stmt = (
            select(GaAssetRelationship)
            .where(
                GaAssetRelationship.tenant_id == tenant_id,
                GaAssetRelationship.source_asset_id == current_id,
            )
        )
        rels = db.execute(stmt).scalars().all()

        for rel in rels:
            target = rel.target_asset_id
            if target in visited:
                continue
            visited.add(target)

            target_asset = db.execute(
                select(GaAsset).where(
                    GaAsset.asset_id == target,
                    GaAsset.tenant_id == tenant_id,
                )
            ).scalar_one_or_none()

            asset_type = target_asset.asset_type if target_asset else "unknown"
            name = target_asset.name if target_asset else target

            if data_cls_severity.get(rel.data_classification, 0) > data_cls_severity.get(highest_cls, 0):
                highest_cls = rel.data_classification

            hops.append({
                "hop": depth + 1,
                "asset_id": target,
                "asset_type": asset_type,
                "name": name,
                "relationship_type": rel.relationship_type,
                "data_classification": rel.data_classification,
                "via_asset_id": current_id,
            })
            queue.append(
                (target, depth + 1, current_id, rel.relationship_type, rel.data_classification)
            )

    unique_types = sorted({h["asset_type"] for h in hops})
    return {
        "origin_asset_id": asset_id,
        "max_depth": max_depth,
        "hops": hops,
        "affected_asset_count": len(hops),
        "unique_asset_types": unique_types,
        "highest_data_classification": highest_cls,
        "summary": (
            f"{len(hops)} downstream asset(s) affected across "
            f"{len(unique_types)} type(s); "
            f"highest data classification: {highest_cls}"
        ),
    }
