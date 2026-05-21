"""Governance topology graph derivation engine.

Public API:
  build_graph(db, *, tenant_id, triggered_by) -> GraphBuildResult
  build_graph_for_engagement(db, *, tenant_id, engagement_id, triggered_by) -> GraphBuildResult
"""

from __future__ import annotations

import hashlib
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEngagement,
    FaNormalizedFinding,
    FaScanResult,
)
from api.db_models_governance_asset_candidates import GaAssetCandidate
from api.db_models_governance_assets import (
    GaAsset,
    GaAssetAttestation,
    GaAssetOwner,
    GaAssetRelationship,
)
from api.db_models_governance_graph import GovernanceGraphSnapshot
from services.canonical import utc_iso8601_z_now
from services.governance_graph import anomaly_patterns
from services.governance_graph.models import GraphBuildResult
from services.governance_graph.mutations import (
    _node_id,
    delete_stale,
    update_centrality,
    upsert_anomaly,
    upsert_edge,
    upsert_node,
)

log = logging.getLogger("frostgate.governance_graph.builder")


def _new_snapshot_id() -> str:
    return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]


def _get_snapshot_seq(db: Session, tenant_id: str) -> int:
    from sqlalchemy import func

    count = db.execute(
        select(func.count()).where(GovernanceGraphSnapshot.tenant_id == tenant_id)
    ).scalar_one()
    return count + 1


# ---------------------------------------------------------------------------
# Derivation helpers
# ---------------------------------------------------------------------------


def _derive_from_assets(
    db: Session, tenant_id: str, snapshot_id: str, derived_at: str, engagement_id: str | None = None
) -> tuple[int, int]:
    """Derive governance_asset, identity, and relationship nodes/edges from GaAsset."""
    nodes_upserted = 0
    edges_upserted = 0

    assets = (
        db.execute(
            select(GaAsset).where(
                GaAsset.tenant_id == tenant_id,
                GaAsset.status == "active",
            )
        )
        .scalars()
        .all()
    )

    for asset in assets:
        upsert_node(
            db,
            tenant_id=tenant_id,
            node_type="governance_asset",
            entity_id=asset.asset_id,
            entity_type="governance_assets",
            label=asset.name,
            properties={
                "asset_type": asset.asset_type,
                "risk_tier": asset.risk_tier,
                "risk_score": asset.risk_score,
                "discovery_source": asset.discovery_source,
                "external_id": asset.external_id,
                "created_at": asset.created_at,
            },
            tags=[],
            trust_score=100,
            source_ref=f"governance_assets:{asset.asset_id}",
            snapshot_id=snapshot_id,
            derived_at=derived_at,
        )
        nodes_upserted += 1

        # Owners
        owners = (
            db.execute(
                select(GaAssetOwner).where(
                    GaAssetOwner.asset_id == asset.asset_id,
                    GaAssetOwner.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        for owner in owners:
            upsert_node(
                db,
                tenant_id=tenant_id,
                node_type="identity",
                entity_id=owner.owner_email,
                entity_type="governance_asset_owners",
                label=owner.owner_email,
                properties={},
                tags=[],
                trust_score=100,
                source_ref=f"governance_asset_owners:{owner.ownership_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            nodes_upserted += 1
            identity_nid = _node_id(tenant_id, "identity", owner.owner_email)
            asset_nid = _node_id(tenant_id, "governance_asset", asset.asset_id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="OWNS",
                source_node_id=identity_nid,
                target_node_id=asset_nid,
                confidence=100,
                properties={},
                source_ref=f"governance_asset_owners:{owner.ownership_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

        # Attestations
        attestations = (
            db.execute(
                select(GaAssetAttestation).where(
                    GaAssetAttestation.asset_id == asset.asset_id,
                    GaAssetAttestation.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        # Use latest attestation per owner_email
        seen_attestors: set[str] = set()
        for att in sorted(attestations, key=lambda a: a.created_at, reverse=True):
            if att.owner_email in seen_attestors:
                continue
            seen_attestors.add(att.owner_email)
            upsert_node(
                db,
                tenant_id=tenant_id,
                node_type="identity",
                entity_id=att.owner_email,
                entity_type="governance_asset_attestations",
                label=att.owner_email,
                properties={},
                tags=[],
                trust_score=100,
                source_ref=f"governance_asset_attestations:{att.attestation_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            nodes_upserted += 1
            asset_nid = _node_id(tenant_id, "governance_asset", asset.asset_id)
            attestor_nid = _node_id(tenant_id, "identity", att.owner_email)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="ATTESTED_BY",
                source_node_id=asset_nid,
                target_node_id=attestor_nid,
                confidence=100,
                properties={},
                source_ref=f"governance_asset_attestations:{att.attestation_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

        # Relationships
        relationships = (
            db.execute(
                select(GaAssetRelationship).where(
                    GaAssetRelationship.tenant_id == tenant_id,
                    GaAssetRelationship.source_asset_id == asset.asset_id,
                )
            )
            .scalars()
            .all()
        )
        for rel in relationships:
            rel_type = rel.relationship_type.upper()
            if rel_type in ("USES", "CONNECTED_TO"):
                edge_type = rel_type
            else:
                edge_type = "RELATED_TO"
            src_nid = _node_id(tenant_id, "governance_asset", asset.asset_id)
            tgt_nid = _node_id(tenant_id, "governance_asset", rel.target_asset_id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type=edge_type,
                source_node_id=src_nid,
                target_node_id=tgt_nid,
                confidence=100,
                properties={},
                source_ref=f"governance_asset_relationships:{rel.relationship_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

    return nodes_upserted, edges_upserted


def _derive_from_candidates(
    db: Session, tenant_id: str, snapshot_id: str, derived_at: str, engagement_id: str | None = None
) -> tuple[int, int]:
    """Derive candidate nodes and PROMOTED_FROM edges from GaAssetCandidate."""
    nodes_upserted = 0
    edges_upserted = 0

    candidates = (
        db.execute(
            select(GaAssetCandidate).where(
                GaAssetCandidate.tenant_id == tenant_id,
                GaAssetCandidate.status == "promoted",
            )
        )
        .scalars()
        .all()
    )

    for cand in candidates:
        node_type = cand.candidate_type  # ai_system, oauth_application, etc.
        upsert_node(
            db,
            tenant_id=tenant_id,
            node_type=node_type,
            entity_id=cand.candidate_id,
            entity_type="ga_asset_candidates",
            label=cand.suggested_name,
            properties={
                "source_type": cand.source_type,
                "risk_signal": cand.risk_signal,
                "confidence": cand.confidence,
            },
            tags=[],
            trust_score=100,
            source_ref=f"ga_asset_candidates:{cand.candidate_id}",
            snapshot_id=snapshot_id,
            derived_at=derived_at,
        )
        nodes_upserted += 1

        if cand.promoted_asset_id:
            asset_nid = _node_id(tenant_id, "governance_asset", cand.promoted_asset_id)
            cand_nid = _node_id(tenant_id, node_type, cand.candidate_id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="PROMOTED_FROM",
                source_node_id=asset_nid,
                target_node_id=cand_nid,
                confidence=100,
                properties={},
                source_ref=f"ga_asset_candidates:{cand.candidate_id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

    return nodes_upserted, edges_upserted


def _derive_from_findings(
    db: Session, tenant_id: str, snapshot_id: str, derived_at: str, engagement_id: str | None = None
) -> tuple[int, int]:
    """Derive finding, control nodes and edges from FaNormalizedFinding."""
    nodes_upserted = 0
    edges_upserted = 0

    stmt = select(FaNormalizedFinding).where(
        FaNormalizedFinding.tenant_id == tenant_id,
        FaNormalizedFinding.status == "open",
    )
    if engagement_id is not None:
        stmt = stmt.where(FaNormalizedFinding.engagement_id == engagement_id)
    findings = db.execute(stmt).scalars().all()

    for finding in findings:
        upsert_node(
            db,
            tenant_id=tenant_id,
            node_type="finding",
            entity_id=finding.id,
            entity_type="fa_normalized_findings",
            label=finding.title,
            properties={
                "severity": finding.severity,
                "finding_type": finding.finding_type,
                "source_attribution": finding.source_attribution,
                "confidence_score": finding.confidence_score,
            },
            tags=[],
            trust_score=100,
            source_ref=f"fa_normalized_findings:{finding.id}",
            engagement_id=finding.engagement_id,
            snapshot_id=snapshot_id,
            derived_at=derived_at,
        )
        nodes_upserted += 1

        finding_nid = _node_id(tenant_id, "finding", finding.id)

        # IMPACTS edge to governance_asset
        if finding.asset_id:
            asset_nid = _node_id(tenant_id, "governance_asset", finding.asset_id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="IMPACTS",
                source_node_id=finding_nid,
                target_node_id=asset_nid,
                confidence=finding.confidence_score,
                properties={},
                source_ref=f"fa_normalized_findings:{finding.id}",
                engagement_id=finding.engagement_id,
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

        # GOVERNED_BY edges from framework_mappings
        for mapping in finding.framework_mappings or []:
            control_ref = mapping.get("control_ref") or mapping.get("id") or ""
            if not control_ref:
                continue
            upsert_node(
                db,
                tenant_id=tenant_id,
                node_type="control",
                entity_id=control_ref,
                entity_type="framework_control",
                label=control_ref,
                properties={"framework": mapping.get("framework", "")},
                tags=[],
                trust_score=100,
                source_ref=f"fa_normalized_findings:{finding.id}",
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            nodes_upserted += 1
            control_nid = _node_id(tenant_id, "control", control_ref)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="GOVERNED_BY",
                source_node_id=finding_nid,
                target_node_id=control_nid,
                confidence=finding.confidence_score,
                properties={},
                source_ref=f"fa_normalized_findings:{finding.id}",
                engagement_id=finding.engagement_id,
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

    return nodes_upserted, edges_upserted


def _derive_from_scans(
    db: Session, tenant_id: str, snapshot_id: str, derived_at: str, engagement_id: str | None = None
) -> tuple[int, int]:
    """Derive scan nodes and DETECTED_BY edges from FaScanResult."""
    nodes_upserted = 0
    edges_upserted = 0

    stmt = select(FaScanResult).where(FaScanResult.tenant_id == tenant_id)
    if engagement_id is not None:
        stmt = stmt.where(FaScanResult.engagement_id == engagement_id)
    scans = db.execute(stmt).scalars().all()

    for scan in scans:
        upsert_node(
            db,
            tenant_id=tenant_id,
            node_type="scan",
            entity_id=scan.id,
            entity_type="fa_scan_results",
            label=f"scan:{scan.source_type}:{scan.id[:8]}",
            properties={
                "source_type": scan.source_type,
                "collected_at": scan.collected_at,
                "object_count": scan.object_count,
                "evidence_hash": scan.evidence_hash,
            },
            tags=[],
            trust_score=100,
            source_ref=f"fa_scan_results:{scan.id}",
            engagement_id=scan.engagement_id,
            snapshot_id=snapshot_id,
            derived_at=derived_at,
        )
        nodes_upserted += 1

        # DETECTED_BY: findings linked to this scan via engagement_id
        findings = (
            db.execute(
                select(FaNormalizedFinding).where(
                    FaNormalizedFinding.tenant_id == tenant_id,
                    FaNormalizedFinding.engagement_id == scan.engagement_id,
                    FaNormalizedFinding.status == "open",
                )
            )
            .scalars()
            .all()
        )
        scan_nid = _node_id(tenant_id, "scan", scan.id)
        for finding in findings:
            finding_nid = _node_id(tenant_id, "finding", finding.id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="DETECTED_BY",
                source_node_id=finding_nid,
                target_node_id=scan_nid,
                confidence=100,
                properties={},
                source_ref=f"fa_scan_results:{scan.id}",
                engagement_id=scan.engagement_id,
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

    return nodes_upserted, edges_upserted


def _derive_from_engagements(
    db: Session, tenant_id: str, snapshot_id: str, derived_at: str, engagement_id: str | None = None
) -> tuple[int, int]:
    """Derive engagement nodes and SUPPORTS edges from FaEngagement."""
    nodes_upserted = 0
    edges_upserted = 0

    stmt = select(FaEngagement).where(FaEngagement.tenant_id == tenant_id)
    if engagement_id is not None:
        stmt = stmt.where(FaEngagement.id == engagement_id)
    engagements = db.execute(stmt).scalars().all()

    for eng in engagements:
        upsert_node(
            db,
            tenant_id=tenant_id,
            node_type="engagement",
            entity_id=eng.id,
            entity_type="fa_engagements",
            label=eng.client_name,
            properties={
                "client_name": eng.client_name,
                "assessment_type": eng.assessment_type,
                "status": eng.status,
            },
            tags=[],
            trust_score=100,
            source_ref=f"fa_engagements:{eng.id}",
            engagement_id=eng.id,
            snapshot_id=snapshot_id,
            derived_at=derived_at,
        )
        nodes_upserted += 1

        eng_nid = _node_id(tenant_id, "engagement", eng.id)

        # SUPPORTS edges to scans
        scans = (
            db.execute(
                select(FaScanResult).where(
                    FaScanResult.tenant_id == tenant_id,
                    FaScanResult.engagement_id == eng.id,
                )
            )
            .scalars()
            .all()
        )
        for scan in scans:
            scan_nid = _node_id(tenant_id, "scan", scan.id)
            upsert_edge(
                db,
                tenant_id=tenant_id,
                edge_type="SUPPORTS",
                source_node_id=eng_nid,
                target_node_id=scan_nid,
                confidence=100,
                properties={},
                source_ref=f"fa_engagements:{eng.id}",
                engagement_id=eng.id,
                snapshot_id=snapshot_id,
                derived_at=derived_at,
            )
            edges_upserted += 1

    return nodes_upserted, edges_upserted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DERIVATION_STEPS = [
    ("assets", _derive_from_assets),
    ("candidates", _derive_from_candidates),
    ("findings", _derive_from_findings),
    ("scans", _derive_from_scans),
    ("engagements", _derive_from_engagements),
]


def _run_build(
    db: Session,
    *,
    tenant_id: str,
    triggered_by: str,
    engagement_id: str | None,
) -> GraphBuildResult:
    rebuild_started_at = utc_iso8601_z_now()
    snapshot_id = _new_snapshot_id()
    snapshot_seq = _get_snapshot_seq(db, tenant_id)

    # Create snapshot record
    snap = GovernanceGraphSnapshot(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        snapshot_seq=snapshot_seq,
        nodes_upserted=0,
        edges_upserted=0,
        nodes_deleted=0,
        edges_deleted=0,
        anomalies_detected=0,
        triggered_by=triggered_by,
        built_at=rebuild_started_at,
        schema_version="1.0",
    )
    db.add(snap)
    db.flush()

    total_nodes = 0
    total_edges = 0
    any_step_failed = False

    # Best-effort derivation — pass engagement_id so scoped rebuilds filter correctly
    for step_name, step_fn in _DERIVATION_STEPS:
        try:
            n, e = step_fn(db, tenant_id, snapshot_id, rebuild_started_at, engagement_id)
            total_nodes += n
            total_edges += e
        except Exception:  # noqa: BLE001
            log.warning("Derivation step %s failed", step_name, exc_info=True)
            any_step_failed = True

    # Centrality
    try:
        update_centrality(db, tenant_id=tenant_id, snapshot_id=snapshot_id)
    except Exception:  # noqa: BLE001
        log.warning("update_centrality failed", exc_info=True)

    # Anomaly detection
    anomalies: list[dict] = []
    try:
        now = utc_iso8601_z_now()
        anomalies = anomaly_patterns.run_all_patterns(db, tenant_id, snapshot_id, now)
        for a in anomalies:
            upsert_anomaly(
                db,
                tenant_id=tenant_id,
                pattern_id=a["pattern_id"],
                description=a["description"],
                severity=a["severity"],
                node_ids=a["node_ids"],
                edge_ids=a["edge_ids"],
                snapshot_id=snapshot_id,
                detected_at=now,
            )
    except Exception:  # noqa: BLE001
        log.warning("Anomaly detection failed", exc_info=True)

    # Delete stale nodes/edges — only when all derivation steps succeeded.
    # If any step failed, retain last-known-good state rather than silently
    # deleting nodes/edges that simply weren't re-derived due to the failure.
    nodes_deleted = 0
    edges_deleted = 0
    if any_step_failed:
        log.warning(
            "Skipping stale-node cleanup for tenant=%s snapshot=%s "
            "because one or more derivation steps failed — retaining last-known-good graph state.",
            tenant_id,
            snapshot_id,
        )
    else:
        try:
            nodes_deleted, edges_deleted = delete_stale(
                db, tenant_id=tenant_id, older_than=rebuild_started_at
            )
        except Exception:  # noqa: BLE001
            log.warning("delete_stale failed", exc_info=True)

    # Update snapshot counts
    snap.nodes_upserted = total_nodes
    snap.edges_upserted = total_edges
    snap.nodes_deleted = nodes_deleted
    snap.edges_deleted = edges_deleted
    snap.anomalies_detected = len(anomalies)
    db.flush()

    return GraphBuildResult(
        snapshot_id=snapshot_id,
        snapshot_seq=snapshot_seq,
        tenant_id=tenant_id,
        nodes_upserted=total_nodes,
        edges_upserted=total_edges,
        nodes_deleted=nodes_deleted,
        edges_deleted=edges_deleted,
        anomalies_detected=len(anomalies),
        triggered_by=triggered_by,
        built_at=rebuild_started_at,
    )


def build_graph(
    db: Session,
    *,
    tenant_id: str,
    triggered_by: str = "rebuild_api",
) -> GraphBuildResult:
    """Rebuild the full governance topology graph for a tenant."""
    return _run_build(db, tenant_id=tenant_id, triggered_by=triggered_by, engagement_id=None)


def build_graph_for_engagement(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    triggered_by: str = "msgraph_import",
) -> GraphBuildResult:
    """Rebuild the graph scoped to a specific engagement."""
    return _run_build(
        db, tenant_id=tenant_id, triggered_by=triggered_by, engagement_id=engagement_id
    )
