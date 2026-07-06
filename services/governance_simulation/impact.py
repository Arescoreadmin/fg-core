"""Deterministic impact analysis engine: analyze governance impact from a graph diff."""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import asdict

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_digital_twin.models import GovernanceDigitalTwinSnapshot
from services.governance_simulation.models import (
    GraphDiff,
    GraphDiffEntry,
    ImpactChain,
    ImpactChainNode,
    ImpactConfidence,
    ImpactEntry,
    ImpactReport,
)


# Map from diff domain to impact domains that should be analyzed
_DOMAIN_TRIGGERS: dict[str, list[str]] = {
    "governance": ["governance", "compliance"],
    "control": ["control", "compliance"],
    "evidence": ["evidence", "trust", "readiness"],
    "framework": ["framework", "compliance"],
    "risk": ["risk", "readiness"],
    "operational": ["operational"],
    "executive": ["executive"],
    "authority": ["authority", "trust"],
    "readiness": ["readiness"],
}

# Entity types that contribute to each impact domain
_ENTITY_TYPE_TO_DOMAINS: dict[str, list[str]] = {
    "policy": ["governance", "compliance"],
    "control": ["control", "compliance"],
    "evidence": ["evidence", "trust", "readiness"],
    "finding": ["risk", "readiness"],
    "remediation": ["risk", "readiness"],
    "assessment": ["operational"],
    "report": ["executive"],
    "decision": ["executive"],
    "workflow": ["operational"],
    "simulation": ["governance"],
    "replay": ["governance"],
    "customer": ["governance"],
    "framework": ["framework", "compliance"],
    "authority": ["authority", "trust"],
}

# Relationship types that contribute to each impact domain
_REL_TYPE_TO_DOMAINS: dict[str, list[str]] = {
    "governs": ["governance"],
    "verifies": ["evidence", "trust"],
    "maps_to": ["framework", "compliance"],
    "supports": ["compliance"],
    "contradicts": ["governance", "trust"],
    "remediates": ["risk", "readiness"],
    "generated_from": ["governance"],
    "published_to": ["executive"],
    "decided_by": ["executive"],
    "depends_on": ["operational"],
    "supersedes": ["governance"],
    "derived_from": ["governance"],
    "affects": ["operational"],
    "owned_by": ["authority"],
}


def _impact_id(scenario_id: str, domain: str, diff_id: str) -> str:
    seed = f"IMPACT:{scenario_id}:{domain}:{diff_id}"
    return hashlib.sha256(seed.encode()).hexdigest()[:20]


def _determine_confidence(
    entry: GraphDiffEntry,
    snapshot: GovernanceDigitalTwinSnapshot,
) -> tuple[str, tuple[str, ...]]:
    """Determine confidence level and supporting evidence ids."""
    # PROVEN: the diff entry has a supporting evidence entity in snapshot
    entity_id = entry.entity_id
    relationship_id = entry.relationship_id
    snapshot_entity_ids = {e.id for e in snapshot.entities}

    # Check if there's an evidence entity connected to this entity in the snapshot
    supporting: list[str] = []
    for rel in snapshot.relationships:
        if entity_id and (
            rel.from_entity_id == entity_id or rel.to_entity_id == entity_id
        ):
            other_id = (
                rel.to_entity_id
                if rel.from_entity_id == entity_id
                else rel.from_entity_id
            )
            # Find the entity type
            for e in snapshot.entities:
                if e.id == other_id and e.type == "evidence":
                    supporting.append(e.id)

        if relationship_id and rel.id == relationship_id:
            for ref in rel.evidence_refs:
                if ref in snapshot_entity_ids:
                    supporting.append(ref)

    if supporting:
        return ImpactConfidence.PROVEN.value, tuple(sorted(set(supporting)))

    # INFERRED: logically connected (entity in snapshot or directly referenced in diff)
    if entity_id and entity_id in snapshot_entity_ids:
        return ImpactConfidence.INFERRED.value, ()
    if relationship_id:
        snap_rel_ids = {r.id for r in snapshot.relationships}
        if relationship_id in snap_rel_ids:
            return ImpactConfidence.INFERRED.value, ()

    # UNKNOWN: cannot be established from authoritative state
    return ImpactConfidence.UNKNOWN.value, ()


def _get_originating_authority(
    entry: GraphDiffEntry, snapshot: GovernanceDigitalTwinSnapshot
) -> str:
    if entry.entity_id:
        for e in snapshot.entities:
            if e.id == entry.entity_id:
                return e.authority
    if entry.relationship_id:
        for r in snapshot.relationships:
            if r.id == entry.relationship_id:
                return r.authority
    # Also check the 'before' payload from the diff entry itself
    if entry.before and isinstance(entry.before, dict):
        return entry.before.get("authority", entry.authority) or entry.authority
    return entry.authority if entry.authority else "unknown"


def _domains_for_entry(entry: GraphDiffEntry, snapshot: GovernanceDigitalTwinSnapshot) -> list[str]:
    """Determine which impact domains are triggered by a diff entry."""
    domains: set[str] = set()

    # From entity type
    if entry.entity_id:
        # look up entity type from before/after payload
        entity_type = None
        if entry.before and isinstance(entry.before, dict):
            entity_type = entry.before.get("type")
        elif entry.after and isinstance(entry.after, dict):
            entity_type = entry.after.get("type")
        if entity_type:
            domains.update(_ENTITY_TYPE_TO_DOMAINS.get(entity_type, ["governance"]))

    # From relationship type
    if entry.relationship_id:
        rel_type = None
        if entry.before and isinstance(entry.before, dict):
            rel_type = entry.before.get("type")
        elif entry.after and isinstance(entry.after, dict):
            rel_type = entry.after.get("type")
        if rel_type:
            domains.update(_REL_TYPE_TO_DOMAINS.get(rel_type, ["governance"]))

    # Fallback: use entry's own domain
    if not domains:
        domains.update(_DOMAIN_TRIGGERS.get(entry.domain, [entry.domain]))

    return sorted(domains)


_DOMAIN_DOWNSTREAM: dict[str, list[str]] = {
    "governance": ["control", "compliance"],
    "control": ["risk", "compliance"],
    "evidence": ["trust", "readiness"],
    "framework": ["compliance"],
    "compliance": ["executive"],
    "risk": ["executive"],
    "readiness": ["executive"],
    "authority": ["trust"],
    "trust": [],
    "operational": ["executive"],
    "executive": [],
}


def _weakest_confidence(entries: list[ImpactEntry]) -> str:
    """Return weakest confidence: UNKNOWN > INFERRED > PROVEN."""
    rank = {"PROVEN": 0, "INFERRED": 1, "UNKNOWN": 2}
    return max((e.confidence for e in entries), key=lambda c: rank.get(c, 2))


def _build_impact_chains(
    entries: list[ImpactEntry],
    scenario_id: str,
) -> tuple[ImpactChain, ...]:
    """Build impact chains following downstream domain dependencies."""
    domains_with_entries: dict[str, list[ImpactEntry]] = {}
    for e in entries:
        domains_with_entries.setdefault(e.domain, []).append(e)

    chains: list[ImpactChain] = []
    # Only build chains starting from root domains (no upstream)
    upstream_domains: set[str] = set()
    for domain, downstreams in _DOMAIN_DOWNSTREAM.items():
        for d in downstreams:
            upstream_domains.add(d)
    root_domains = [d for d in domains_with_entries if d not in upstream_domains]

    for root in sorted(root_domains):
        chain_nodes: list[ImpactChainNode] = []
        visited: set[str] = set()
        queue: list[str] = [root]
        while queue:
            current = queue.pop(0)
            if current in visited or current not in domains_with_entries:
                continue
            visited.add(current)
            current_entries = domains_with_entries[current]
            node = ImpactChainNode(
                domain=current,
                impacted_object_ids=tuple(sorted({oid for e in current_entries for oid in e.impacted_object_ids})),
                confidence=_weakest_confidence(current_entries),
            )
            chain_nodes.append(node)
            for downstream in _DOMAIN_DOWNSTREAM.get(current, []):
                if downstream not in visited:
                    queue.append(downstream)

        if len(chain_nodes) > 1:  # only record chains with actual propagation
            chain_id = hashlib.sha256(
                f"CHAIN:{scenario_id}:{root}".encode()
            ).hexdigest()[:20]
            chain_hash_payload = [dataclasses.asdict(n) for n in chain_nodes]
            chain_hash = hashlib.sha256(canonical_json_bytes(chain_hash_payload)).hexdigest()
            chains.append(ImpactChain(
                chain_id=chain_id,
                scenario_id=scenario_id,
                origin_domain=root,
                chain=tuple(chain_nodes),
                chain_hash=chain_hash,
            ))

    return tuple(sorted(chains, key=lambda c: c.chain_id))


def analyze_impact(
    snapshot: GovernanceDigitalTwinSnapshot,
    diff: GraphDiff,
    scenario_id: str,
) -> ImpactReport:
    """Analyze impact from a GraphDiff against the snapshot.

    For each diff entry, produce one ImpactEntry per affected domain.
    Never fabricates impact — returns UNKNOWN when domain cannot be established.
    """
    entries: list[ImpactEntry] = []

    if not diff.entries:
        # No diff → produce UNKNOWN entries for all domains to indicate analysis was attempted
        pass

    for diff_entry in diff.entries:
        affected_domains = _domains_for_entry(diff_entry, snapshot)
        confidence, supporting = _determine_confidence(diff_entry, snapshot)
        authority = _get_originating_authority(diff_entry, snapshot)

        impacted_ids: list[str] = []
        if diff_entry.entity_id:
            impacted_ids.append(diff_entry.entity_id)
        if diff_entry.relationship_id:
            impacted_ids.append(diff_entry.relationship_id)

        limitations: list[str] = []
        if confidence == ImpactConfidence.UNKNOWN.value:
            limitations.append(
                f"Impact in domain '{affected_domains[0] if affected_domains else diff_entry.domain}' "
                "cannot be proven from authoritative state"
            )

        for domain in affected_domains:
            impact_id = _impact_id(scenario_id, domain, diff_entry.diff_id)
            entry = ImpactEntry(
                impact_id=impact_id,
                domain=domain,
                impacted_object_ids=tuple(sorted(set(impacted_ids))),
                reason=diff_entry.reason,
                originating_authority=authority,
                confidence=confidence,
                supporting_evidence_ids=supporting,
                limitations=tuple(limitations),
            )
            entries.append(entry)

    # Deduplicate by (domain, impact_id)
    seen: set[str] = set()
    deduped: list[ImpactEntry] = []
    for e in entries:
        if e.impact_id not in seen:
            seen.add(e.impact_id)
            deduped.append(e)

    report_id_seed = f"IMPACT_REPORT:{scenario_id}:{snapshot.snapshot_id}"
    report_id = hashlib.sha256(report_id_seed.encode()).hexdigest()[:24]

    sorted_entries = tuple(sorted(deduped, key=lambda e: e.impact_id))

    report_hash_payload = sorted(
        (asdict(e) for e in sorted_entries),
        key=lambda x: x["impact_id"],
    )
    report_hash = hashlib.sha256(canonical_json_bytes(report_hash_payload)).hexdigest()

    global_limitations: list[str] = []
    if not diff.entries:
        global_limitations.append("No diff entries — no impact could be determined")

    chains = _build_impact_chains(deduped, scenario_id)

    return ImpactReport(
        report_id=report_id,
        scenario_id=scenario_id,
        source_snapshot_id=snapshot.snapshot_id,
        entries=sorted_entries,
        report_hash=report_hash,
        created_at=utc_iso8601_z_now(),
        limitations=tuple(global_limitations),
        chains=chains,
    )
