"""Release authority for canonical governance result truth.

The gate validates outputs produced by FGA-025 through FGA-028.  It does not
derive findings, posture, epistemic state, or claims; it only decides whether
the already-derived canonical result is complete, scoped, and lineage-safe to
release.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

RESULT_TRUTH_GATE_VERSION = "1.0"
_EPISTEMIC_STATES = {
    "NOT_PROVEN",
    "CONTRADICTORY",
    "STALE",
    "PARTIALLY_SUPPORTED",
    "VERIFIED_DEFICIENT",
    "VERIFIED_EFFECTIVE",
}
_DISPOSITION_BY_STATE = {
    "NOT_PROVEN": "not_proven",
    "CONTRADICTORY": "contradictory",
    "STALE": "stale",
    "PARTIALLY_SUPPORTED": "partially_supported",
    "VERIFIED_DEFICIENT": "verified_deficient",
    "VERIFIED_EFFECTIVE": "verified_effective",
}


@dataclass(frozen=True)
class ResultTruthGateResult:
    """Deterministic, immutable release decision."""

    version: str
    decision: str
    tenant_id: str
    engagement_id: str
    evidence_state_hash: str
    grounded_claims_fingerprint: str
    result_fingerprint: str
    failure_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_version": self.version,
            "decision": self.decision,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "evidence_state_hash": self.evidence_state_hash,
            "grounded_claims_fingerprint": self.grounded_claims_fingerprint,
            "result_fingerprint": self.result_fingerprint,
            "failure_reasons": list(self.failure_reasons),
        }


class ResultTruthGateError(ValueError):
    """Raised when canonical truth is not safe to release."""

    def __init__(self, reasons: tuple[str, ...]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def load_production_gate_attestations() -> dict[str, bool]:
    """Load explicit deployment gate attestations; invalid input fails closed."""
    raw = os.environ.get("FG_RESULT_TRUTH_GATE_PRODUCTION_GATES", "")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(item, bool)}


def evaluate_result_truth_gate(
    report: Mapping[str, Any], *, tenant_id: str, engagement_id: str
) -> ResultTruthGateResult:
    """Validate canonical FGA-025..028 outputs without recalculating them."""

    reasons: list[str] = []
    if not tenant_id or report.get("tenant_id") != tenant_id:
        reasons.append("TENANT_SCOPE_MISMATCH")
    report_engagement = report.get("engagement_id") or report.get("assessment_id")
    if not engagement_id or report_engagement != engagement_id:
        reasons.append("ENGAGEMENT_SCOPE_MISMATCH")

    population = report.get("evidence_population")
    if not isinstance(population, Mapping):
        reasons.append("MISSING_EVIDENCE_POPULATION")
        population = {}
    evidence_hash = population.get("fingerprint")
    if not isinstance(evidence_hash, str) or not evidence_hash:
        reasons.append("MISSING_EVIDENCE_FINGERPRINT")
        evidence_hash = ""
    if report.get("evidence_state_hash") != evidence_hash:
        reasons.append("EVIDENCE_FINGERPRINT_MISMATCH")
    for key in (
        "total_discovered",
        "eligible_count",
        "evaluated_count",
        "excluded_count",
    ):
        value = population.get(key)
        if not isinstance(value, int) or value < 0:
            reasons.append(f"INVALID_EVIDENCE_COUNT:{key}")
    if (
        isinstance(population.get("total_discovered"), int)
        and isinstance(population.get("eligible_count"), int)
        and population["eligible_count"] > population["total_discovered"]
    ):
        reasons.append("EVIDENCE_COUNTS_INCONSISTENT")
    if population.get("eligible_count") == 0:
        reasons.append("EMPTY_EVIDENCE_POPULATION")
    if (
        isinstance(population.get("evaluated_count"), int)
        and isinstance(population.get("eligible_count"), int)
        and population["evaluated_count"] != population["eligible_count"]
    ):
        reasons.append("EVIDENCE_POPULATION_NOT_COMPLETE")

    appendix = report.get("evidence_appendix", [])
    if not isinstance(appendix, list):
        reasons.append("INVALID_EVIDENCE_APPENDIX")
        appendix = []
    evidence_ids = [
        item.get("evidence_id") for item in appendix if isinstance(item, Mapping)
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        reasons.append("DUPLICATE_EVIDENCE_IDENTITY")
    evidence_set = {item for item in evidence_ids if isinstance(item, str) and item}
    if (
        isinstance(population.get("eligible_count"), int)
        and len(evidence_set) != population["eligible_count"]
    ):
        reasons.append("EVIDENCE_APPENDIX_INCOMPLETE")

    findings = report.get("findings", [])
    claims = report.get("material_claims", [])
    epistemic = report.get("epistemic_states", {})
    if (
        not isinstance(findings, list)
        or not isinstance(claims, list)
        or not isinstance(epistemic, Mapping)
    ):
        reasons.append("MISSING_CANONICAL_TRUTH_SECTION")
        findings = findings if isinstance(findings, list) else []
        claims = claims if isinstance(claims, list) else []
        epistemic = epistemic if isinstance(epistemic, Mapping) else {}

    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping) or not isinstance(
            finding.get("finding_id"), str
        ):
            reasons.append("MALFORMED_FINDING")
            continue
        finding_id = finding["finding_id"]
        if finding_id in finding_ids:
            reasons.append("DUPLICATE_FINDING_IDENTITY")
        finding_ids.add(finding_id)
        refs = finding.get("evidence_ids", [])
        if not isinstance(refs, list) or not set(refs).issubset(evidence_set):
            reasons.append("UNRESOLVED_FINDING_LINEAGE")

    claim_ids: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping):
            reasons.append("MALFORMED_MATERIAL_CLAIM")
            continue
        claim_id = claim.get("claim_id")
        finding_id = claim.get("finding_id")
        state = claim.get("epistemic_state")
        if not isinstance(claim_id, str) or not claim_id:
            reasons.append("MALFORMED_MATERIAL_CLAIM")
        elif claim_id in claim_ids:
            reasons.append("DUPLICATE_CLAIM_IDENTITY")
        else:
            claim_ids.add(claim_id)
        if (
            claim.get("tenant_id") != tenant_id
            or claim.get("engagement_id") != engagement_id
        ):
            reasons.append("CLAIM_SCOPE_MISMATCH")
        if finding_id not in finding_ids:
            reasons.append("UNRESOLVED_CLAIM_FINDING_LINEAGE")
        if state not in _EPISTEMIC_STATES:
            reasons.append("UNKNOWN_EPISTEMIC_STATE")
        elif claim.get("disposition") != _DISPOSITION_BY_STATE[state]:
            reasons.append("EPISTEMIC_DISPOSITION_MISMATCH")
        refs = claim.get("evidence_ids", [])
        if not isinstance(refs, list) or not set(refs).issubset(evidence_set):
            reasons.append("UNRESOLVED_CLAIM_EVIDENCE_LINEAGE")
        lineage = claim.get("lineage")
        if (
            not isinstance(lineage, list)
            or f"engagement:{engagement_id}" not in lineage
        ):
            reasons.append("INVALID_CLAIM_LINEAGE_SCOPE")
        if isinstance(state, str) and (
            not isinstance(epistemic.get(finding_id), Mapping)
            or epistemic[finding_id].get("state") != state
        ):
            reasons.append("EPISTEMIC_INPUT_MISMATCH")

    normalized_reasons = tuple(sorted(set(reasons)))
    if not isinstance(report.get("grounded_claims_fingerprint"), str) or not report.get(
        "grounded_claims_fingerprint"
    ):
        reasons.append("MISSING_GROUNDED_CLAIMS_FINGERPRINT")
    canonical = {
        "authority_version": RESULT_TRUTH_GATE_VERSION,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "evidence_state_hash": evidence_hash,
        "grounded_claims_fingerprint": report.get("grounded_claims_fingerprint", ""),
        "findings": sorted(
            findings,
            key=lambda item: str(
                item.get("finding_id", "") if isinstance(item, Mapping) else ""
            ),
        ),
        "material_claims": sorted(
            claims,
            key=lambda item: str(
                item.get("claim_id", "") if isinstance(item, Mapping) else ""
            ),
        ),
        "epistemic_states": dict(
            sorted(epistemic.items(), key=lambda item: str(item[0]))
        ),
    }
    result = ResultTruthGateResult(
        version=RESULT_TRUTH_GATE_VERSION,
        decision="FAIL" if normalized_reasons else "PASS",
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_state_hash=evidence_hash,
        grounded_claims_fingerprint=str(report.get("grounded_claims_fingerprint", "")),
        result_fingerprint=_fingerprint(canonical),
        failure_reasons=normalized_reasons,
    )
    if normalized_reasons:
        raise ResultTruthGateError(normalized_reasons)
    return result
