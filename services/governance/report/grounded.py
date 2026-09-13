"""Grounded material-claim authority for customer-facing governance reports.

This module is a pure projection from the frozen report and FGA-026 epistemic
determinations.  It is deliberately independent of presentation and AI
narrative generation: a claim cannot be emitted without resolvable lineage.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .epistemic import EpistemicDetermination, EpistemicState
from .models import GovernanceReport

GROUNDED_CLAIM_VERSION = "1.0"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class GroundedClaimError(ValueError):
    """Raised when a material claim cannot be resolved to canonical truth."""


@dataclass(frozen=True)
class MaterialClaim:
    """Immutable, deterministic customer-facing governance claim."""

    claim_id: str
    claim_type: str
    statement: str
    disposition: str
    severity: str
    epistemic_state: EpistemicState
    finding_id: str | None
    control_id: str | None
    domain: str | None
    evidence_ids: tuple[str, ...]
    methodology_version: str
    tenant_id: str
    engagement_id: str
    lineage: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "statement": self.statement,
            "disposition": self.disposition,
            "severity": self.severity,
            "epistemic_state": self.epistemic_state.value,
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "domain": self.domain,
            "evidence_ids": list(self.evidence_ids),
            "methodology_version": self.methodology_version,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "lineage": list(self.lineage),
        }


def _claim_disposition(state: EpistemicState) -> str:
    return {
        EpistemicState.VERIFIED_DEFICIENT: "verified_deficient",
        EpistemicState.VERIFIED_EFFECTIVE: "verified_effective",
        EpistemicState.CONTRADICTORY: "contradictory",
        EpistemicState.STALE: "stale",
        EpistemicState.PARTIALLY_SUPPORTED: "partially_supported",
        EpistemicState.NOT_PROVEN: "not_proven",
    }[state]


def _claim_statement(domain: str, state: EpistemicState, severity: str) -> str:
    label = domain.replace("_", " ").title()
    if state == EpistemicState.VERIFIED_DEFICIENT:
        return f"{label} has a verified {severity} governance deficiency."
    if state == EpistemicState.VERIFIED_EFFECTIVE:
        return f"{label} is verified effective within the established evidence scope."
    if state == EpistemicState.CONTRADICTORY:
        return f"{label} has contradictory evidence; no definitive conclusion is established."
    if state == EpistemicState.STALE:
        return (
            f"{label} lacks current verification because supporting evidence is stale."
        )
    if state == EpistemicState.PARTIALLY_SUPPORTED:
        return f"{label} is only partially supported by the available evidence."
    return f"{label} is not proven by the available evidence."


def build_material_claims(
    report: GovernanceReport,
    determinations: Mapping[str, EpistemicDetermination],
    *,
    methodology_version: str = GROUNDED_CLAIM_VERSION,
) -> tuple[MaterialClaim, ...]:
    """Project every report finding into a grounded material claim.

    Finding and evidence references must resolve inside this report's tenant
    and assessment scope. Unknown/missing determinations or duplicate finding
    identities fail closed; no unsupported claim is emitted as verified.
    """
    evidence_ids = {ref.evidence_id for ref in report.evidence_appendix}
    if len(evidence_ids) != len(report.evidence_appendix):
        raise GroundedClaimError("duplicate evidence identity in report appendix")

    seen: set[str] = set()
    claims: list[MaterialClaim] = []
    for finding in report.findings:
        if finding.finding_id in seen:
            raise GroundedClaimError("duplicate finding identity in report")
        seen.add(finding.finding_id)
        determination = determinations.get(finding.finding_id)
        if determination is None:
            raise GroundedClaimError("missing epistemic determination for finding")
        refs = tuple(sorted(set(determination.evidence_ids)))
        if not set(refs).issubset(evidence_ids):
            raise GroundedClaimError("claim evidence lineage does not resolve")
        for ref in report.evidence_appendix:
            if (
                ref.evidence_id in refs
                and ref.provenance != f"engagement:{report.assessment_id}"
            ):
                raise GroundedClaimError("evidence lineage scope mismatch")
        # The determination must describe exactly the finding's evidence slice.
        finding_refs = tuple(sorted(set(finding.evidence_ids)))
        if refs != finding_refs:
            raise GroundedClaimError("finding and epistemic evidence lineage mismatch")
        state = determination.state
        severity = str(finding.severity).lower()
        payload = {
            "version": methodology_version,
            "tenant_id": report.tenant_id,
            "engagement_id": report.assessment_id,
            "finding_id": finding.finding_id,
            "control_id": finding.control_id,
            "domain": finding.domain,
            "severity": severity,
            "epistemic_state": state.value,
            "evidence_ids": refs,
        }
        claim_id = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        claims.append(
            MaterialClaim(
                claim_id=claim_id,
                claim_type="finding",
                statement=_claim_statement(finding.domain, state, severity),
                disposition=_claim_disposition(state),
                severity=severity,
                epistemic_state=state,
                finding_id=finding.finding_id,
                control_id=finding.control_id,
                domain=finding.domain,
                evidence_ids=refs,
                methodology_version=determination.methodology_version,
                tenant_id=report.tenant_id,
                engagement_id=report.assessment_id,
                lineage=(
                    f"engagement:{report.assessment_id}",
                    f"finding:{finding.finding_id}",
                    f"control:{finding.control_id}",
                    *(f"evidence:{eid}" for eid in refs),
                    f"epistemic:{state.value}",
                ),
            )
        )
    return tuple(
        sorted(
            claims,
            key=lambda claim: (
                _SEVERITY_ORDER.get(claim.severity, 99),
                claim.domain or "",
                claim.claim_id,
            ),
        )
    )


def claims_fingerprint(claims: Sequence[MaterialClaim]) -> str:
    """Return a versioned, canonical fingerprint of the grounded claim set."""
    payload = {
        "version": GROUNDED_CLAIM_VERSION,
        "claims": [
            claim.to_dict()
            for claim in sorted(claims, key=lambda claim: claim.claim_id)
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def enforce_grounded_summary(
    summary: Mapping[str, object], claims: Sequence[MaterialClaim]
) -> dict[str, object]:
    """Keep advisory narrative subordinate to deterministic grounded claims."""
    out = dict(summary)
    adverse = [
        claim
        for claim in claims
        if claim.disposition
        in {
            "verified_deficient",
            "contradictory",
            "stale",
            "not_proven",
            "partially_supported",
        }
    ]
    if adverse:
        most_adverse = min(
            adverse,
            key=lambda claim: (_SEVERITY_ORDER.get(claim.severity, 99), claim.claim_id),
        )
        out["risk_posture"] = (
            most_adverse.severity
            if most_adverse.severity in _SEVERITY_ORDER
            else "high"
        )
        raw_concerns = out.get("key_concerns")
        concerns = (
            [str(item) for item in raw_concerns if isinstance(item, str)]
            if isinstance(raw_concerns, list)
            else []
        )
        for claim in adverse:
            if claim.statement not in concerns:
                concerns.append(claim.statement)
        out["key_concerns"] = concerns[: max(3, len(adverse))]
        narrative = str(out.get("narrative") or "").strip()
        canonical = " ".join(claim.statement for claim in adverse)
        out["narrative"] = (
            f"{narrative}\n\nCanonical grounded determinations: {canonical}".strip()
        )
    else:
        out["risk_posture"] = "low"
    out["grounded_claims_fingerprint"] = claims_fingerprint(claims)
    out["generation_note"] = (
        "AI narrative is advisory only; canonical grounded claims are authoritative."
    )
    return out
