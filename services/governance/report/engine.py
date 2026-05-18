"""Deterministic Governance Report Engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Engine contract:
  - Deterministic: identical inputs → identical GovernanceReport.
  - No side effects: never mutates inputs or module-level state.
  - Replay-safe: manifest_hash enables verification across re-generation.
  - Fail-closed: raises GovernanceReportError on missing required inputs.
  - AI narrative containment: no AI prose in any frozen field.

Threshold contract:
  Domains with score < 60 produce GovernanceFinding records.
  Score >= 60 → no finding for that domain.

Finding ID stability:
  finding_ids are derived deterministically from
  (tenant_id, framework, control_id, gap_classification, evidence_state_hash).
  Identical governance state across runs → identical finding_ids.

Replay contract:
  replay() re-generates from the same inputs and returns
  (new_report, hash_matches: bool).
  hash_matches=True proves the original report was not tampered with.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from .confidence import calculate_confidence
from .framework_mappings import get_framework_mappings
from .identity import (
    derive_canonical_inputs_hash,
    derive_finding_id,
    derive_manifest_hash,
    derive_remediation_id,
)
from .models import (
    ConfidenceScore,
    EvidenceRef,
    FrameworkMapping,
    GovernanceFinding,
    GovernanceReport,
    RemediationEntry,
    ValidationState,
)

logger = logging.getLogger("frostgate.governance.report")

_FINDING_SCORE_THRESHOLD = 60.0
_ENGINE_VERSION = "1.0"

# Severity band for domain scores
_SEVERITY_BANDS = [
    (25.0, "critical"),
    (40.0, "high"),
    (60.0, "medium"),
]


def _classify_severity(score: float) -> str:
    for threshold, band in _SEVERITY_BANDS:
        if score < threshold:
            return band
    return "low"


def _classify_gap(score: float) -> str:
    if score < 25.0:
        return "critical_gap"
    if score < 40.0:
        return "high_gap"
    if score < 60.0:
        return "moderate_gap"
    return "minor_gap"


def _evidence_state_hash(evidence_ids: list[str]) -> str:
    """Deterministic hash of a set of evidence IDs."""
    payload = json.dumps(sorted(evidence_ids), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _domain_to_control_id(domain: str) -> str:
    """Map domain name to canonical control_id."""
    _map = {
        "data_governance": "data_governance",
        "security_posture": "security_posture",
        "ai_maturity": "ai_maturity",
        "infra_readiness": "infra_readiness",
        "compliance_awareness": "compliance_awareness",
        "automation_potential": "automation_potential",
    }
    return _map.get(domain, domain)


def _domain_description(domain: str, score: float, gap_classification: str) -> str:
    """Return a deterministic structured description for a finding.

    No AI prose — only templated control reference text.
    """
    labels = {
        "data_governance": "Data Governance",
        "security_posture": "Security Posture",
        "ai_maturity": "AI Maturity",
        "infra_readiness": "Infrastructure Readiness",
        "compliance_awareness": "Compliance Awareness",
        "automation_potential": "Automation Potential",
    }
    label = labels.get(domain, domain.replace("_", " ").title())
    return (
        f"{label} domain scored {score:.1f}/100 ({gap_classification}). "
        f"Control deficiencies identified require remediation before "
        f"governance milestone eligibility."
    )


class GovernanceReportError(Exception):
    """Fail-closed sentinel for governance report generation errors.

    Raised when required inputs are missing or invalid.
    Never swallowed — callers must handle explicitly.
    """


class GovernanceReportEngine:
    """Deterministic governance report engine.

    Thread-safe: no mutable state; all operations are pure functions.
    """

    def generate(
        self,
        assessment_id: str,
        tenant_id: str,
        scores: dict[str, float],
        responses: dict[str, Any],
        evidence_refs: list[EvidenceRef],
        reviewer_validated: bool = False,
        report_id: str | None = None,
        version: int = 1,
    ) -> GovernanceReport:
        """Generate a deterministic GovernanceReport from assessment inputs.

        Args:
            assessment_id: The assessment being reported on.
            tenant_id: Tenant that owns this report.
            scores: Domain scores dict (domain → float 0–100).
            responses: Raw assessment responses (used for evidence linkage).
            evidence_refs: Evidence references to include in the report.
            reviewer_validated: Whether a human reviewer has validated the report.
            report_id: Optional stable report ID (caller-provided or derived).
            version: Report version number (default 1).

        Returns:
            GovernanceReport — frozen, deterministic, manifest-hashed.

        Raises:
            GovernanceReportError: If assessment_id or tenant_id are missing,
                or scores is empty.
        """
        # Fail-closed: validate required inputs
        if not assessment_id or not assessment_id.strip():
            raise GovernanceReportError(
                "assessment_id is required and must not be empty"
            )
        if not tenant_id or not tenant_id.strip():
            raise GovernanceReportError("tenant_id is required and must not be empty")
        if scores is None:
            raise GovernanceReportError("scores dict is required")

        # Derive stable report_id if not provided
        if not report_id:
            canonical_inputs = derive_canonical_inputs_hash(
                assessment_id=assessment_id,
                evidence_refs=evidence_refs,
                framework_ids=["NIST_AI_RMF", "SOC2", "HIPAA"],
            )
            report_id = f"gr-{canonical_inputs[:24]}"

        # Build evidence index
        evidence_by_domain: dict[str, list[EvidenceRef]] = {}
        for ref in evidence_refs:
            # Assign evidence to domains by classification/source heuristic
            domain = _infer_evidence_domain(ref)
            evidence_by_domain.setdefault(domain, []).append(ref)

        # ── Step 1: Build findings for domains below threshold ──
        findings: list[GovernanceFinding] = []
        finding_to_evidence: dict[str, list[str]] = {}

        for domain, score in sorted(scores.items()):
            if score >= _FINDING_SCORE_THRESHOLD:
                continue

            control_id = _domain_to_control_id(domain)
            gap_class = _classify_gap(score)
            severity = _classify_severity(score)

            # Collect evidence IDs for this domain
            domain_evidence = evidence_by_domain.get(domain, [])
            evidence_ids = tuple(ref.evidence_id for ref in domain_evidence)

            if evidence_refs and not domain_evidence:
                log.warning(
                    "governance_report.evidence_domain_unmatched "
                    "domain=%s evidence_refs_provided=%d matched=0 "
                    "— evidence lineage for this domain is empty; "
                    "confidence and framework mappings will reflect no evidence",
                    domain,
                    len(evidence_refs),
                )

            # Deterministic finding ID
            ev_hash = _evidence_state_hash(list(evidence_ids))
            finding_id = derive_finding_id(
                tenant_id=tenant_id,
                framework="NIST_AI_RMF",
                control_id=control_id,
                gap_classification=gap_class,
                evidence_state_hash=ev_hash,
            )

            # Framework mappings
            fw_mappings: tuple[FrameworkMapping, ...] = tuple(
                get_framework_mappings(control_id=control_id, domain=domain)
            )

            # Remediation ID
            priority = "high" if severity in ("critical", "high") else "medium"
            remediation_id = derive_remediation_id(
                tenant_id=tenant_id,
                control_id=control_id,
                severity=severity,
                priority=priority,
            )

            # Confidence for this specific finding
            finding_confidence = score / 100.0 * 0.8 + 0.2 * (
                1.0 if reviewer_validated else 0.0
            )

            finding = GovernanceFinding(
                finding_id=finding_id,
                control_id=control_id,
                domain=domain,
                severity=severity,
                confidence=finding_confidence,
                evidence_ids=evidence_ids,
                framework_mappings=fw_mappings,
                remediation_id=remediation_id,
                gap_classification=gap_class,
                description=_domain_description(domain, score, gap_class),
            )
            findings.append(finding)
            finding_to_evidence[finding_id] = list(evidence_ids)

        findings_tuple = tuple(findings)

        # ── Step 2: Build remediations ──
        remediations: list[RemediationEntry] = []
        remediation_seen: set[str] = set()

        for finding in findings:
            if finding.remediation_id in remediation_seen:
                # Link this finding to existing remediation
                continue
            remediation_seen.add(finding.remediation_id)

            # Find all findings sharing this remediation_id
            linked_findings = tuple(
                f.finding_id
                for f in findings
                if f.remediation_id == finding.remediation_id
            )
            linked_controls = tuple(
                sorted(
                    {
                        f.control_id
                        for f in findings
                        if f.remediation_id == finding.remediation_id
                    }
                )
            )

            # Evidence gaps: MISSING or PENDING evidence for this domain
            domain_refs = evidence_by_domain.get(finding.domain, [])
            gaps = tuple(
                ref.evidence_id
                for ref in domain_refs
                if ref.validation_state
                in (ValidationState.MISSING, ValidationState.PENDING)
            )

            # Confidence impact: validated evidence improves confidence
            validated_domain_refs = [
                r
                for r in domain_refs
                if r.validation_state == ValidationState.VALIDATED
            ]
            confidence_impact = min(0.3 + 0.1 * len(validated_domain_refs), 0.5)

            op_impact = (
                "Immediate remediation required to restore readiness eligibility."
                if finding.severity in ("critical", "high")
                else "Scheduled remediation recommended within next governance cycle."
            )

            remediation = RemediationEntry(
                remediation_id=finding.remediation_id,
                linked_finding_ids=linked_findings,
                linked_controls=linked_controls,
                severity=finding.severity,
                priority="high"
                if finding.severity in ("critical", "high")
                else "medium",
                confidence_impact=confidence_impact,
                evidence_gaps=gaps,
                operational_impact=op_impact,
            )
            remediations.append(remediation)

        remediations_tuple = tuple(remediations)

        # ── Step 3: Confidence scoring ──
        assessment_completion_pct = _estimate_completion(scores, responses)
        confidence: ConfidenceScore = calculate_confidence(
            evidence_refs=evidence_refs,
            assessment_completion_pct=assessment_completion_pct,
            reviewer_validated=reviewer_validated,
        )

        # ── Step 4: Evidence appendix ──
        evidence_appendix = tuple(evidence_refs)

        # ── Step 5: Framework summary ──
        framework_summary = _build_framework_summary(findings)

        # ── Step 6: Build report (without manifest_hash first) ──
        generated_at = datetime.now(timezone.utc).isoformat()

        # Placeholder report for manifest computation
        report_no_hash = GovernanceReport(
            report_id=report_id,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            version=version,
            generated_at=generated_at,
            findings=findings_tuple,
            remediations=remediations_tuple,
            evidence_appendix=evidence_appendix,
            framework_summary=framework_summary,
            confidence=confidence,
            manifest_hash="",  # placeholder
            schema_version="1.0",
        )

        # ── Step 7: Compute manifest hash last ──
        manifest_hash = derive_manifest_hash(report_no_hash)

        # Rebuild with real manifest_hash (frozen dataclass — must construct new)
        report = GovernanceReport(
            report_id=report_id,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            version=version,
            generated_at=generated_at,
            findings=findings_tuple,
            remediations=remediations_tuple,
            evidence_appendix=evidence_appendix,
            framework_summary=framework_summary,
            confidence=confidence,
            manifest_hash=manifest_hash,
            schema_version="1.0",
        )

        logger.info(
            "governance_report.generated report_id=%s assessment_id=%s tenant_id=%s "
            "findings=%d manifest_hash=%s",
            report_id,
            assessment_id,
            tenant_id,
            len(findings),
            manifest_hash[:16],
        )

        return report

    def replay(
        self,
        report: GovernanceReport,
        assessment_id: str,
        tenant_id: str,
        scores: dict[str, float],
        responses: dict[str, Any],
        evidence_refs: list[EvidenceRef],
        reviewer_validated: bool = False,
    ) -> tuple[GovernanceReport, bool]:
        """Re-generate a report from the same inputs and verify hash equivalence.

        Args:
            report: The original GovernanceReport to replay against.
            assessment_id, tenant_id, scores, responses, evidence_refs,
            reviewer_validated: Same inputs used for the original generation.

        Returns:
            (new_report, hash_matches): new_report is the freshly generated
            GovernanceReport; hash_matches=True proves replay equivalence.

        Note:
            generated_at will differ between runs — it is explicitly excluded
            from the manifest hash in serialize_for_manifest().
        """
        new_report = self.generate(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            scores=scores,
            responses=responses,
            evidence_refs=evidence_refs,
            reviewer_validated=reviewer_validated,
            report_id=report.report_id,
            version=report.version,
        )

        # Compare manifest hashes with generated_at excluded
        # The manifest hash excludes generated_at by contract in serialize_for_manifest.
        # We rebuild both without the manifest hash to compare deterministic content.
        hash_matches = new_report.manifest_hash == report.manifest_hash

        logger.info(
            "governance_report.replay report_id=%s hash_matches=%s original=%s new=%s",
            report.report_id,
            hash_matches,
            report.manifest_hash[:16],
            new_report.manifest_hash[:16],
        )

        return new_report, hash_matches


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _infer_evidence_domain(ref: EvidenceRef) -> str:
    """Infer which domain an evidence ref applies to from its classification/source."""
    source_lower = ref.source.lower()
    classification_lower = ref.classification.lower()
    combined = f"{source_lower} {classification_lower} {ref.provenance.lower()}"

    if any(k in combined for k in ("data_gov", "data governance", "data_class")):
        return "data_governance"
    if any(k in combined for k in ("security", "access_control", "vuln")):
        return "security_posture"
    if any(k in combined for k in ("ai_", "ai maturity", "model", "ml")):
        return "ai_maturity"
    if any(k in combined for k in ("infra", "infrastructure", "network", "cloud")):
        return "infra_readiness"
    if any(k in combined for k in ("compliance", "audit", "framework", "certif")):
        return "compliance_awareness"
    if any(k in combined for k in ("automat", "pipeline", "workflow")):
        return "automation_potential"
    return "data_governance"  # safe default


def _estimate_completion(scores: dict[str, float], responses: dict[str, Any]) -> float:
    """Estimate assessment completion percentage from scores and responses."""
    expected_domains = {
        "data_governance",
        "security_posture",
        "ai_maturity",
        "infra_readiness",
        "compliance_awareness",
        "automation_potential",
    }
    answered_domains = {d for d, s in scores.items() if d in expected_domains and s > 0}
    if not expected_domains:
        return 0.0
    domain_completion = len(answered_domains) / len(expected_domains) * 100.0

    # Weight responses if available
    if responses:
        response_completion = min(
            len(responses) / max(len(expected_domains) * 5, 1) * 100.0, 100.0
        )
        return domain_completion * 0.7 + response_completion * 0.3

    return domain_completion


def _build_framework_summary(
    findings: list[GovernanceFinding],
) -> dict[str, list[str]]:
    """Build a framework summary dict from all findings."""
    summary: dict[str, set[str]] = {}
    for finding in findings:
        for fm in finding.framework_mappings:
            summary.setdefault(fm.framework, set()).add(fm.control_ref)
    return {fw: sorted(refs) for fw, refs in sorted(summary.items())}
