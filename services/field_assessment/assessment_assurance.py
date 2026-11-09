"""Assessment assurance authority — L14-ASSESSMENT-ASSURANCE-001.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform, and extends existing canonical
authorities instead of adding a parallel governance system:

* **Provenance** (CZ-23): one evaluator over the canonical runtime evidence
  (``fa_scan_evidence_envelopes`` + ``fa_scan_results`` + normalized findings),
  AND-combined with the older ``evidence_provenance`` chain where that chain
  genuinely exists (manual ingest routes).  Every trust consumer reaches it
  through ``trust_enforcement_adapter.derive_engagement_trust_inputs``.
* **Independent QA** (CZ-12B): a QA decision needs a named human reviewer who
  made no material contribution to the engagement assessment.  Material
  contribution is read from the append-only engagement audit trail, never from
  caller-supplied display fields (``compiled_by``).
* **Draft access** (CZ-17): one policy function decides who may read report
  content that is not FINAL.

Separate security assertions stay separate: payload integrity
(VERIFIED_INTEGRITY_ONLY) is never reported as source authenticity
(VERIFIED_AUTHENTIC), and neither says anything about customer authorization
or finding accuracy.

Everything here is read-only and deterministic for a persisted snapshot; no
network calls are made.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.evidence_integrity import ProvenanceStatus

# Bounded reads: an engagement larger than this is refused (INDETERMINATE)
# rather than silently evaluated on a truncated sample.
MAX_EVIDENCE_RECORDS = 20_000
_IN_CHUNK = 500

# ---------------------------------------------------------------------------
# Release blocker codes (mode-independent)
# ---------------------------------------------------------------------------

BLOCKER_INTEGRITY_FAILED = "PROVENANCE_INTEGRITY_FAILED"
BLOCKER_SCOPE_VIOLATION = "PROVENANCE_SCOPE_VIOLATION"
BLOCKER_UNVERIFIABLE = "PROVENANCE_EVIDENCE_UNVERIFIABLE"
BLOCKER_ABSENT = "PROVENANCE_EVIDENCE_ABSENT"
BLOCKER_LEGACY_CHAIN = "PROVENANCE_LEGACY_CHAIN_INVALID"
BLOCKER_TOO_LARGE = "PROVENANCE_EVALUATION_BOUND_EXCEEDED"
BLOCKER_QA_MISSING = "QA_INDEPENDENT_APPROVAL_MISSING"
BLOCKER_QA_REJECTED = "QA_REJECTED"

# Blockers that refuse a QA approval in every FG_PROVENANCE_MODE.  Absent
# evidence is not here: it cannot reach FINAL (see release_blockers) but a
# reviewer may still approve the narrative of an evidence-free report.
APPROVAL_HARD_BLOCKERS = frozenset(
    {
        BLOCKER_INTEGRITY_FAILED,
        BLOCKER_SCOPE_VIOLATION,
        BLOCKER_LEGACY_CHAIN,
        BLOCKER_TOO_LARGE,
    }
)

_VERIFIED = frozenset(
    {ProvenanceStatus.VERIFIED_AUTHENTIC, ProvenanceStatus.VERIFIED_INTEGRITY_ONLY}
)


class AssuranceDenied(Exception):
    """A controlled assurance refusal; carries an API reason code."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Workstream A — canonical provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceDecision:
    """Structured, reproducible provenance decision for one engagement."""

    tenant_id: str
    engagement_id: str
    evidence_count: int
    classification_counts: Mapping[str, int]
    integrity_failure_count: int
    unverifiable_count: int
    scope_violation_count: int
    findings_total: int
    findings_without_evidence: int
    legacy_record_count: int
    legacy_chain_valid: bool | None
    bound_exceeded: bool
    snapshot_fingerprint: str
    verified_at: str
    _legacy_inputs: Any = field(default=None, repr=False, compare=False)

    @property
    def source_authenticated(self) -> bool:
        """True only when every runtime evidence item is VERIFIED_AUTHENTIC."""
        return (
            self.evidence_count > 0
            and self.classification_counts.get(
                ProvenanceStatus.VERIFIED_AUTHENTIC.value, 0
            )
            == self.evidence_count
        )

    @property
    def evidence_absent(self) -> bool:
        return self.evidence_count == 0 and self.legacy_record_count == 0

    def release_blockers(self) -> list[str]:
        out: set[str] = set()
        if self.bound_exceeded:
            out.add(BLOCKER_TOO_LARGE)
        if self.integrity_failure_count:
            out.add(BLOCKER_INTEGRITY_FAILED)
        if self.scope_violation_count:
            out.add(BLOCKER_SCOPE_VIOLATION)
        if self.unverifiable_count:
            out.add(BLOCKER_UNVERIFIABLE)
        if self.legacy_chain_valid is False:
            out.add(BLOCKER_LEGACY_CHAIN)
        return sorted(out)

    def disclosure_codes(self) -> list[str]:
        """Conditions disclosed but not blocking in warn mode.

        Absent evidence is not a release blocker on its own (questionnaire
        assessments carry no scanner evidence; per-finding rules such as
        CONFIRMED_WITHOUT_VERIFIED_EVIDENCE still apply), but STRICT mode
        refuses it through ``to_trust_inputs`` (all dimensions False).
        """
        out = [BLOCKER_ABSENT] if self.evidence_absent else []
        if self.evidence_count and not self.source_authenticated:
            out.append("SOURCE_AUTHENTICITY_NOT_ESTABLISHED")
        if self.findings_without_evidence:
            out.append("FINDINGS_WITHOUT_EVIDENCE")
        return out

    def approval_blockers(self) -> list[str]:
        return [b for b in self.release_blockers() if b in APPROVAL_HARD_BLOCKERS]

    @property
    def decision(self) -> str:
        blockers = self.release_blockers()
        if not blockers:
            return "LIMITED" if self.evidence_absent else "VERIFIED"
        return "BLOCKED" if set(blockers) & APPROVAL_HARD_BLOCKERS else "LIMITED"

    def to_trust_inputs(self) -> Any:
        """Project onto the trust-enforcement engine's dimensions.

        ``signature_valid`` here means "the evidence authority's verification
        passed" (canonical digest re-verification for runtime evidence, record
        signature for the legacy chain).  Source authenticity is reported only
        by ``source_authenticated`` / ``classification_counts`` and is never
        upgraded by this projection.
        """
        from services.field_assessment.trust_enforcement import TrustInputs  # noqa: PLC0415
        from services.field_assessment.trust_enforcement_adapter import (  # noqa: PLC0415
            _and_trust_inputs,
        )

        if self.evidence_absent or self.bound_exceeded:
            return TrustInputs(
                chain_valid=False,
                signature_valid=False,
                link_valid=False,
                replay_valid=False,
                tenant_valid=True,
                engagement_valid=True,
            )
        runtime = None
        if self.evidence_count:
            # Scope violations fold into chain_valid as well: several consumers
            # pass only chain/link/replay dimensions to the engine.
            runtime = TrustInputs(
                chain_valid=self.integrity_failure_count == 0
                and self.scope_violation_count == 0,
                signature_valid=self.integrity_failure_count == 0,
                link_valid=True,
                replay_valid=self.unverifiable_count == 0,
                tenant_valid=True,
                engagement_valid=self.scope_violation_count == 0,
                is_legacy=False,
            )
        legacy = self._legacy_inputs
        if runtime is None:
            return legacy
        if legacy is None:
            return runtime
        return _and_trust_inputs(runtime, legacy)

    def summary(self) -> dict[str, Any]:
        """Audit-safe summary: counts and codes only, no evidence payloads."""
        return {
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "decision": self.decision,
            "reason_codes": self.release_blockers(),
            "disclosures": self.disclosure_codes(),
            "evidence_count": self.evidence_count,
            "classification_counts": dict(sorted(self.classification_counts.items())),
            "integrity_failure_count": self.integrity_failure_count,
            "unverifiable_count": self.unverifiable_count,
            "scope_violation_count": self.scope_violation_count,
            "findings_total": self.findings_total,
            "findings_without_evidence": self.findings_without_evidence,
            "legacy_record_count": self.legacy_record_count,
            "legacy_chain_valid": self.legacy_chain_valid,
            "source_authenticated": self.source_authenticated,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "verified_at": self.verified_at,
        }


def _chunks(values: list[str]) -> Iterable[list[str]]:
    for i in range(0, len(values), _IN_CHUNK):
        yield values[i : i + _IN_CHUNK]


def _legacy_chain(
    db: Session, *, tenant_id: str, engagement_id: str
) -> tuple[int, Any]:
    """Replay the older evidence_provenance chain only where it exists."""
    from api.db_models_field_assessment import FaEvidenceProvenance  # noqa: PLC0415
    from services.field_assessment.trust_enforcement_adapter import (  # noqa: PLC0415
        legacy_provenance_trust_inputs,
    )

    count = int(
        db.execute(
            select(func.count(FaEvidenceProvenance.id)).where(
                FaEvidenceProvenance.tenant_id == tenant_id,
                FaEvidenceProvenance.engagement_id == engagement_id,
            )
        ).scalar_one()
        or 0
    )
    if not count:
        return 0, None
    return count, legacy_provenance_trust_inputs(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )


def evaluate_engagement_provenance(
    db: Session, *, tenant_id: str, engagement_id: str
) -> ProvenanceDecision:
    """Canonical, read-only provenance decision for an engagement snapshot.

    Bounded, batched reads (no per-evidence queries).  Sticky INVALID markings
    persisted by earlier verifications are honoured; nothing is written.
    """
    from api.db_models_field_assessment import (  # noqa: PLC0415
        FaEvidenceCustodyEvent,
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
        FaScanResult,
    )
    from services.field_assessment.custody import CustodyEventType  # noqa: PLC0415
    from services.field_assessment.evidence_integrity import (  # noqa: PLC0415
        evidence_integrity_svc,
    )
    from services.field_assessment.runtime_evidence import (  # noqa: PLC0415
        _as_envelope,
        resolve_observation,
    )

    verified_at = utc_iso8601_z_now()
    envs = list(
        db.execute(
            select(FaScanEvidenceEnvelope)
            .where(
                FaScanEvidenceEnvelope.tenant_id == tenant_id,
                FaScanEvidenceEnvelope.engagement_id == engagement_id,
            )
            .order_by(FaScanEvidenceEnvelope.id)
            .limit(MAX_EVIDENCE_RECORDS + 1)
        ).scalars()
    )
    bound_exceeded = len(envs) > MAX_EVIDENCE_RECORDS
    envs = envs[:MAX_EVIDENCE_RECORDS]

    sr_ids = sorted({str(e.scan_result_id) for e in envs if e.scan_result_id})
    scan_rows: dict[str, Any] = {}
    for chunk in _chunks(sr_ids):
        for row in db.execute(
            select(FaScanResult).where(
                FaScanResult.tenant_id == tenant_id, FaScanResult.id.in_(chunk)
            )
        ).scalars():
            scan_rows[str(row.id)] = row

    counts: dict[str, int] = {}
    integrity_failures = unverifiable = scope_violations = 0
    snapshot: list[tuple[str, str, str]] = []
    for env in envs:
        scope_ok = True
        if env.provenance_status == ProvenanceStatus.INVALID.value:
            status = ProvenanceStatus.INVALID
        elif env.scan_result_id is None:
            status = ProvenanceStatus.INDETERMINATE
        else:
            sr = scan_rows.get(str(env.scan_result_id))
            if sr is None:
                status = ProvenanceStatus.MISSING
            elif str(sr.engagement_id) != engagement_id:
                status, scope_ok = ProvenanceStatus.INVALID, False
            else:
                sub = resolve_observation(sr.raw_payload, env.observation_path)
                status = (
                    ProvenanceStatus.INVALID
                    if sub is None
                    else evidence_integrity_svc.verify_envelope(_as_envelope(env), sub)
                )
        counts[status.value] = counts.get(status.value, 0) + 1
        if not scope_ok:
            scope_violations += 1
        elif status == ProvenanceStatus.INVALID:
            integrity_failures += 1
        elif status not in _VERIFIED:
            unverifiable += 1
        snapshot.append((str(env.id), status.value, str(env.payload_digest or "")))

    env_ids = {str(e.id) for e in envs}
    findings = list(
        db.execute(
            select(FaNormalizedFinding.id, FaNormalizedFinding.evidence_envelope_id)
            .where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
            )
            .limit(MAX_EVIDENCE_RECORDS + 1)
        ).all()
    )
    bound_exceeded = bound_exceeded or len(findings) > MAX_EVIDENCE_RECORDS
    supported: set[str] = set()
    if envs:
        for ev_id, reason in db.execute(
            select(FaEvidenceCustodyEvent.evidence_id, FaEvidenceCustodyEvent.reason)
            .where(
                FaEvidenceCustodyEvent.tenant_id == tenant_id,
                FaEvidenceCustodyEvent.engagement_id == engagement_id,
                FaEvidenceCustodyEvent.event_type == CustodyEventType.NORMALIZED.value,
            )
            .limit(MAX_EVIDENCE_RECORDS * 4)
        ).all():
            if str(ev_id) in env_ids and (reason or "").startswith("finding:"):
                supported.add((reason or "")[len("finding:") :])
    without_evidence = 0
    for fid, env_ref in findings:
        if env_ref and str(env_ref) not in env_ids:
            # A finding citing evidence outside this tenant+engagement (or a
            # deleted record) is a reference-integrity failure.  Cross-tenant
            # and absent look identical by design (no existence oracle).
            scope_violations += 1
        elif not env_ref and str(fid) not in supported:
            without_evidence += 1

    legacy_count, legacy_inputs = _legacy_chain(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )
    legacy_valid: bool | None = None
    if legacy_inputs is not None:
        legacy_valid = bool(
            legacy_inputs.chain_valid
            and legacy_inputs.replay_valid
            and legacy_inputs.link_valid
            and legacy_inputs.signature_valid is not False
        )

    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "evidence": sorted(snapshot),
                "findings": len(findings),
                "legacy_records": legacy_count,
                "legacy_chain_valid": legacy_valid,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    return ProvenanceDecision(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_count=len(envs),
        classification_counts=counts,
        integrity_failure_count=integrity_failures,
        unverifiable_count=unverifiable,
        scope_violation_count=scope_violations,
        findings_total=len(findings),
        findings_without_evidence=without_evidence,
        legacy_record_count=legacy_count,
        legacy_chain_valid=legacy_valid,
        bound_exceeded=bound_exceeded,
        snapshot_fingerprint=fingerprint,
        verified_at=verified_at,
        _legacy_inputs=legacy_inputs,
    )


# ---------------------------------------------------------------------------
# Workstream B — independent QA
# ---------------------------------------------------------------------------

# Engagement audit events that make an actor a material contributor to the
# assessment.  A contributor cannot be the independent reviewer of any report
# for that engagement.
MATERIAL_CONTRIBUTION_EVENTS: frozenset[str] = frozenset(
    {
        "engagement_report_created",
        "report_version_created",
        "finding_status_updated",
        "finding.remediation_hint_updated",
        "observation.captured",
        "observation.updated",
        "observation.deleted",
        "observation.bulk_imported",
        "scan.initiated",
        "scan_result.ingested",
        "field_assessment.scan.ingested",
        "field_assessment.evidence.linked",
        "evidence_link.created",
        "artifact.uploaded",
        "artifact.registered",
        "questionnaire.submitted",
        "document_analysis.registered",
    }
)

_HUMAN_AUTH_SOURCES_PREFIX = "oidc_"


def require_human_reviewer(actor_ctx: Any) -> str:
    """A QA decision is a human attestation.

    API keys carry no holder binding (``tenant_credentials`` records the
    issuer, not the holder), so the platform cannot show that a key's holder
    is independent of the author.  Service principals are machines.  Both are
    refused rather than certified as independent.
    """
    subject = (getattr(actor_ctx, "subject", "") or "").strip()
    source = getattr(actor_ctx, "auth_source", "") or ""
    if getattr(actor_ctx, "service_principal_id", None):
        raise AssuranceDenied(
            403,
            "HUMAN_REVIEWER_REQUIRED",
            "A service principal cannot make a human QA decision.",
        )
    if not (source.startswith(_HUMAN_AUTH_SOURCES_PREFIX) or source == "dev_bypass"):
        raise AssuranceDenied(
            403,
            "HUMAN_REVIEWER_REQUIRED",
            "QA decisions require a named human reviewer; API-key credentials "
            "cannot establish reviewer independence.",
        )
    if not subject or subject in {"anonymous", "unknown"}:
        raise AssuranceDenied(
            401, "CANONICAL_ACTOR_REQUIRED", "authenticated actor required"
        )
    return subject


def reviewer_identity_set(
    db: Session, *, tenant_id: str, subject: str
) -> frozenset[str]:
    """Every identity subject bound to the reviewer's canonical principal.

    A principal may sign in through more than one provider; all of its bound
    subjects in this tenant are treated as the same person.  Lookup failure
    fails closed (raises) — independence is never assumed.
    """
    from api.db_models import TenantUser  # noqa: PLC0415

    ids: set[str] = {subject}
    try:
        principal_ids = {
            str(p)
            for (p,) in db.execute(
                select(TenantUser.principal_id).where(
                    TenantUser.tenant_id == tenant_id,
                    TenantUser.identity_subject == subject,
                    TenantUser.principal_id.is_not(None),
                )
            ).all()
            if p
        }
        if principal_ids:
            ids |= {f"principal:{p}" for p in principal_ids}
            ids |= {
                str(s)
                for (s,) in db.execute(
                    select(TenantUser.identity_subject).where(
                        TenantUser.tenant_id == tenant_id,
                        TenantUser.principal_id.in_(sorted(principal_ids)),
                        TenantUser.identity_subject.is_not(None),
                    )
                ).all()
                if s
            }
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch
        raise AssuranceDenied(
            503,
            "QA_IDENTITY_RESOLUTION_UNAVAILABLE",
            "Reviewer identity could not be resolved; independence not certified.",
        ) from exc
    return frozenset(ids)


def enforce_independent_reviewer(
    db: Session,
    *,
    actor_ctx: Any,
    tenant_id: str,
    engagement_id: str,
    report_authors: Iterable[str | None] = (),
) -> dict[str, Any]:
    """Refuse a QA decision by anyone who contributed to the assessment.

    Returns audit-safe independence evidence on success.
    """
    from api.db_models_field_assessment import FaEngagementAuditEvent  # noqa: PLC0415

    subject = require_human_reviewer(actor_ctx)
    identities = reviewer_identity_set(db, tenant_id=tenant_id, subject=subject)
    subjects = sorted(i for i in identities if not i.startswith("principal:"))

    if any(a and a.strip() in identities for a in report_authors):
        raise AssuranceDenied(
            409,
            "REPORT_QA_SELF_REVIEW",
            "The report author cannot make the QA decision for this report.",
        )
    contribution = db.execute(
        select(FaEngagementAuditEvent.event_type)
        .where(
            FaEngagementAuditEvent.tenant_id == tenant_id,
            FaEngagementAuditEvent.engagement_id == engagement_id,
            FaEngagementAuditEvent.actor.in_(subjects),
            FaEngagementAuditEvent.event_type.in_(sorted(MATERIAL_CONTRIBUTION_EVENTS)),
        )
        .limit(1)
    ).first()
    if contribution is not None:
        raise AssuranceDenied(
            409,
            "REPORT_QA_SELF_REVIEW",
            "A material contributor to this assessment cannot make its QA decision.",
        )
    return {
        "reviewer_subject": subject,
        "reviewer_auth_source": getattr(actor_ctx, "auth_source", ""),
        "linked_identity_count": len(identities),
        "principal_linked": any(i.startswith("principal:") for i in identities),
        "independence_basis": "no_material_contribution_by_reviewer_principal",
    }


def governance_qa_status(
    db: Session, *, tenant_id: str, engagement_id: str, report_id: str
) -> dict[str, Any]:
    """QA standing of a governance report record from the append-only QA log."""
    from api.db_models_field_assessment import FaReportQaDecision  # noqa: PLC0415

    rows = list(
        db.execute(
            select(
                FaReportQaDecision.decision,
                FaReportQaDecision.actor_type,
                FaReportQaDecision.qa_stage,
            ).where(
                FaReportQaDecision.tenant_id == tenant_id,
                FaReportQaDecision.engagement_id == engagement_id,
                FaReportQaDecision.report_id == report_id,
            )
        ).all()
    )
    rejected = any(r.decision == "rejected" for r in rows)
    independent = any(
        r.decision == "approved"
        and r.actor_type == "human"
        and r.qa_stage == "governance"
        for r in rows
    )
    return {"rejected": rejected, "independent_approval": independent}


# ---------------------------------------------------------------------------
# Workstream D — draft access policy
# ---------------------------------------------------------------------------

# Internal assessment personnel: assessor, QA reviewer, compliance reviewer.
INTERNAL_DRAFT_PERMISSIONS: frozenset[str] = frozenset(
    {"report.generate", "report.qa_approve", "report.qualify"}
)


def customer_draft_review_enabled(engagement_metadata: Any) -> bool:
    """Explicit engagement policy; absent or malformed means disabled."""
    if not isinstance(engagement_metadata, Mapping):
        return False
    policy = engagement_metadata.get("report_access_policy")
    return isinstance(policy, Mapping) and policy.get("customer_draft_review") is True


def draft_access_decision(
    *,
    actor_permissions: Iterable[str],
    portal_origin: bool,
    engagement_metadata: Any,
    report_state: str,
) -> tuple[bool, str]:
    """Who may read report content in a given authoritative state.

    FINAL is released content.  Anything else is internal unless the
    engagement explicitly opts customers into draft review; a QA-rejected
    report is never shown to customers.  Portal-origin requests are always
    treated as customer access regardless of the transport credential.
    """
    if report_state == "FINAL":
        return True, "FINAL_RELEASED"
    if not portal_origin and set(actor_permissions) & INTERNAL_DRAFT_PERMISSIONS:
        return True, "INTERNAL_DRAFT_REVIEW"
    if (
        portal_origin
        and report_state != "REJECTED"
        and customer_draft_review_enabled(engagement_metadata)
    ):
        return True, "CUSTOMER_DRAFT_REVIEW_PERMITTED"
    return False, "DRAFT_ACCESS_NOT_PERMITTED"
