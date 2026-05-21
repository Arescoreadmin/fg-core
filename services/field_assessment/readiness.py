"""Deterministic readiness evaluation for field assessment engagements."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from services.field_assessment.playbooks import FieldAssessmentPlaybook


READINESS_SCHEMA_VERSION = "1.0"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_GATE_STATUS_RANK = {"blocked": 0, "warning": 1, "passed": 2, "not_applicable": 3}


@dataclass(frozen=True)
class ConfidenceImpact:
    reason: str
    delta: int
    affected_scope: str


@dataclass(frozen=True)
class ReadinessGate:
    gate_id: str
    gate_type: str
    readiness_category: str
    severity: str
    priority: int
    status: str
    title: str
    explanation: str
    why_it_matters: str
    evidence_required: list[str]
    evidence_present: list[str]
    missing_items: list[str]
    related_entity_ids: list[str]
    blocks_status_transition: list[str]
    recommended_action_id: str | None
    confidence_impact: ConfidenceImpact | None = None


@dataclass(frozen=True)
class NextAction:
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
    severity: str = "medium"


@dataclass(frozen=True)
class EscalationItem:
    escalation_id: str
    severity: str
    reason: str
    ambiguity_type: str
    related_entities: list[str]
    recommended_reviewer_role: str
    must_block_progression: bool


@dataclass(frozen=True)
class TransitionBlocker:
    target_status: str
    blocked_by_gate_ids: list[str]
    explanation: str


@dataclass(frozen=True)
class AssetCandidateAction:
    candidate_action_id: str
    source_type: str
    source_entity_id: str
    title: str
    instruction: str
    lineage_refs: list[str]
    candidate_type: str = "scan_source"
    risk_signal: str = "review_required"
    confidence: int = 70
    evidence_refs: list[str] = field(default_factory=list)
    promotion_state: str = "candidate_only"
    target_ui_section: str = "evidence"


@dataclass(frozen=True)
class ContinuityOpportunity:
    opportunity_id: str
    opportunity_type: str
    title: str
    related_entity_ids: list[str]
    recommended_follow_up: str


@dataclass(frozen=True)
class ExecutionState:
    engagement_id: str
    assessment_type: str
    playbook_id: str
    playbook_version: str
    overall_readiness_state: str
    readiness_score: int
    completion_ratio: float
    blocking_gate_count: int
    warning_gate_count: int
    completed_gate_count: int
    gates: list[ReadinessGate]
    next_actions: list[NextAction]
    escalation_items: list[EscalationItem]
    transition_blockers: list[TransitionBlocker]
    asset_candidate_actions: list[AssetCandidateAction]
    continuity_opportunities: list[ContinuityOpportunity]
    generated_at: str
    schema_version: str = READINESS_SCHEMA_VERSION
    readiness_categories: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_execution_state(
    *,
    engagement: Any,
    playbook: FieldAssessmentPlaybook,
    scan_results: Iterable[Any],
    document_analyses: Iterable[Any],
    observations: Iterable[Any],
    findings: Iterable[Any],
    evidence_links: Iterable[Any],
    generated_at: str,
    reports: Iterable[Any] = (),
) -> ExecutionState:
    scans = sorted(
        scan_results, key=lambda row: (_str(row, "source_type"), _str(row, "id"))
    )
    docs = sorted(
        document_analyses,
        key=lambda row: (_str(row, "document_classification"), _str(row, "id")),
    )
    obs = sorted(observations, key=lambda row: (_str(row, "domain"), _str(row, "id")))
    finding_rows = sorted(
        findings, key=lambda row: (_str(row, "severity"), _str(row, "id"))
    )
    links = sorted(
        evidence_links,
        key=lambda row: (
            _str(row, "source_entity_type"),
            _str(row, "source_entity_id"),
            _str(row, "evidence_entity_type"),
            _str(row, "evidence_entity_id"),
        ),
    )

    report_list = list(reports)

    gate_builder = _ReadinessBuilder(
        engagement=engagement,
        playbook=playbook,
        scans=scans,
        docs=docs,
        observations=obs,
        findings=finding_rows,
        evidence_links=links,
        generated_at=generated_at,
        reports=report_list if report_list else None,
    )
    return gate_builder.build()


class _ReadinessBuilder:
    def __init__(
        self,
        *,
        engagement: Any,
        playbook: FieldAssessmentPlaybook,
        scans: list[Any],
        docs: list[Any],
        observations: list[Any],
        findings: list[Any],
        evidence_links: list[Any],
        generated_at: str,
        reports: list[Any] | None = None,
    ) -> None:
        self.engagement = engagement
        self.playbook = playbook
        self.scans = scans
        self.docs = docs
        self.observations = observations
        self.findings = findings
        self.evidence_links = evidence_links
        self.generated_at = generated_at
        self.reports: list[Any] = reports if reports is not None else []
        self.gates: list[ReadinessGate] = []
        self.actions: list[NextAction] = []
        self.escalations: list[EscalationItem] = []
        self.asset_actions: list[AssetCandidateAction] = []
        self.continuity: list[ContinuityOpportunity] = []

    def build(self) -> ExecutionState:
        self._scan_gates()
        self._document_gates()
        self._interview_gates()
        self._observation_gates()
        self._evidence_link_gates()
        self._finding_gates()
        self._report_qa_gate()
        self._asset_candidate_actions()
        self._continuity_opportunities()

        gates = sorted(
            self.gates,
            key=lambda gate: (
                _GATE_STATUS_RANK.get(gate.status, 9),
                _SEVERITY_RANK.get(gate.severity, 9),
                gate.priority,
                gate.gate_id,
            ),
        )
        actions = sorted(self.actions, key=lambda item: (item.priority, item.action_id))
        escalations = sorted(
            self.escalations,
            key=lambda item: (
                _SEVERITY_RANK.get(item.severity, 9),
                item.escalation_id,
            ),
        )
        asset_actions = sorted(
            self.asset_actions,
            key=lambda item: (
                item.source_type,
                item.source_entity_id,
                item.candidate_action_id,
            ),
        )
        continuity = sorted(
            self.continuity,
            key=lambda item: (item.opportunity_type, item.opportunity_id),
        )
        transition_blockers = self._transition_blockers(gates, escalations)

        completed = sum(1 for gate in gates if gate.status == "passed")
        warnings = sum(1 for gate in gates if gate.status == "warning")
        blocked = sum(1 for gate in gates if gate.status == "blocked")
        applicable = sum(1 for gate in gates if gate.status != "not_applicable")
        completion_ratio = round(completed / applicable, 4) if applicable else 1.0
        readiness_score = int(round(completion_ratio * 100))
        overall = self._overall_state(blocked, warnings, escalations)

        categories = self._category_states(gates)
        return ExecutionState(
            engagement_id=_str(self.engagement, "id"),
            assessment_type=_str(self.engagement, "assessment_type"),
            playbook_id=self.playbook.playbook_id,
            playbook_version=self.playbook.version,
            overall_readiness_state=overall,
            readiness_score=readiness_score,
            completion_ratio=completion_ratio,
            blocking_gate_count=blocked,
            warning_gate_count=warnings,
            completed_gate_count=completed,
            gates=gates,
            next_actions=actions,
            escalation_items=escalations,
            transition_blockers=transition_blockers,
            asset_candidate_actions=asset_actions,
            continuity_opportunities=continuity,
            generated_at=self.generated_at,
            readiness_categories=categories,
        )

    def _scan_gates(self) -> None:
        scans_by_source = _group_by(self.scans, "source_type")
        for idx, source in enumerate(self.playbook.required_scan_sources, start=10):
            present = [_str(scan, "id") for scan in scans_by_source.get(source, [])]
            gate_id = f"scan.{source}.required"
            status = "passed" if present else "blocked"
            self.gates.append(
                ReadinessGate(
                    gate_id=gate_id,
                    gate_type="required_scan_source",
                    readiness_category="evidence",
                    severity="high",
                    priority=idx,
                    status=status,
                    title=f"{_label(source)} scan imported",
                    explanation=(
                        f"{_label(source)} scan evidence is present."
                        if present
                        else f"{_label(source)} scan evidence is required and missing."
                    ),
                    why_it_matters=(
                        "Required scan evidence anchors asset discovery, exposure "
                        "validation, and repeatable governance state initialization."
                    ),
                    evidence_required=[source],
                    evidence_present=present,
                    missing_items=[] if present else [source],
                    related_entity_ids=present,
                    blocks_status_transition=["evidence_collected"]
                    if not present
                    else [],
                    recommended_action_id=None
                    if present
                    else f"action.import_scan.{source}",
                    confidence_impact=None
                    if present
                    else ConfidenceImpact(
                        reason="required_scan_missing",
                        delta=-20,
                        affected_scope=source,
                    ),
                )
            )
            if not present:
                self.actions.append(
                    NextAction(
                        action_id=f"action.import_scan.{source}",
                        priority=idx,
                        severity="high",
                        title=f"Import {_label(source)} scan results",
                        instruction=(
                            f"Import {_label(source)} scan results for this engagement. "
                            "This closes the required scan gate and gives the system "
                            "tenant-scoped evidence for governance state initialization."
                        ),
                        why_it_matters=(
                            "Without this scan, readiness can miss unmanaged identities, "
                            "apps, endpoints, or shadow AI exposure."
                        ),
                        closes_gate_ids=[gate_id],
                        required_input_type="scan_result",
                        target_ui_section="scans",
                        expected_evidence=[source],
                        safe_for_junior_assessor=True,
                    )
                )

        for scan in self.scans:
            scan_id = _str(scan, "id")
            linked = any(
                _str(link, "evidence_entity_type") == "scan_result"
                and _str(link, "evidence_entity_id") == scan_id
                for link in self.evidence_links
            )
            if linked:
                continue
            gate_id = f"scan.{scan_id}.evidence_linked"
            self.gates.append(
                ReadinessGate(
                    gate_id=gate_id,
                    gate_type="evidence_graph_linkage",
                    readiness_category="governance_continuity",
                    severity="medium",
                    priority=60,
                    status="warning",
                    title=f"{_label(_str(scan, 'source_type'))} scan linked to evidence graph",
                    explanation="The scan is imported but not linked into the evidence graph.",
                    why_it_matters=(
                        "Unlinked scan evidence is harder to replay into findings, "
                        "assets, and governance reports."
                    ),
                    evidence_required=[scan_id],
                    evidence_present=[],
                    missing_items=[scan_id],
                    related_entity_ids=[scan_id],
                    blocks_status_transition=[],
                    recommended_action_id=f"action.link_scan.{scan_id}",
                    confidence_impact=ConfidenceImpact(
                        reason="scan_not_linked_to_evidence_graph",
                        delta=-8,
                        affected_scope=scan_id,
                    ),
                )
            )
            self.actions.append(
                NextAction(
                    action_id=f"action.link_scan.{scan_id}",
                    priority=60,
                    title="Link imported scan to the evidence graph",
                    instruction=(
                        "Create an evidence link from the scan to the relevant finding, "
                        "observation, or governance asset candidate."
                    ),
                    why_it_matters="Replay-safe reporting needs explicit evidence lineage.",
                    closes_gate_ids=[gate_id],
                    required_input_type="evidence_link",
                    target_ui_section="evidence",
                    expected_evidence=[scan_id],
                    safe_for_junior_assessor=True,
                )
            )

    def _document_gates(self) -> None:
        docs_by_class = _group_by(self.docs, "document_classification")
        evaluation_dt = _parse_datetime(self.generated_at)
        for idx, doc_class in enumerate(
            self.playbook.required_document_classes, start=100
        ):
            docs = docs_by_class.get(doc_class, [])
            doc_ids = [_str(doc, "id") for doc in docs]
            gate_id = f"document.{doc_class}.required"
            status = "passed" if doc_ids else "blocked"
            self.gates.append(
                ReadinessGate(
                    gate_id=gate_id,
                    gate_type="required_document_class",
                    readiness_category="evidence",
                    severity="high",
                    priority=idx,
                    status=status,
                    title=f"{_label(doc_class)} document registered",
                    explanation=(
                        f"{_label(doc_class)} document evidence is present."
                        if doc_ids
                        else f"{_label(doc_class)} document evidence is required and missing."
                    ),
                    why_it_matters=(
                        "Required policy and governance documents support defensible "
                        "findings, remediation, and executive reporting."
                    ),
                    evidence_required=[doc_class],
                    evidence_present=doc_ids,
                    missing_items=[] if doc_ids else [doc_class],
                    related_entity_ids=doc_ids,
                    blocks_status_transition=["evidence_collected"]
                    if not doc_ids
                    else [],
                    recommended_action_id=None
                    if doc_ids
                    else f"action.register_document.{doc_class}",
                    confidence_impact=None
                    if doc_ids
                    else ConfidenceImpact(
                        reason="required_document_missing",
                        delta=-15,
                        affected_scope=doc_class,
                    ),
                )
            )
            if not doc_ids:
                self.actions.append(
                    NextAction(
                        action_id=f"action.register_document.{doc_class}",
                        priority=idx,
                        severity="high",
                        title=f"Register current {_label(doc_class)} document",
                        instruction=(
                            f"Upload or register a current {_label(doc_class)} document "
                            "and include approval or freshness metadata when available."
                        ),
                        why_it_matters=(
                            "Document-backed readiness prevents findings from relying "
                            "on assessor memory or unsupported client statements."
                        ),
                        closes_gate_ids=[gate_id],
                        required_input_type="document_analysis",
                        target_ui_section="documents",
                        expected_evidence=[doc_class],
                        safe_for_junior_assessor=True,
                    )
                )

        freshness_days = {
            item.evidence_type.removeprefix("document."): item.freshness_days
            for item in self.playbook.minimum_evidence_expectations
            if item.evidence_type.startswith("document.")
        }
        for doc in self.docs:
            doc_id = _str(doc, "id")
            doc_class = _str(doc, "document_classification")
            if doc_class == "other":
                self._classified_document_gate(doc_id)
            max_age = freshness_days.get(doc_class)
            if max_age is not None:
                self._freshness_gate(doc, doc_class, doc_id, max_age, evaluation_dt)

    def _classified_document_gate(self, doc_id: str) -> None:
        gate_id = f"document.{doc_id}.classified"
        self.gates.append(
            ReadinessGate(
                gate_id=gate_id,
                gate_type="document_classification",
                readiness_category="evidence",
                severity="medium",
                priority=155,
                status="warning",
                title="Document classified to governance category",
                explanation="A document is registered as other and needs review.",
                why_it_matters=(
                    "Unclassified evidence cannot reliably close deterministic "
                    "document requirements."
                ),
                evidence_required=["classified_document"],
                evidence_present=[],
                missing_items=[doc_id],
                related_entity_ids=[doc_id],
                blocks_status_transition=[],
                recommended_action_id=f"action.classify_document.{doc_id}",
                confidence_impact=ConfidenceImpact(
                    reason="document_unclassified",
                    delta=-6,
                    affected_scope=doc_id,
                ),
            )
        )

    def _freshness_gate(
        self,
        doc: Any,
        doc_class: str,
        doc_id: str,
        max_age: int,
        evaluation_dt: datetime | None,
    ) -> None:
        freshness = _str(doc, "freshness_date")
        if not freshness or evaluation_dt is None:
            return
        freshness_dt = _parse_datetime(freshness)
        if freshness_dt is None:
            return
        age_days = (evaluation_dt.date() - freshness_dt.date()).days
        if age_days <= max_age:
            return
        gate_id = f"document.{doc_id}.freshness"
        self.gates.append(
            ReadinessGate(
                gate_id=gate_id,
                gate_type="document_freshness",
                readiness_category="evidence",
                severity="medium",
                priority=160,
                status="warning",
                title=f"{_label(doc_class)} document freshness reviewed",
                explanation=(
                    f"The document freshness date is {age_days} days old, "
                    f"which exceeds the {max_age}-day playbook window."
                ),
                why_it_matters=(
                    "Stale policy evidence can support historical lineage, but it "
                    "should not silently support current readiness conclusions."
                ),
                evidence_required=[f"fresh_{doc_class}"],
                evidence_present=[doc_id],
                missing_items=[f"freshness_within_{max_age}_days"],
                related_entity_ids=[doc_id],
                blocks_status_transition=[],
                recommended_action_id=f"action.refresh_document.{doc_id}",
                confidence_impact=ConfidenceImpact(
                    reason="document_stale",
                    delta=-10,
                    affected_scope=doc_id,
                ),
            )
        )
        self.actions.append(
            NextAction(
                action_id=f"action.refresh_document.{doc_id}",
                priority=160,
                title=f"Refresh {_label(doc_class)} document evidence",
                instruction=(
                    f"Upload or register a current {_label(doc_class)} document "
                    "dated within the accepted freshness window."
                ),
                why_it_matters=(
                    "Current evidence is required before the platform can defend "
                    "present-state governance readiness."
                ),
                closes_gate_ids=[gate_id],
                required_input_type="document_analysis",
                target_ui_section="documents",
                expected_evidence=[doc_class],
                safe_for_junior_assessor=True,
            )
        )

    def _interview_gates(self) -> None:
        interviews = [
            row
            for row in self.observations
            if _str(row, "observation_type") == "interview"
        ]
        roles = {
            _normalize_role(_str(row, "interview_role")): row for row in interviews
        }
        for idx, role in enumerate(self.playbook.required_interview_roles, start=200):
            row = roles.get(role)
            present = [_str(row, "id")] if row else []
            gate_id = f"interview.{role}.required"
            self.gates.append(
                ReadinessGate(
                    gate_id=gate_id,
                    gate_type="required_interview",
                    readiness_category="engagement",
                    severity="medium",
                    priority=idx,
                    status="passed" if row else "blocked",
                    title=f"{_label(role)} interview captured",
                    explanation=(
                        f"{_label(role)} interview is captured."
                        if row
                        else f"{_label(role)} interview is required and missing."
                    ),
                    why_it_matters=(
                        "Role-based interviews reduce assessor variance and capture "
                        "governance context that scans cannot prove."
                    ),
                    evidence_required=[role],
                    evidence_present=present,
                    missing_items=[] if row else [role],
                    related_entity_ids=present,
                    blocks_status_transition=["evidence_collected"] if not row else [],
                    recommended_action_id=None
                    if row
                    else f"action.capture_interview.{role}",
                    confidence_impact=None
                    if row
                    else ConfidenceImpact(
                        reason="required_interview_missing",
                        delta=-8,
                        affected_scope=role,
                    ),
                )
            )
            if row:
                continue
            self.actions.append(
                NextAction(
                    action_id=f"action.capture_interview.{role}",
                    priority=idx,
                    title=f"Capture {_label(role)} interview",
                    instruction=(
                        f"Capture a structured interview for the {_label(role)}. "
                        "Use role/category references rather than personal details."
                    ),
                    why_it_matters=(
                        "The interview establishes accountable governance context "
                        "without requiring the assessor to infer authority."
                    ),
                    closes_gate_ids=[gate_id],
                    required_input_type="field_observation",
                    target_ui_section="interviews",
                    expected_evidence=[role],
                    safe_for_junior_assessor=True,
                )
            )

    def _observation_gates(self) -> None:
        domains = _group_by(
            [
                row
                for row in self.observations
                if _str(row, "observation_type") != "interview"
            ],
            "domain",
        )
        for idx, domain in enumerate(
            self.playbook.required_observation_domains, start=300
        ):
            rows = domains.get(domain, [])
            ids = [_str(row, "id") for row in rows]
            gate_id = f"observation.{domain}.required"
            self.gates.append(
                ReadinessGate(
                    gate_id=gate_id,
                    gate_type="required_observation_domain",
                    readiness_category="engagement",
                    severity="medium",
                    priority=idx,
                    status="passed" if ids else "blocked",
                    title=f"{_label(domain)} observation captured",
                    explanation=(
                        f"{_label(domain)} observation evidence is present."
                        if ids
                        else f"{_label(domain)} observation evidence is missing."
                    ),
                    why_it_matters=(
                        "Domain observations preserve site-level governance memory "
                        "and prevent report-only conclusions."
                    ),
                    evidence_required=[domain],
                    evidence_present=ids,
                    missing_items=[] if ids else [domain],
                    related_entity_ids=ids,
                    blocks_status_transition=[],
                    recommended_action_id=None
                    if ids
                    else f"action.capture_observation.{domain}",
                    confidence_impact=None
                    if ids
                    else ConfidenceImpact(
                        reason="required_observation_missing",
                        delta=-6,
                        affected_scope=domain,
                    ),
                )
            )
            if ids:
                continue
            self.actions.append(
                NextAction(
                    action_id=f"action.capture_observation.{domain}",
                    priority=idx,
                    title=f"Capture {_label(domain)} observation",
                    instruction=(
                        f"Capture at least one {_label(domain)} observation with "
                        "structured evidence where available."
                    ),
                    why_it_matters=(
                        "Structured observations give the platform explainable "
                        "governance memory beyond imported artifacts."
                    ),
                    closes_gate_ids=[gate_id],
                    required_input_type="field_observation",
                    target_ui_section="observations",
                    expected_evidence=[domain],
                    safe_for_junior_assessor=True,
                )
            )

        for row in self.observations:
            if _looks_ambiguous(row):
                obs_id = _str(row, "id")
                self.escalations.append(
                    EscalationItem(
                        escalation_id=f"escalation.observation.{obs_id}.ambiguous",
                        severity=_str(row, "severity") or "medium",
                        reason="Observation contains ambiguous owner, shadow asset, or unsupported evidence language.",
                        ambiguity_type="ambiguous_observation",
                        related_entities=[obs_id],
                        recommended_reviewer_role="governance_lead",
                        must_block_progression=_str(row, "severity")
                        in {"critical", "high"},
                    )
                )

    def _evidence_link_gates(self) -> None:
        if self.evidence_links:
            self.gates.append(
                ReadinessGate(
                    gate_id="evidence.link.required",
                    gate_type="evidence_linkage",
                    readiness_category="governance_continuity",
                    severity="high",
                    priority=400,
                    status="passed",
                    title="Evidence graph linkage exists",
                    explanation="At least one evidence link is present.",
                    why_it_matters=(
                        "Evidence links make findings and reports replay-safe."
                    ),
                    evidence_required=["evidence_link"],
                    evidence_present=[_str(link, "id") for link in self.evidence_links],
                    missing_items=[],
                    related_entity_ids=[
                        _str(link, "id") for link in self.evidence_links
                    ],
                    blocks_status_transition=[],
                    recommended_action_id=None,
                )
            )
            return
        self.gates.append(
            ReadinessGate(
                gate_id="evidence.link.required",
                gate_type="evidence_linkage",
                readiness_category="governance_continuity",
                severity="high",
                priority=400,
                status="blocked",
                title="Evidence graph linkage exists",
                explanation="No evidence links exist for this engagement.",
                why_it_matters=(
                    "Findings and reports must be backed by explicit evidence lineage."
                ),
                evidence_required=["evidence_link"],
                evidence_present=[],
                missing_items=["evidence_link"],
                related_entity_ids=[],
                blocks_status_transition=["report_generation", "delivered"],
                recommended_action_id="action.create_evidence_link",
                confidence_impact=ConfidenceImpact(
                    reason="no_evidence_links",
                    delta=-25,
                    affected_scope="engagement",
                ),
            )
        )
        self.actions.append(
            NextAction(
                action_id="action.create_evidence_link",
                priority=400,
                severity="high",
                title="Create evidence links",
                instruction=(
                    "Link scans, documents, and observations to the findings or "
                    "governance asset candidates they support."
                ),
                why_it_matters=(
                    "Evidence linkage is the difference between notes and "
                    "defensible governance state."
                ),
                closes_gate_ids=["evidence.link.required"],
                required_input_type="evidence_link",
                target_ui_section="evidence",
                expected_evidence=[
                    "scan_result",
                    "document_analysis",
                    "field_observation",
                ],
                safe_for_junior_assessor=True,
            )
        )

    def _finding_gates(self) -> None:
        finding_ids = [_str(row, "id") for row in self.findings]
        if not self.findings:
            self.gates.append(
                ReadinessGate(
                    gate_id="finding.normalized.required",
                    gate_type="normalized_findings",
                    readiness_category="report",
                    severity="medium",
                    priority=500,
                    status="warning",
                    title="Normalized findings available",
                    explanation="No normalized findings are available yet.",
                    why_it_matters=(
                        "Report readiness depends on normalized findings with "
                        "evidence and remediation metadata."
                    ),
                    evidence_required=["normalized_finding"],
                    evidence_present=[],
                    missing_items=["normalized_finding"],
                    related_entity_ids=[],
                    blocks_status_transition=[],
                    recommended_action_id=None,
                    confidence_impact=ConfidenceImpact(
                        reason="no_findings_yet",
                        delta=-10,
                        affected_scope="report",
                    ),
                )
            )
            return

        unlinked: list[str] = []
        no_remediation: list[str] = []
        low_confidence: list[str] = []
        for finding in self.findings:
            finding_id = _str(finding, "id")
            refs = [str(ref) for ref in (_value(finding, "evidence_ref_ids") or [])]
            link_refs = [
                _str(link, "id")
                for link in self.evidence_links
                if _str(link, "source_entity_id") == finding_id
            ]
            if not refs and not link_refs:
                unlinked.append(finding_id)
            if _str(finding, "severity") in {"critical", "high"} and not _str(
                finding, "remediation_hint"
            ):
                no_remediation.append(finding_id)
            confidence = int(_value(finding, "confidence_score") or 0)
            if confidence < 60:
                low_confidence.append(finding_id)

        self._finding_evidence_gate(finding_ids, unlinked)
        self._finding_remediation_gate(finding_ids, no_remediation)

        for finding_id in low_confidence:
            self.escalations.append(
                EscalationItem(
                    escalation_id=f"escalation.finding.{finding_id}.confidence",
                    severity="medium",
                    reason="Finding confidence is below deterministic review threshold.",
                    ambiguity_type="low_confidence_finding",
                    related_entities=[finding_id],
                    recommended_reviewer_role="senior_assessor",
                    must_block_progression=False,
                )
            )

    def _finding_evidence_gate(
        self, finding_ids: list[str], unlinked: list[str]
    ) -> None:
        blocked = bool(unlinked)
        self.gates.append(
            ReadinessGate(
                gate_id="finding.evidence.required",
                gate_type="finding_evidence",
                readiness_category="report",
                severity="high",
                priority=510,
                status="blocked" if blocked else "passed",
                title="Findings linked to evidence",
                explanation=(
                    "All findings have evidence references."
                    if not blocked
                    else "One or more findings lack evidence references."
                ),
                why_it_matters=(
                    "Findings without evidence cannot support deterministic reports."
                ),
                evidence_required=["finding_evidence_ref"],
                evidence_present=[item for item in finding_ids if item not in unlinked],
                missing_items=unlinked,
                related_entity_ids=finding_ids,
                blocks_status_transition=["report_generation", "delivered"]
                if blocked
                else [],
                recommended_action_id="action.link_finding_evidence"
                if blocked
                else None,
                confidence_impact=ConfidenceImpact(
                    reason="finding_without_evidence",
                    delta=-25,
                    affected_scope="report",
                )
                if blocked
                else None,
            )
        )
        if blocked:
            self.actions.append(
                NextAction(
                    action_id="action.link_finding_evidence",
                    priority=510,
                    severity="high",
                    title="Link findings to supporting evidence",
                    instruction=(
                        "Open the evidence tab and link each finding to the scans, "
                        "documents, or observations that support it."
                    ),
                    why_it_matters="Unsupported findings must block report generation.",
                    closes_gate_ids=["finding.evidence.required"],
                    required_input_type="evidence_link",
                    target_ui_section="evidence",
                    expected_evidence=unlinked,
                    safe_for_junior_assessor=True,
                )
            )

    def _finding_remediation_gate(
        self, finding_ids: list[str], missing: list[str]
    ) -> None:
        blocked = bool(missing)
        self.gates.append(
            ReadinessGate(
                gate_id="finding.remediation.required",
                gate_type="finding_remediation",
                readiness_category="report",
                severity="high",
                priority=520,
                status="blocked" if blocked else "passed",
                title="High-risk findings include remediation metadata",
                explanation=(
                    "All high-risk findings include remediation metadata."
                    if not blocked
                    else "One or more high-risk findings lack remediation metadata."
                ),
                why_it_matters=(
                    "Enterprise reviewers need actionable remediation tied to "
                    "high-risk governance gaps."
                ),
                evidence_required=["remediation_hint"],
                evidence_present=[item for item in finding_ids if item not in missing],
                missing_items=missing,
                related_entity_ids=finding_ids,
                blocks_status_transition=["report_generation", "delivered"]
                if blocked
                else [],
                recommended_action_id="action.add_finding_remediation"
                if blocked
                else None,
                confidence_impact=ConfidenceImpact(
                    reason="high_risk_finding_without_remediation",
                    delta=-15,
                    affected_scope="report",
                )
                if blocked
                else None,
            )
        )
        if blocked:
            self.escalations.append(
                EscalationItem(
                    escalation_id="escalation.finding.remediation.required",
                    severity="high",
                    reason="High-risk finding lacks remediation metadata.",
                    ambiguity_type="missing_remediation",
                    related_entities=missing,
                    recommended_reviewer_role="governance_lead",
                    must_block_progression=True,
                )
            )

    def _report_qa_gate(self) -> None:
        approved = any(
            _value(r, "qa_approved_by") and _value(r, "is_finalized")
            for r in self.reports
        )
        if approved:
            self.gates.append(
                ReadinessGate(
                    gate_id="report.qa.approved",
                    gate_type="report_qa",
                    readiness_category="report",
                    severity="critical",
                    priority=550,
                    status="passed",
                    title="Report QA approved",
                    explanation="A finalized report has been QA-approved for client delivery.",
                    why_it_matters=(
                        "Client delivery requires a senior-reviewed, signed-off report. "
                        "QA approval is the final check before handoff."
                    ),
                    evidence_required=["qa_approved_report"],
                    evidence_present=[
                        str(_value(r, "id"))
                        for r in self.reports
                        if _value(r, "qa_approved_by") and _value(r, "is_finalized")
                    ],
                    missing_items=[],
                    related_entity_ids=[
                        str(_value(r, "id"))
                        for r in self.reports
                        if _value(r, "is_finalized")
                    ],
                    blocks_status_transition=[],
                    recommended_action_id=None,
                )
            )
            return

        self.gates.append(
            ReadinessGate(
                gate_id="report.qa.approved",
                gate_type="report_qa",
                readiness_category="report",
                severity="critical",
                priority=550,
                status="blocked",
                title="Report QA approved",
                explanation=(
                    "No QA-approved report found. A finalized report must be reviewed "
                    "and approved before the engagement can be delivered."
                ),
                why_it_matters=(
                    "Client delivery requires a senior-reviewed, signed-off report. "
                    "QA approval is the final check before handoff."
                ),
                evidence_required=["qa_approved_report"],
                evidence_present=[],
                missing_items=["qa_approved_report"],
                related_entity_ids=[
                    str(_value(r, "id")) for r in self.reports if _value(r, "is_finalized")
                ],
                blocks_status_transition=["delivered"],
                recommended_action_id="action.approve_report_qa",
                confidence_impact=ConfidenceImpact(
                    reason="no_qa_approved_report",
                    delta=-20,
                    affected_scope="report",
                ),
            )
        )
        self.actions.append(
            NextAction(
                action_id="action.approve_report_qa",
                priority=550,
                severity="critical",
                title="Complete report QA review",
                instruction=(
                    "Have a senior assessor review the finalized report, then call "
                    "POST /engagements/{id}/reports/{report_id}/qa-approve to record approval."
                ),
                why_it_matters=(
                    "QA approval is the last gate before client delivery. It ensures "
                    "the report is accurate, complete, and free of sensitive raw data."
                ),
                closes_gate_ids=["report.qa.approved"],
                required_input_type="report_qa_approval",
                target_ui_section="report",
                expected_evidence=["qa_approved_report"],
                safe_for_junior_assessor=False,
            )
        )

    def _asset_candidate_actions(self) -> None:
        for scan in self.scans:
            source = _str(scan, "source_type")
            if source not in self.playbook.required_asset_candidate_sources:
                continue
            normalized_payload = _value(scan, "normalized_payload") or {}
            if isinstance(normalized_payload, dict):
                for candidate in normalized_payload.get("asset_candidates", []) or []:
                    if not isinstance(candidate, dict):
                        continue
                    scan_id = _str(scan, "id")
                    candidate_id = str(
                        candidate.get("candidate_id")
                        or f"{source}.{scan_id}.{len(self.asset_actions)}"
                    )
                    candidate_type = str(candidate.get("candidate_type") or source)
                    risk_signal = str(candidate.get("risk_signal") or "review_required")
                    self.asset_actions.append(
                        AssetCandidateAction(
                            candidate_action_id=(
                                f"asset_candidate.review.{source}.{candidate_id}"
                            ),
                            source_type=source,
                            source_entity_id=scan_id,
                            title=f"Review {_label(source)} {_label(candidate_type)} candidate",
                            instruction=(
                                f"Review the {_label(candidate_type)} candidate "
                                f"flagged by {_label(source)} for {risk_signal} "
                                "before promotion into the Governance Asset Registry."
                            ),
                            lineage_refs=[
                                scan_id,
                                str(candidate.get("source_ref", "")),
                            ],
                            candidate_type=candidate_type,
                            risk_signal=risk_signal,
                            confidence=int(candidate.get("confidence") or 70),
                            evidence_refs=[
                                str(ref)
                                for ref in candidate.get("evidence_refs", [])
                                if ref
                            ],
                            promotion_state=str(
                                candidate.get("promotion_state") or "candidate_only"
                            ),
                        )
                    )
                if normalized_payload.get("asset_candidates"):
                    continue
            if int(_value(scan, "object_count") or 0) <= 0:
                continue
            scan_id = _str(scan, "id")
            self.asset_actions.append(
                AssetCandidateAction(
                    candidate_action_id=f"asset_candidate.review.{source}.{scan_id}",
                    source_type=source,
                    source_entity_id=scan_id,
                    title=f"Review {_label(source)} asset candidates",
                    instruction=(
                        f"Review asset candidates discovered from {_label(source)} "
                        "before onboarding them into the Governance Asset Registry."
                    ),
                    lineage_refs=[scan_id],
                )
            )

        for row in self.observations:
            if (
                "shadow"
                not in f"{_str(row, 'title')} {_str(row, 'description')}".lower()
            ):
                continue
            obs_id = _str(row, "id")
            self.asset_actions.append(
                AssetCandidateAction(
                    candidate_action_id=f"asset_candidate.review.observation.{obs_id}",
                    source_type="field_observation",
                    source_entity_id=obs_id,
                    title="Review shadow asset candidate",
                    instruction=(
                        "Review the observed shadow asset candidate and decide "
                        "whether it should become a governance asset record."
                    ),
                    lineage_refs=[obs_id],
                    target_ui_section="observations",
                )
            )

    def _continuity_opportunities(self) -> None:
        for finding in self.findings:
            finding_id = _str(finding, "id")
            severity = _str(finding, "severity")
            if severity in {"critical", "high"}:
                self.continuity.append(
                    ContinuityOpportunity(
                        opportunity_id=f"continuity.remediation.{finding_id}",
                        opportunity_type="remediation_workflow_candidate",
                        title="Create remediation workflow from high-risk finding",
                        related_entity_ids=[finding_id],
                        recommended_follow_up=(
                            "Convert this finding into a tracked remediation workflow "
                            "after report review."
                        ),
                    )
                )
        for action in self.asset_actions:
            self.continuity.append(
                ContinuityOpportunity(
                    opportunity_id=f"continuity.asset_registry.{action.source_entity_id}",
                    opportunity_type="asset_registry_onboarding_candidate",
                    title="Prepare asset registry onboarding",
                    related_entity_ids=[action.source_entity_id],
                    recommended_follow_up=(
                        "Review lineage and create a governance asset candidate in "
                        "a follow-on workflow."
                    ),
                )
            )
        if self.evidence_links:
            self.continuity.append(
                ContinuityOpportunity(
                    opportunity_id="continuity.recurring_attestation.engagement",
                    opportunity_type="recurring_attestation_candidate",
                    title="Establish recurring attestation cadence",
                    related_entity_ids=[
                        _str(link, "id") for link in self.evidence_links
                    ],
                    recommended_follow_up=(
                        "Use linked evidence to define recurring attestation and "
                        "monitoring expectations."
                    ),
                )
            )
            self.continuity.append(
                ContinuityOpportunity(
                    opportunity_id="continuity.monitoring.engagement",
                    opportunity_type="monitoring_candidate",
                    title="Identify monitoring candidates",
                    related_entity_ids=[
                        _str(link, "id") for link in self.evidence_links
                    ],
                    recommended_follow_up=(
                        "Promote repeatedly assessed evidence sources into continuous "
                        "monitoring candidates."
                    ),
                )
            )

    def _transition_blockers(
        self,
        gates: list[ReadinessGate],
        escalations: list[EscalationItem],
    ) -> list[TransitionBlocker]:
        blockers: list[TransitionBlocker] = []
        blocked_gate_ids = {gate.gate_id for gate in gates if gate.status == "blocked"}
        for status, required_gates in sorted(
            self.playbook.status_transition_requirements.items()
        ):
            matching = sorted(set(required_gates) & blocked_gate_ids)
            if status == "delivered" and any(
                item.must_block_progression for item in escalations
            ):
                matching.append("escalation.critical.required")
            if not matching:
                continue
            blockers.append(
                TransitionBlocker(
                    target_status=status,
                    blocked_by_gate_ids=sorted(set(matching)),
                    explanation=(
                        f"Transition to {status} is blocked until required "
                        "readiness gates are closed."
                    ),
                )
            )
        return blockers

    def _overall_state(
        self,
        blocked_count: int,
        warning_count: int,
        escalations: list[EscalationItem],
    ) -> str:
        if blocked_count:
            return "blocked"
        if any(item.must_block_progression for item in escalations):
            return "needs_review"
        if warning_count:
            return "warning"
        return "ready"

    def _category_states(self, gates: list[ReadinessGate]) -> dict[str, str]:
        categories: dict[str, list[str]] = {
            "engagement": [],
            "evidence": [],
            "report": [],
            "governance_continuity": [],
        }
        for gate in gates:
            categories.setdefault(gate.readiness_category, []).append(gate.status)
        result: dict[str, str] = {}
        for category, statuses in sorted(categories.items()):
            if not statuses:
                result[category] = "not_applicable"
            elif "blocked" in statuses:
                result[category] = "blocked"
            elif "warning" in statuses:
                result[category] = "warning"
            else:
                result[category] = "ready"
        return result


def _value(row: Any, name: str) -> Any:
    if isinstance(row, dict):
        return row.get(name)
    return getattr(row, name, None)


def _str(row: Any, name: str) -> str:
    value = _value(row, name)
    if value is None:
        return ""
    return str(value)


def _group_by(rows: Iterable[Any], attr: str) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for row in rows:
        grouped.setdefault(_str(row, attr), []).append(row)
    return grouped


def _normalize_role(role: str) -> str:
    return role.strip().lower().replace(" ", "_").replace("-", "_")


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _looks_ambiguous(row: Any) -> bool:
    text = f"{_str(row, 'title')} {_str(row, 'description')}".lower()
    structured = _value(row, "structured_evidence") or {}
    owner = ""
    if isinstance(structured, dict):
        owner = str(
            structured.get("owner") or structured.get("asset_owner") or ""
        ).lower()
    ambiguous_terms = ("unknown", "unclear", "unsupported", "conflicting", "shadow")
    return any(term in text for term in ambiguous_terms) or owner in {
        "unknown",
        "unclear",
        "tbd",
    }
