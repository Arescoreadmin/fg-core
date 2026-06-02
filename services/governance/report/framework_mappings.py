"""Deterministic framework mapping registry.

All mappings are hardcoded authoritative lookups — no LLM inference.
get_framework_mappings() returns FrameworkMapping instances for a given
control_id / domain pair.  Unknown controls return an empty list.

Registry contract:
  - All lookups are pure dict operations: O(1), deterministic, no I/O.
  - Adding a new framework requires a new key in FRAMEWORK_CONTROL_MAP.
  - Confidence values are fixed constants for each mapping tier.

NIST AI RMF categories:
  GOVERN, MAP, MEASURE, MANAGE

SOC 2 Trust Services Criteria:
  CC1–CC9 (Common Criteria), A1 (Availability), C1 (Confidentiality),
  PI1 (Processing Integrity), P1–P8 (Privacy)

HIPAA safeguard categories:
  Administrative, Physical, Technical
"""

from __future__ import annotations

from types import MappingProxyType

from .models import FrameworkMapping

# ---------------------------------------------------------------------------
# NIST AI RMF control registry
# ---------------------------------------------------------------------------
# Each entry: control_id → {function, title, description}
# Used to build the deterministic control matrix and prompt context.
# ---------------------------------------------------------------------------

NIST_AI_RMF_CONTROLS: dict[str, dict[str, str]] = {
    # GOVERN — Policies, accountability, culture, roles, transparency
    "GOVERN 1.1": {
        "function": "GOVERN",
        "title": "Organizational AI Risk Management Policies",
        "description": "Policies and processes for AI risk management are established and communicated.",
    },
    "GOVERN 1.2": {
        "function": "GOVERN",
        "title": "Accountability for AI Risk Outcomes",
        "description": "Roles, responsibilities, and accountability for AI risk are defined and assigned.",
    },
    "GOVERN 1.5": {
        "function": "GOVERN",
        "title": "Organizational Culture for Responsible AI",
        "description": "Organizational culture promotes responsible AI use and employees are encouraged to raise concerns.",
    },
    "GOVERN 1.7": {
        "function": "GOVERN",
        "title": "Transparent AI Communication Processes",
        "description": "Processes exist to communicate AI risk information to relevant stakeholders, including transparency with end users.",
    },
    "GOVERN 2.2": {
        "function": "GOVERN",
        "title": "AI Security Policies and Access Controls",
        "description": "AI risk management processes incorporate security policies and access control requirements.",
    },
    "GOVERN 3.1": {
        "function": "GOVERN",
        "title": "Resources Allocated for AI Risk Management",
        "description": "Adequate resources, including MFA and access infrastructure, are allocated to AI risk management.",
    },
    "GOVERN 3.2": {
        "function": "GOVERN",
        "title": "Executive Leadership Commitment to AI Risk",
        "description": "Executive leadership allocates budget and demonstrates active commitment to responsible AI investment.",
    },
    "GOVERN 4.1": {
        "function": "GOVERN",
        "title": "Human Oversight in AI Decision-Making",
        "description": "Organizational teams ensure human oversight is maintained for high-stakes AI-assisted decisions.",
    },
    "GOVERN 4.2": {
        "function": "GOVERN",
        "title": "AI Ethics and Responsible Use Framework",
        "description": "AI risk management decisions are communicated and an ethics framework guides AI deployment.",
    },
    "GOVERN 5.1": {
        "function": "GOVERN",
        "title": "AI Vendor Risk and Data Agreements",
        "description": "Organizational risk tolerances for AI are established and vendor agreements (BAAs, DPAs) are in place.",
    },
    # MAP — Context, risk identification, stakeholder impact, AI system categorization
    "MAP 1.5": {
        "function": "MAP",
        "title": "AI Risk Likelihood and Data Inventory",
        "description": "Likelihood of AI risks is considered with a complete inventory of data used in AI workflows.",
    },
    "MAP 2.2": {
        "function": "MAP",
        "title": "AI Risk Awareness and Team Knowledge",
        "description": "AI risk management teams are trained and organizational awareness of AI risks is current.",
    },
    "MAP 2.3": {
        "function": "MAP",
        "title": "AI System Technical Basis and Data Provenance",
        "description": "The scientific/technical basis of AI systems is examined, including data lineage and training data provenance.",
    },
    "MAP 3.1": {
        "function": "MAP",
        "title": "AI System Purpose and Inventory",
        "description": "The task, purpose, and context of AI systems are established and a register of all deployed AI systems is maintained.",
    },
    "MAP 3.5": {
        "function": "MAP",
        "title": "AI Tool Deployment Risk Evaluation",
        "description": "Risks of using AI systems are established and vendors are evaluated before deployment.",
    },
    "MAP 4.1": {
        "function": "MAP",
        "title": "AI Workflow Identification",
        "description": "AI-enabled workflows and automation candidates are identified and documented.",
    },
    "MAP 4.2": {
        "function": "MAP",
        "title": "AI Supply Chain and Third-Party Risk",
        "description": "Internal and external expert perspectives are incorporated; third-party and supply chain AI components are risk-assessed.",
    },
    "MAP 5.1": {
        "function": "MAP",
        "title": "AI Regulatory Risk Identification",
        "description": "Likelihood of AI-related harms is identified, including regulatory triggers and compliance obligations.",
    },
    "MAP 5.2": {
        "function": "MAP",
        "title": "AI Impact Assessment and Stakeholder Mapping",
        "description": "AI impact assessment practices are established and all stakeholder groups affected by AI systems are identified.",
    },
    # MEASURE — Testing, evaluation, bias, fairness, privacy, monitoring, TEVV
    "MEASURE 1.1": {
        "function": "MEASURE",
        "title": "Pre-Deployment AI Testing Protocols",
        "description": "AI risk measurement approaches are established, including formal pre-deployment testing protocols.",
    },
    "MEASURE 1.3": {
        "function": "MEASURE",
        "title": "Third-Party AI Evaluation",
        "description": "Internal experts and external third parties verify and validate AI system performance and fairness.",
    },
    "MEASURE 2.3": {
        "function": "MEASURE",
        "title": "AI Adversarial Testing",
        "description": "AI system performance metrics are evaluated, including adversarial input and prompt injection testing.",
    },
    "MEASURE 2.4": {
        "function": "MEASURE",
        "title": "AI Bias Evaluation",
        "description": "AI system performance is evaluated for bias against protected characteristics.",
    },
    "MEASURE 2.5": {
        "function": "MEASURE",
        "title": "Comprehensive AI Testing Coverage",
        "description": "AI testing is comprehensive, including data quality assessments for training and inference data.",
    },
    "MEASURE 2.6": {
        "function": "MEASURE",
        "title": "AI Output Interpretability and Explainability",
        "description": "AI system outputs are interpretable; systems can explain or justify recommendations to users.",
    },
    "MEASURE 2.8": {
        "function": "MEASURE",
        "title": "AI Security Assessment and Penetration Testing",
        "description": "AI risks are evaluated for impact through targeted security assessments and penetration tests.",
    },
    "MEASURE 2.9": {
        "function": "MEASURE",
        "title": "AI Operational Output Monitoring",
        "description": "Risks from AI system operation are evaluated through monitoring of AI outputs for anomalies and misuse.",
    },
    "MEASURE 2.10": {
        "function": "MEASURE",
        "title": "AI Privacy Risk and Data Subject Rights",
        "description": "Privacy risks from AI systems are considered through privacy impact assessments and data subject rights processes.",
    },
    "MEASURE 3.1": {
        "function": "MEASURE",
        "title": "Continuous AI Performance Monitoring",
        "description": "AI system performance is continuously monitored post-deployment; formal re-evaluation schedules exist.",
    },
    # MANAGE — Risk response, treatment plans, incident handling, decommissioning
    "MANAGE 1.2": {
        "function": "MANAGE",
        "title": "AI Risk Response Planning",
        "description": "Documented risk response plans and AI-specific incident response procedures are in place.",
    },
    "MANAGE 1.3": {
        "function": "MANAGE",
        "title": "AI Vulnerability Management and IR Readiness",
        "description": "Responses for high-priority AI risks are established, including vulnerability management and incident response.",
    },
    "MANAGE 2.2": {
        "function": "MANAGE",
        "title": "AI Risk Management Mechanisms",
        "description": "Mechanisms for ongoing AI risk management are in place, including documented manual review processes.",
    },
    "MANAGE 2.4": {
        "function": "MANAGE",
        "title": "AI Risk Tracking and Secrets Management",
        "description": "AI risks are tracked; credentials and API keys are managed through secrets management systems.",
    },
    "MANAGE 3.1": {
        "function": "MANAGE",
        "title": "Privileged Access Management",
        "description": "Risk responses for privileged access are monitored and PAM systems control AI platform credentials.",
    },
    "MANAGE 3.2": {
        "function": "MANAGE",
        "title": "AI System Rollback and Shutdown Capability",
        "description": "AI risk responses are adjusted based on feedback; documented procedures exist to disable or roll back AI systems.",
    },
    "MANAGE 3.3": {
        "function": "MANAGE",
        "title": "AI System Decommissioning Procedures",
        "description": "Documented procedures exist for retiring or decommissioning AI systems, including data deletion and access revocation.",
    },
    "MANAGE 4.1": {
        "function": "MANAGE",
        "title": "Network Security and Encryption Controls",
        "description": "Risk treatment plans for network security are in place, including TLS encryption and network segmentation for AI workloads.",
    },
}

# ---------------------------------------------------------------------------
# Question → NIST AI RMF control mapping
# ---------------------------------------------------------------------------
# Maps assessment question IDs to their primary NIST AI RMF control.
# Drives the deterministic nist_control_matrix in generated reports.
# ---------------------------------------------------------------------------

QUESTION_NIST_CONTROL_MAP: dict[str, str] = {
    # Data governance
    "dg_001": "GOVERN 1.1",
    "dg_002": "MAP 1.5",
    "dg_003": "MEASURE 2.5",
    "dg_004": "GOVERN 1.2",
    "dg_005": "MAP 2.3",
    "dg_006": "MEASURE 2.10",
    "dg_007": "MAP 3.1",
    "dg_008": "MAP 2.3",
    # Security posture
    "sp_001": "GOVERN 2.2",
    "sp_002": "MANAGE 1.3",
    "sp_003": "MEASURE 2.8",
    "sp_004": "GOVERN 2.2",
    "sp_005": "MEASURE 2.9",
    "sp_006": "MANAGE 2.4",
    "sp_007": "MEASURE 1.1",
    "sp_008": "MEASURE 2.3",
    # AI maturity
    "am_001": "GOVERN 1.1",
    "am_002": "MAP 3.5",
    "am_003": "GOVERN 1.2",
    "am_004": "MAP 3.5",
    "am_005": "MAP 2.2",
    "am_006": "GOVERN 1.7",
    "am_007": "GOVERN 1.7",
    "am_008": "GOVERN 1.2",
    "am_009": "GOVERN 1.5",
    "am_010": "MANAGE 3.3",
    # AI trustworthiness
    "at_001": "MEASURE 2.4",
    "at_002": "MEASURE 2.6",
    "at_003": "MEASURE 2.10",
    "at_004": "GOVERN 4.1",
    "at_005": "MAP 5.2",
    "at_006": "MEASURE 1.3",
    "at_007": "MEASURE 2.6",
    "at_008": "MEASURE 3.1",
    # Infrastructure readiness
    "ir_001": "GOVERN 3.1",
    "ir_002": "MANAGE 3.1",
    "ir_003": "MANAGE 4.1",
    "ir_004": "MANAGE 4.1",
    "ir_005": "MANAGE 1.3",
    "ir_006": "MANAGE 3.2",
    "ir_007": "MEASURE 3.1",
    # Compliance awareness
    "ca_001": "MAP 5.1",
    "ca_002": "GOVERN 5.1",
    "ca_003": "MAP 5.2",
    "ca_004": "MAP 5.1",
    "ca_005": "GOVERN 1.7",
    "ca_006": "GOVERN 4.2",
    "ca_007": "MANAGE 1.2",
    "ca_008": "MANAGE 1.2",
    "ca_009": "MAP 4.2",
    # Automation potential
    "ap_001": "MAP 4.1",
    "ap_002": "MANAGE 2.2",
    "ap_003": "MAP 3.1",
    "ap_004": "MANAGE 4.1",
    "ap_005": "GOVERN 3.2",
}

# ---------------------------------------------------------------------------
# Authoritative framework control map
# ---------------------------------------------------------------------------

_FRAMEWORK_CONTROL_MAP_RAW: dict[str, dict[str, list[str]]] = {
    "NIST_AI_RMF": {
        "data_governance": [
            "GOVERN 1.1",
            "GOVERN 1.2",
            "MAP 1.5",
            "MAP 2.3",
            "MAP 3.1",
            "MEASURE 2.5",
            "MEASURE 2.10",
        ],
        "security_posture": [
            "GOVERN 2.2",
            "MANAGE 1.3",
            "MANAGE 2.4",
            "MEASURE 1.1",
            "MEASURE 2.3",
            "MEASURE 2.8",
            "MEASURE 2.9",
        ],
        "ai_maturity": [
            "GOVERN 1.1",
            "GOVERN 1.2",
            "GOVERN 1.5",
            "GOVERN 1.7",
            "MAP 2.2",
            "MAP 3.5",
            "MANAGE 3.3",
        ],
        "ai_trustworthiness": [
            "GOVERN 4.1",
            "MAP 5.2",
            "MEASURE 1.3",
            "MEASURE 2.4",
            "MEASURE 2.6",
            "MEASURE 2.10",
            "MEASURE 3.1",
        ],
        "infra_readiness": [
            "GOVERN 3.1",
            "MANAGE 1.3",
            "MANAGE 3.1",
            "MANAGE 3.2",
            "MANAGE 4.1",
            "MEASURE 3.1",
        ],
        "compliance_awareness": [
            "GOVERN 1.7",
            "GOVERN 4.2",
            "GOVERN 5.1",
            "MANAGE 1.2",
            "MAP 4.2",
            "MAP 5.1",
            "MAP 5.2",
        ],
        "automation_potential": [
            "GOVERN 3.2",
            "MAP 3.1",
            "MAP 4.1",
            "MANAGE 2.2",
            "MANAGE 4.1",
        ],
        # Control-level mappings
        "access_control": ["GOVERN 2.2", "MANAGE 1.3"],
        "audit_logging": ["GOVERN 1.2", "MEASURE 2.8"],
        "data_classification": ["GOVERN 1.1", "MAP 1.5"],
        "incident_response": ["MANAGE 1.2", "MANAGE 3.2"],
        "risk_assessment": ["MAP 1.5", "MAP 2.2", "MAP 5.2", "MEASURE 1.1"],
        "vendor_management": ["GOVERN 5.1", "MAP 4.2", "MAP 5.1"],
    },
    "SOC2": {
        "data_governance": ["CC6.1", "CC6.3", "CC6.7", "C1.1", "P1.1"],
        "security_posture": ["CC6.1", "CC6.2", "CC6.6", "CC7.1", "CC7.2"],
        "ai_maturity": ["CC8.1", "PI1.1", "PI1.2"],
        "ai_trustworthiness": ["CC3.1", "CC3.2", "PI1.2", "P3.1", "P4.1"],
        "infra_readiness": ["A1.1", "A1.2", "CC6.6", "CC9.1"],
        "compliance_awareness": ["CC1.1", "CC1.2", "CC2.1", "CC3.1", "CC5.1"],
        "automation_potential": ["CC8.1", "CC8.2"],
        "access_control": ["CC6.1", "CC6.2", "CC6.3"],
        "audit_logging": ["CC7.2", "CC7.3"],
        "data_classification": ["C1.1", "C1.2"],
        "incident_response": ["CC7.4", "CC7.5"],
        "risk_assessment": ["CC3.1", "CC3.2", "CC3.3"],
        "vendor_management": ["CC9.1", "CC9.2"],
        "availability": ["A1.1", "A1.2", "A1.3"],
        "processing_integrity": ["PI1.1", "PI1.2", "PI1.3"],
        "privacy": ["P1.1", "P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1", "P8.1"],
    },
    "HIPAA": {
        "data_governance": [
            "Administrative:Security Management Process",
            "Administrative:Information Access Management",
            "Technical:Access Control",
            "Technical:Audit Controls",
        ],
        "security_posture": [
            "Administrative:Security Management Process",
            "Administrative:Workforce Security",
            "Physical:Facility Access Controls",
            "Technical:Access Control",
            "Technical:Transmission Security",
        ],
        "ai_maturity": [
            "Administrative:Security Management Process",
            "Administrative:Evaluation",
        ],
        "ai_trustworthiness": [
            "Administrative:Security Management Process",
            "Administrative:Evaluation",
            "Administrative:Risk Analysis",
        ],
        "infra_readiness": [
            "Physical:Facility Access Controls",
            "Physical:Device and Media Controls",
            "Technical:Audit Controls",
            "Technical:Transmission Security",
        ],
        "compliance_awareness": [
            "Administrative:Security Awareness and Training",
            "Administrative:Evaluation",
            "Administrative:Business Associate Contracts",
        ],
        "automation_potential": [
            "Administrative:Security Management Process",
            "Technical:Automatic Logoff",
        ],
        "access_control": [
            "Technical:Access Control",
            "Administrative:Information Access Management",
        ],
        "audit_logging": [
            "Technical:Audit Controls",
            "Administrative:Security Management Process",
        ],
        "data_classification": [
            "Administrative:Security Management Process",
            "Administrative:Evaluation",
        ],
        "incident_response": ["Administrative:Security Incident Procedures"],
        "risk_assessment": [
            "Administrative:Risk Analysis",
            "Administrative:Risk Management",
        ],
        "vendor_management": ["Administrative:Business Associate Contracts"],
    },
    "CMMC": {
        "data_governance": ["AC.1.001", "AC.1.002", "AU.2.041", "AU.2.042", "CM.2.061"],
        "security_posture": ["AC.1.001", "IA.1.076", "IA.1.077", "SC.1.175", "SC.1.176", "SI.1.210"],
        "ai_maturity": ["CM.2.061", "CM.2.062", "RM.2.141", "RM.2.142"],
        "ai_trustworthiness": ["RM.2.141", "RM.2.142", "CA.2.157", "CA.2.158"],
        "infra_readiness": ["CM.2.061", "SC.1.175", "SC.1.176", "SC.3.177", "SC.3.187"],
        "compliance_awareness": ["CA.2.157", "CA.2.158", "CA.3.161", "RM.2.141"],
        "automation_potential": ["CM.2.061", "CM.2.062"],
        "access_control": ["AC.1.001", "AC.1.002", "AC.2.006", "AC.2.007", "IA.1.076"],
        "audit_logging": ["AU.2.041", "AU.2.042", "AU.2.043", "AU.3.045"],
        "data_classification": ["MP.1.001", "MP.1.002"],
        "incident_response": ["IR.2.092", "IR.2.093", "IR.3.098"],
        "risk_assessment": ["RM.2.141", "RM.2.142", "RM.3.144"],
        "vendor_management": ["SR.3.169", "SR.3.170", "SR.5.108"],
    },
}

FRAMEWORK_CONTROL_MAP: MappingProxyType = MappingProxyType(_FRAMEWORK_CONTROL_MAP_RAW)

_DIRECT_DOMAIN_CONFIDENCE = 0.9
_CONTROL_LEVEL_CONFIDENCE = 0.95

# Status thresholds for NIST control matrix
_NIST_STATUS_MET = 75.0
_NIST_STATUS_PARTIAL = 40.0


def get_framework_mappings(control_id: str, domain: str) -> list[FrameworkMapping]:
    """Return deterministic framework mappings for a control_id / domain pair."""
    mappings: list[FrameworkMapping] = []

    for framework, control_map in sorted(_FRAMEWORK_CONTROL_MAP_RAW.items()):
        if control_id in control_map:
            refs = control_map[control_id]
            confidence = _CONTROL_LEVEL_CONFIDENCE
        elif domain in control_map:
            refs = control_map[domain]
            confidence = _DIRECT_DOMAIN_CONFIDENCE
        else:
            continue

        for ref in sorted(refs):
            mappings.append(
                FrameworkMapping(
                    framework=framework,
                    control_ref=ref,
                    confidence=confidence,
                )
            )

    return mappings


def get_supported_frameworks() -> list[str]:
    """Return the sorted list of supported framework keys."""
    return sorted(_FRAMEWORK_CONTROL_MAP_RAW.keys())


def build_nist_control_matrix(
    questions: list[dict],
    responses: dict,
    question_score_fn,
) -> list[dict]:
    """Build the deterministic NIST AI RMF control matrix from assessment data.

    Groups questions by their nist_control_id, scores each control based on
    contributing question responses, and maps status as met/partial/gap/not_assessed.

    question_score_fn: callable(question_dict, raw_value) -> float | None
      Pass assessments._question_score to avoid circular imports.
    """
    control_scores: dict[str, list[float]] = {}
    control_question_ids: dict[str, list[str]] = {}

    for q in questions:
        control_id = q.get("nist_control_id") or QUESTION_NIST_CONTROL_MAP.get(
            q.get("id", "")
        )
        if not control_id:
            continue

        q_id = q.get("id", "")
        raw = responses.get(q_id)
        score = question_score_fn(q, raw) if raw is not None else None

        if control_id not in control_scores:
            control_scores[control_id] = []
            control_question_ids[control_id] = []

        control_question_ids[control_id].append(q_id)
        if score is not None:
            control_scores[control_id].append(score)

    matrix = []
    for control_id in sorted(control_scores.keys()):
        scores = control_scores[control_id]
        ctrl_info = NIST_AI_RMF_CONTROLS.get(control_id, {})

        if not scores:
            status = "not_assessed"
            avg_score = None
        else:
            avg_score = round(sum(scores) / len(scores), 1)
            if avg_score >= _NIST_STATUS_MET:
                status = "met"
            elif avg_score >= _NIST_STATUS_PARTIAL:
                status = "partial"
            else:
                status = "gap"

        matrix.append(
            {
                "control_id": control_id,
                "function": ctrl_info.get("function", control_id.split(" ")[0]),
                "title": ctrl_info.get("title", control_id),
                "description": ctrl_info.get("description", ""),
                "status": status,
                "score": avg_score,
                "question_ids": control_question_ids[control_id],
            }
        )

    return matrix


def nist_coverage_text(matrix: list[dict]) -> str:
    """Format the NIST AI RMF control matrix as prompt-ready context text.

    Groups controls by function (GOVERN, MAP, MEASURE, MANAGE) and renders
    each control with its status symbol and score so Claude can reference
    specific gaps in its narrative.
    """
    status_symbol = {
        "met": "✓ MET    ",
        "partial": "~ PARTIAL",
        "gap": "✗ GAP    ",
        "not_assessed": "  N/A    ",
    }
    function_labels = {
        "GOVERN": "GOVERN (Accountability & Culture)",
        "MAP": "MAP (Risk Identification & Context)",
        "MEASURE": "MEASURE (Testing & Evaluation)",
        "MANAGE": "MANAGE (Risk Response & Treatment)",
    }

    by_function: dict[str, list[dict]] = {}
    for entry in matrix:
        fn = entry["function"]
        by_function.setdefault(fn, []).append(entry)

    lines = []
    for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
        entries = by_function.get(fn, [])
        if not entries:
            continue
        assessed = [e for e in entries if e["status"] != "not_assessed"]
        gaps = [e for e in assessed if e["status"] == "gap"]
        partials = [e for e in assessed if e["status"] == "partial"]
        label = function_labels.get(fn, fn)
        lines.append(
            f"\n{label}: {len(assessed)}/{len(entries)} controls assessed, {len(gaps)} gaps, {len(partials)} partial"
        )
        for entry in entries:
            sym = status_symbol.get(entry["status"], "  ?      ")
            score_str = (
                f"(score: {entry['score']})"
                if entry["score"] is not None
                else "(not assessed)"
            )
            lines.append(
                f"  {sym} {entry['control_id']} — {entry['title']} {score_str}"
            )

    return "\n".join(lines) if lines else "No NIST control data available."
