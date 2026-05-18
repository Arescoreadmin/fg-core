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

from .models import FrameworkMapping

# ---------------------------------------------------------------------------
# Authoritative framework control map
# ---------------------------------------------------------------------------
# Structure: { framework_key: { domain_or_control_id: [control_refs] } }
# ---------------------------------------------------------------------------

FRAMEWORK_CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    "NIST_AI_RMF": {
        "data_governance": ["GOVERN 1.1", "GOVERN 1.2", "MAP 1.5", "MEASURE 2.5"],
        "security_posture": ["GOVERN 2.2", "MANAGE 1.3", "MANAGE 2.4", "MEASURE 2.8"],
        "ai_maturity": ["GOVERN 4.1", "MAP 2.2", "MAP 3.5", "MEASURE 1.1"],
        "infra_readiness": ["GOVERN 3.1", "MANAGE 3.1", "MANAGE 4.1"],
        "compliance_awareness": ["GOVERN 1.7", "GOVERN 5.1", "MAP 5.1", "MAP 5.2"],
        "automation_potential": ["GOVERN 4.2", "MAP 4.1", "MANAGE 2.2"],
        # Control-level mappings
        "access_control": ["GOVERN 2.2", "MANAGE 1.3"],
        "audit_logging": ["GOVERN 1.2", "MEASURE 2.8"],
        "data_classification": ["GOVERN 1.1", "MAP 1.5"],
        "incident_response": ["MANAGE 2.4", "MANAGE 3.2"],
        "risk_assessment": ["MAP 1.5", "MAP 2.2", "MEASURE 1.1"],
        "vendor_management": ["GOVERN 5.1", "MAP 5.2"],
    },
    "SOC2": {
        "data_governance": ["CC6.1", "CC6.3", "CC6.7", "C1.1", "P1.1"],
        "security_posture": ["CC6.1", "CC6.2", "CC6.6", "CC7.1", "CC7.2"],
        "ai_maturity": ["CC8.1", "PI1.1", "PI1.2"],
        "infra_readiness": ["A1.1", "A1.2", "CC6.6", "CC9.1"],
        "compliance_awareness": ["CC1.1", "CC1.2", "CC2.1", "CC3.1", "CC5.1"],
        "automation_potential": ["CC8.1", "CC8.2"],
        # Control-level mappings
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
        # Control-level mappings
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
}

# Confidence tiers for explicit vs inferred mappings
_DIRECT_DOMAIN_CONFIDENCE = 0.9
_CONTROL_LEVEL_CONFIDENCE = 0.95


def get_framework_mappings(control_id: str, domain: str) -> list[FrameworkMapping]:
    """Return deterministic framework mappings for a control_id / domain pair.

    Looks up by control_id first, then falls back to domain.
    Returns an empty list for unknown control_ids and domains.

    All returned FrameworkMapping instances are deterministic — same inputs
    always produce the same list in the same order.
    """
    mappings: list[FrameworkMapping] = []

    for framework, control_map in sorted(FRAMEWORK_CONTROL_MAP.items()):
        # Prefer control-level lookup
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
    return sorted(FRAMEWORK_CONTROL_MAP.keys())
