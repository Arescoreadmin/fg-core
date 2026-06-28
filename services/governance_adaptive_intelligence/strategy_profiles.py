"""services/governance_adaptive_intelligence/strategy_profiles.py

Static strategy profile definitions. No I/O. No AI. No LLMs.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

from services.governance_adaptive_intelligence.models import StrategyProfile

STRATEGY_PROFILES: dict[str, dict] = {
    "HEALTHCARE": {
        "recommended_controls": [
            "access_control",
            "encryption",
            "audit_logging",
            "incident_response",
        ],
        "recommended_remediation_types": ["POLICY", "TECHNICAL", "TRAINING"],
        "historical_success_patterns": [
            "verification_first",
            "documentation_priority",
        ],
        "historical_failure_patterns": [
            "delayed_remediation",
            "incomplete_evidence",
        ],
        "confidence": "CALIBRATED_MEDIUM",
    },
    "FINANCIAL": {
        "recommended_controls": [
            "access_control",
            "encryption",
            "fraud_detection",
            "audit_logging",
            "change_management",
        ],
        "recommended_remediation_types": ["TECHNICAL", "POLICY", "PROCESS"],
        "historical_success_patterns": [
            "automated_verification",
            "rapid_patch_cycle",
        ],
        "historical_failure_patterns": [
            "manual_process_reliance",
            "incomplete_coverage",
        ],
        "confidence": "CALIBRATED_HIGH",
    },
    "INSURANCE": {
        "recommended_controls": [
            "data_governance",
            "access_control",
            "audit_logging",
            "risk_scoring",
        ],
        "recommended_remediation_types": ["POLICY", "PROCESS", "TECHNICAL"],
        "historical_success_patterns": [
            "risk_tiering",
            "attestation_cycles",
        ],
        "historical_failure_patterns": [
            "stale_evidence",
            "siloed_remediation",
        ],
        "confidence": "CALIBRATED_MEDIUM",
    },
    "GOVERNMENT": {
        "recommended_controls": [
            "access_control",
            "audit_logging",
            "incident_response",
            "supply_chain_risk",
        ],
        "recommended_remediation_types": ["POLICY", "TECHNICAL", "TRAINING"],
        "historical_success_patterns": [
            "mandatory_attestation",
            "centralized_control",
        ],
        "historical_failure_patterns": [
            "slow_approval_cycles",
            "legacy_system_gaps",
        ],
        "confidence": "CALIBRATED_MEDIUM",
    },
    "LEGAL": {
        "recommended_controls": [
            "data_governance",
            "access_control",
            "encryption",
            "audit_logging",
        ],
        "recommended_remediation_types": ["POLICY", "PROCESS", "TRAINING"],
        "historical_success_patterns": [
            "privilege_separation",
            "documentation_first",
        ],
        "historical_failure_patterns": [
            "undocumented_exceptions",
            "ad_hoc_access",
        ],
        "confidence": "CALIBRATED_LOW",
    },
    "MSP": {
        "recommended_controls": [
            "multi_tenant_isolation",
            "access_control",
            "audit_logging",
            "change_management",
        ],
        "recommended_remediation_types": ["TECHNICAL", "PROCESS", "POLICY"],
        "historical_success_patterns": [
            "automation_first",
            "tenant_scoped_remediation",
        ],
        "historical_failure_patterns": [
            "cross_tenant_contamination",
            "manual_escalation_delays",
        ],
        "confidence": "CALIBRATED_MEDIUM",
    },
    "GENERAL": {
        "recommended_controls": [
            "access_control",
            "audit_logging",
            "incident_response",
        ],
        "recommended_remediation_types": ["POLICY", "TECHNICAL", "TRAINING"],
        "historical_success_patterns": [
            "consistent_verification",
            "timely_remediation",
        ],
        "historical_failure_patterns": [
            "delayed_response",
            "insufficient_evidence",
        ],
        "confidence": "CALIBRATED_UNKNOWN",
    },
}


def get_strategy_profile(profile: StrategyProfile) -> dict:
    """Return the strategy profile dict for the given profile enum."""
    return STRATEGY_PROFILES.get(profile.value, STRATEGY_PROFILES["GENERAL"])
