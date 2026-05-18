"""Deterministic alert rules catalog.

All rules are pure Python constants — no I/O, no side effects.

Rules catalog contract:
  - One rule per AlertRuleClass covering all DriftType values.
  - RULES_BY_DRIFT_TYPE maps DriftType.value → AlertRule for O(1) lookup.
  - Rule severity_threshold is the minimum source drift severity that triggers
    alert generation for that rule class.
  - Version pins: ALERT_GENERATION_VERSION and ESCALATION_POLICY_VERSION are
    frozen for this release. Bumping either invalidates cached dedup windows.

Severity thresholds (per domain):
  POLICY:       severity_threshold=LOW (any policy drift is noteworthy)
  PROVENANCE:   severity_threshold=MODERATE (high-signal governance failure)
  PROVIDER:     severity_threshold=LOW (any provider governance issue tracked)
  GROUNDING:    severity_threshold=MODERATE (grounded-answer enforcement signal)
  RETRIEVAL:    severity_threshold=MODERATE (retrieval governance degradation)
  AUDIT:        severity_threshold=HIGH (audit integrity is compliance-critical)
  GOVERNANCE:   severity_threshold=LOW (framework and readiness regression)
  RUNTIME:      severity_threshold=MODERATE (runtime enforcement degradation)
  REPLAY:       severity_threshold=LOW (replay integrity is audit-critical)
  MONITORING_VISIBILITY: severity_threshold=LOW (all visibility events tracked)
"""

from __future__ import annotations

from .models import AlertCertainty, AlertRule, AlertRuleClass, AlertSeverity

ALERT_GENERATION_VERSION = "1.0"
ESCALATION_POLICY_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Default alert rules — one per AlertRuleClass
# ---------------------------------------------------------------------------

_POLICY_RULE = AlertRule(
    rule_id="rule:policy:001",
    rule_class=AlertRuleClass.POLICY,
    name="Policy Drift Detected",
    severity_threshold=AlertSeverity.LOW,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on POLICY_DRIFT events. "
        "Covers disabled policies, enforcement mode degradation, "
        "policy state changes, and policy hash drift."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_PROVENANCE_RULE = AlertRule(
    rule_id="rule:provenance:001",
    rule_class=AlertRuleClass.PROVENANCE,
    name="Provenance Enforcement Degraded",
    severity_threshold=AlertSeverity.MODERATE,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on PROVENANCE_ENFORCEMENT_DISABLED and PROVENANCE_DEGRADATION events. "
        "Covers provenance validation disabled, citation enforcement disabled, "
        "and high provenance failure rates."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_PROVIDER_RULE = AlertRule(
    rule_id="rule:provider:001",
    rule_class=AlertRuleClass.PROVIDER,
    name="Provider Governance Change Detected",
    severity_threshold=AlertSeverity.LOW,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on PROVIDER_GOVERNANCE_CHANGE and PROVIDER_BLOCKED events. "
        "Covers blocked, restricted, and unknown provider governance states."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_GROUNDING_RULE = AlertRule(
    rule_id="rule:grounding:001",
    rule_class=AlertRuleClass.GROUNDING,
    name="Grounded Answer Enforcement Failed",
    severity_threshold=AlertSeverity.MODERATE,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on GROUNDED_ANSWER_ENFORCEMENT_FAILED events. "
        "Covers grounded-answer enforcement disabled or failed."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_RETRIEVAL_RULE = AlertRule(
    rule_id="rule:retrieval:001",
    rule_class=AlertRuleClass.RETRIEVAL,
    name="Retrieval Governance Degradation Detected",
    severity_threshold=AlertSeverity.MODERATE,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on RETRIEVAL_DEGRADATION and RETRIEVAL_POLICY_MISMATCH events. "
        "Covers retrieval policy disabled, reranker degradation, and high failure rates."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_AUDIT_RULE = AlertRule(
    rule_id="rule:audit:001",
    rule_class=AlertRuleClass.AUDIT,
    name="Audit Integrity Failure",
    severity_threshold=AlertSeverity.HIGH,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=30,
    burst_ceiling=5,
    description=(
        "Triggered on AUDIT_INTEGRITY_FAILURE and AUDIT_CHAIN_BROKEN events. "
        "Covers audit chain broken (BLOCKING), high failure rates (CRITICAL), "
        "and invariant failures (HIGH). Cooldown is tighter due to compliance criticality."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_GOVERNANCE_RULE = AlertRule(
    rule_id="rule:governance:001",
    rule_class=AlertRuleClass.GOVERNANCE,
    name="Framework Compliance Degradation",
    severity_threshold=AlertSeverity.LOW,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=120,
    burst_ceiling=20,
    description=(
        "Triggered on FRAMEWORK_COMPLIANCE_DEGRADATION, MISSING_REQUIRED_CONTROL, "
        "READINESS_REGRESSION, STALE_EVIDENCE, MISSING_EVIDENCE, "
        "INVALID_EVIDENCE_INTEGRITY, and INVALID_EVIDENCE_LINKAGE events. "
        "Covers all governance readiness degradation not covered by other rule classes."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_RUNTIME_RULE = AlertRule(
    rule_id="rule:runtime:001",
    rule_class=AlertRuleClass.RUNTIME,
    name="Runtime Governance Degradation",
    severity_threshold=AlertSeverity.MODERATE,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=10,
    description=(
        "Triggered on RUNTIME_GOVERNANCE_DEGRADATION events. "
        "Covers enforcement mode disabled (CRITICAL), permissive (MODERATE), "
        "unknown (LOW), and high signal failure rates (HIGH)."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_REPLAY_RULE = AlertRule(
    rule_id="rule:replay:001",
    rule_class=AlertRuleClass.REPLAY,
    name="Replay Integrity Degradation",
    severity_threshold=AlertSeverity.LOW,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=60,
    burst_ceiling=5,
    description=(
        "Triggered on REPLAY_INTEGRITY_DEGRADATION events. "
        "Covers replay contract integrity failures that affect forensic reconstructability."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

_MONITORING_VISIBILITY_RULE = AlertRule(
    rule_id="rule:monitoring_visibility:001",
    rule_class=AlertRuleClass.MONITORING_VISIBILITY,
    name="Monitoring Visibility Degradation",
    severity_threshold=AlertSeverity.LOW,
    certainty_threshold=AlertCertainty.SUSPECTED,
    cooldown_window_minutes=30,
    burst_ceiling=5,
    description=(
        "Triggered on MONITORING_VISIBILITY_DEGRADATION events. "
        "Covers monitoring evaluator failures and degraded governance visibility."
    ),
    alert_generation_version=ALERT_GENERATION_VERSION,
    escalation_policy_version=ESCALATION_POLICY_VERSION,
)

DEFAULT_ALERT_RULES: tuple[AlertRule, ...] = (
    _POLICY_RULE,
    _PROVENANCE_RULE,
    _PROVIDER_RULE,
    _GROUNDING_RULE,
    _RETRIEVAL_RULE,
    _AUDIT_RULE,
    _GOVERNANCE_RULE,
    _RUNTIME_RULE,
    _REPLAY_RULE,
    _MONITORING_VISIBILITY_RULE,
)

# ---------------------------------------------------------------------------
# DriftType → AlertRule mapping
# ---------------------------------------------------------------------------

# Maps DriftType.value (string) → AlertRule for O(1) lookup in generator.
RULES_BY_DRIFT_TYPE: dict[str, AlertRule] = {
    # Policy domain
    "policy_drift": _POLICY_RULE,
    # Provenance domain
    "provenance_enforcement_disabled": _PROVENANCE_RULE,
    "provenance_degradation": _PROVENANCE_RULE,
    # Grounding domain
    "grounded_answer_enforcement_failed": _GROUNDING_RULE,
    # Provider domain
    "provider_governance_change": _PROVIDER_RULE,
    "provider_blocked": _PROVIDER_RULE,
    # Retrieval domain
    "retrieval_degradation": _RETRIEVAL_RULE,
    "retrieval_policy_mismatch": _RETRIEVAL_RULE,
    # Audit domain
    "audit_integrity_failure": _AUDIT_RULE,
    "audit_chain_broken": _AUDIT_RULE,
    # Governance / readiness domain
    "stale_evidence": _GOVERNANCE_RULE,
    "missing_evidence": _GOVERNANCE_RULE,
    "invalid_evidence_integrity": _GOVERNANCE_RULE,
    "invalid_evidence_linkage": _GOVERNANCE_RULE,
    "readiness_regression": _GOVERNANCE_RULE,
    "framework_compliance_degradation": _GOVERNANCE_RULE,
    "missing_required_control": _GOVERNANCE_RULE,
    # Runtime domain
    "runtime_governance_degradation": _RUNTIME_RULE,
    # Replay domain
    "replay_integrity_degradation": _REPLAY_RULE,
    # Monitoring visibility domain
    "monitoring_visibility_degradation": _MONITORING_VISIBILITY_RULE,
}
