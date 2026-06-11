"""Trust Enforcement Authority — PR 1.5.

FrostGate Principle: Trust But Verify.
If verification fails, the platform must be capable of stopping the workflow.

Enforcement modes (FG_PROVENANCE_MODE):
  off    — validation runs, failures recorded, no enforcement action
  warn   — validation runs, failures logged and audited, operations continue
  strict — validation runs, failures block the operation, TrustEnforcementError raised

Trust score (0–100, deterministic, no AI or heuristics):
  100  fully trusted (all checks pass)
   75  authority warning (legacy unsigned record)
   50  replay integrity issue
   25  link integrity issue
    0  chain failure / invalid signature / tenant or engagement mismatch

Usage:
    from services.field_assessment.trust_enforcement import (
        TrustInputs, ProvenanceMode, enforce_full_trust_chain,
        TrustEnforcementError,
    )

    inputs = TrustInputs(
        chain_valid=chain_result["chain_valid"],
        signature_valid=sig_result["valid"],       # None = legacy_unsigned
        link_valid=link_result["link_valid"],
        replay_valid=replay_result["chain_valid"],
        tenant_valid=True,
        engagement_valid=True,
    )
    decision = enforce_full_trust_chain(
        inputs,
        mode=ProvenanceMode.from_env(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,                                     # optional — emits audit event when set
    )
    # Raises TrustEnforcementError in STRICT mode if decision.allowed is False.

Moat extensibility:
    The enforcement engine is deliberately decoupled from evidence records.
    Future authorities (Identity, RBAC, Agent, AI Governance, AGI Governance)
    supply TrustInputs from their own verification systems and call the same
    enforce_full_trust_chain() entry point.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from prometheus_client import Counter

from services.canonical import utc_iso8601_z_now

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
# tenant label intentionally omitted — unbounded cardinality; use audit events
# for per-tenant trust state queries.

TRUST_VALIDATION_TOTAL = Counter(
    "frostgate_trust_validation_total",
    "Total trust enforcement evaluations by mode and decision",
    ["mode", "decision"],
)

TRUST_VALIDATION_FAILED_TOTAL = Counter(
    "frostgate_trust_validation_failed_total",
    "Total trust enforcement failures by mode and violation type",
    ["mode", "violation_type"],
)

TRUST_VALIDATION_WARNING_TOTAL = Counter(
    "frostgate_trust_validation_warning_total",
    "Total trust enforcement evaluations that produced a warn decision",
    ["mode"],
)

TRUST_VALIDATION_BLOCKED_TOTAL = Counter(
    "frostgate_trust_validation_blocked_total",
    "Total trust enforcement evaluations that blocked an operation (strict mode)",
    ["mode"],
)

TRUST_CHAIN_FAILURE_TOTAL = Counter(
    "frostgate_trust_chain_failure_total",
    "Total provenance chain integrity failures by mode and violation type",
    ["mode", "violation_type"],
)

# ---------------------------------------------------------------------------
# Enforcement error
# ---------------------------------------------------------------------------


class TrustEnforcementError(RuntimeError):
    """Raised in STRICT mode when a trust gate blocks the operation.

    Wraps the TrustDecision so callers can inspect violations and trust_score
    without reparsing the error message.
    """

    def __init__(self, decision: "TrustDecision") -> None:
        self.decision = decision
        super().__init__(
            f"trust_enforcement_blocked: score={decision.trust_score} "
            f"violations={list(decision.violations)} mode={decision.mode}"
        )


# ---------------------------------------------------------------------------
# Enforcement mode
# ---------------------------------------------------------------------------


class ProvenanceMode(str, Enum):
    OFF = "off"
    WARN = "warn"
    STRICT = "strict"

    @classmethod
    def from_env(cls) -> "ProvenanceMode":
        """Read FG_PROVENANCE_MODE from the environment; default=warn."""
        raw = os.getenv("FG_PROVENANCE_MODE", "warn").strip().lower()
        try:
            return cls(raw)
        except ValueError:
            return cls.WARN


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _allow_legacy_unsigned() -> bool:
    """FG_ALLOW_LEGACY_UNSIGNED controls STRICT mode behavior for pre-authority records."""
    return _env_bool("FG_ALLOW_LEGACY_UNSIGNED", False)


# ---------------------------------------------------------------------------
# Trust inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustInputs:
    """Pre-computed trust state inputs for the enforcement engine.

    The enforcement engine evaluates — it does not compute — these values.
    Callers derive each field from their respective authority systems:

      chain_valid      from trust_replay.verify_full_provenance_chain()
      signature_valid  from evidence_authority.verify_provenance_signature()
                       None = legacy_unsigned (warning, not failure)
                       True = verified, False = invalid (hard failure)
      link_valid       from report_link_authority.verify_report_links_bulk()
      replay_valid     from trust_replay chain_valid output
      tenant_valid     caller-enforced tenant boundary check
      engagement_valid caller-enforced engagement boundary check
      is_legacy        True for records that predate the authority system;
                       combined with FG_ALLOW_LEGACY_UNSIGNED to control
                       STRICT mode behavior for legacy records
    """

    chain_valid: bool = True
    signature_valid: bool | None = True
    link_valid: bool = True
    replay_valid: bool = True
    tenant_valid: bool = True
    engagement_valid: bool = True
    is_legacy: bool = False


# ---------------------------------------------------------------------------
# Trust decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustDecision:
    """Immutable enforcement decision output.

    Every decision is reconstructable from the inputs + mode at verification time.
    Store verified_at alongside the decision to support auditor queries:
      "What trust state existed when this decision was made?"
    """

    allowed: bool
    mode: str
    decision: str  # allow | warn | block
    severity: str  # low | medium | high | critical
    violations: list[str]
    verified_at: str
    trust_score: int  # 0–100, deterministic


# ---------------------------------------------------------------------------
# Violation constants
# ---------------------------------------------------------------------------

_CRITICAL_VIOLATIONS = frozenset(
    {"chain_failure", "tenant_mismatch", "engagement_mismatch"}
)
_HIGH_VIOLATIONS = frozenset({"authority_failure"})
_MEDIUM_VIOLATIONS = frozenset({"report_link_failure", "replay_failure"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_hard_violations(inputs: TrustInputs) -> list[str]:
    """Hard violations that block operations in STRICT mode."""
    v: list[str] = []
    if not inputs.chain_valid:
        v.append("chain_failure")
    if not inputs.tenant_valid:
        v.append("tenant_mismatch")
    if not inputs.engagement_valid:
        v.append("engagement_mismatch")
    if inputs.signature_valid is False:
        v.append("authority_failure")
    if not inputs.link_valid:
        v.append("report_link_failure")
    if not inputs.replay_valid:
        v.append("replay_failure")
    return v


def _collect_all_violations(inputs: TrustInputs) -> list[str]:
    """All violations including soft warnings (legacy_unsigned)."""
    v = _collect_hard_violations(inputs)
    if inputs.signature_valid is None:
        v.append("legacy_unsigned")
    return v


def _severity_for(violations: list[str]) -> str:
    if any(v in _CRITICAL_VIOLATIONS for v in violations):
        return "critical"
    if any(v in _HIGH_VIOLATIONS for v in violations):
        return "high"
    if any(v in _MEDIUM_VIOLATIONS for v in violations):
        return "medium"
    if violations:
        return "low"
    return "low"


def _compute_trust_score(inputs: TrustInputs) -> int:
    """Deterministic 0–100 trust score. No AI, no heuristics, no probabilistic output.

    Score hierarchy (worst violation wins):
      0   chain_failure | invalid signature | tenant mismatch | engagement mismatch
      25  report link integrity failure
      50  replay integrity issue
      75  legacy unsigned (authority warning — signed records expected but absent)
      100 fully trusted
    """
    if (
        not inputs.chain_valid
        or not inputs.tenant_valid
        or not inputs.engagement_valid
        or inputs.signature_valid is False
    ):
        return 0
    if not inputs.link_valid:
        return 25
    if not inputs.replay_valid:
        return 50
    if inputs.signature_valid is None:
        return 75
    return 100


def _apply_mode(
    hard_violations: list[str],
    all_violations: list[str],
    mode: ProvenanceMode,
    is_legacy: bool,
) -> tuple[bool, str, str]:
    """Derive (allowed, decision, severity) from violations and mode."""
    severity = _severity_for(all_violations)

    if mode == ProvenanceMode.OFF:
        # Validation ran; failures recorded; no enforcement
        if not all_violations:
            return True, "allow", "low"
        return True, "allow", severity

    if mode == ProvenanceMode.WARN:
        # Failures logged and audited; operations continue
        if not all_violations:
            return True, "allow", "low"
        return True, "warn", severity

    # STRICT mode — fail closed
    if hard_violations:
        return False, "block", severity

    if not all_violations:
        return True, "allow", "low"

    # Only soft violations remain (legacy_unsigned).
    # FG_ALLOW_LEGACY_UNSIGNED=true permits legacy records with a warning.
    if is_legacy and _allow_legacy_unsigned():
        return True, "warn", "low"

    # Legacy unsigned blocked by default in STRICT mode.
    return False, "block", "low"


# ---------------------------------------------------------------------------
# Metrics emission (lazy import to decouple service from api layer)
# ---------------------------------------------------------------------------


def _emit_metrics(decision: TrustDecision, all_violations: list[str]) -> None:
    """Emit Prometheus metrics for an enforcement decision."""
    mode = decision.mode
    dec = decision.decision

    TRUST_VALIDATION_TOTAL.labels(mode=mode, decision=dec).inc()

    if all_violations:
        for vtype in all_violations:
            TRUST_VALIDATION_FAILED_TOTAL.labels(mode=mode, violation_type=vtype).inc()
            if vtype in ("chain_failure", "tenant_mismatch", "engagement_mismatch"):
                TRUST_CHAIN_FAILURE_TOTAL.labels(mode=mode, violation_type=vtype).inc()

    if dec == "warn":
        TRUST_VALIDATION_WARNING_TOTAL.labels(mode=mode).inc()
    elif dec == "block":
        TRUST_VALIDATION_BLOCKED_TOTAL.labels(mode=mode).inc()


# ---------------------------------------------------------------------------
# Audit event emission
# ---------------------------------------------------------------------------


def _emit_enforcement_audit_event(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    decision: TrustDecision,
    gate: str,
) -> None:
    """Emit an H13-atomic trust enforcement audit event.

    Must be called BEFORE db.commit() so the audit event commits with the mutation.
    """
    from services.field_assessment.audit import emit_engagement_audit_event  # noqa: PLC0415

    event_type_map = {
        "allow": "trust_validation_passed",
        "warn": "trust_validation_warning",
        "block": "trust_validation_blocked",
    }
    event_type = event_type_map.get(decision.decision, "trust_validation_passed")

    # Emit per-violation events for chain and authority failures
    if "chain_failure" in decision.violations:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="trust_chain_failure",
            actor="trust_enforcement_service",
            actor_type="system",
            reason_code="TRUST_CHAIN_FAILURE",
            entity_type="trust_gate",
            entity_id=gate,
            payload={
                "gate": gate,
                "trust_score": decision.trust_score,
                "mode": decision.mode,
                "violations": decision.violations,
                "decision": decision.decision,
            },
        )

    if "authority_failure" in decision.violations:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="authority_failure",
            actor="trust_enforcement_service",
            actor_type="system",
            reason_code="AUTHORITY_FAILURE",
            entity_type="trust_gate",
            entity_id=gate,
            payload={
                "gate": gate,
                "trust_score": decision.trust_score,
                "mode": decision.mode,
                "violations": decision.violations,
                "decision": decision.decision,
            },
        )

    if "report_link_failure" in decision.violations:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="report_link_failure",
            actor="trust_enforcement_service",
            actor_type="system",
            reason_code="REPORT_LINK_FAILURE",
            entity_type="trust_gate",
            entity_id=gate,
            payload={
                "gate": gate,
                "trust_score": decision.trust_score,
                "mode": decision.mode,
                "violations": decision.violations,
                "decision": decision.decision,
            },
        )

    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type=event_type,
        actor="trust_enforcement_service",
        actor_type="system",
        reason_code=f"TRUST_ENFORCEMENT_{decision.decision.upper()}",
        entity_type="trust_gate",
        entity_id=gate,
        payload={
            "gate": gate,
            "trust_score": decision.trust_score,
            "mode": decision.mode,
            "decision": decision.decision,
            "violations": decision.violations,
            "severity": decision.severity,
            "verified_at": decision.verified_at,
        },
    )


# ---------------------------------------------------------------------------
# Core gate
# ---------------------------------------------------------------------------


def _enforce_gate(
    inputs: TrustInputs,
    *,
    mode: ProvenanceMode,
    tenant_id: str,
    engagement_id: str,
    db: Any = None,
    gate: str,
) -> TrustDecision:
    """Core enforcement gate — evaluate, emit, and optionally block.

    In STRICT mode, raises TrustEnforcementError when not allowed.
    In OFF/WARN modes, always returns (never raises).
    """
    hard_violations = _collect_hard_violations(inputs)
    all_violations = _collect_all_violations(inputs)
    trust_score = _compute_trust_score(inputs)
    allowed, dec_str, severity = _apply_mode(
        hard_violations, all_violations, mode, inputs.is_legacy
    )

    decision = TrustDecision(
        allowed=allowed,
        mode=mode.value,
        decision=dec_str,
        severity=severity,
        violations=all_violations,
        verified_at=utc_iso8601_z_now(),
        trust_score=trust_score,
    )

    _emit_metrics(decision, all_violations)

    if db is not None:
        _emit_enforcement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            decision=decision,
            gate=gate,
        )

    if not allowed and mode == ProvenanceMode.STRICT:
        raise TrustEnforcementError(decision)

    return decision


# ---------------------------------------------------------------------------
# Public enforcement API
# ---------------------------------------------------------------------------


def evaluate_trust_state(
    inputs: TrustInputs,
    *,
    tenant_id: str,
    engagement_id: str,
) -> TrustDecision:
    """Evaluate trust state without enforcement.

    Always returns a TrustDecision — never raises, never blocks.
    Use this for dashboard queries, reporting, or when you need the trust state
    for observability without triggering enforcement side effects.

    The decision field reflects WARN-mode semantics: violations produce "warn",
    not "block". Callers must use enforce_* functions for enforcement.
    """
    all_violations = _collect_all_violations(inputs)
    trust_score = _compute_trust_score(inputs)
    severity = _severity_for(all_violations)

    if not all_violations:
        dec_str = "allow"
    else:
        dec_str = "warn"

    return TrustDecision(
        allowed=True,
        mode=ProvenanceMode.WARN.value,
        decision=dec_str,
        severity=severity,
        violations=all_violations,
        verified_at=utc_iso8601_z_now(),
        trust_score=trust_score,
    )


def enforce_provenance_integrity(
    inputs: TrustInputs,
    *,
    mode: ProvenanceMode,
    tenant_id: str,
    engagement_id: str,
    db: Any = None,
) -> TrustDecision:
    """Enforce evidence chain integrity: chain_valid, tenant_valid, engagement_valid.

    This gate targets the structural provenance chain — hash continuity and
    cross-tenant/cross-engagement contamination. Signature and link validity
    are evaluated in their respective gates.
    """
    filtered = TrustInputs(
        chain_valid=inputs.chain_valid,
        signature_valid=True,  # not evaluated here
        link_valid=True,  # not evaluated here
        replay_valid=True,  # not evaluated here
        tenant_valid=inputs.tenant_valid,
        engagement_valid=inputs.engagement_valid,
        is_legacy=inputs.is_legacy,
    )
    return _enforce_gate(
        filtered,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
        gate="provenance_integrity",
    )


def enforce_evidence_authority(
    inputs: TrustInputs,
    *,
    mode: ProvenanceMode,
    tenant_id: str,
    engagement_id: str,
    db: Any = None,
) -> TrustDecision:
    """Enforce Ed25519 signature authority on evidence provenance records.

    Evaluates signature_valid. Legacy unsigned records (signature_valid=None)
    produce a warning; invalid signatures (signature_valid=False) are hard failures.
    Tenant and engagement validity are always checked as cross-cutting concerns.
    """
    filtered = TrustInputs(
        chain_valid=True,  # not evaluated here
        signature_valid=inputs.signature_valid,
        link_valid=True,  # not evaluated here
        replay_valid=True,  # not evaluated here
        tenant_valid=inputs.tenant_valid,
        engagement_valid=inputs.engagement_valid,
        is_legacy=inputs.is_legacy,
    )
    return _enforce_gate(
        filtered,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
        gate="evidence_authority",
    )


def enforce_report_link_authority(
    inputs: TrustInputs,
    *,
    mode: ProvenanceMode,
    tenant_id: str,
    engagement_id: str,
    db: Any = None,
) -> TrustDecision:
    """Enforce evidence-to-report link integrity.

    Evaluates link_valid. An invalid report link means the evidence-to-report
    binding was tampered with or could not be verified.
    Tenant and engagement validity are always checked as cross-cutting concerns.
    """
    filtered = TrustInputs(
        chain_valid=True,  # not evaluated here
        signature_valid=True,  # not evaluated here
        link_valid=inputs.link_valid,
        replay_valid=True,  # not evaluated here
        tenant_valid=inputs.tenant_valid,
        engagement_valid=inputs.engagement_valid,
        is_legacy=inputs.is_legacy,
    )
    return _enforce_gate(
        filtered,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
        gate="report_link_authority",
    )


def enforce_full_trust_chain(
    inputs: TrustInputs,
    *,
    mode: ProvenanceMode,
    tenant_id: str,
    engagement_id: str,
    db: Any = None,
) -> TrustDecision:
    """Enforce the complete trust chain across all dimensions.

    Evaluates all inputs: chain_valid, signature_valid, link_valid,
    replay_valid, tenant_valid, engagement_valid.

    In STRICT mode, any hard violation raises TrustEnforcementError.
    In OFF/WARN mode, always returns a TrustDecision.

    This is the primary integration point for:
      - Evidence creation and review
      - Evidence approval
      - Report finalization and export
      - Trust replay verification
      - Any operation consuming provenance records
    """
    return _enforce_gate(
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
        gate="full_trust_chain",
    )
