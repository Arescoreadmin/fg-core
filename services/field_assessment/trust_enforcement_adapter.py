"""Trust Enforcement Adapter — workflow-level enforcement integration layer.

Decouples production workflows from enforcement implementation details.
Each function builds TrustInputs for its operation context and delegates
exclusively to enforce_full_trust_chain() — no workflow assembles TrustInputs
manually.

Coverage Matrix
---------------
  Evidence Creation      Protected  enforce_evidence_creation()
  Evidence Review        Protected  enforce_evidence_review()
  Evidence Approval      Protected  enforce_evidence_approval()
  Report Finalization    Protected  enforce_report_finalization()
  Report Export          Protected  enforce_report_export()
  Trust Replay           Protected  enforce_trust_replay()

Future authorities (Identity, RBAC, Agent, AGI Governance) extend this matrix
by adding adapter functions that build TrustInputs from their own context —
no workflow code changes required.

Environment variables
---------------------
  FG_PROVENANCE_MODE        off | warn | strict  (default: warn)
  FG_ALLOW_LEGACY_UNSIGNED  true | false          (default: false)
"""

from __future__ import annotations

from typing import Any

from prometheus_client import Counter

from services.field_assessment.trust_enforcement import (
    ProvenanceMode,
    TrustDecision,
    TrustInputs,
    enforce_full_trust_chain,
)

# ---------------------------------------------------------------------------
# Operation-level metrics
# ---------------------------------------------------------------------------
# "operation" is a bounded label: one value per adapter function (6 values).
# No tenant_id, no high-cardinality dimensions. Prometheus-safe.

ENFORCEMENT_OPERATIONS_TOTAL = Counter(
    "frostgate_trust_enforcement_operations_total",
    "Total trust enforcement operations by operation, mode, and decision",
    ["operation", "mode", "decision"],
)

ENFORCEMENT_ALLOWED_TOTAL = Counter(
    "frostgate_trust_enforcement_allowed_total",
    "Trust enforcement operations that were allowed",
    ["operation"],
)

ENFORCEMENT_WARNED_TOTAL = Counter(
    "frostgate_trust_enforcement_warned_total",
    "Trust enforcement operations that produced warnings",
    ["operation"],
)

ENFORCEMENT_BLOCKED_TOTAL = Counter(
    "frostgate_trust_enforcement_blocked_total",
    "Trust enforcement operations blocked in strict mode",
    ["operation"],
)


# ---------------------------------------------------------------------------
# Metric helper
# ---------------------------------------------------------------------------


def _emit_op_metrics(operation: str, decision: TrustDecision) -> None:
    ENFORCEMENT_OPERATIONS_TOTAL.labels(
        operation=operation, mode=decision.mode, decision=decision.decision
    ).inc()
    if decision.decision == "block":
        ENFORCEMENT_BLOCKED_TOTAL.labels(operation=operation).inc()
    elif decision.decision == "warn":
        ENFORCEMENT_WARNED_TOTAL.labels(operation=operation).inc()
    else:
        ENFORCEMENT_ALLOWED_TOTAL.labels(operation=operation).inc()


def _run_gate(operation: str, inputs: TrustInputs, **kwargs: Any) -> TrustDecision:
    """Call enforce_full_trust_chain and emit operation metrics regardless of outcome.

    Catches TrustEnforcementError to ensure blocked operations are counted before
    the exception propagates to the caller.
    """
    from services.field_assessment.trust_enforcement import TrustEnforcementError  # noqa: PLC0415

    try:
        decision = enforce_full_trust_chain(inputs, **kwargs)
    except TrustEnforcementError as te:
        _emit_op_metrics(operation, te.decision)
        raise
    _emit_op_metrics(operation, decision)
    return decision


# ---------------------------------------------------------------------------
# Replay result → TrustInputs conversion
# ---------------------------------------------------------------------------


def _trust_inputs_from_replay_result(result: dict[str, Any]) -> TrustInputs:
    """Derive TrustInputs from a verify_full_provenance_chain() result dict.

    Score mapping:
      100 (SCORE_PERFECT)   → chain_valid=True,  signature_valid=True
       75 (SCORE_WARNINGS)  → chain_valid=True,  signature_valid=True (non-sig warnings)
       50 (SCORE_DEGRADED)  → chain_valid=True,  signature_valid=None (legacy_unsigned)
        0 (SCORE_BROKEN)    → chain_valid=False; signature_valid=False if sig failure else True
    """
    score = result.get("chain_replay_score", 0)
    chain_valid = result.get("chain_valid", False)

    if score == 0:
        failed_nodes = result.get("failed_nodes", [])
        has_sig_failure = any(
            "invalid_signature" in (n.get("signature_status", "") or "")
            or "invalid_signature" in (n.get("reason", "") or "")
            for n in failed_nodes
        )
        signature_valid: bool | None = False if has_sig_failure else True
    elif score == 50:
        signature_valid = None  # SCORE_DEGRADED = all nodes hash-valid, legacy_unsigned
    else:
        signature_valid = True  # 75 or 100

    invalid_links = result.get("invalid_report_links", [])
    link_status = result.get("report_link_status", "unlinked")
    link_valid = len(invalid_links) == 0 and link_status != "invalid"

    replay_valid = chain_valid and score > 0

    return TrustInputs(
        chain_valid=chain_valid,
        signature_valid=signature_valid,
        link_valid=link_valid,
        replay_valid=replay_valid,
        tenant_valid=True,
        engagement_valid=True,
        is_legacy=(signature_valid is None),
    )


def _and_trust_inputs(a: TrustInputs, b: TrustInputs) -> TrustInputs:
    """AND-combine two TrustInputs: result is valid only if both branches are valid.

    signature_valid severity order: False > None > True.
    """
    if a.signature_valid is False or b.signature_valid is False:
        sig: bool | None = False
    elif a.signature_valid is None or b.signature_valid is None:
        sig = None
    else:
        sig = True
    return TrustInputs(
        chain_valid=a.chain_valid and b.chain_valid,
        signature_valid=sig,
        link_valid=a.link_valid and b.link_valid,
        replay_valid=a.replay_valid and b.replay_valid,
        tenant_valid=a.tenant_valid and b.tenant_valid,
        engagement_valid=a.engagement_valid and b.engagement_valid,
        is_legacy=a.is_legacy or b.is_legacy,
    )


def derive_engagement_trust_inputs(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> TrustInputs:
    """Derive TrustInputs from all independent provenance chain heads.

    Fetches all provenance records and identifies chain heads — records whose
    event_hash is not referenced as any other record's previous_hash. Each
    head is the tip of an independent evidence branch. All branches are
    replayed and AND-combined so a tampered or unsigned branch in any
    independent chain is visible under STRICT mode.

    Returns all chain dimensions False if no chain exists or verification
    fails — never defaults unknown trust dimensions to True.
    """
    from services.field_assessment.evidence_provenance import (  # noqa: PLC0415
        list_evidence_provenance_for_engagement,
    )
    from services.field_assessment.trust_replay import (  # noqa: PLC0415
        verify_full_provenance_chain,
    )

    _UNKNOWN = TrustInputs(
        chain_valid=False,
        signature_valid=False,
        link_valid=False,
        replay_valid=False,
        tenant_valid=True,
        engagement_valid=True,
    )
    try:
        records = list_evidence_provenance_for_engagement(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=100, offset=0
        )
        if not records:
            return _UNKNOWN

        # Find chain heads: records whose event_hash is not referenced as
        # previous_hash by any other record in this engagement. Each head
        # is the tip of an independent evidence branch.
        referenced = {r.previous_hash for r in records if r.previous_hash}
        heads = [r for r in records if r.event_hash not in referenced]
        if not heads:
            heads = [records[0]]  # fallback: replay from most recent record

        combined: TrustInputs | None = None
        for head in heads:
            result = verify_full_provenance_chain(
                db, tenant_id=tenant_id, provenance_id=head.id
            )
            branch = _trust_inputs_from_replay_result(result)
            combined = (
                branch if combined is None else _and_trust_inputs(combined, branch)
            )
        return combined if combined is not None else _UNKNOWN
    except Exception:
        return _UNKNOWN


# ---------------------------------------------------------------------------
# Adapter functions
# ---------------------------------------------------------------------------


def enforce_evidence_creation(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    signature_valid: bool | None = True,
    is_legacy: bool = False,
    tenant_valid: bool = True,
    engagement_valid: bool = True,
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy before evidence provenance record is persisted.

    Called from create_evidence_provenance() after signing, before flush.
    signature_valid: True=signed, None=unsigned/legacy, False=invalid signature.
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = TrustInputs(
        chain_valid=True,
        signature_valid=signature_valid,
        link_valid=True,
        replay_valid=True,
        tenant_valid=tenant_valid,
        engagement_valid=engagement_valid,
        is_legacy=is_legacy,
    )
    return _run_gate(
        "evidence_creation",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )


def enforce_evidence_review(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    signature_valid: bool | None = True,
    is_legacy: bool = False,
    tenant_valid: bool = True,
    engagement_valid: bool = True,
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy before a provenance review event is persisted.

    Called from mark_provenance_reviewed() after signing, before flush.
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = TrustInputs(
        chain_valid=True,
        signature_valid=signature_valid,
        link_valid=True,
        replay_valid=True,
        tenant_valid=tenant_valid,
        engagement_valid=engagement_valid,
        is_legacy=is_legacy,
    )
    return _run_gate(
        "evidence_review",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )


def enforce_evidence_approval(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    chain_valid: bool = True,
    signature_valid: bool | None = True,
    link_valid: bool = True,
    replay_valid: bool = True,
    is_legacy: bool = False,
    tenant_valid: bool = True,
    engagement_valid: bool = True,
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy before QA approval of a report.

    Called before marking a report as qa-approved. Callers derive trust
    dimensions from the report's current authority state.
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = TrustInputs(
        chain_valid=chain_valid,
        signature_valid=signature_valid,
        link_valid=link_valid,
        replay_valid=replay_valid,
        tenant_valid=tenant_valid,
        engagement_valid=engagement_valid,
        is_legacy=is_legacy,
    )
    return _run_gate(
        "evidence_approval",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )


def enforce_report_finalization(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    chain_valid: bool = True,
    signature_valid: bool | None = True,
    link_valid: bool = True,
    replay_valid: bool = True,
    is_legacy: bool = False,
    tenant_valid: bool = True,
    engagement_valid: bool = True,
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy before report finalization.

    Called before setting approval_status="finalized". STRICT mode blocks
    finalization when trust requirements are not met.
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = TrustInputs(
        chain_valid=chain_valid,
        signature_valid=signature_valid,
        link_valid=link_valid,
        replay_valid=replay_valid,
        tenant_valid=tenant_valid,
        engagement_valid=engagement_valid,
        is_legacy=is_legacy,
    )
    return _run_gate(
        "report_finalization",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )


def enforce_report_export(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    chain_valid: bool = True,
    signature_valid: bool | None = True,
    link_valid: bool = True,
    replay_valid: bool = True,
    is_legacy: bool = False,
    tenant_valid: bool = True,
    engagement_valid: bool = True,
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy before report export (JSON or PDF).

    Called before generating report content. STRICT mode blocks export when
    trust requirements are not met.
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = TrustInputs(
        chain_valid=chain_valid,
        signature_valid=signature_valid,
        link_valid=link_valid,
        replay_valid=replay_valid,
        tenant_valid=tenant_valid,
        engagement_valid=engagement_valid,
        is_legacy=is_legacy,
    )
    return _run_gate(
        "report_export",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )


def enforce_trust_replay(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    replay_result: dict[str, Any],
    mode: ProvenanceMode | None = None,
) -> TrustDecision:
    """Enforce trust policy after verify_full_provenance_chain() completes.

    Called from generate_trust_proof() before building the proof package.
    In STRICT mode, a broken chain or invalid signatures prevent proof generation.

    replay_result: the dict returned by verify_full_provenance_chain().
    """
    if mode is None:
        mode = ProvenanceMode.from_env()
    inputs = _trust_inputs_from_replay_result(replay_result)
    return _run_gate(
        "trust_replay",
        inputs,
        mode=mode,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )
