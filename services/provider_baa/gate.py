"""
BAA Gate — PHI classification and BAA enforcement orchestration boundary.

Design contract:
- evaluate_baa_gate() returns BaaGateResult; never raises on BAA denial
- enforce_baa_gate_for_route() raises HTTPException(403) on any denial
- Fail-closed: classifier error → contains_phi=True → BAA enforced
- Fail-closed: blank/None tenant_id or provider_id → ValueError immediately
- All PHI + BAA audit emissions happen here; routing layers emit nothing directly
- Never logs raw text, extracted PHI values, or request body

This is the SINGLE composition point for classify_phi() and
enforce_provider_baa_for_route(). Routing code MUST depend on this interface,
not on direct calls to the underlying services, so the implementation can
be replaced (policy plane, ML classifier, remote compliance service) without
rewriting routing code.

Future evolution:
  Replace evaluate_baa_gate() body with a policy plane delegate.
  The BaaGateResult contract and enforce_baa_gate_for_route() signature are stable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy.orm import Session

from services.phi_classifier.classifier import (
    classify_phi,
    emit_phi_classification_audit,
    emit_phi_enforcement_block_audit,
)
from services.phi_classifier.models import SensitivityLevel
from services.provider_baa.policy import enforce_provider_baa_for_route

if TYPE_CHECKING:
    from fastapi import Request

log = logging.getLogger("frostgate.baa_gate")

# Stable action constants — never change meaning once published
GATE_ACTION_ALLOWED = "allowed"
GATE_ACTION_DENIED = "denied"

# Stable error codes for gate-level failures (not BAA record failures)
GATE_REASON_MISSING_TENANT = "BAA_GATE_MISSING_TENANT"
GATE_REASON_MISSING_PROVIDER = "BAA_GATE_MISSING_PROVIDER"


@dataclass(frozen=True)
class BaaGateResult:
    """Result of a BAA gate evaluation.

    `allowed` is the single routing gate signal — always inspect this first.
    `reason_code` is a stable PROVIDER_BAA_* or BAA_GATE_* string, safe for
    logging and error responses. It is never a raw PHI value or DB detail.
    `enforcement_action` is GATE_ACTION_ALLOWED or GATE_ACTION_DENIED.
    """

    allowed: bool
    contains_phi: bool
    sensitivity_level: SensitivityLevel
    phi_types: frozenset[str]
    provider_id: str
    tenant_id: str
    reason_code: str
    enforcement_action: str


def evaluate_baa_gate(
    db: Session,
    *,
    tenant_id: str,
    provider_id: str,
    text: str,
    source: str = "",
    request: "Request | None" = None,
) -> BaaGateResult:
    """Evaluate the BAA gate for a request. Returns result; never raises on denial.

    Classifies PHI, emits audit events, and — only when PHI is present —
    calls enforce_provider_baa_for_route(). Non-regulated providers pass
    BAA enforcement unconditionally; this function does not shortcut them.

    Returns BaaGateResult(allowed=False) on BAA denial; callers must check
    .allowed before continuing. evaluate_baa_gate never silently allows.

    Raises:
        ValueError: On blank/None tenant_id or provider_id (programming error).
    """
    if not tenant_id or not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError(GATE_REASON_MISSING_TENANT)
    if not provider_id or not isinstance(provider_id, str) or not provider_id.strip():
        raise ValueError(GATE_REASON_MISSING_PROVIDER)

    tenant_id = tenant_id.strip()
    provider_id = provider_id.strip()

    # classify_phi never raises — classifier errors return contains_phi=True (fail-closed)
    phi_result = classify_phi(text)

    if not phi_result.contains_phi:
        emit_phi_classification_audit(
            phi_result,
            tenant_id=tenant_id,
            enforcement_action=GATE_ACTION_ALLOWED,
            request=request,
        )
        return BaaGateResult(
            allowed=True,
            contains_phi=False,
            sensitivity_level=phi_result.sensitivity_level,
            phi_types=phi_result.phi_types,
            provider_id=provider_id,
            tenant_id=tenant_id,
            reason_code=phi_result.reasoning_code,
            enforcement_action=GATE_ACTION_ALLOWED,
        )

    # PHI detected — enforce BAA. enforce_provider_baa_for_route handles
    # non-regulated providers correctly (returns without raising).
    try:
        enforce_provider_baa_for_route(
            db, tenant_id=tenant_id, provider_id=provider_id, request=request
        )
    except HTTPException as baa_exc:
        emit_phi_enforcement_block_audit(
            phi_result,
            tenant_id=tenant_id,
            provider_id=provider_id,
            request=request,
        )
        detail = baa_exc.detail
        reason_code = (
            detail.get("error_code", phi_result.reasoning_code)
            if isinstance(detail, dict)
            else phi_result.reasoning_code
        )
        log.warning(
            "baa_gate: PHI detected and BAA enforcement denied — request blocked",
            extra={
                "tenant_id": tenant_id,
                "provider_id": provider_id,
                "reason_code": reason_code,
                "source": source,
            },
        )
        return BaaGateResult(
            allowed=False,
            contains_phi=True,
            sensitivity_level=phi_result.sensitivity_level,
            phi_types=phi_result.phi_types,
            provider_id=provider_id,
            tenant_id=tenant_id,
            reason_code=reason_code,
            enforcement_action=GATE_ACTION_DENIED,
        )

    # BAA passed — PHI present but provider is authorized
    emit_phi_classification_audit(
        phi_result,
        tenant_id=tenant_id,
        enforcement_action=GATE_ACTION_ALLOWED,
        request=request,
    )
    return BaaGateResult(
        allowed=True,
        contains_phi=True,
        sensitivity_level=phi_result.sensitivity_level,
        phi_types=phi_result.phi_types,
        provider_id=provider_id,
        tenant_id=tenant_id,
        reason_code=phi_result.reasoning_code,
        enforcement_action=GATE_ACTION_ALLOWED,
    )


def enforce_baa_gate_for_route(
    db: Session,
    *,
    tenant_id: str,
    provider_id: str,
    text: str,
    source: str = "",
    request: "Request | None" = None,
) -> BaaGateResult:
    """Enforce the BAA gate; raises HTTPException(403) on any denial.

    This is the primary call site for routing code. Callers MUST NOT catch
    and suppress the 403, retry with a different provider, or fall back
    to an unenforced path after denial.

    Raises:
        HTTPException(403): On BAA denial. detail contains error_code (stable
            PROVIDER_BAA_* constant), message (safe), provider_id. Never
            contains PHI, expiry_date, contract text, or internal DB errors.
        ValueError: On blank/None tenant_id or provider_id (programming error).
    """
    result = evaluate_baa_gate(
        db,
        tenant_id=tenant_id,
        provider_id=provider_id,
        text=text,
        source=source,
        request=request,
    )
    if not result.allowed:
        exc = HTTPException(
            status_code=403,
            detail={
                "error_code": result.reason_code,
                "message": "request denied by BAA enforcement gate",
                "provider_id": result.provider_id,
            },
        )
        setattr(exc, "baa_gate_result", result)
        raise exc
    return result
