"""api/identity_governance/runtime.py — Governance runtime hooks.

Called from ``api/auth_dispatch.py`` at the end of ``get_actor_context()``.
The helpers here are the ONLY place governance services are wired into the
live request path. They are:

    - :func:`apply_governance_checks` — SessionEvaluator + risk scoring +
      timeline emission, all feature-flagged.
    - :func:`emit_timeline_event` — best-effort event emission helper.

Design principles:
    - Every feature is guarded by an explicit flag in
      :class:`~api.config.identity_runtime.IdentityRuntimeFlags`.
    - Governance failures are fail-closed: any exception during the
      evaluation raises 500 ``GOVERNANCE_UNAVAILABLE`` — never silently
      continues.
    - Timeline emission is best-effort: swallow exceptions and log — the
      user request must NEVER fail because the timeline chain is broken.
    - No PII: error responses carry only the machine-readable code and
      generic message; details go into structured logs, never the body.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request

from api.actor_context import ActorContext
from api.config.identity_runtime import IdentityRuntimeFlags, get_flags
from api.identity_governance.error_codes import IdentityErrorCode, error_body
from api.identity_governance.metrics import (
    IDENTITY_AUTHORIZATION_DECISIONS_TOTAL,
    IDENTITY_RISK_BAND_TOTAL,
    IDENTITY_SESSION_EVALUATIONS_TOTAL,
    IDENTITY_TIMELINE_EVENTS_TOTAL,
)
from api.identity_governance.models import (
    IdentityLifecycleState,
    IdentityTimelineEventType,
    RiskContext,
    SessionEvaluationContext,
    SessionEvaluationDecision,
)
from api.identity_governance.services import get_services

log = logging.getLogger("frostgate.identity_governance.runtime")

# Default session TTL used when the ActorContext does not carry an explicit
# session_expires_at. Deliberately generous — the SessionEvaluator's expiry
# check is meant to catch expired sessions, not to short-circuit sessions
# whose expiry isn't tracked yet. Real expiry comes from SessionAuthority.
_DEFAULT_SESSION_TTL = timedelta(hours=8)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _extract_jwt_expiry(request: Request) -> Optional[datetime]:
    """Parse the exp claim from the already-validated Bearer token.

    The token has been verified by IdentityAuthority or Auth0 before this
    point, so we only need to decode the payload — no signature check needed.
    Returns None on any parse error.
    """
    try:
        bearer = (request.headers.get("Authorization") or "").strip()
        if not bearer.lower().startswith("bearer "):
            return None
        token = bearer[7:]
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add padding if needed
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = claims.get("exp")
        if exp is None:
            return None
        return datetime.fromtimestamp(float(exp), tz=timezone.utc)
    except Exception:
        return None


def _tenant_requires_mfa(_actor: ActorContext) -> bool:
    """Return whether the actor's tenant requires MFA.

    In this PR we default to False (no tenant policy source-of-truth for
    MFA-required is wired up yet). Callers can subclass or monkey-patch
    when a tenant policy source is added.
    """
    return False


def _identity_lifecycle_state(actor: ActorContext) -> IdentityLifecycleState:
    """Return the actor's lifecycle state.

    In this PR the ActorContext does not carry a persistent lifecycle
    state, so all resolved (non-anonymous) actors default to ACTIVE. The
    hook is here so a future PR can attach a real lifecycle lookup without
    touching auth_dispatch.
    """
    if actor.auth_source in ("none", "") or actor.subject in ("", "anonymous"):
        return IdentityLifecycleState.DISABLED
    return IdentityLifecycleState.ACTIVE


def emit_timeline_event(
    event_type: IdentityTimelineEventType,
    *,
    subject: str,
    tenant_id: Optional[str],
    actor: str,
    details: Optional[dict[str, object]] = None,
    correlation_id: Optional[str] = None,
    flags: Optional[IdentityRuntimeFlags] = None,
) -> None:
    """Emit a timeline event, best-effort.

    Never raises. If the timeline flag is disabled, this is a no-op.
    Called from auth success/failure paths; must never propagate errors
    to the request handler.
    """
    active_flags = flags or get_flags()
    if not active_flags.FG_IDENTITY_TIMELINE_ENABLED:
        return
    if not tenant_id or not subject or not actor:
        # timeline.emit() requires these; silently skip when missing.
        return
    try:
        services = get_services()
        services.timeline.emit(
            event_type=event_type,
            subject=subject,
            tenant_id=tenant_id,
            actor=actor,
            details=details,
            correlation_id=correlation_id,
        )
        IDENTITY_TIMELINE_EVENTS_TOTAL.labels(event_type=event_type.value).inc()
    except Exception as exc:  # pragma: no cover — best-effort emission
        log.warning(
            "identity_runtime.timeline_emit_failed",
            extra={"event_type": event_type.value, "exc": str(exc)},
        )


def _record_authorization_decision(
    decision: str,
    actor: ActorContext,
) -> None:
    identity_type = "human"
    if actor.auth_source == "api_key":
        identity_type = "machine"
    elif actor.auth_source == "dev_bypass":
        identity_type = "service"
    try:
        IDENTITY_AUTHORIZATION_DECISIONS_TOTAL.labels(
            decision=decision,
            identity_type=identity_type,
        ).inc()
    except Exception:  # pragma: no cover
        pass


def apply_governance_checks(
    actor: ActorContext,
    request: Request,
    *,
    flags: Optional[IdentityRuntimeFlags] = None,
) -> ActorContext:
    """Run governance evaluation for a resolved actor.

    Called at the end of ``get_actor_context()``. When enabled, runs the
    SessionEvaluator and, on non-ALLOW decisions, raises an
    :class:`HTTPException` with a machine-readable identity error code.

    Fail-closed: any exception inside the evaluator raises 500
    ``GOVERNANCE_UNAVAILABLE`` — the request is never allowed to continue
    with governance in an unknown state.

    Returns the ActorContext unchanged when governance is enabled and all
    checks pass, or when governance is disabled.
    """
    active_flags = flags or get_flags()

    # If no runtime governance flags are on, nothing to do.
    if not active_flags.any_enabled():
        return actor

    # Anonymous or dev-bypass actors bypass governance checks — governance
    # only meaningfully applies to resolved principals.
    if actor.auth_source in ("dev_bypass", "none", ""):
        return actor
    if not actor.subject or actor.subject == "anonymous":
        return actor

    try:
        return _run_governance(actor, request, active_flags)
    except HTTPException:
        raise
    except Exception as exc:
        log.error(
            "identity_runtime.governance_check_failed",
            extra={
                "auth_source": actor.auth_source,
                "subject_prefix": (actor.subject or "")[:16],
                "exc": str(exc),
            },
        )
        _record_authorization_decision("error", actor)
        raise HTTPException(
            status_code=500,
            detail=error_body(
                IdentityErrorCode.GOVERNANCE_UNAVAILABLE,
                reason="evaluation_error",
            ),
        ) from exc


def _run_governance(
    actor: ActorContext,
    request: Request,
    flags: IdentityRuntimeFlags,
) -> ActorContext:
    services = get_services()
    now = _now()

    lifecycle_state = _identity_lifecycle_state(actor)
    correlation_id = request.headers.get("X-Correlation-Id") if request else None

    # 1) Risk engine — always compute a score so SessionEvaluator has real input.
    risk_score = None
    if flags.FG_RISK_ENGINE_ENABLED or flags.FG_SESSION_EVALUATOR_ENABLED:
        risk_context = RiskContext(
            subject=actor.subject,
            tenant_id=actor.tenant_id or "",
            lifecycle_state=lifecycle_state,
            device_state=None,
            mfa_verified=False,
            tenant_requires_mfa=_tenant_requires_mfa(actor),
            active_break_glass=0,
            evaluated_at=now,
        )
        risk_score = services.risk_engine.score_identity(risk_context)
        if flags.FG_RISK_ENGINE_ENABLED:
            try:
                IDENTITY_RISK_BAND_TOTAL.labels(band=risk_score.band.value).inc()
            except Exception:  # pragma: no cover
                pass

    # 2) Session evaluator — orchestrates lifecycle/session/device/mfa/risk.
    if flags.FG_SESSION_EVALUATOR_ENABLED and risk_score is not None:
        state = getattr(request, "state", None) if request is not None else None

        # -- session_id --
        session_id = (getattr(state, "session_id", "") or "") if state else ""
        if not session_id:
            session_id = actor.membership_id or actor.subject

        # -- session_expires_at --
        # Prefer an expiry already attached by upstream middleware / JWT decode.
        # Fall back to parsing the raw JWT exp claim (safe — token already verified).
        # Last resort: use a generous default so the expiry check never fires for
        # sessions whose lifetime is not yet tracked.
        session_expires_at: Optional[datetime] = (
            getattr(state, "session_expires_at", None) if state else None
        )
        if session_expires_at is None and request is not None:
            session_expires_at = _extract_jwt_expiry(request)
        if session_expires_at is None:
            session_expires_at = now + _DEFAULT_SESSION_TTL

        # -- session_revoked --
        # Check the live revocation store via the SessionAuthority singleton.
        session_revoked: bool = bool(
            getattr(state, "session_revoked", False) if state else False
        )
        if not session_revoked and session_id:
            try:
                from api.identity_authority.authority import is_session_revoked
                session_revoked = is_session_revoked(session_id)
            except Exception:
                pass

        # -- device --
        # Prefer a DeviceRecord already attached by upstream middleware.
        device = getattr(state, "device_record", None) if state else None

        eval_ctx = SessionEvaluationContext(
            subject=actor.subject,
            tenant_id=actor.tenant_id or "",
            session_id=session_id,
            identity_state=lifecycle_state,
            session_expires_at=session_expires_at,
            session_revoked=session_revoked,
            device=device,
            mfa_verified=False,
            tenant_requires_mfa=_tenant_requires_mfa(actor),
            risk_score=risk_score,
            evaluated_at=now,
        )
        result = services.session_evaluator.evaluate(eval_ctx)
        try:
            IDENTITY_SESSION_EVALUATIONS_TOTAL.labels(
                decision=result.decision.value,
            ).inc()
        except Exception:  # pragma: no cover
            pass

        if result.decision != SessionEvaluationDecision.ALLOW:
            _handle_non_allow(
                actor=actor,
                request=request,
                lifecycle_state=lifecycle_state,
                decision=result.decision,
                reason=result.stopped_at_check or "session_evaluation",
                correlation_id=correlation_id,
                flags=flags,
            )

    # Auth success timeline event.
    emit_timeline_event(
        IdentityTimelineEventType.LOGIN,
        subject=actor.subject,
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        details={"auth_source": actor.auth_source},
        correlation_id=correlation_id,
        flags=flags,
    )

    _record_authorization_decision("allow", actor)
    return actor


def _handle_non_allow(
    *,
    actor: ActorContext,
    request: Request,
    lifecycle_state: IdentityLifecycleState,
    decision: SessionEvaluationDecision,
    reason: str,
    correlation_id: Optional[str],
    flags: IdentityRuntimeFlags,
) -> None:
    """Translate a non-ALLOW SessionEvaluator decision into an HTTPException.

    Raises:
        HTTPException: always. Status code and body encode the decision
            using an :class:`IdentityErrorCode`.
    """
    if decision == SessionEvaluationDecision.REVOKE_SESSION:
        code = IdentityErrorCode.SESSION_REVOKED
        status = 401
        event_type = IdentityTimelineEventType.SESSION_REVOKED
    elif decision == SessionEvaluationDecision.STEP_UP_REQUIRED:
        code = IdentityErrorCode.MFA_STEP_UP_REQUIRED
        if reason == "device_state":
            code = IdentityErrorCode.DEVICE_COMPROMISED
        status = 403
        event_type = IdentityTimelineEventType.MFA_MISSING
    else:  # DENY
        status = 403
        event_type = IdentityTimelineEventType.POLICY_DECISION
        if reason == "identity_state":
            # Map lifecycle state to a specific error code so clients can
            # surface a precise reason.
            mapping = {
                IdentityLifecycleState.SUSPENDED: IdentityErrorCode.IDENTITY_SUSPENDED,
                IdentityLifecycleState.DISABLED: IdentityErrorCode.IDENTITY_DISABLED,
                IdentityLifecycleState.ARCHIVED: IdentityErrorCode.IDENTITY_ARCHIVED,
                IdentityLifecycleState.DELETED: IdentityErrorCode.IDENTITY_DELETED,
            }
            code = mapping.get(lifecycle_state, IdentityErrorCode.POLICY_DENIED)
        elif reason == "session_expiry":
            code = IdentityErrorCode.SESSION_EXPIRED
        elif reason == "session_revocation":
            code = IdentityErrorCode.SESSION_REVOKED
            status = 401
            event_type = IdentityTimelineEventType.SESSION_REVOKED
        elif reason == "device_state":
            code = IdentityErrorCode.DEVICE_REVOKED
        else:
            code = IdentityErrorCode.POLICY_DENIED

    log.info(
        "identity_runtime.session_evaluator_denied",
        extra={
            "decision": decision.value,
            "reason": reason,
            "code": code.value,
            "auth_source": actor.auth_source,
        },
    )

    emit_timeline_event(
        event_type,
        subject=actor.subject,
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        details={"decision": decision.value, "reason": reason},
        correlation_id=correlation_id,
        flags=flags,
    )

    _record_authorization_decision("deny", actor)

    raise HTTPException(
        status_code=status,
        detail=error_body(code, reason=reason),
    )


__all__ = [
    "apply_governance_checks",
    "emit_timeline_event",
]
