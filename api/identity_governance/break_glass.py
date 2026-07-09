"""api/identity_governance/break_glass.py — Emergency access workflow.

Break-glass grants are:
- REASON-REQUIRED (empty reason raises ``ValueError``)
- DURATION-BOUNDED (0 < duration <= :data:`MAX_BREAK_GLASS_DURATION_SECONDS`)
- APPROVAL-GATED (PENDING -> APPROVED -> ACTIVE by approver)
- SELF-EXPIRING (past ``expires_at`` becomes EXPIRED on next read)
- REVOCABLE at any time by an admin

All state changes emit a timeline event on the injected
:class:`IdentityTimeline`. No mutable in-place state — each transition
produces a new :class:`BreakGlassRequest`.
"""

from __future__ import annotations

import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from api.identity_governance.models import (
    BreakGlassRequest,
    BreakGlassStatus,
    IdentityTimelineEventType,
)
from api.identity_governance.timeline import IdentityTimeline

MAX_BREAK_GLASS_DURATION_SECONDS: int = 3600 * 4  # 4 hours


class BreakGlassAuthority:
    """Break-glass workflow authority (in-memory Phase 1)."""

    def __init__(self, timeline: Optional[IdentityTimeline] = None) -> None:
        self._timeline = timeline or IdentityTimeline()
        # (tenant_id, request_id) -> BreakGlassRequest
        self._requests: dict[tuple[str, str], BreakGlassRequest] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_access(
        self,
        subject: str,
        tenant_id: str,
        requested_capability: str,
        reason: str,
        requested_by: str,
        duration_seconds: int,
    ) -> BreakGlassRequest:
        """Create a new PENDING break-glass request."""
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not requested_capability:
            raise ValueError("requested_capability is required")
        if not reason or not reason.strip():
            raise ValueError("break-glass request requires a non-empty reason")
        if not requested_by:
            raise ValueError("requested_by is required")
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be > 0")
        if duration_seconds > MAX_BREAK_GLASS_DURATION_SECONDS:
            raise ValueError(
                "duration_seconds exceeds MAX_BREAK_GLASS_DURATION_SECONDS "
                f"({MAX_BREAK_GLASS_DURATION_SECONDS})"
            )

        request_id = secrets.token_hex(16)
        now = datetime.now(tz=timezone.utc)
        request = BreakGlassRequest(
            request_id=request_id,
            tenant_id=tenant_id,
            subject=subject,
            requested_capability=requested_capability,
            reason=reason,
            requested_by=requested_by,
            requested_at=now,
            duration_seconds=duration_seconds,
            status=BreakGlassStatus.PENDING,
        )
        with self._lock:
            self._requests[(tenant_id, request_id)] = request

        self._timeline.emit(
            IdentityTimelineEventType.BREAK_GLASS_REQUESTED,
            subject=subject,
            tenant_id=tenant_id,
            actor=requested_by,
            details={
                "request_id": request_id,
                "capability": requested_capability,
                "duration_seconds": duration_seconds,
            },
        )
        return request

    def approve(
        self,
        request_id: str,
        approver: str,
        tenant_id: str,
    ) -> BreakGlassRequest:
        """Approve a PENDING request, activating it. Enforces tenant isolation."""
        if not approver:
            raise ValueError("approver is required")
        with self._lock:
            request = self._requests.get((tenant_id, request_id))
            if request is None:
                raise ValueError(
                    f"break-glass request {request_id!r} not found for tenant "
                    f"{tenant_id!r}"
                )
            if request.status != BreakGlassStatus.PENDING:
                raise ValueError(
                    f"cannot approve request in status {request.status.value!r}"
                )
            if approver == request.requested_by:
                raise ValueError("approver must differ from requester")

            now = datetime.now(tz=timezone.utc)
            expires_at = now + timedelta(seconds=request.duration_seconds)
            updated = BreakGlassRequest(
                request_id=request.request_id,
                tenant_id=request.tenant_id,
                subject=request.subject,
                requested_capability=request.requested_capability,
                reason=request.reason,
                requested_by=request.requested_by,
                requested_at=request.requested_at,
                duration_seconds=request.duration_seconds,
                status=BreakGlassStatus.ACTIVE,
                approver=approver,
                approved_at=now,
                expires_at=expires_at,
            )
            self._requests[(tenant_id, request_id)] = updated

        self._timeline.emit(
            IdentityTimelineEventType.BREAK_GLASS_APPROVED,
            subject=updated.subject,
            tenant_id=tenant_id,
            actor=approver,
            details={
                "request_id": updated.request_id,
                "capability": updated.requested_capability,
                "expires_at": updated.expires_at.isoformat()
                if updated.expires_at
                else "",
            },
        )
        return updated

    def revoke(
        self,
        request_id: str,
        tenant_id: str,
        revoker: str,
    ) -> BreakGlassRequest:
        """Revoke a request in any non-terminal status."""
        if not revoker:
            raise ValueError("revoker is required")
        with self._lock:
            request = self._requests.get((tenant_id, request_id))
            if request is None:
                raise ValueError(
                    f"break-glass request {request_id!r} not found for tenant "
                    f"{tenant_id!r}"
                )
            if request.status in (BreakGlassStatus.REVOKED, BreakGlassStatus.EXPIRED):
                return request
            now = datetime.now(tz=timezone.utc)
            updated = BreakGlassRequest(
                request_id=request.request_id,
                tenant_id=request.tenant_id,
                subject=request.subject,
                requested_capability=request.requested_capability,
                reason=request.reason,
                requested_by=request.requested_by,
                requested_at=request.requested_at,
                duration_seconds=request.duration_seconds,
                status=BreakGlassStatus.REVOKED,
                approver=request.approver,
                approved_at=request.approved_at,
                expires_at=request.expires_at,
                revoked_by=revoker,
                revoked_at=now,
            )
            self._requests[(tenant_id, request_id)] = updated

        self._timeline.emit(
            IdentityTimelineEventType.BREAK_GLASS_EXPIRED,
            subject=updated.subject,
            tenant_id=tenant_id,
            actor=revoker,
            details={"request_id": updated.request_id, "reason": "revoked_by_admin"},
        )
        return updated

    def is_active(self, request_id: str, tenant_id: str) -> bool:
        """Return True iff the request is ACTIVE and unexpired."""
        with self._lock:
            request = self._requests.get((tenant_id, request_id))
        if request is None:
            return False
        checked = self._check_expiry(request)
        # Persist expiry transition if it occurred.
        if checked.status != request.status:
            self._persist_expiry(checked)
        return checked.status == BreakGlassStatus.ACTIVE

    def get_active_requests(
        self, subject: str, tenant_id: str
    ) -> list[BreakGlassRequest]:
        """Return all ACTIVE, unexpired requests for the subject."""
        with self._lock:
            candidates = [
                r
                for (tid, _rid), r in self._requests.items()
                if tid == tenant_id and r.subject == subject
            ]
        results: list[BreakGlassRequest] = []
        for r in candidates:
            checked = self._check_expiry(r)
            if checked.status != r.status:
                self._persist_expiry(checked)
            if checked.status == BreakGlassStatus.ACTIVE:
                results.append(checked)
        return sorted(results, key=lambda r: r.request_id)

    def get_request(
        self, request_id: str, tenant_id: str
    ) -> Optional[BreakGlassRequest]:
        """Return a request with expiry evaluated. Enforces tenant isolation."""
        with self._lock:
            request = self._requests.get((tenant_id, request_id))
        if request is None:
            return None
        checked = self._check_expiry(request)
        if checked.status != request.status:
            self._persist_expiry(checked)
        return checked

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_expiry(self, request: BreakGlassRequest) -> BreakGlassRequest:
        """Return an EXPIRED-status copy of ``request`` if past ``expires_at``."""
        if request.status != BreakGlassStatus.ACTIVE:
            return request
        if request.expires_at is None:
            return request
        if datetime.now(tz=timezone.utc) < request.expires_at:
            return request
        return BreakGlassRequest(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            subject=request.subject,
            requested_capability=request.requested_capability,
            reason=request.reason,
            requested_by=request.requested_by,
            requested_at=request.requested_at,
            duration_seconds=request.duration_seconds,
            status=BreakGlassStatus.EXPIRED,
            approver=request.approver,
            approved_at=request.approved_at,
            expires_at=request.expires_at,
        )

    def _persist_expiry(self, request: BreakGlassRequest) -> None:
        with self._lock:
            self._requests[(request.tenant_id, request.request_id)] = request
        self._timeline.emit(
            IdentityTimelineEventType.BREAK_GLASS_EXPIRED,
            subject=request.subject,
            tenant_id=request.tenant_id,
            actor="system",
            details={
                "request_id": request.request_id,
                "reason": "duration_elapsed",
            },
        )
