"""
Scan authorization service — enforces FVA-01 Authorized Scope.

Provides fail-closed authorization checks for scanner dispatch.
Every public scanner route and every worker execution boundary must
call check_scan_authorized() before any outbound network activity.

Authorization model
-------------------
Per-engagement ``fa_scan_authorizations`` records carry an approved target list
(JSONB array) with lifecycle states: draft → pending_approval → approved →
active → expired | revoked.

Only records in state ``active`` with effective_from <= NOW() < expires_at are
accepted.  Missing, expired, or revoked authorizations cause a fail-closed
ScanAuthorizationError — never a silent permit.

Emergency stops
---------------
``fa_scan_emergency_stops`` records a durable kill-switch at platform,
tenant, or engagement scope.  Any active stop in the scope hierarchy blocks
new scan dispatch until explicitly cleared by an authorized operator.

Target normalization
--------------------
All targets (candidate and approved) are normalized via normalize_target()
before comparison.  Parse failure always fails closed — it never treats a
malformed target as a match.

L14-SCAN-SAFETY-001
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Public error type
# ---------------------------------------------------------------------------


class ScanAuthorizationError(Exception):
    """Raised when scan authorization fails.  Always fail-closed.

    Attributes:
        reason      — human-readable description (do NOT return to callers
                      without filtering for cross-tenant information leakage).
        audit_code  — machine-readable code for audit log.
    """

    def __init__(self, reason: str, audit_code: str) -> None:
        self.reason = reason
        self.audit_code = audit_code
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------

# FQDN label: 1-63 octets, alphanumeric + hyphens, no leading/trailing hyphen.
_FQDN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$|^[a-z0-9]$")


def _normalize_fqdn(raw: str) -> str:
    """Normalize a fully-qualified domain name.

    - Lowercase and strip trailing dot.
    - Reject labels longer than 63 characters.
    - Reject total length > 253 characters (after stripping trailing dot).
    - Reject empty string, bare dot, wildcards, underscores, whitespace.

    Returns the normalized form or raises ValueError.
    """
    if not raw or not raw.strip():
        raise ValueError("empty target")
    s = raw.strip().lower()
    # Strip exactly one trailing dot if present.
    if s.endswith("."):
        s = s[:-1]
    if not s:
        raise ValueError("empty target after stripping trailing dot")
    if len(s) > 253:
        raise ValueError(f"FQDN too long: {len(s)} characters (max 253)")
    labels = s.split(".")
    for label in labels:
        if not label:
            raise ValueError(f"empty label in FQDN: {raw!r}")
        if not _FQDN_LABEL.match(label):
            raise ValueError(f"invalid FQDN label {label!r} in {raw!r}")
    return s


def _normalize_ipv4(raw: str) -> str:
    try:
        return ipaddress.IPv4Address(raw.strip()).compressed
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError(f"invalid IPv4 address: {raw!r}") from exc


def _normalize_ipv6(raw: str) -> str:
    s = raw.strip()
    # Reject zone IDs — they are ambiguous in a multi-host context.
    if "%" in s:
        raise ValueError(f"IPv6 zone IDs are not permitted in scan targets: {raw!r}")
    try:
        addr = ipaddress.IPv6Address(s)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError(f"invalid IPv6 address: {raw!r}") from exc
    # Reject IPv4-mapped IPv6 (::ffff:a.b.c.d) — these are ambiguous and must not
    # silently match a plain IPv4 address in the approved scope.
    if addr.ipv4_mapped is not None:
        raise ValueError(
            f"IPv4-mapped IPv6 addresses are not permitted in scan targets "
            f"(use the plain IPv4 form instead): {raw!r}"
        )
    return addr.compressed


def _normalize_cidr(raw: str) -> str:
    s = raw.strip()
    try:
        # strict=False collapses host bits (e.g. 10.0.0.1/24 → 10.0.0.0/24).
        return ipaddress.ip_network(s, strict=False).compressed
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError(f"invalid CIDR: {raw!r}") from exc


def normalize_target(target: str, target_type: str) -> str:
    """Canonical normalization of scan targets.

    Raises ValueError for ambiguous, malformed, or unsupported targets.
    Never returns a form that could match a different host than the input.

    target_type must be one of: fqdn | ipv4 | ipv6 | cidr
    """
    if not target or not target.strip():
        raise ValueError("empty target")
    t = target_type.lower().strip()
    if t == "fqdn":
        return _normalize_fqdn(target)
    if t == "ipv4":
        return _normalize_ipv4(target)
    if t == "ipv6":
        return _normalize_ipv6(target)
    if t == "cidr":
        return _normalize_cidr(target)
    raise ValueError(f"unsupported target_type: {target_type!r}")


# ---------------------------------------------------------------------------
# Scope matching
# ---------------------------------------------------------------------------


def target_in_scope(
    candidate: str,
    candidate_type: str,
    approved_targets: list[dict[str, Any]],
) -> bool:
    """Check whether a candidate target is within any approved scope entry.

    Matching rules:
    - FQDN:   exact match only by default.  An approved entry may set
              ``"allow_subdomains": true`` to also permit child FQDNs
              (e.g., approved "example.com" with allow_subdomains → permits
              "sub.example.com").  This is opt-in — not the default.
    - IPv4:   exact match, or containment within an approved CIDR.
    - IPv6:   exact match, or containment within an approved IPv6 CIDR.
    - CIDR:   exact match against an approved CIDR only.

    Both candidate and approved entries are normalized before comparison.
    Raises ValueError for malformed inputs — never treats a parse failure
    as a match (fail-closed).
    """
    # Normalize the candidate once; raises ValueError on malformed input.
    norm_candidate = normalize_target(candidate, candidate_type)

    for entry in approved_targets:
        try:
            approved_target = entry.get("target", "")
            approved_type = entry.get("type", "")
            if not approved_target or not approved_type:
                continue
            norm_approved = normalize_target(approved_target, approved_type)
        except ValueError:
            # Malformed approved entry — skip it, never match.
            continue

        # --- FQDN matching ---
        if candidate_type.lower() == "fqdn" and approved_type.lower() == "fqdn":
            if norm_candidate == norm_approved:
                return True
            allow_sub = entry.get("allow_subdomains", False)
            if allow_sub:
                # Subdomain match: candidate must end with ".{approved}"
                if norm_candidate.endswith("." + norm_approved):
                    return True
            continue

        # --- IPv4 exact or CIDR containment ---
        if candidate_type.lower() == "ipv4":
            if approved_type.lower() == "ipv4" and norm_candidate == norm_approved:
                return True
            if approved_type.lower() == "cidr":
                try:
                    net = ipaddress.ip_network(norm_approved, strict=False)
                    addr = ipaddress.ip_address(norm_candidate)
                    if addr in net:
                        return True
                except ValueError:
                    continue
            continue

        # --- IPv6 exact or CIDR containment ---
        if candidate_type.lower() == "ipv6":
            if approved_type.lower() == "ipv6" and norm_candidate == norm_approved:
                return True
            if approved_type.lower() == "cidr":
                try:
                    net = ipaddress.ip_network(norm_approved, strict=False)
                    addr = ipaddress.ip_address(norm_candidate)
                    if addr in net:
                        return True
                except ValueError:
                    continue
            continue

        # --- CIDR exact match (a CIDR submitted as a target must match exactly) ---
        if candidate_type.lower() == "cidr":
            if approved_type.lower() == "cidr" and norm_candidate == norm_approved:
                return True
            continue

    return False


# ---------------------------------------------------------------------------
# Emergency stop helpers
# ---------------------------------------------------------------------------


def _scopes_for(*, tenant_id: str, engagement_id: str) -> list[str]:
    """Return the ordered list of emergency stop scopes to check.

    Hierarchy: platform → tenant → engagement.
    """
    return [
        "platform",
        f"tenant:{tenant_id}",
        f"engagement:{engagement_id}",
    ]


def _emergency_stop_active(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> bool:
    """Return True if any active emergency stop applies to this scope."""
    scopes = _scopes_for(tenant_id=tenant_id, engagement_id=engagement_id)
    # Raw SQL for performance; uses parameterized query (no string interpolation).
    result = db.execute(
        text(
            "SELECT 1 FROM fa_scan_emergency_stops "
            "WHERE scope = ANY(:scopes) AND is_active = TRUE "
            "LIMIT 1"
        ),
        {"scopes": scopes},
    ).fetchone()
    return result is not None


# ---------------------------------------------------------------------------
# Main authorization check
# ---------------------------------------------------------------------------


def check_scan_authorized(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    target: str,
    target_type: str,  # "fqdn" | "ipv4" | "ipv6" | "cidr"
    operation: str,  # "network_scan" | "web_headers" | "dns_email"
    now: datetime | None = None,
) -> dict[str, Any]:
    """Fail-closed authorization check.

    Raises ScanAuthorizationError on any failure.
    Returns the matched authorization record (as a plain dict) on success
    so the caller can reference it in audit log entries.

    Checks in order:
    1. Emergency stop active for any scope in the hierarchy
    2. Active authorization exists for tenant+engagement
    3. Authorization not expired
    4. Authorization not revoked
    5. Target normalized and matched in approved_targets
    6. Operation permitted for the matched target entry
    """
    _now = now or datetime.now(timezone.utc)

    # 1. Emergency stop check.
    # We catch all DB errors — if we cannot determine stop status, fail closed.
    try:
        if _emergency_stop_active(db, tenant_id=tenant_id, engagement_id=engagement_id):
            raise ScanAuthorizationError(
                reason="emergency stop is active for this scope",
                audit_code="EMERGENCY_STOP_ACTIVE",
            )
    except ScanAuthorizationError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ScanAuthorizationError(
            reason=f"unable to verify emergency stop status: {exc}",
            audit_code="EMERGENCY_STOP_CHECK_FAILED",
        ) from exc

    # 2–4. Load the active authorization record.
    try:
        row = db.execute(
            text(
                "SELECT id, tenant_id, engagement_id, approved_targets, "
                "       status, effective_from, expires_at, revoked_at "
                "FROM fa_scan_authorizations "
                "WHERE tenant_id = :tenant_id "
                "  AND engagement_id = :engagement_id "
                "  AND status = 'active' "
                "ORDER BY effective_from DESC NULLS LAST "
                "LIMIT 1"
            ),
            {"tenant_id": tenant_id, "engagement_id": engagement_id},
        ).fetchone()
    except Exception as exc:  # noqa: BLE001
        raise ScanAuthorizationError(
            reason=f"authorization lookup failed: {exc}",
            audit_code="AUTHORIZATION_LOOKUP_FAILED",
        ) from exc

    if row is None:
        raise ScanAuthorizationError(
            reason="no active scan authorization found for this engagement",
            audit_code="NO_ACTIVE_AUTHORIZATION",
        )

    auth_id = str(row[0])
    auth_tenant_id = str(row[1])
    auth_engagement_id = str(row[2])
    approved_targets_raw = row[3]  # already a Python list from JSONB
    auth_status = str(row[4])
    effective_from = row[5]
    expires_at = row[6]
    revoked_at = row[7]

    # Tenant isolation: the row tenant must match the caller's tenant.
    if auth_tenant_id != tenant_id:
        raise ScanAuthorizationError(
            reason="authorization tenant mismatch",
            audit_code="AUTHORIZATION_TENANT_MISMATCH",
        )

    # Engagement isolation: the row engagement must match the caller's engagement.
    if auth_engagement_id != engagement_id:
        raise ScanAuthorizationError(
            reason="authorization engagement mismatch",
            audit_code="AUTHORIZATION_ENGAGEMENT_MISMATCH",
        )

    # Status must be active (redundant with query, but defence in depth).
    if auth_status != "active":
        raise ScanAuthorizationError(
            reason=f"authorization is not active (status={auth_status})",
            audit_code="AUTHORIZATION_NOT_ACTIVE",
        )

    # 3. Revocation check.
    if revoked_at is not None:
        raise ScanAuthorizationError(
            reason="authorization has been revoked",
            audit_code="AUTHORIZATION_REVOKED",
        )

    # 3. Expiry check.
    if expires_at is not None:
        # expires_at may be a datetime or a string depending on driver.
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ScanAuthorizationError(
                    reason="authorization expiry timestamp is malformed",
                    audit_code="AUTHORIZATION_EXPIRY_MALFORMED",
                ) from exc
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if _now >= expires_at:
            raise ScanAuthorizationError(
                reason="authorization has expired",
                audit_code="AUTHORIZATION_EXPIRED",
            )

    # 4. Effective-from check.
    if effective_from is not None:
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.fromisoformat(
                    effective_from.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ScanAuthorizationError(
                    reason="authorization effective_from timestamp is malformed",
                    audit_code="AUTHORIZATION_EFFECTIVE_FROM_MALFORMED",
                ) from exc
        if effective_from.tzinfo is None:
            effective_from = effective_from.replace(tzinfo=timezone.utc)
        if _now < effective_from:
            raise ScanAuthorizationError(
                reason="authorization is not yet effective",
                audit_code="AUTHORIZATION_NOT_YET_EFFECTIVE",
            )

    # 5–6. Target and operation scope check.
    if not isinstance(approved_targets_raw, list):
        raise ScanAuthorizationError(
            reason="authorization approved_targets is malformed",
            audit_code="AUTHORIZATION_TARGETS_MALFORMED",
        )

    if not approved_targets_raw:
        raise ScanAuthorizationError(
            reason="authorization approved_targets list is empty",
            audit_code="AUTHORIZATION_TARGETS_EMPTY",
        )

    # Normalize the candidate; fail closed on parse error.
    try:
        norm_candidate = normalize_target(target, target_type)
    except ValueError as exc:
        raise ScanAuthorizationError(
            reason=f"target normalization failed: {exc}",
            audit_code="TARGET_NORMALIZATION_FAILED",
        ) from exc

    # Find the first matching entry and check the operation.
    matched_entry: dict[str, Any] | None = None
    for entry in approved_targets_raw:
        try:
            entry_target = entry.get("target", "")
            entry_type = entry.get("type", "")
            if not entry_target or not entry_type:
                continue
            if target_in_scope(norm_candidate, target_type, [entry]):
                matched_entry = entry
                break
        except ValueError:
            # Malformed entry — skip, never match.
            continue

    if matched_entry is None:
        raise ScanAuthorizationError(
            reason="target not found in authorization scope",
            audit_code="TARGET_NOT_IN_SCOPE",
        )

    # 6. Operation check.
    permitted_ops = matched_entry.get("operations", [])
    if not isinstance(permitted_ops, list) or operation not in permitted_ops:
        raise ScanAuthorizationError(
            reason=f"operation {operation!r} not permitted for this target",
            audit_code="OPERATION_NOT_PERMITTED",
        )

    return {
        "authorization_id": auth_id,
        "tenant_id": auth_tenant_id,
        "engagement_id": auth_engagement_id,
        "matched_target": matched_entry,
        "operation": operation,
    }


# ---------------------------------------------------------------------------
# Cancellation helpers
# ---------------------------------------------------------------------------


def cancel_scan(
    db: Session,
    *,
    scan_job_id: str,
    tenant_id: str,
    engagement_id: str,
    reason: str,
    actor: str,
) -> dict[str, Any]:
    """Request cancellation of a scan job.

    Atomic CAS: transitions QUEUED or RUNNING → cancel_requested.
    Raises ScanAuthorizationError when:
    - The job is not found for this tenant+engagement.
    - The job is in a terminal state (complete, failed, dead_letter, cancelled).

    Returns the updated job state dict.
    """
    now = datetime.now(timezone.utc)

    result = db.execute(
        text(
            "UPDATE fa_scan_jobs "
            "SET status = 'cancel_requested', "
            "    cancel_requested_at = :now, "
            "    cancellation_reason = :reason, "
            "    cancelled_by = :actor "
            "WHERE id = :job_id "
            "  AND tenant_id = :tenant_id "
            "  AND engagement_id = :engagement_id "
            "  AND status IN ('queued', 'running') "
            "RETURNING id, status, cancel_requested_at"
        ),
        {
            "job_id": scan_job_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "reason": reason,
            "actor": actor,
            "now": now,
        },
    )
    updated = result.fetchone()

    if updated is None:
        # Check whether the job exists but is in a terminal state.
        existing = db.execute(
            text(
                "SELECT id, status FROM fa_scan_jobs "
                "WHERE id = :job_id "
                "  AND tenant_id = :tenant_id "
                "  AND engagement_id = :engagement_id"
            ),
            {
                "job_id": scan_job_id,
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
            },
        ).fetchone()

        if existing is None:
            raise ScanAuthorizationError(
                reason="scan job not found",
                audit_code="CANCEL_JOB_NOT_FOUND",
            )

        current_status = str(existing[1])
        if current_status == "cancelled":
            # Idempotent — already cancelled.
            return {
                "scan_job_id": scan_job_id,
                "status": "cancelled",
                "idempotent": True,
            }

        if current_status == "cancel_requested":
            # Idempotent — already requested.
            return {
                "scan_job_id": scan_job_id,
                "status": "cancel_requested",
                "idempotent": True,
            }

        raise ScanAuthorizationError(
            reason=f"cannot cancel scan in terminal state: {current_status}",
            audit_code="CANCEL_TERMINAL_STATE",
        )

    db.commit()
    return {
        "scan_job_id": str(updated[0]),
        "status": str(updated[1]),
        "cancel_requested_at": updated[2].isoformat() if updated[2] else None,
    }


def confirm_scan_cancelled(
    db: Session,
    *,
    scan_job_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Worker confirms cancellation: transitions cancel_requested → cancelled.

    If the job is already cancelled, returns idempotent success.
    If the job is in a terminal state other than cancel_requested, raises.
    If COMPLETED arrives after CANCEL_REQUESTED, CANCELLED wins — the
    worker must call this instead of mark_complete when it observes
    cancel_requested.
    """
    now = datetime.now(timezone.utc)

    result = db.execute(
        text(
            "UPDATE fa_scan_jobs "
            "SET status = 'cancelled', "
            "    cancelled_at = :now "
            "WHERE id = :job_id "
            "  AND tenant_id = :tenant_id "
            "  AND status = 'cancel_requested' "
            "RETURNING id, status, cancelled_at"
        ),
        {"job_id": scan_job_id, "tenant_id": tenant_id, "now": now},
    )
    updated = result.fetchone()

    if updated is None:
        existing = db.execute(
            text(
                "SELECT status FROM fa_scan_jobs "
                "WHERE id = :job_id AND tenant_id = :tenant_id"
            ),
            {"job_id": scan_job_id, "tenant_id": tenant_id},
        ).fetchone()

        if existing is None:
            raise ScanAuthorizationError(
                reason="scan job not found",
                audit_code="CONFIRM_CANCEL_JOB_NOT_FOUND",
            )

        current_status = str(existing[0])
        if current_status == "cancelled":
            return {
                "scan_job_id": scan_job_id,
                "status": "cancelled",
                "idempotent": True,
            }

        raise ScanAuthorizationError(
            reason=f"cannot confirm cancel from state: {current_status}",
            audit_code="CONFIRM_CANCEL_INVALID_STATE",
        )

    db.commit()
    return {
        "scan_job_id": str(updated[0]),
        "status": str(updated[1]),
        "cancelled_at": updated[2].isoformat() if updated[2] else None,
    }


# ---------------------------------------------------------------------------
# Emergency stop management
# ---------------------------------------------------------------------------

_PLATFORM_STOP_PERMISSION = "scan.emergency_stop.platform"
_TENANT_STOP_PERMISSION = "scan.emergency_stop"
_ENGAGEMENT_STOP_PERMISSION = "scan.emergency_stop"


def request_emergency_stop(
    db: Session,
    *,
    scope: str,
    reason: str,
    actor: str,
    actor_tenant_id: str | None,
    permissions: list[str],
) -> dict[str, Any]:
    """Activate an emergency stop.

    scope must be: 'platform' | 'tenant:{id}' | 'engagement:{id}'

    Permission rules:
    - 'platform' scope requires scan.emergency_stop.platform permission.
    - 'tenant:{id}' scope requires scan.emergency_stop permission AND
      the actor_tenant_id must match the target tenant.
    - 'engagement:{id}' scope requires scan.emergency_stop permission.

    Cross-tenant stop: a tenant-level stop cannot affect another tenant.
    Raises ScanAuthorizationError for permission violations.
    """
    if scope == "platform":
        if _PLATFORM_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="platform emergency stop requires scan.emergency_stop.platform permission",
                audit_code="EMERGENCY_STOP_PERMISSION_DENIED",
            )
    elif scope.startswith("tenant:"):
        if _TENANT_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="tenant emergency stop requires scan.emergency_stop permission",
                audit_code="EMERGENCY_STOP_PERMISSION_DENIED",
            )
        target_tenant = scope[len("tenant:") :]
        if actor_tenant_id and actor_tenant_id != target_tenant:
            raise ScanAuthorizationError(
                reason="cannot activate emergency stop for a different tenant",
                audit_code="EMERGENCY_STOP_CROSS_TENANT_DENIED",
            )
    elif scope.startswith("engagement:"):
        if _ENGAGEMENT_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="engagement emergency stop requires scan.emergency_stop permission",
                audit_code="EMERGENCY_STOP_PERMISSION_DENIED",
            )
        if actor_tenant_id:
            engagement_id_from_scope = scope[len("engagement:") :]
            eng_row = db.execute(
                text(
                    "SELECT id FROM fa_engagements WHERE id = :eid AND tenant_id = :tid"
                ),
                {"eid": engagement_id_from_scope, "tid": actor_tenant_id},
            ).fetchone()
            if eng_row is None:
                raise ScanAuthorizationError(
                    reason="engagement not found in actor's tenant",
                    audit_code="EMERGENCY_STOP_CROSS_TENANT_DENIED",
                )
    else:
        raise ScanAuthorizationError(
            reason=f"invalid emergency stop scope: {scope!r}",
            audit_code="EMERGENCY_STOP_INVALID_SCOPE",
        )

    result = db.execute(
        text(
            "INSERT INTO fa_scan_emergency_stops "
            "    (scope, activated_by, reason, is_active) "
            "VALUES (:scope, :actor, :reason, TRUE) "
            "RETURNING id, scope, is_active, activated_at"
        ),
        {"scope": scope, "actor": actor, "reason": reason},
    ).fetchone()
    db.commit()

    return {
        "stop_id": str(result[0]),
        "scope": str(result[1]),
        "is_active": bool(result[2]),
        "activated_at": result[3].isoformat() if result[3] else None,
    }


def clear_emergency_stop(
    db: Session,
    *,
    stop_id: str,
    actor: str,
    actor_tenant_id: str | None,
    permissions: list[str],
) -> dict[str, Any]:
    """Clear an active emergency stop.

    Permission rules mirror those for activation.
    """
    row = db.execute(
        text(
            "SELECT id, scope, is_active FROM fa_scan_emergency_stops "
            "WHERE id = :stop_id"
        ),
        {"stop_id": stop_id},
    ).fetchone()

    if row is None:
        raise ScanAuthorizationError(
            reason="emergency stop not found",
            audit_code="EMERGENCY_STOP_NOT_FOUND",
        )

    scope = str(row[1])
    is_active = bool(row[2])

    if not is_active:
        return {
            "stop_id": stop_id,
            "scope": scope,
            "is_active": False,
            "idempotent": True,
        }

    # Permission check mirrors activation.
    if scope == "platform":
        if _PLATFORM_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="clearing platform emergency stop requires scan.emergency_stop.platform",
                audit_code="EMERGENCY_STOP_CLEAR_PERMISSION_DENIED",
            )
    elif scope.startswith("tenant:"):
        if _TENANT_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="clearing tenant emergency stop requires scan.emergency_stop",
                audit_code="EMERGENCY_STOP_CLEAR_PERMISSION_DENIED",
            )
        target_tenant = scope[len("tenant:") :]
        if actor_tenant_id and actor_tenant_id != target_tenant:
            raise ScanAuthorizationError(
                reason="cannot clear emergency stop for a different tenant",
                audit_code="EMERGENCY_STOP_CLEAR_CROSS_TENANT_DENIED",
            )
    else:
        if _ENGAGEMENT_STOP_PERMISSION not in permissions:
            raise ScanAuthorizationError(
                reason="clearing engagement emergency stop requires scan.emergency_stop",
                audit_code="EMERGENCY_STOP_CLEAR_PERMISSION_DENIED",
            )

    now = datetime.now(timezone.utc)
    db.execute(
        text(
            "UPDATE fa_scan_emergency_stops "
            "SET is_active = FALSE, cleared_at = :now, cleared_by = :actor "
            "WHERE id = :stop_id"
        ),
        {"stop_id": stop_id, "actor": actor, "now": now},
    )
    db.commit()

    return {
        "stop_id": stop_id,
        "scope": scope,
        "is_active": False,
        "cleared_at": now.isoformat(),
    }
