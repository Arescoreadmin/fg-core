"""Customer scan authorization receipts — L14-SCAN-AUTH-HARDENING-001 (AUTH-GAP-001).

Purpose
-------
``fa_scan_authorizations`` (migration 0200) records an OPERATOR-created scope.
An operator asserting that consent exists is not customer consent.  This module
owns the customer-side approval record: an authenticated customer principal,
derived from trusted authentication context, approves an explicit set of
targets, operations and a time window for one tenant + engagement.

Proof model (what is actually implemented — do not overstate)
------------------------------------------------------------
* ``SERVER_ATTESTED_AUTHENTICATED_APPROVAL`` — the approver was authenticated by
  FrostGate identity infrastructure (interactive OIDC, verified email, customer
  authority role, same tenant), every material approval field is bound by a
  versioned canonical SHA-256 digest, and FrostGate attests the digest with an
  HMAC-SHA256 under a trusted, non-revoked key id from the configured key ring.
  This is a SERVER attestation.  It is NOT a customer-controlled digital
  signature: the customer does not hold the key, and a party holding the
  attestation key could forge an attestation.  Offline customer verification
  with a public key is NOT implemented (requires an asymmetric signing
  authority — see L14-SCAN-VAULT-001).
* ``AUTHENTICATED_APPROVAL_DIGEST_ONLY`` — same authenticated approval and
  digest, but no attestation key is configured.  Tamper-evident against
  accidental change only; permitted outside production only.  In production
  (FG_ENV=prod|staging) approval fails closed without an attestation key.
* ``LEGACY_OPERATOR_ASSERTED`` — scope record has no customer receipt.  Never
  presented as verified customer consent.  Rejected wherever consent is
  required (always in production).

Lifecycle
---------
pending_approval → approved → revoked
pending_approval → rejected
``expired`` is DERIVED (now >= window_end) — never stored, never auto-renewed.
Re-approval creates a NEW receipt row (same receipt_group_id, version + 1).
Material fields are immutable after approval (DB trigger, migration 0203).

Not standalone: this module is bound to ``fa_scan_authorizations`` through
``check_scan_authorized()`` in ``scan_authorization.py``; it is never consulted
on its own to permit outbound I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping

from sqlalchemy import text
from sqlalchemy.orm import Session

from services.field_assessment.evidence_integrity import canonicalize_payload
from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    normalize_target,
    target_in_scope,
)

# ---------------------------------------------------------------------------
# Versioned contract constants
# ---------------------------------------------------------------------------

RECEIPT_SCHEMA_VERSION = "fg.customer_scan_authorization.v1"
CONSENT_STATEMENT_VERSION = "fg.scan_consent_statement.v1"
TARGET_NORMALIZATION_VERSION = "fg.scan_target_normalization.v1"
DIGEST_ALGORITHM = "sha256"
ATTESTATION_ALGORITHM = "HMAC-SHA256"

SUPPORTED_OPERATIONS: frozenset[str] = frozenset(
    {"network_scan", "web_headers", "dns_email"}
)
SUPPORTED_TARGET_TYPES: frozenset[str] = frozenset({"fqdn", "ipv4", "ipv6", "cidr"})

MAX_APPROVAL_WINDOW = timedelta(days=366)
MAX_APPROVED_TARGETS = 256

# Roles whose holders may approve scanning on behalf of the customer.
# tenant_admin is the customer organization administrator (see actor_context SoD
# notes); client_security_owner is the delegated customer security owner.
CUSTOMER_AUTHORITY_ROLES: frozenset[str] = frozenset(
    {"tenant_admin", "client_security_owner"}
)
# FrostGate staff roles can never stand in for the customer.
_NON_CUSTOMER_ROLES: frozenset[str] = frozenset({"platform_admin"})
# Only interactive, human, IdP-backed authentication may approve.
_APPROVER_AUTH_SOURCES: frozenset[str] = frozenset(
    {"oidc_auth0", "oidc_entra", "oidc_okta"}
)

APPROVE_PERMISSION = "scan.consent.approve"

PENDING = "pending_approval"
APPROVED = "approved"
REJECTED = "rejected"
REVOKED = "revoked"
EXPIRED = "expired"  # derived only


class ProofLevel(str, Enum):
    SERVER_ATTESTED_AUTHENTICATED_APPROVAL = "SERVER_ATTESTED_AUTHENTICATED_APPROVAL"
    AUTHENTICATED_APPROVAL_DIGEST_ONLY = "AUTHENTICATED_APPROVAL_DIGEST_ONLY"
    LEGACY_OPERATOR_ASSERTED = "LEGACY_OPERATOR_ASSERTED"


class CustomerAuthorizationError(ScanAuthorizationError):
    """Fail-closed customer authorization failure (subclass of the canonical error)."""


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def _production() -> bool:
    try:
        from api.config.env import is_production_env

        return is_production_env()
    except Exception:  # noqa: BLE001 — undeterminable environment fails closed
        return True


def consent_required() -> bool:
    """Customer receipt required for scope activation and scan execution.

    Always required in production/staging (no downgrade switch).  Outside
    production it is opt-in via FG_SCAN_REQUIRE_CUSTOMER_CONSENT=1 so legacy
    development fixtures keep working — those scans are labelled
    LEGACY_OPERATOR_ASSERTED, never verified.
    """
    if _production():
        return True
    return os.getenv("FG_SCAN_REQUIRE_CUSTOMER_CONSENT", "").strip() == "1"


def attestation_required() -> bool:
    if _production():
        return True
    return os.getenv("FG_SCAN_CONSENT_REQUIRE_ATTESTATION", "").strip() == "1"


# ---------------------------------------------------------------------------
# Attestation key ring (never logged, never persisted)
# ---------------------------------------------------------------------------

_KEYRING_ENV = "FG_SCAN_CONSENT_ATTESTATION_KEYS"  # JSON {"kid": "<hex key>"}
_ACTIVE_KID_ENV = "FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID"
_REVOKED_KIDS_ENV = "FG_SCAN_CONSENT_ATTESTATION_REVOKED_KIDS"  # comma-separated
_MIN_KEY_BYTES = 32


def _keyring() -> dict[str, bytes]:
    raw = os.getenv(_KEYRING_ENV, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        # Do not echo the value — it is key material.
        raise CustomerAuthorizationError(
            reason="attestation key ring is malformed",
            audit_code="ATTESTATION_KEYRING_MALFORMED",
        ) from None
    if not isinstance(parsed, dict):
        raise CustomerAuthorizationError(
            reason="attestation key ring is malformed",
            audit_code="ATTESTATION_KEYRING_MALFORMED",
        )
    ring: dict[str, bytes] = {}
    for kid, hex_key in parsed.items():
        try:
            key = bytes.fromhex(str(hex_key))
        except ValueError:
            continue  # malformed keys are unusable, never trusted
        if len(key) >= _MIN_KEY_BYTES and str(kid).strip():
            ring[str(kid)] = key
    return ring


def _revoked_kids() -> frozenset[str]:
    raw = os.getenv(_REVOKED_KIDS_ENV, "")
    return frozenset(k.strip() for k in raw.split(",") if k.strip())


def _active_attestation_key() -> tuple[str, bytes] | None:
    kid = os.getenv(_ACTIVE_KID_ENV, "").strip()
    if not kid:
        return None
    if kid in _revoked_kids():
        raise CustomerAuthorizationError(
            reason="active attestation key id is revoked",
            audit_code="ATTESTATION_KEY_REVOKED",
        )
    key = _keyring().get(kid)
    if key is None:
        return None
    return kid, key


def _attest(key: bytes, canonical: bytes) -> str:
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _iso_z(value: Any) -> str:
    dt = _as_utc(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CustomerAuthorizationError(
                reason="malformed timestamp",
                audit_code="RECEIPT_TIMESTAMP_MALFORMED",
            ) from exc
    else:
        raise CustomerAuthorizationError(
            reason="missing timestamp", audit_code="RECEIPT_TIMESTAMP_MALFORMED"
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_approved_targets(
    entries: Any, *, authorized_operations: list[str]
) -> list[dict[str, Any]]:
    """Validate + canonicalize approved target entries.  Fail closed on anything odd."""
    if not isinstance(entries, list) or not entries:
        raise CustomerAuthorizationError(
            reason="approved_targets must be a non-empty list",
            audit_code="RECEIPT_TARGETS_INVALID",
        )
    if len(entries) > MAX_APPROVED_TARGETS:
        raise CustomerAuthorizationError(
            reason="too many approved targets", audit_code="RECEIPT_TARGETS_INVALID"
        )
    allowed_ops = set(authorized_operations)
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise CustomerAuthorizationError(
                reason="approved target entry must be an object",
                audit_code="RECEIPT_TARGETS_INVALID",
            )
        extra = set(entry.keys()) - {"target", "type", "operations", "allow_subdomains"}
        if extra:
            raise CustomerAuthorizationError(
                reason="approved target entry has unknown fields",
                audit_code="RECEIPT_TARGETS_INVALID",
            )
        ttype = str(entry.get("type", "")).lower().strip()
        if ttype not in SUPPORTED_TARGET_TYPES:
            raise CustomerAuthorizationError(
                reason="unsupported target type", audit_code="RECEIPT_TARGETS_INVALID"
            )
        try:
            norm = normalize_target(str(entry.get("target", "")), ttype)
        except ValueError as exc:
            raise CustomerAuthorizationError(
                reason=f"target normalization failed: {exc}",
                audit_code="RECEIPT_TARGETS_INVALID",
            ) from exc
        ops = entry.get("operations")
        if not isinstance(ops, list) or not ops:
            raise CustomerAuthorizationError(
                reason="each approved target must list operations",
                audit_code="RECEIPT_TARGETS_INVALID",
            )
        ops_set = {str(o) for o in ops}
        if not ops_set <= allowed_ops:
            raise CustomerAuthorizationError(
                reason="target operations exceed authorized operations",
                audit_code="RECEIPT_OPERATIONS_INVALID",
            )
        allow_sub = entry.get("allow_subdomains", False)
        if not isinstance(allow_sub, bool):
            raise CustomerAuthorizationError(
                reason="allow_subdomains must be boolean",
                audit_code="RECEIPT_TARGETS_INVALID",
            )
        if allow_sub and ttype != "fqdn":
            raise CustomerAuthorizationError(
                reason="allow_subdomains is only valid for fqdn targets",
                audit_code="RECEIPT_TARGETS_INVALID",
            )
        key = (ttype, norm)
        if key in out:
            raise CustomerAuthorizationError(
                reason="duplicate approved target", audit_code="RECEIPT_TARGETS_INVALID"
            )
        out[key] = {
            "target": norm,
            "type": ttype,
            "operations": sorted(ops_set),
            "allow_subdomains": allow_sub,
        }
    return [out[k] for k in sorted(out)]


def normalize_operations(ops: Any) -> list[str]:
    if not isinstance(ops, list) or not ops:
        raise CustomerAuthorizationError(
            reason="authorized_operations must be a non-empty list",
            audit_code="RECEIPT_OPERATIONS_INVALID",
        )
    s = {str(o) for o in ops}
    if not s <= SUPPORTED_OPERATIONS:
        raise CustomerAuthorizationError(
            reason="unsupported operation in authorized_operations",
            audit_code="RECEIPT_OPERATIONS_INVALID",
        )
    return sorted(s)


# ---------------------------------------------------------------------------
# Canonical approval payload + digest
# ---------------------------------------------------------------------------


def canonical_approval_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Every material approval field.  Changing any of these changes the digest."""
    return {
        "receipt_id": str(receipt["id"]),
        "receipt_group_id": str(receipt["receipt_group_id"]),
        "receipt_version": int(receipt["receipt_version"]),
        "schema_version": str(receipt["schema_version"]),
        "tenant_id": str(receipt["tenant_id"]),
        "engagement_id": str(receipt["engagement_id"]),
        "customer_org_name": str(receipt["customer_org_name"]),
        "assessment_purpose": str(receipt["assessment_purpose"]),
        "rules_of_engagement_ref": str(receipt["rules_of_engagement_ref"]),
        "consent_statement_version": str(receipt["consent_statement_version"]),
        "target_normalization_version": str(receipt["target_normalization_version"]),
        "approved_targets": _json_value(receipt["approved_targets"]),
        "authorized_operations": sorted(_json_value(receipt["authorized_operations"])),
        "window_start": _iso_z(receipt["window_start"]),
        "window_end": _iso_z(receipt["window_end"]),
        "requested_by_subject": str(receipt["requested_by_subject"]),
        "approver": {
            "subject": str(receipt["approver_subject"]),
            "email": str(receipt.get("approver_email") or ""),
            "auth_source": str(receipt["approver_auth_source"]),
            "authority_basis": str(receipt["approver_authority_basis"]),
            "membership_id": str(receipt.get("approver_membership_id") or ""),
            "also_assessor": bool(receipt.get("approver_also_assessor") or False),
        },
        "approved_at": _iso_z(receipt["approved_at"]),
    }


def _json_value(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError as exc:
            raise CustomerAuthorizationError(
                reason="receipt JSON field is malformed",
                audit_code="RECEIPT_MALFORMED",
            ) from exc
    return v


def approval_digest(receipt: Mapping[str, Any]) -> tuple[str, bytes]:
    canonical = canonicalize_payload(
        canonical_approval_payload(receipt), schema_version=RECEIPT_SCHEMA_VERSION
    )
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}", canonical


def verify_receipt_integrity(receipt: Mapping[str, Any]) -> ProofLevel:
    """Recompute the digest from stored fields and verify the attestation.

    Raises CustomerAuthorizationError on ANY mismatch.  Never returns a proof
    level stronger than what was actually verified.
    """
    if str(receipt.get("schema_version")) != RECEIPT_SCHEMA_VERSION:
        raise CustomerAuthorizationError(
            reason="unsupported receipt schema version",
            audit_code="RECEIPT_SCHEMA_UNSUPPORTED",
        )
    stored_digest = receipt.get("payload_digest")
    if not stored_digest:
        raise CustomerAuthorizationError(
            reason="receipt has no approval digest",
            audit_code="RECEIPT_DIGEST_MISSING",
        )
    try:
        digest, canonical = approval_digest(receipt)
    except (KeyError, TypeError) as exc:
        raise CustomerAuthorizationError(
            reason="receipt is missing material approval fields",
            audit_code="RECEIPT_MALFORMED",
        ) from exc
    if not hmac.compare_digest(str(stored_digest), digest):
        raise CustomerAuthorizationError(
            reason="receipt approval digest mismatch (fields altered)",
            audit_code="RECEIPT_DIGEST_MISMATCH",
        )

    kid = receipt.get("attestation_kid")
    value = receipt.get("attestation_value")
    if not kid and not value:
        if attestation_required():
            raise CustomerAuthorizationError(
                reason="receipt is not attested and attestation is required",
                audit_code="RECEIPT_ATTESTATION_MISSING",
            )
        return ProofLevel.AUTHENTICATED_APPROVAL_DIGEST_ONLY
    if not kid or not value:
        raise CustomerAuthorizationError(
            reason="receipt attestation is incomplete",
            audit_code="RECEIPT_ATTESTATION_INVALID",
        )
    if str(receipt.get("attestation_alg")) != ATTESTATION_ALGORITHM:
        # Downgrade / algorithm substitution is never accepted.
        raise CustomerAuthorizationError(
            reason="unsupported attestation algorithm",
            audit_code="RECEIPT_ATTESTATION_ALG_UNSUPPORTED",
        )
    if str(kid) in _revoked_kids():
        raise CustomerAuthorizationError(
            reason="receipt attestation key id is revoked",
            audit_code="RECEIPT_ATTESTATION_KEY_REVOKED",
        )
    key = _keyring().get(str(kid))
    if key is None:
        raise CustomerAuthorizationError(
            reason="receipt attestation key id is not trusted",
            audit_code="RECEIPT_ATTESTATION_KEY_UNKNOWN",
        )
    if not hmac.compare_digest(_attest(key, canonical), str(value)):
        raise CustomerAuthorizationError(
            reason="receipt attestation verification failed",
            audit_code="RECEIPT_ATTESTATION_INVALID",
        )
    return ProofLevel.SERVER_ATTESTED_AUTHENTICATED_APPROVAL


# ---------------------------------------------------------------------------
# Approver identity validation (trusted ActorContext only)
# ---------------------------------------------------------------------------


def validate_approver(
    actor_ctx: Any, *, tenant_id: str, requested_by_subject: str
) -> dict[str, Any]:
    """Return the approver identity record or raise.  Never reads request bodies."""
    subject = str(getattr(actor_ctx, "subject", "") or "")
    if not subject:
        raise CustomerAuthorizationError(
            reason="approver identity missing", audit_code="APPROVER_IDENTITY_MISSING"
        )
    perms = getattr(actor_ctx, "permissions", frozenset()) or frozenset()
    if APPROVE_PERMISSION not in perms:
        raise CustomerAuthorizationError(
            reason="approver lacks scan.consent.approve",
            audit_code="APPROVER_PERMISSION_DENIED",
        )
    roles = set(getattr(actor_ctx, "roles", []) or [])
    if roles & _NON_CUSTOMER_ROLES:
        raise CustomerAuthorizationError(
            reason="platform operators cannot approve on behalf of a customer",
            audit_code="APPROVER_NOT_CUSTOMER",
        )
    basis = sorted(roles & CUSTOMER_AUTHORITY_ROLES)
    if not basis:
        raise CustomerAuthorizationError(
            reason="approver holds no customer authority role",
            audit_code="APPROVER_NOT_CUSTOMER",
        )
    if getattr(actor_ctx, "service_principal_id", None):
        raise CustomerAuthorizationError(
            reason="service principals cannot approve customer consent",
            audit_code="APPROVER_NOT_HUMAN",
        )
    auth_source = str(getattr(actor_ctx, "auth_source", "") or "")
    if auth_source not in _APPROVER_AUTH_SOURCES:
        raise CustomerAuthorizationError(
            reason="approval requires interactive identity-provider authentication",
            audit_code="APPROVER_AUTH_SOURCE_DENIED",
        )
    if not bool(getattr(actor_ctx, "email_verified", False)):
        raise CustomerAuthorizationError(
            reason="approver email is not verified",
            audit_code="APPROVER_EMAIL_UNVERIFIED",
        )
    actor_tenant = getattr(actor_ctx, "tenant_id", None)
    if not actor_tenant or str(actor_tenant) != str(tenant_id):
        raise CustomerAuthorizationError(
            reason="approver tenant does not match receipt tenant",
            audit_code="APPROVER_TENANT_MISMATCH",
        )
    if subject == str(requested_by_subject):
        # The assessor who requested the scan cannot also consent to it.
        raise CustomerAuthorizationError(
            reason="requester cannot approve their own authorization request",
            audit_code="APPROVER_SELF_APPROVAL_DENIED",
        )
    return {
        "approver_subject": subject,
        "approver_email": str(getattr(actor_ctx, "email", "") or ""),
        "approver_auth_source": auth_source,
        "approver_authority_basis": ",".join(basis),
        "approver_membership_id": getattr(actor_ctx, "membership_id", None),
        # Recorded, not hidden: an identity that also holds assessor authority.
        "approver_also_assessor": "assessor" in roles,
    }


# ---------------------------------------------------------------------------
# Receipt evaluation (pure — no I/O)
# ---------------------------------------------------------------------------


def derived_status(receipt: Mapping[str, Any], now: datetime) -> str:
    status = str(receipt.get("status"))
    if status == APPROVED and receipt.get("revoked_at") is None:
        if now >= _as_utc(receipt["window_end"]):
            return EXPIRED
    return status


def _require_usable(
    receipt: Mapping[str, Any], *, tenant_id: str, engagement_id: str, now: datetime
) -> ProofLevel:
    if str(receipt.get("tenant_id")) != str(tenant_id):
        raise CustomerAuthorizationError(
            reason="receipt tenant mismatch", audit_code="RECEIPT_TENANT_MISMATCH"
        )
    if str(receipt.get("engagement_id")) != str(engagement_id):
        raise CustomerAuthorizationError(
            reason="receipt engagement mismatch",
            audit_code="RECEIPT_ENGAGEMENT_MISMATCH",
        )
    if receipt.get("revoked_at") is not None or receipt.get("status") == REVOKED:
        raise CustomerAuthorizationError(
            reason="customer authorization revoked", audit_code="RECEIPT_REVOKED"
        )
    if receipt.get("status") != APPROVED:
        raise CustomerAuthorizationError(
            reason="customer authorization is not approved",
            audit_code="RECEIPT_NOT_APPROVED",
        )
    if now < _as_utc(receipt["window_start"]):
        raise CustomerAuthorizationError(
            reason="customer authorization window not yet open",
            audit_code="RECEIPT_NOT_YET_VALID",
        )
    if now >= _as_utc(receipt["window_end"]):
        raise CustomerAuthorizationError(
            reason="customer authorization expired", audit_code="RECEIPT_EXPIRED"
        )
    return verify_receipt_integrity(receipt)


def evaluate_receipt_for_target(
    receipt: Mapping[str, Any],
    *,
    tenant_id: str,
    engagement_id: str,
    target: str,
    target_type: str,
    operation: str,
    now: datetime,
) -> ProofLevel:
    """Fail-closed check that the CUSTOMER approved this exact target + operation now."""
    proof = _require_usable(
        receipt, tenant_id=tenant_id, engagement_id=engagement_id, now=now
    )
    ops = set(_json_value(receipt["authorized_operations"]))
    if operation not in ops:
        raise CustomerAuthorizationError(
            reason="operation not approved by customer",
            audit_code="RECEIPT_OPERATION_NOT_APPROVED",
        )
    for entry in _json_value(receipt["approved_targets"]):
        try:
            if target_in_scope(target, target_type, [entry]) and operation in (
                entry.get("operations") or []
            ):
                return proof
        except ValueError:
            continue
    raise CustomerAuthorizationError(
        reason="target not approved by customer",
        audit_code="RECEIPT_TARGET_NOT_APPROVED",
    )


def _scope_entry_covered(scope_entry: Mapping[str, Any], receipt_entries: list) -> bool:
    s_type = str(scope_entry.get("type", "")).lower()
    s_target = str(scope_entry.get("target", ""))
    s_ops = set(scope_entry.get("operations") or [])
    s_sub = bool(scope_entry.get("allow_subdomains", False))
    if not s_ops:
        return False
    for r in receipt_entries:
        r_type = str(r.get("type", "")).lower()
        r_ops = set(r.get("operations") or [])
        if not s_ops <= r_ops:
            continue
        try:
            if s_type == "cidr" and r_type == "cidr":
                s_net = ipaddress.ip_network(normalize_target(s_target, "cidr"))
                r_net = ipaddress.ip_network(r.get("target", ""))
                if s_net.version == r_net.version and s_net.subnet_of(r_net):  # type: ignore[arg-type]
                    return True
                continue
            if not target_in_scope(s_target, s_type, [r]):
                continue
        except (ValueError, TypeError):
            continue
        if s_sub and not bool(r.get("allow_subdomains", False)):
            continue
        return True
    return False


def evaluate_receipt_for_scope(
    receipt: Mapping[str, Any],
    *,
    scope_targets: list,
    scope_expires_at: Any,
    tenant_id: str,
    engagement_id: str,
    now: datetime,
) -> ProofLevel:
    """Every scope entry must be within the customer-approved targets/operations/window."""
    proof = _require_usable(
        receipt, tenant_id=tenant_id, engagement_id=engagement_id, now=now
    )
    if not isinstance(scope_targets, list) or not scope_targets:
        raise CustomerAuthorizationError(
            reason="scope has no targets", audit_code="SCOPE_TARGETS_EMPTY"
        )
    receipt_entries = _json_value(receipt["approved_targets"])
    for entry in scope_targets:
        if not isinstance(entry, Mapping) or not _scope_entry_covered(
            entry, receipt_entries
        ):
            raise CustomerAuthorizationError(
                reason="scope exceeds customer-approved targets or operations",
                audit_code="SCOPE_EXCEEDS_CUSTOMER_APPROVAL",
            )
    if _as_utc(scope_expires_at) > _as_utc(receipt["window_end"]):
        raise CustomerAuthorizationError(
            reason="scope expiry exceeds customer approval window",
            audit_code="SCOPE_WINDOW_EXCEEDS_CUSTOMER_APPROVAL",
        )
    return proof


# ---------------------------------------------------------------------------
# Persistence (raw SQL, tenant + engagement predicates on every statement)
# ---------------------------------------------------------------------------

_RECEIPT_COLUMNS = (
    "id, receipt_group_id, receipt_version, schema_version, tenant_id, "
    "engagement_id, customer_org_name, assessment_purpose, rules_of_engagement_ref, "
    "consent_statement_version, target_normalization_version, approved_targets, "
    "authorized_operations, window_start, window_end, status, requested_by_subject, "
    "requested_at, approver_subject, approver_email, approver_auth_source, "
    "approver_authority_basis, approver_membership_id, approver_also_assessor, "
    "approved_at, payload_digest, digest_algorithm, attestation_kid, "
    "attestation_alg, attestation_value, proof_level, rejected_at, "
    "rejected_by_subject, rejection_reason, revoked_at, revoked_by_subject, "
    "revocation_reason, created_at"
)


def _row_to_dict(row: Any) -> dict[str, Any]:
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return dict(mapping)
    if isinstance(row, Mapping):
        return dict(row)
    raise CustomerAuthorizationError(
        reason="receipt row is malformed", audit_code="RECEIPT_MALFORMED"
    )


def load_receipt(
    db: Session, *, receipt_id: str, tenant_id: str, engagement_id: str
) -> dict[str, Any] | None:
    try:
        uuid.UUID(str(receipt_id))
    except ValueError:
        return None
    row = db.execute(
        text(
            f"SELECT {_RECEIPT_COLUMNS} FROM fa_customer_authorization_receipts "
            "WHERE id = CAST(:rid AS uuid) AND tenant_id = :tid "
            "  AND engagement_id = :eid"
        ),
        {"rid": str(receipt_id), "tid": tenant_id, "eid": engagement_id},
    ).fetchone()
    return _row_to_dict(row) if row is not None else None


def create_request(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    requested_by_subject: str,
    customer_org_name: str,
    assessment_purpose: str,
    rules_of_engagement_ref: str,
    approved_targets: list,
    authorized_operations: list,
    window_start: Any,
    window_end: Any,
    supersedes_receipt_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    _now = now or datetime.now(timezone.utc)
    ops = normalize_operations(authorized_operations)
    targets = normalize_approved_targets(approved_targets, authorized_operations=ops)
    start = _as_utc(window_start)
    end = _as_utc(window_end)
    if end <= start:
        raise CustomerAuthorizationError(
            reason="window_end must be after window_start",
            audit_code="RECEIPT_WINDOW_INVALID",
        )
    if end <= _now:
        raise CustomerAuthorizationError(
            reason="window_end is in the past", audit_code="RECEIPT_WINDOW_INVALID"
        )
    if end - start > MAX_APPROVAL_WINDOW:
        raise CustomerAuthorizationError(
            reason="approval window exceeds maximum",
            audit_code="RECEIPT_WINDOW_INVALID",
        )
    for name, val in (
        ("customer_org_name", customer_org_name),
        ("assessment_purpose", assessment_purpose),
        ("rules_of_engagement_ref", rules_of_engagement_ref),
    ):
        if not str(val or "").strip():
            raise CustomerAuthorizationError(
                reason=f"{name} is required", audit_code="RECEIPT_FIELD_MISSING"
            )

    group_id = str(uuid.uuid4())
    version = 1
    if supersedes_receipt_id:
        prior = load_receipt(
            db,
            receipt_id=supersedes_receipt_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
        if prior is None:
            raise CustomerAuthorizationError(
                reason="superseded receipt not found", audit_code="RECEIPT_NOT_FOUND"
            )
        group_id = str(prior["receipt_group_id"])
        latest = db.execute(
            text(
                "SELECT COALESCE(MAX(receipt_version), 0) "
                "FROM fa_customer_authorization_receipts "
                "WHERE receipt_group_id = CAST(:gid AS uuid) AND tenant_id = :tid"
            ),
            {"gid": group_id, "tid": tenant_id},
        ).fetchone()
        version = int(latest[0]) + 1 if latest else 2

    row = db.execute(
        text(
            "INSERT INTO fa_customer_authorization_receipts ("
            " receipt_group_id, receipt_version, schema_version, tenant_id,"
            " engagement_id, customer_org_name, assessment_purpose,"
            " rules_of_engagement_ref, consent_statement_version,"
            " target_normalization_version, approved_targets, authorized_operations,"
            " window_start, window_end, status, requested_by_subject, requested_at"
            ") VALUES ("
            " CAST(:gid AS uuid), :ver, :schema, :tid, :eid, :org, :purpose, :roe,"
            " :csv, :tnv, CAST(:targets AS jsonb), CAST(:ops AS jsonb),"
            " :wstart, :wend, 'pending_approval', :req, :now"
            f") RETURNING {_RECEIPT_COLUMNS}"
        ),
        {
            "gid": group_id,
            "ver": version,
            "schema": RECEIPT_SCHEMA_VERSION,
            "tid": tenant_id,
            "eid": engagement_id,
            "org": customer_org_name.strip(),
            "purpose": assessment_purpose.strip(),
            "roe": rules_of_engagement_ref.strip(),
            "csv": CONSENT_STATEMENT_VERSION,
            "tnv": TARGET_NORMALIZATION_VERSION,
            "targets": json.dumps(targets, sort_keys=True),
            "ops": json.dumps(ops),
            "wstart": start,
            "wend": end,
            "req": requested_by_subject,
            "now": _now,
        },
    ).fetchone()
    return _row_to_dict(row)


def approve(
    db: Session,
    *,
    receipt_id: str,
    tenant_id: str,
    engagement_id: str,
    actor_ctx: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Customer approval: atomic pending_approval → approved with digest + attestation."""
    _now = now or datetime.now(timezone.utc)
    receipt = load_receipt(
        db, receipt_id=receipt_id, tenant_id=tenant_id, engagement_id=engagement_id
    )
    if receipt is None:
        raise CustomerAuthorizationError(
            reason="authorization request not found", audit_code="RECEIPT_NOT_FOUND"
        )
    if receipt["status"] != PENDING:
        raise CustomerAuthorizationError(
            reason=f"authorization request is not pending (status={receipt['status']})",
            audit_code="RECEIPT_NOT_PENDING",
        )
    if _now >= _as_utc(receipt["window_end"]):
        raise CustomerAuthorizationError(
            reason="authorization window already ended", audit_code="RECEIPT_EXPIRED"
        )
    approver = validate_approver(
        actor_ctx,
        tenant_id=tenant_id,
        requested_by_subject=str(receipt["requested_by_subject"]),
    )

    candidate = {**receipt, **approver, "approved_at": _now}
    digest, canonical = approval_digest(candidate)
    active = _active_attestation_key()
    if active is None and attestation_required():
        raise CustomerAuthorizationError(
            reason="no trusted attestation key is configured; approval fails closed",
            audit_code="ATTESTATION_KEY_UNAVAILABLE",
        )
    kid, alg, value = (None, None, None)
    proof = ProofLevel.AUTHENTICATED_APPROVAL_DIGEST_ONLY
    if active is not None:
        kid, key = active
        alg, value = ATTESTATION_ALGORITHM, _attest(key, canonical)
        proof = ProofLevel.SERVER_ATTESTED_AUTHENTICATED_APPROVAL

    row = db.execute(
        text(
            "UPDATE fa_customer_authorization_receipts SET"
            " status = 'approved', approver_subject = :subj, approver_email = :email,"
            " approver_auth_source = :src, approver_authority_basis = :basis,"
            " approver_membership_id = :mid, approver_also_assessor = :also,"
            " approved_at = :now, payload_digest = :digest, digest_algorithm = :dalg,"
            " attestation_kid = :kid, attestation_alg = :alg,"
            " attestation_value = :val, proof_level = :proof, updated_at = :now"
            " WHERE id = CAST(:rid AS uuid) AND tenant_id = :tid"
            "   AND engagement_id = :eid AND status = 'pending_approval'"
            f" RETURNING {_RECEIPT_COLUMNS}"
        ),
        {
            "subj": approver["approver_subject"],
            "email": approver["approver_email"],
            "src": approver["approver_auth_source"],
            "basis": approver["approver_authority_basis"],
            "mid": approver["approver_membership_id"],
            "also": approver["approver_also_assessor"],
            "now": _now,
            "digest": digest,
            "dalg": DIGEST_ALGORITHM,
            "kid": kid,
            "alg": alg,
            "val": value,
            "proof": proof.value,
            "rid": str(receipt_id),
            "tid": tenant_id,
            "eid": engagement_id,
        },
    ).fetchone()
    if row is None:
        # Lost a concurrent race (duplicate approval submission).
        raise CustomerAuthorizationError(
            reason="authorization request is no longer pending",
            audit_code="RECEIPT_NOT_PENDING",
        )
    return _row_to_dict(row)


def reject(
    db: Session,
    *,
    receipt_id: str,
    tenant_id: str,
    engagement_id: str,
    actor_ctx: Any,
    reason: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    _now = now or datetime.now(timezone.utc)
    receipt = load_receipt(
        db, receipt_id=receipt_id, tenant_id=tenant_id, engagement_id=engagement_id
    )
    if receipt is None:
        raise CustomerAuthorizationError(
            reason="authorization request not found", audit_code="RECEIPT_NOT_FOUND"
        )
    approver = validate_approver(
        actor_ctx,
        tenant_id=tenant_id,
        requested_by_subject=str(receipt["requested_by_subject"]),
    )
    row = db.execute(
        text(
            "UPDATE fa_customer_authorization_receipts SET status = 'rejected',"
            " rejected_at = :now, rejected_by_subject = :subj,"
            " rejection_reason = :reason, updated_at = :now"
            " WHERE id = CAST(:rid AS uuid) AND tenant_id = :tid"
            "   AND engagement_id = :eid AND status = 'pending_approval'"
            f" RETURNING {_RECEIPT_COLUMNS}"
        ),
        {
            "now": _now,
            "subj": approver["approver_subject"],
            "reason": reason[:1024],
            "rid": str(receipt_id),
            "tid": tenant_id,
            "eid": engagement_id,
        },
    ).fetchone()
    if row is None:
        raise CustomerAuthorizationError(
            reason="authorization request is no longer pending",
            audit_code="RECEIPT_NOT_PENDING",
        )
    return _row_to_dict(row)


def revoke(
    db: Session,
    *,
    receipt_id: str,
    tenant_id: str,
    engagement_id: str,
    revoked_by_subject: str,
    reason: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Revoke an approved (or pending) receipt.  Idempotent; history retained."""
    _now = now or datetime.now(timezone.utc)
    row = db.execute(
        text(
            "UPDATE fa_customer_authorization_receipts SET status = 'revoked',"
            " revoked_at = :now, revoked_by_subject = :subj,"
            " revocation_reason = :reason, updated_at = :now"
            " WHERE id = CAST(:rid AS uuid) AND tenant_id = :tid"
            "   AND engagement_id = :eid"
            "   AND status IN ('approved', 'pending_approval')"
            f" RETURNING {_RECEIPT_COLUMNS}"
        ),
        {
            "now": _now,
            "subj": revoked_by_subject,
            "reason": reason[:1024],
            "rid": str(receipt_id),
            "tid": tenant_id,
            "eid": engagement_id,
        },
    ).fetchone()
    if row is not None:
        return _row_to_dict(row)
    existing = load_receipt(
        db, receipt_id=receipt_id, tenant_id=tenant_id, engagement_id=engagement_id
    )
    if existing is None:
        raise CustomerAuthorizationError(
            reason="authorization not found", audit_code="RECEIPT_NOT_FOUND"
        )
    if existing["status"] == REVOKED:
        return {**existing, "idempotent": True}
    raise CustomerAuthorizationError(
        reason=f"cannot revoke authorization in state {existing['status']}",
        audit_code="RECEIPT_NOT_REVOCABLE",
    )


def public_view(receipt: Mapping[str, Any], *, now: datetime | None = None) -> dict:
    """Customer/operator-safe projection.  Never includes attestation key material."""
    _now = now or datetime.now(timezone.utc)

    def _s(v: Any) -> str | None:
        return _iso_z(v) if v is not None else None

    return {
        "receipt_id": str(receipt["id"]),
        "receipt_group_id": str(receipt["receipt_group_id"]),
        "receipt_version": int(receipt["receipt_version"]),
        "schema_version": receipt["schema_version"],
        "engagement_id": str(receipt["engagement_id"]),
        "customer_org_name": receipt["customer_org_name"],
        "assessment_purpose": receipt["assessment_purpose"],
        "rules_of_engagement_ref": receipt["rules_of_engagement_ref"],
        "consent_statement_version": receipt["consent_statement_version"],
        "target_normalization_version": receipt["target_normalization_version"],
        "approved_targets": _json_value(receipt["approved_targets"]),
        "authorized_operations": _json_value(receipt["authorized_operations"]),
        "window_start": _s(receipt["window_start"]),
        "window_end": _s(receipt["window_end"]),
        "status": receipt["status"],
        "effective_status": derived_status(receipt, _now),
        "requested_by": receipt["requested_by_subject"],
        "approved_by": receipt.get("approver_subject"),
        "approver_authority_basis": receipt.get("approver_authority_basis"),
        "approver_also_assessor": receipt.get("approver_also_assessor"),
        "approved_at": _s(receipt.get("approved_at")),
        "payload_digest": receipt.get("payload_digest"),
        "attestation_kid": receipt.get("attestation_kid"),
        "attestation_alg": receipt.get("attestation_alg"),
        "proof_level": receipt.get("proof_level"),
        "revoked_at": _s(receipt.get("revoked_at")),
        "revocation_reason": receipt.get("revocation_reason"),
        "rejected_at": _s(receipt.get("rejected_at")),
    }
