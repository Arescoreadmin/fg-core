"""services/actor_identity/engine.py — Actor Identity Authority engine (PR 535).

Resolves actor identity from request state, captures immutable snapshots,
computes cryptographic fingerprints, and emits attribution records that
provide non-repudiation for every governance event.

Usage::

    engine = ActorIdentityEngine()
    actor = engine.resolve_actor_identity(request, tenant_id, db)
    snapshot_id = engine.capture_identity_snapshot(actor, db, actor_context=ctx)
    attribution = engine.attach_actor_to_audit_event(
        event_data, actor, request, AttributionEventType.governance_decision,
        db, snapshot_id, actor_context=ctx,
    )
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.db_models_actor_attribution import (
    ActorAuditEvent,  # noqa: F401 — imported so init_db sees the table
    ActorAttributionRecord,
    ActorIdentity,
    ActorIdentitySnapshot as ActorIdentitySnapshotOrm,
)
from services.actor_identity.metrics import (
    ACTOR_RESOLUTIONS_TOTAL,
    ACTOR_RESOLUTION_FAILURES_TOTAL,
    ATTRIBUTION_LATENCY,
    ATTRIBUTION_RECORDS_CREATED_TOTAL,
    AUTOMATION_ACTOR_USAGE_TOTAL,
    CROSS_TENANT_DENIAL_TOTAL,
    IDENTITY_FAILURES_TOTAL,
    IDENTITY_SNAPSHOTS_CREATED_TOTAL,
    SPOOF_ATTEMPTS_TOTAL,
    SYSTEM_ACTOR_USAGE_TOTAL,
    UNKNOWN_ACTORS_TOTAL,
)
from services.actor_identity.models import (
    ActorAttributionContext,
    ActorFingerprint,
    ActorIdentityResolved,
    ActorType,
    AttributionEventType,
    AutonomousActorFields,
    IdentityValidationResult,
    SnapshotReason,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

_SYSTEM_ACTOR_TYPES = {
    ActorType.system_process,
    ActorType.automation,
    ActorType.ai_agent,
    ActorType.governance_workflow,
    ActorType.autonomous_system,
    ActorType.scheduled_job,
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_email(email: str) -> Optional[str]:
    if not email or email == "":
        return None
    return _sha256(email.lower().strip())


def _hash_ip(ip: str) -> Optional[str]:
    """Privacy-safe IP hash: zero the last octet for IPv4, then SHA-256."""
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        anonymised = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        return _sha256(anonymised)
    return _sha256(ip)


def _hash_user_agent(ua: str) -> Optional[str]:
    if not ua:
        return None
    return _sha256(ua)


def _new_id() -> str:
    return str(uuid.uuid4()).replace("-", "")


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# ActorIdentityEngine
# ---------------------------------------------------------------------------


class ActorIdentityEngine:
    """Stateless Actor Identity Authority.

    Instantiate once per application (or per request — there is no instance
    state). All session/DB interactions are passed in as arguments so the
    engine is trivially testable without a running database.
    """

    # ------------------------------------------------------------------
    # Identity resolution
    # ------------------------------------------------------------------

    def resolve_actor_identity(
        self,
        request: Request,
        tenant_id: str,
        db: Session,
    ) -> ActorIdentityResolved:
        """Resolve and persist the actor identity for the current request.

        Reads identity signals from ``request.state``, upserts a row in
        ``actor_identities``, and returns a fully-populated
        :class:`ActorIdentityResolved`.

        Does not commit — callers own the transaction.
        """
        with ATTRIBUTION_LATENCY.time():
            try:
                return self._resolve(request, tenant_id, db)
            except Exception:
                ACTOR_RESOLUTION_FAILURES_TOTAL.inc()
                raise

    def _resolve(
        self,
        request: Request,
        tenant_id: str,
        db: Session,
    ) -> ActorIdentityResolved:
        # --- Extract request.state signals ---
        # AuthGate stores the verified AuthResult on request.state.auth; read key_prefix
        # from there first so API-key requests resolve to the actual caller, not anonymous.
        _auth_result = getattr(request.state, "auth", None)
        actor_subject: str = (
            getattr(_auth_result, "key_prefix", None)
            or getattr(request.state, "actor_subject", None)
            or "anonymous"
        )
        actor_type_str: Optional[str] = getattr(request.state, "actor_type", None)
        auth_source: str = getattr(request.state, "auth_source", None) or "api_key"
        display_name: str = (
            getattr(request.state, "actor_display_name", None) or actor_subject[:32]
        )
        email: str = getattr(request.state, "email", None) or ""
        governance_role: Optional[str] = getattr(request.state, "governance_role", None)

        # --- Map auth_source → identity_provider ---
        _provider_map: dict[str, str] = {
            "oidc_auth0": "auth0",
            "oidc_entra": "entra",
            "api_key": "api_key",
            "system": "system",
            "dev_bypass": "dev_bypass",
        }
        identity_provider = _provider_map.get(auth_source, "unknown")

        # --- authentication_method is kept as-is (default "api_key") ---
        authentication_method: str = auth_source if auth_source else "api_key"

        # --- Trust level ---
        if auth_source in ("oidc_auth0", "oidc_entra"):
            trust_level = TrustLevel.verified
        elif auth_source == "api_key":
            trust_level = TrustLevel.high
        elif auth_source == "system":
            trust_level = TrustLevel.medium
        elif auth_source == "dev_bypass":
            trust_level = TrustLevel.low
        else:
            trust_level = TrustLevel.unverified

        # --- Actor type ---
        if actor_type_str is not None:
            try:
                actor_type = ActorType(actor_type_str)
            except ValueError:
                actor_type = ActorType.unknown
        else:
            if auth_source == "api_key":
                actor_type = ActorType.api_client
            elif auth_source in ("oidc_auth0", "oidc_entra"):
                actor_type = ActorType.human_user
            else:
                actor_type = ActorType.unknown

        # --- Stable actor_id (deterministic per tenant+subject) ---
        actor_id = _sha256(f"actor:{tenant_id}:{actor_subject}")[:64]
        email_hash = _hash_email(email)
        now = _utcnow()

        # --- Upsert actor_identities ---
        existing = (
            db.query(ActorIdentity)
            .filter(
                ActorIdentity.id == actor_id,
                ActorIdentity.tenant_id == tenant_id,
            )
            .first()
        )

        if existing is None:
            row = ActorIdentity(
                id=actor_id,
                tenant_id=tenant_id,
                actor_type=actor_type.value,
                actor_subject=actor_subject,
                actor_display_name=display_name,
                email_hash=email_hash,
                authentication_method=authentication_method,
                identity_provider=identity_provider,
                governance_role=governance_role,
                trust_level=trust_level.value,
                is_service_account=0,
                is_robot=0,
                status="active",
                created_at=now,
                updated_at=now,
                last_seen_at=now,
                schema_version="1.0",
            )
            db.add(row)
            db.flush()
        else:
            existing.last_seen_at = now
            db.flush()

        # --- Metrics ---
        ACTOR_RESOLUTIONS_TOTAL.inc()
        if actor_type == ActorType.system_process:
            SYSTEM_ACTOR_USAGE_TOTAL.inc()
        elif actor_type == ActorType.automation:
            AUTOMATION_ACTOR_USAGE_TOTAL.inc()
        if actor_subject == "anonymous":
            UNKNOWN_ACTORS_TOTAL.inc()

        return ActorIdentityResolved(
            actor_id=actor_id,
            actor_type=actor_type,
            actor_subject=actor_subject,
            actor_display_name=display_name,
            email_hash=email_hash,
            authentication_method=authentication_method,
            identity_provider=identity_provider,
            governance_role=governance_role,
            trust_level=trust_level,
            is_service_account=False,
            is_robot=False,
            tenant_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # Snapshot capture
    # ------------------------------------------------------------------

    def capture_identity_snapshot(
        self,
        actor_resolved: ActorIdentityResolved,
        db: Session,
        snapshot_reason: SnapshotReason = SnapshotReason.action_time,
        actor_context: Optional[ActorContext] = None,
    ) -> str:
        """Capture an immutable identity snapshot and return its snapshot_id.

        Flushes but does not commit — callers own the transaction.
        """
        snapshot_id = _new_id()
        now = _utcnow()

        # Extract permission and role snapshots from ActorContext if provided.
        permission_snapshot: list[str] = []
        groups_snapshot: list[str] = []
        if actor_context is not None:
            permission_snapshot = sorted(list(actor_context.permissions))
            groups_snapshot = list(actor_context.roles)

        row = ActorIdentitySnapshotOrm(
            id=snapshot_id,
            tenant_id=actor_resolved.tenant_id,
            actor_id=actor_resolved.actor_id,
            snapshot_reason=snapshot_reason.value,
            actor_type=actor_resolved.actor_type.value,
            actor_subject=actor_resolved.actor_subject,
            actor_display_name=actor_resolved.actor_display_name,
            email_hash=actor_resolved.email_hash,
            authentication_method=actor_resolved.authentication_method,
            identity_provider=actor_resolved.identity_provider,
            governance_role=actor_resolved.governance_role,
            permission_snapshot=json.dumps(permission_snapshot),
            groups_snapshot=json.dumps(groups_snapshot),
            trust_level=actor_resolved.trust_level.value,
            is_service_account=1 if actor_resolved.is_service_account else 0,
            is_robot=1 if actor_resolved.is_robot else 0,
            delegated_by=actor_resolved.delegated_by,
            captured_at=now,
            schema_version="1.0",
        )
        db.add(row)
        db.flush()

        IDENTITY_SNAPSHOTS_CREATED_TOTAL.inc()
        return snapshot_id

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def create_actor_fingerprint(
        self,
        actor_resolved: ActorIdentityResolved,
    ) -> str:
        """Return a stable SHA-256 fingerprint derived from actor identity fields."""
        return _sha256(
            f"fp:actor:{actor_resolved.actor_id}:"
            f"{actor_resolved.actor_type.value}:"
            f"{actor_resolved.tenant_id}"
        )

    def create_identity_hash(
        self,
        actor_resolved: ActorIdentityResolved,
        actor_context: Optional[ActorContext] = None,
    ) -> str:
        """Return a SHA-256 hash of canonical identity fields."""
        payload = {
            "email_hash": actor_resolved.email_hash or "",
            "authentication_method": actor_resolved.authentication_method,
            "identity_provider": actor_resolved.identity_provider,
            "governance_role": actor_resolved.governance_role or "",
            "tenant_id": actor_resolved.tenant_id,
        }
        return _sha256(_canonical_json(payload))

    def create_request_fingerprint(
        self,
        request: Request,
        request_id: str,
    ) -> str:
        """Return a SHA-256 fingerprint derived from privacy-safe request signals."""
        client_host = request.client.host if request.client else ""
        payload = {
            "request_id": request_id,
            "client_ip_hash": _hash_ip(client_host),
            "user_agent_hash": _hash_user_agent(request.headers.get("user-agent", "")),
        }
        return _sha256(_canonical_json(payload))

    # ------------------------------------------------------------------
    # Attribution record
    # ------------------------------------------------------------------

    def attach_actor_to_audit_event(
        self,
        event_data: dict,
        actor_resolved: ActorIdentityResolved,
        request: Request,
        event_type: AttributionEventType,
        db: Session,
        snapshot_id: str,
        actor_context: Optional[ActorContext] = None,
        event_ref: Optional[str] = None,
        event_ref_type: Optional[str] = None,
        previous_hash: Optional[str] = None,
        autonomous_fields: Optional[AutonomousActorFields] = None,
    ) -> ActorAttributionContext:
        """Create an attribution record and return its context.

        Flushes but does not commit — callers own the transaction.
        """
        request_id = str(uuid.uuid4())
        now = _utcnow()

        actor_fp = self.create_actor_fingerprint(actor_resolved)
        identity_fp = self.create_identity_hash(actor_resolved, actor_context)
        request_fp = self.create_request_fingerprint(request, request_id)

        attribution_hash = _sha256(f"{actor_fp}:{identity_fp}:{request_fp}")
        # Bind event classification fields into the hash so misclassifying event_type,
        # event_ref, or event_ref_type is detectable during replay verification.
        _event_context = dict(event_data)
        _event_context["_event_type"] = event_type.value
        _event_context["_event_ref"] = event_ref or ""
        _event_context["_event_ref_type"] = event_ref_type or ""
        event_hash = _sha256(f"{attribution_hash}:{_canonical_json(_event_context)}")
        attribution_id = _new_id()

        client_ip_hash = _hash_ip(request.client.host if request.client else "")
        user_agent_hash = _hash_user_agent(request.headers.get("user-agent", ""))
        session_id: Optional[str] = getattr(request.state, "session_id", None)

        # Autonomous fields serialisation
        auto_confidence: Optional[str] = None
        auto_policy_version: Optional[str] = None
        auto_authority_chain: Optional[str] = None
        auto_execution_context: Optional[str] = None
        auto_reasoning_reference: Optional[str] = None
        auto_governance_scope: Optional[str] = None

        if autonomous_fields is not None:
            if autonomous_fields.decision_confidence is not None:
                auto_confidence = json.dumps(autonomous_fields.decision_confidence)
            auto_policy_version = autonomous_fields.policy_version
            if autonomous_fields.authority_chain is not None:
                auto_authority_chain = json.dumps(autonomous_fields.authority_chain)
            if autonomous_fields.execution_context is not None:
                auto_execution_context = json.dumps(autonomous_fields.execution_context)
            auto_reasoning_reference = autonomous_fields.reasoning_reference
            auto_governance_scope = autonomous_fields.governance_scope

        row = ActorAttributionRecord(
            id=attribution_id,
            tenant_id=actor_resolved.tenant_id,
            organization_id=actor_resolved.organization_id,
            actor_id=actor_resolved.actor_id,
            snapshot_id=snapshot_id,
            event_type=event_type.value,
            event_ref=event_ref,
            event_ref_type=event_ref_type,
            actor_type=actor_resolved.actor_type.value,
            actor_display_name=actor_resolved.actor_display_name,
            authentication_method=actor_resolved.authentication_method,
            identity_provider=actor_resolved.identity_provider,
            session_id=session_id,
            request_id=request_id,
            client_ip_hash=client_ip_hash,
            user_agent_hash=user_agent_hash,
            governance_role=actor_resolved.governance_role,
            trust_level=actor_resolved.trust_level.value,
            actor_fingerprint=actor_fp,
            identity_fingerprint=identity_fp,
            request_fingerprint=request_fp,
            attribution_hash=attribution_hash,
            event_hash=event_hash,
            previous_hash=previous_hash,
            created_at=now,
            schema_version="1.0",
            autonomous_decision_confidence=auto_confidence,
            autonomous_policy_version=auto_policy_version,
            autonomous_authority_chain=auto_authority_chain,
            autonomous_execution_context=auto_execution_context,
            autonomous_reasoning_reference=auto_reasoning_reference,
            autonomous_governance_scope=auto_governance_scope,
        )
        db.add(row)
        db.flush()

        ATTRIBUTION_RECORDS_CREATED_TOTAL.inc()

        fingerprints = ActorFingerprint(
            actor_fingerprint=actor_fp,
            identity_fingerprint=identity_fp,
            request_fingerprint=request_fp,
            attribution_hash=attribution_hash,
            event_hash=event_hash,
            previous_hash=previous_hash,
        )

        return ActorAttributionContext(
            attribution_id=attribution_id,
            actor_id=actor_resolved.actor_id,
            snapshot_id=snapshot_id,
            event_type=event_type,
            event_ref=event_ref,
            event_ref_type=event_ref_type,
            actor_type=actor_resolved.actor_type,
            actor_display_name=actor_resolved.actor_display_name,
            authentication_method=actor_resolved.authentication_method,
            identity_provider=actor_resolved.identity_provider,
            session_id=session_id,
            request_id=request_id,
            client_ip_hash=client_ip_hash,
            user_agent_hash=user_agent_hash,
            governance_role=actor_resolved.governance_role,
            trust_level=actor_resolved.trust_level,
            fingerprints=fingerprints,
            created_at=now,
            tenant_id=actor_resolved.tenant_id,
            organization_id=actor_resolved.organization_id,
            autonomous_fields=autonomous_fields,
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_actor_context(
        self,
        actor_resolved: ActorIdentityResolved,
        tenant_id: str,
    ) -> IdentityValidationResult:
        """Validate that the actor context is legitimate for the given tenant.

        Checks cross-tenant isolation, anonymous actor abuse, unknown actor
        types, and authentication method presence.  Does not query the DB —
        purely in-process validation.
        """
        violations: list[str] = []
        is_system_actor = actor_resolved.actor_type in _SYSTEM_ACTOR_TYPES

        # 1. Cross-tenant check
        if actor_resolved.tenant_id != tenant_id:
            CROSS_TENANT_DENIAL_TOTAL.inc()
            SPOOF_ATTEMPTS_TOTAL.inc()
            violations.append("cross_tenant_attribution")

        # 2. Anonymous actor used for non-system action
        if not is_system_actor and actor_resolved.actor_subject == "anonymous":
            violations.append("anonymous_privileged_actor")

        # 3. Unknown actor type for non-system actors
        if not is_system_actor and actor_resolved.actor_type == ActorType.unknown:
            violations.append("unknown_actor_type")

        # 4. Authentication method must be present
        if not actor_resolved.authentication_method:
            violations.append("missing_authentication_method")

        valid = len(violations) == 0
        if not valid:
            IDENTITY_FAILURES_TOTAL.inc()

        return IdentityValidationResult(
            valid=valid,
            actor_id=actor_resolved.actor_id,
            actor_type=actor_resolved.actor_type,
            violations=violations,
            trust_level=actor_resolved.trust_level,
            validated_at=_utcnow(),
        )
