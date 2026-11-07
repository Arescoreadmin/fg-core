"""
Canonical scanner evidence envelope — provenance, payload canonicalization,
and integrity verification.

L14-SCAN-INTEGRITY-001

Architecture
------------
Evidence is captured by scanner runners and must carry a cryptographically
verifiable digest so downstream consumers (report engine, audit trail) can
detect accidental or adversarial payload mutation.

Canonicalization is deterministic: sorted keys, stable JSON (no floats that
differ across encoders), NFC unicode normalization, explicit nulls retained.
The digest format is ``"sha256:<hex>"`` so the algorithm is always self-describing.

Signing
-------
Vault Transit is present in this repo (services/field_assessment/auditor_proof_authority.py)
but it is scoped to delivery-artifact signing (Ed25519 proof packages).  It is
NOT wired to scanner evidence receipts in this PR.  Scanner evidence records
``signature_ref=None`` and ``provenance_status=VERIFIED_INTEGRITY_ONLY``
(digest matches, no authenticated signature) or ``VERIFIED_AUTHENTIC`` for
future Vault integration.  Signatures are NEVER fabricated.

Vault wiring gate
-----------------
When a future PR provisions a Vault Transit key scoped to scanner receipts,
update ``EvidenceIntegrityService._try_vault_sign()`` to call the Vault API
and return ``(signature_bytes, key_ref)``.  Until then it returns ``(None, None)``
and ``provenance_status`` remains ``VERIFIED_INTEGRITY_ONLY``.

NOT_STANDALONE: This module is part of the FrostGate Core field assessment
pipeline.  It requires the full fg-core stack (api/, services/, Postgres).
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

_CANONICALIZATION_VERSION = "1.0"


def _nfc(value: Any) -> Any:
    """Recursively apply NFC normalization to all strings in a value."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {_nfc(k): _nfc(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_nfc(item) for item in value]
    return value


def _canonical_dict(payload: dict) -> dict:
    """Return a recursively sorted, NFC-normalized dict (nulls retained)."""
    normalized = _nfc(payload)
    if not isinstance(normalized, dict):
        raise TypeError("payload must be a dict")

    def _sort(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _sort(obj[k]) for k in sorted(obj.keys())}
        if isinstance(obj, list):
            return [_sort(item) for item in obj]
        return obj

    return _sort(normalized)


def canonicalize_payload(payload: dict, schema_version: str = "1.0") -> bytes:
    """Return deterministic UTF-8 bytes for *payload*.

    The envelope includes a ``__meta__`` key with the canonicalization version
    and the declared schema version so the digest is version-scoped.

    Rules:
    - Sorted keys (recursive)
    - NFC unicode normalization
    - Explicit nulls retained (not stripped)
    - schema_version changes produce a different digest
    - JSON separators are ``(',', ':')`` for compactness and stability
    """
    canonical = _canonical_dict(payload)
    envelope = {
        "__meta__": {
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "schema_version": schema_version,
        },
        "payload": canonical,
    }
    return json.dumps(
        envelope, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")


def compute_payload_digest(payload: dict, schema_version: str = "1.0") -> str:
    """Return ``"sha256:<hex>"`` of the canonical payload bytes."""
    raw = canonicalize_payload(payload, schema_version=schema_version)
    hex_digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{hex_digest}"


# ---------------------------------------------------------------------------
# Provenance status
# ---------------------------------------------------------------------------


class ProvenanceStatus(str, Enum):
    """Evidence provenance verification outcome.

    VERIFIED_AUTHENTIC      — digest matches AND an authenticated signature
                              is present and valid (Vault Transit or equivalent).
    VERIFIED_INTEGRITY_ONLY — digest matches; no authenticated signature
                              (Vault Transit not wired to scanner receipts yet).
    UNVERIFIED              — envelope exists but integrity has not been checked.
    MISSING                 — referenced evidence record was not found (or
                              cross-tenant access was attempted — both return
                              MISSING to prevent information leakage).
    INVALID                 — digest or signature verification failed.
    INDETERMINATE           — verification could not reach a conclusion (e.g.,
                              verification service unavailable).
    """

    VERIFIED_AUTHENTIC = "VERIFIED_AUTHENTIC"
    VERIFIED_INTEGRITY_ONLY = "VERIFIED_INTEGRITY_ONLY"
    UNVERIFIED = "UNVERIFIED"
    MISSING = "MISSING"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


# ---------------------------------------------------------------------------
# Evidence envelope dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScannerEvidenceEnvelope:
    """Canonical metadata envelope for a single scanner evidence payload.

    The envelope binds the payload digest to the scanner identity, tenant,
    engagement, and authorization reference.  It does NOT store the payload
    itself — only its digest.

    Fields
    ------
    schema_version          : always "1.0" for this implementation
    evidence_id             : UUID for this envelope record
    scan_id                 : UUID of the parent fa_scan_results row
    scanner_id              : e.g. "network_scan", "dns_email", "web_headers"
    scanner_version         : optional semver or build tag from the runner
    tenant_id               : must match the engagement's tenant
    engagement_id           : FK to fa_engagements
    authorization_ref       : FK to fa_scan_authorizations (nullable)
    authorization_version   : monotonic version of the authorization record
    collected_at            : ISO8601 UTC timestamp from the runner
    collection_status       : "complete" | "partial" | "failed"
    source_type             : e.g. "network_scan_result", "dns_record"
    source_id               : optional stable identifier within source_type
    payload_digest          : "sha256:<hex>" — computed by build_envelope()
    canonicalization_version: "1.0" — matches _CANONICALIZATION_VERSION
    provenance_status       : VERIFIED_INTEGRITY_ONLY until Vault is wired
    signature_ref           : Vault key ref when signed; None otherwise
    data_sensitivity        : "internal" | "confidential" | "restricted"
    correlation_id          : optional cross-service trace ID
    """

    schema_version: str
    evidence_id: str
    scan_id: str
    scanner_id: str
    scanner_version: str | None
    tenant_id: str
    engagement_id: str
    authorization_ref: str | None
    authorization_version: int | None
    collected_at: str
    collection_status: str
    source_type: str
    source_id: str | None
    payload_digest: str
    canonicalization_version: str
    provenance_status: ProvenanceStatus
    signature_ref: str | None
    data_sensitivity: str
    correlation_id: str | None


# ---------------------------------------------------------------------------
# Integrity verification service
# ---------------------------------------------------------------------------


class EvidenceIntegrityService:
    """Verify and build scanner evidence envelopes.

    All public methods are fail-closed:
    - Cross-tenant access returns MISSING (never raises with cross-tenant info)
    - Digest mismatch returns INVALID (never silently passes)
    - Internal errors return INDETERMINATE (never silently passes)
    """

    # ------------------------------------------------------------------
    # Vault gate (NOT_IMPLEMENTED until L14-SCAN-VAULT-001)
    # ------------------------------------------------------------------

    def _try_vault_sign(self, envelope_bytes: bytes) -> tuple[bytes | None, str | None]:
        """Attempt Vault Transit signature of the envelope bytes.

        Returns ``(signature_bytes, key_ref)`` or ``(None, None)`` when
        Vault Transit is not wired for scanner receipts.

        Current status: NOT_IMPLEMENTED.  Vault Transit in this repo is
        scoped to delivery-artifact signing only (see
        services/field_assessment/auditor_proof_authority.py).  Scanner
        receipt signing requires a dedicated Vault key provisioned under
        L14-SCAN-VAULT-001.  Until then, this method always returns
        ``(None, None)`` and callers record VERIFIED_INTEGRITY_ONLY.
        """
        return None, None

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_envelope(
        self,
        *,
        scan_id: str,
        scanner_id: str,
        tenant_id: str,
        engagement_id: str,
        payload: dict,
        scanner_version: str | None = None,
        authorization_ref: str | None = None,
        authorization_version: int | None = None,
        collected_at: str | None = None,
        collection_status: str = "complete",
        source_type: str = "scan_result",
        source_id: str | None = None,
        schema_version: str = "1.0",
        data_sensitivity: str = "internal",
        correlation_id: str | None = None,
    ) -> ScannerEvidenceEnvelope:
        """Construct an envelope with computed digest.

        The digest is computed over the payload + schema_version via
        ``compute_payload_digest()``.  Vault signing is attempted but
        silently skipped when unavailable.
        """
        evidence_id = str(uuid.uuid4())
        digest = compute_payload_digest(payload, schema_version=schema_version)

        if collected_at is None:
            collected_at = datetime.now(timezone.utc).isoformat()

        # Attempt Vault signing — currently returns (None, None)
        _sig, key_ref = self._try_vault_sign(digest.encode("utf-8"))
        if key_ref is not None:
            provenance_status = ProvenanceStatus.VERIFIED_AUTHENTIC
        else:
            provenance_status = ProvenanceStatus.VERIFIED_INTEGRITY_ONLY

        return ScannerEvidenceEnvelope(
            schema_version=schema_version,
            evidence_id=evidence_id,
            scan_id=scan_id,
            scanner_id=scanner_id,
            scanner_version=scanner_version,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            authorization_ref=authorization_ref,
            authorization_version=authorization_version,
            collected_at=collected_at,
            collection_status=collection_status,
            source_type=source_type,
            source_id=source_id,
            payload_digest=digest,
            canonicalization_version=_CANONICALIZATION_VERSION,
            provenance_status=provenance_status,
            signature_ref=key_ref,
            data_sensitivity=data_sensitivity,
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify_envelope(
        self, envelope: ScannerEvidenceEnvelope, payload: dict
    ) -> ProvenanceStatus:
        """Verify the envelope digest against the supplied payload.

        Returns:
        - VERIFIED_INTEGRITY_ONLY if digest matches and no signature is recorded
        - VERIFIED_AUTHENTIC if digest matches and a signature_ref is present
          (future: will also verify the signature against Vault)
        - INVALID if the digest does not match
        - INDETERMINATE on unexpected internal error
        """
        try:
            schema_version = envelope.schema_version or "1.0"
            expected = compute_payload_digest(payload, schema_version=schema_version)
            if expected != envelope.payload_digest:
                return ProvenanceStatus.INVALID
            if envelope.signature_ref is not None:
                # Vault Transit signature wiring is deferred to L14-SCAN-VAULT-001.
                # Until actual signature verification is implemented, a non-null
                # signature_ref cannot establish authenticity — return integrity-only
                # rather than falsely claiming VERIFIED_AUTHENTIC.
                pass
            return ProvenanceStatus.VERIFIED_INTEGRITY_ONLY
        except Exception:
            return ProvenanceStatus.INDETERMINATE

    def verify_by_id(
        self, db: Session, evidence_id: str, tenant_id: str
    ) -> ProvenanceStatus:
        """Fetch envelope from DB and verify digest.

        Fail-closed on cross-tenant: returns MISSING (not a 403 that leaks
        the existence of the record).
        """
        try:
            row = db.execute(
                text(
                    """
                    SELECT tenant_id, payload_digest, schema_version, signature_ref
                    FROM fa_scan_evidence_envelopes
                    WHERE id = :eid
                    """
                ),
                {"eid": evidence_id},
            ).fetchone()

            if row is None:
                return ProvenanceStatus.MISSING

            # Fail closed on cross-tenant — return MISSING, not 403
            if row.tenant_id != tenant_id:
                return ProvenanceStatus.MISSING

            # Without the original payload we cannot recompute and compare the
            # digest — returning VERIFIED_INTEGRITY_ONLY without recomputation
            # would miss tampering of fa_scan_results.raw_payload after ingestion.
            # Return UNVERIFIED; callers with the payload must use verify_envelope().
            return ProvenanceStatus.UNVERIFIED
        except Exception:
            return ProvenanceStatus.INDETERMINATE

    def batch_verify(
        self, db: Session, evidence_ids: list[str], tenant_id: str
    ) -> dict[str, ProvenanceStatus]:
        """Verify multiple evidence records.

        Cross-tenant entries return MISSING (fail-closed, no information leakage).
        """
        result: dict[str, ProvenanceStatus] = {}
        for eid in evidence_ids:
            result[eid] = self.verify_by_id(db, eid, tenant_id)
        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

evidence_integrity_svc = EvidenceIntegrityService()
