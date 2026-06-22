"""Report Link Authority — Ed25519 signing for evidence-to-report linkage.

Every link record answers:
  Which evidence → report_id, evidence_id, provenance_record_id
  What report was produced → report_hash, report_signature
  Who created the link → linked_by, linked_at
  Was it tampered with → event_hash (hash chain), signature (authority chain)
  Which authority certified it → authority_version, link_version

Canonical event shape:
  {event_hash, evidence_id, provenance_record_id, report_id, report_hash,
   report_signature, tenant_id, engagement_id, signing_key_id,
   authority_version, link_version}

Append-only: no UPDATE or DELETE on fa_evidence_report_links.
Signing key: FG_EVIDENCE_SIGNING_KEY_B64 (same Ed25519 seed as Evidence Authority).
Fail-closed in prod: missing key raises RuntimeError.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceReportLink
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.store import _new_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LINK_AUTHORITY_VERSION: str = "evidence-report-authority-v1"
LINK_VERSION: str = "report-link-v1"
LINK_SIGNATURE_VERSION: str = "report-link-signature-v1"


class ReportLinkAuthorityError(RuntimeError):
    """Raised when signing key material is missing or invalid."""


# ---------------------------------------------------------------------------
# Key management (reuses FG_EVIDENCE_SIGNING_KEY_B64)
# ---------------------------------------------------------------------------


def _load_signing_seed() -> bytes:
    import base64
    import os

    raw = (os.getenv("FG_EVIDENCE_SIGNING_KEY_B64") or "").strip()
    if not raw:
        raise ReportLinkAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 is required for report link authority signing"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise ReportLinkAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 must be valid base64"
        ) from exc
    if len(seed) != 32:
        raise ReportLinkAuthorityError(
            f"FG_EVIDENCE_SIGNING_KEY_B64 must decode to 32 bytes (got {len(seed)})"
        )
    return seed


def _load_verification_pub_bytes() -> bytes:
    """Load public key for verification. Tries FG_EVIDENCE_VERIFY_KEY_B64 first."""
    import base64
    import os

    raw = (os.getenv("FG_EVIDENCE_VERIFY_KEY_B64") or "").strip()
    if raw:
        try:
            pub = base64.b64decode(raw)
        except Exception as exc:
            raise ReportLinkAuthorityError(
                "FG_EVIDENCE_VERIFY_KEY_B64 must be valid base64"
            ) from exc
        if len(pub) != 32:
            raise ReportLinkAuthorityError(
                f"FG_EVIDENCE_VERIFY_KEY_B64 must decode to 32 bytes (got {len(pub)})"
            )
        return pub
    seed = _load_signing_seed()
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _derive_key_id(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Canonical event
# ---------------------------------------------------------------------------


def _link_hash_payload(
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    provenance_record_id: str | None,
    report_id: str,
    report_hash: str | None,
    report_signature: str | None,
    linked_at: str,
    linked_by: str | None,
    previous_hash: str | None,
    created_at: str,
) -> dict[str, Any]:
    """Core link payload for event_hash derivation."""
    return {
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "evidence_id": evidence_id,
        "provenance_record_id": provenance_record_id,
        "report_id": report_id,
        "report_hash": report_hash,
        "report_signature": report_signature,
        "linked_at": linked_at,
        "linked_by": linked_by,
        "previous_hash": previous_hash,
        "created_at": created_at,
    }


def compute_link_event_hash(payload: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON — used as event_hash."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _build_canonical_link_event(
    *,
    event_hash: str,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    provenance_record_id: str | None,
    report_id: str,
    report_hash: str | None,
    report_signature: str | None,
    signing_key_id: str | None,
    authority_version: str,
    link_version: str,
) -> dict[str, Any]:
    """Deterministic dict that is Ed25519-signed.

    Includes signing_key_id, authority_version, and link_version so stripping
    or tampering with any of them changes the digest and fails verification.
    Callers must pass the actual stored values (not module-level constants) when
    rebuilding a canonical event for an existing record.
    """
    return {
        "event_hash": event_hash,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "evidence_id": evidence_id,
        "provenance_record_id": provenance_record_id,
        "report_id": report_id,
        "report_hash": report_hash,
        "report_signature": report_signature,
        "signing_key_id": signing_key_id,
        "authority_version": authority_version,
        "link_version": link_version,
    }


def build_canonical_report_link_event(link: FaEvidenceReportLink) -> dict[str, Any]:
    """Build the canonical authority event dict from an existing link record.

    Uses the stored authority_version and link_version so that tampering with
    either field changes the digest and fails signature verification.
    A verifier recomputes this, hashes it, and verifies the Ed25519 signature.
    """
    return _build_canonical_link_event(
        event_hash=link.event_hash,
        tenant_id=link.tenant_id,
        engagement_id=link.engagement_id,
        evidence_id=link.evidence_id,
        provenance_record_id=link.provenance_record_id,
        report_id=link.report_id,
        report_hash=link.report_hash,
        report_signature=link.report_signature,
        signing_key_id=link.signing_key_id,
        authority_version=link.authority_version or LINK_AUTHORITY_VERSION,
        link_version=link.link_version or LINK_VERSION,
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _sign_canonical_link(canonical: dict[str, Any]) -> str:
    """Ed25519-sign SHA-256(canonical_json_bytes(canonical)). Returns hex."""
    seed = _load_signing_seed()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    digest = hashlib.sha256(canonical_json_bytes(canonical)).digest()
    return priv.sign(digest).hex()


def _try_sign_link(
    *,
    event_hash: str,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    provenance_record_id: str | None,
    report_id: str,
    report_hash: str | None,
    report_signature: str | None,
) -> dict:
    """Return authority fields for a new link, or {} if key not configured.

    In prod: raises if signing key missing (fail-closed).
    In dev/test: returns {} — link is created unsigned (legacy-compatible).
    """
    try:
        seed = _load_signing_seed()
        pub_bytes = (
            Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        )
        key_id = _derive_key_id(pub_bytes)
        canonical = _build_canonical_link_event(
            event_hash=event_hash,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            evidence_id=evidence_id,
            provenance_record_id=provenance_record_id,
            report_id=report_id,
            report_hash=report_hash,
            report_signature=report_signature,
            signing_key_id=key_id,
            authority_version=LINK_AUTHORITY_VERSION,
            link_version=LINK_VERSION,
        )
        sig = _sign_canonical_link(canonical)
        return {
            "signature": sig,
            "signing_key_id": key_id,
            "signed_at": utc_iso8601_z_now(),
            "signature_version": LINK_SIGNATURE_VERSION,
            "authority_version": LINK_AUTHORITY_VERSION,
        }
    except Exception as exc:
        from api.config.env import is_production_env

        if is_production_env():
            raise RuntimeError(f"report_link_authority.signing_failed: {exc}") from exc
        return {}


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------


def create_report_link(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    report_id: str,
    provenance_record_id: str | None = None,
    report_hash: str | None = None,
    report_signature: str | None = None,
    linked_by: str | None = None,
    previous_hash: str | None = None,
) -> FaEvidenceReportLink:
    """Create an append-only evidence-to-report link authority record.

    Computes event_hash and Ed25519 signature before flush (append-only
    Postgres triggers block post-INSERT UPDATE).

    Caller owns db.commit().
    """
    now = utc_iso8601_z_now()

    payload = _link_hash_payload(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        provenance_record_id=provenance_record_id,
        report_id=report_id,
        report_hash=report_hash,
        report_signature=report_signature,
        linked_at=now,
        linked_by=linked_by,
        previous_hash=previous_hash,
        created_at=now,
    )
    event_hash = compute_link_event_hash(payload)

    authority = _try_sign_link(
        event_hash=event_hash,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        provenance_record_id=provenance_record_id,
        report_id=report_id,
        report_hash=report_hash,
        report_signature=report_signature,
    )

    link = FaEvidenceReportLink(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        provenance_record_id=provenance_record_id,
        report_id=report_id,
        report_hash=report_hash,
        report_signature=report_signature,
        linked_at=now,
        linked_by=linked_by,
        authority_version=authority.get("authority_version") or LINK_AUTHORITY_VERSION,
        link_version=LINK_VERSION,
        event_hash=event_hash,
        previous_hash=previous_hash,
        signature=authority.get("signature"),
        signing_key_id=authority.get("signing_key_id"),
        signed_at=authority.get("signed_at"),
        signature_version=authority.get("signature_version"),
        schema_version="1.1" if authority.get("signature") else "1.0",
        created_at=now,
    )
    db.add(link)
    db.flush()
    from services.field_assessment.trust_enforcement import (  # noqa: PLC0415
        TrustInputs,
        ProvenanceMode,
        enforce_report_link_authority,
    )

    _link_signed = bool(authority.get("signature"))
    enforce_report_link_authority(
        TrustInputs(
            link_valid=_link_signed,
            is_legacy=not _link_signed,
            tenant_valid=True,
            engagement_valid=True,
        ),
        mode=ProvenanceMode.from_env(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        db=db,
    )
    return link


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


def get_report_link(
    db: Session,
    *,
    link_id: str,
    tenant_id: str,
) -> FaEvidenceReportLink | None:
    stmt = select(FaEvidenceReportLink).where(
        FaEvidenceReportLink.id == link_id,
        FaEvidenceReportLink.tenant_id == tenant_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def list_report_links_for_evidence(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[FaEvidenceReportLink]:
    limit = min(limit, 100)
    stmt = (
        select(FaEvidenceReportLink)
        .where(
            FaEvidenceReportLink.tenant_id == tenant_id,
            FaEvidenceReportLink.engagement_id == engagement_id,
            FaEvidenceReportLink.evidence_id == evidence_id,
        )
        .order_by(FaEvidenceReportLink.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def list_report_links_for_report(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    report_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[FaEvidenceReportLink]:
    limit = min(limit, 100)
    stmt = (
        select(FaEvidenceReportLink)
        .where(
            FaEvidenceReportLink.tenant_id == tenant_id,
            FaEvidenceReportLink.engagement_id == engagement_id,
            FaEvidenceReportLink.report_id == report_id,
        )
        .order_by(FaEvidenceReportLink.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def list_report_links_for_engagement(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> list[FaEvidenceReportLink]:
    """Return all links for an engagement — used by trust replay."""
    stmt = select(FaEvidenceReportLink).where(
        FaEvidenceReportLink.tenant_id == tenant_id,
        FaEvidenceReportLink.engagement_id == engagement_id,
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_link_signature(link: FaEvidenceReportLink) -> dict[str, Any]:
    """Verify the Ed25519 authority signature on a link record.

    Returns:
      valid             bool | None  (None = legacy_unsigned)
      status            "verified" | "legacy_unsigned" | "invalid" | "key_unavailable"
      reason            str
      authority_version str | None
      signing_key_id    str | None
    """
    if link.signature is None:
        if link.signing_key_id is not None:
            return {
                "valid": False,
                "status": "invalid",
                "reason": "partial_authority_fields",
                "authority_version": link.authority_version,
                "signing_key_id": link.signing_key_id,
            }
        if (link.schema_version or "1.0") >= "1.1":
            return {
                "valid": False,
                "status": "invalid",
                "reason": "missing_signature",
                "authority_version": None,
                "signing_key_id": None,
            }
        return {
            "valid": None,
            "status": "legacy_unsigned",
            "reason": "no_signature",
            "authority_version": None,
            "signing_key_id": None,
        }

    try:
        pub_bytes = _load_verification_pub_bytes()
    except ReportLinkAuthorityError as exc:
        return {
            "valid": False,
            "status": "key_unavailable",
            "reason": f"signing_key_not_configured: {exc}",
            "authority_version": link.authority_version,
            "signing_key_id": link.signing_key_id,
        }

    current_key_id = _derive_key_id(pub_bytes)
    if link.signing_key_id and link.signing_key_id != current_key_id:
        return {
            "valid": False,
            "status": "invalid",
            "reason": f"key_id_mismatch: stored={link.signing_key_id} current={current_key_id}",
            "authority_version": link.authority_version,
            "signing_key_id": link.signing_key_id,
        }

    canonical = build_canonical_report_link_event(link)
    digest = hashlib.sha256(canonical_json_bytes(canonical)).digest()

    try:
        sig_bytes = bytes.fromhex(link.signature)
    except ValueError:
        return {
            "valid": False,
            "status": "invalid",
            "reason": "signature_encoding_error",
            "authority_version": link.authority_version,
            "signing_key_id": link.signing_key_id,
        }

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, digest)
        return {
            "valid": True,
            "status": "verified",
            "reason": "ok",
            "authority_version": link.authority_version or LINK_AUTHORITY_VERSION,
            "signing_key_id": link.signing_key_id,
        }
    except InvalidSignature:
        return {
            "valid": False,
            "status": "invalid",
            "reason": "signature_mismatch",
            "authority_version": link.authority_version,
            "signing_key_id": link.signing_key_id,
        }
    except Exception as exc:
        return {
            "valid": False,
            "status": "error",
            "reason": f"verification_error: {type(exc).__name__}",
            "authority_version": link.authority_version,
            "signing_key_id": link.signing_key_id,
        }


def verify_report_link(
    db: Session,
    *,
    link_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Verify a report link's event_hash and Ed25519 signature.

    Returns:
      valid             bool
      link_id           str
      reason            str ("ok" | "not_found" | "hash_mismatch" | sig reasons)
      evidence_id       str | None
      report_id         str | None
      event_hash        str | None
      signature_valid   bool | None
      signature_status  str
      authority_version str | None
    """
    link = get_report_link(db, link_id=link_id, tenant_id=tenant_id)
    if link is None:
        return {
            "valid": False,
            "link_id": link_id,
            "reason": "not_found",
            "evidence_id": None,
            "report_id": None,
            "event_hash": None,
            "signature_valid": None,
            "signature_status": "unknown",
            "authority_version": None,
        }

    expected_payload = _link_hash_payload(
        tenant_id=link.tenant_id,
        engagement_id=link.engagement_id,
        evidence_id=link.evidence_id,
        provenance_record_id=link.provenance_record_id,
        report_id=link.report_id,
        report_hash=link.report_hash,
        report_signature=link.report_signature,
        linked_at=link.linked_at,
        linked_by=link.linked_by,
        previous_hash=link.previous_hash,
        created_at=link.created_at,
    )
    expected_hash = compute_link_event_hash(expected_payload)

    if expected_hash != link.event_hash:
        return {
            "valid": False,
            "link_id": link_id,
            "reason": "hash_mismatch",
            "evidence_id": link.evidence_id,
            "report_id": link.report_id,
            "event_hash": link.event_hash,
            "signature_valid": None,
            "signature_status": "not_checked",
            "authority_version": link.authority_version,
        }

    sig_result = verify_link_signature(link)

    return {
        "valid": sig_result["valid"] is True,
        "link_id": link_id,
        "reason": sig_result.get("reason", "ok"),
        "evidence_id": link.evidence_id,
        "report_id": link.report_id,
        "event_hash": link.event_hash,
        "signature_valid": sig_result["valid"],
        "signature_status": sig_result["status"],
        "authority_version": link.authority_version,
    }


def verify_report_links_bulk(
    links: list[FaEvidenceReportLink],
) -> tuple[list[dict], list[dict]]:
    """Verify a list of link records without DB queries (no N+1).

    Returns (verified_links, invalid_links) — each is a list of dicts.
    Used by trust replay to avoid per-link DB round-trips.
    """
    verified: list[dict] = []
    invalid: list[dict] = []

    for link in links:
        expected_payload = _link_hash_payload(
            tenant_id=link.tenant_id,
            engagement_id=link.engagement_id,
            evidence_id=link.evidence_id,
            provenance_record_id=link.provenance_record_id,
            report_id=link.report_id,
            report_hash=link.report_hash,
            report_signature=link.report_signature,
            linked_at=link.linked_at,
            linked_by=link.linked_by,
            previous_hash=link.previous_hash,
            created_at=link.created_at,
        )
        expected_hash = compute_link_event_hash(expected_payload)

        if expected_hash != link.event_hash:
            invalid.append(
                {
                    "link_id": link.id,
                    "evidence_id": link.evidence_id,
                    "report_id": link.report_id,
                    "reason": "hash_mismatch",
                    "signature_valid": None,
                    "signature_status": "not_checked",
                }
            )
            continue

        sig_result = verify_link_signature(link)

        entry = {
            "link_id": link.id,
            "evidence_id": link.evidence_id,
            "provenance_record_id": link.provenance_record_id,
            "report_id": link.report_id,
            "event_hash": link.event_hash,
            "signature_valid": sig_result["valid"],
            "signature_status": sig_result["status"],
            "authority_version": link.authority_version,
        }

        if sig_result["valid"] is False:
            invalid.append({**entry, "reason": sig_result.get("reason", "invalid")})
        else:
            verified.append(entry)

    return verified, invalid
