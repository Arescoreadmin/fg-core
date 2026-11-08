"""Runtime scanner evidence capture — L14-SCAN-RUNNER-INTEGRITY-001.

Connects the PR #810 evidence authorities to real scanner execution:

    persisted fa_scan_results.raw_payload
        → canonical ScannerEvidenceEnvelope(s)   (EvidenceIntegrityService.build_envelope)
        → fa_scan_evidence_envelopes rows        (one per scan + one per observation)
        → append-only custody                    (EvidenceCustodyService.record)
        → finding ↔ evidence links + confidence  (classify_confidence)

What the digest covers
----------------------
The digest is computed over the evidence AS STORED in ``fa_scan_results.raw_payload``
(the bridge's persisted payload, after any redaction the bridge applies) — not
over network bytes received from the source.  It therefore proves the stored
evidence has not changed since capture (integrity).  It does NOT prove the
external source or the scanner produced it (authenticity): provenance is
``VERIFIED_INTEGRITY_ONLY`` until Vault Transit signing lands (L14-SCAN-VAULT-001).
No payload is duplicated: envelopes hold digests and a path into the stored payload.

Timestamps
----------
``collected_at`` is the runner-reported collection time (``scan_completed_at``
or the scan result's ``collected_at``).  ``created_at`` is the FrostGate capture
and persistence time.  Source-side timestamps, where a scanner records them,
stay inside the digested observation.

Authorization provenance
------------------------
Taken from ``authorization_context`` written into the payload at WORKER START by
the guarded worker (PR #812) — i.e. the authorization that actually permitted
collection, never the current state.  Graph-family payloads carry no FrostGate
customer receipt and are labelled ``GRAPH_CUSTOMER_DEVICE_CODE_LOGIN_ONLY``.

Not standalone: every write goes through the canonical evidence, custody and
confidence authorities; this module adds no second evidence store.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEngagement,
    FaNormalizedFinding,
    FaScanEvidenceEnvelope,
    FaScanJob,
    FaScanResult,
)
from services.canonical import utc_iso8601_z_now
from services.connectors.collection_status import CollectionStatus
from services.field_assessment.custody import CustodyEventType, custody_svc
from services.field_assessment.evidence_integrity import (
    ProvenanceStatus,
    ScannerEvidenceEnvelope,
    canonicalize_payload,
    evidence_integrity_svc,
)
from services.field_assessment.finding_confidence import (
    ConfidenceLevel,
    VerificationMethod,
    classify_confidence,
)
from services.field_assessment.store import derive_finding_id

log = logging.getLogger("frostgate.runtime_evidence")

EVIDENCE_SCHEMA_VERSION = "1.0"
CONFIDENCE_POLICY_VERSION = "fg.finding_confidence.v1"
MANIFEST_SCHEMA_VERSION = "fg.evidence_manifest.v1"
SYSTEM_ACTOR = "system:runtime_evidence"

# Bounded resource policy: canonical bytes per envelope.  The payload is already
# resident (loaded from fa_scan_results); these caps bound the extra canonical
# copy and refuse to digest pathological payloads.
MAX_SCAN_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_OBSERVATION_BYTES = 4 * 1024 * 1024

# Scanners wired to runtime capture, and how their findings are verified.
_DIRECT = VerificationMethod.DIRECT_TECHNICAL_OBSERVATION
_EXPORT = VerificationMethod.AUTHORITATIVE_CONFIGURATION_EXPORT
SCANNER_VERIFICATION_METHOD: dict[str, VerificationMethod] = {
    "network_scan": _DIRECT,
    "dns_email": _DIRECT,
    "web_headers": _DIRECT,
    "microsoft_graph": _EXPORT,
    "oauth_inventory": _EXPORT,
    "endpoint_inventory": _EXPORT,
    "entra_governance": _EXPORT,
    "sharepoint_onedrive": _EXPORT,
    "oauth_risk": _EXPORT,
    "ai_tool_discovery": _EXPORT,
}
TARGET_SCANNERS = frozenset({"network_scan", "dns_email", "web_headers"})
GRAPH_PROOF_LEVEL = "GRAPH_CUSTOMER_DEVICE_CODE_LOGIN_ONLY"

_CANONICAL_STATUSES = {s.value for s in CollectionStatus}
# Worst-first ordering for combining several observation statuses.
_STATUS_SEVERITY = [
    CollectionStatus.FAILED.value,
    CollectionStatus.DENIED.value,
    CollectionStatus.TIMEOUT.value,
    CollectionStatus.CANCELLED.value,
    CollectionStatus.TRUNCATED.value,
    CollectionStatus.PARTIAL.value,
    CollectionStatus.UNKNOWN.value,
    CollectionStatus.NOT_ASSESSED.value,
    CollectionStatus.COMPLETE.value,
]


class EvidenceCaptureError(Exception):
    """Fail-closed capture failure.  ``code`` is safe to log and audit."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass
class Observation:
    source_type: str
    source_id: str
    path: str
    payload: dict
    collection_status: str


@dataclass
class CaptureResult:
    scan_result_id: str
    scan_envelope_id: str
    observation_envelope_ids: dict[str, str] = field(default_factory=dict)
    created: int = 0
    reused: int = 0
    findings_linked: int = 0
    collection_status: str = CollectionStatus.UNKNOWN.value
    integrity_failures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Collection status helpers
# ---------------------------------------------------------------------------


def canonical_status(value: Any) -> str:
    """Map any recorded status to the canonical vocabulary; unknown → UNKNOWN."""
    if isinstance(value, CollectionStatus):
        return value.value
    if isinstance(value, str) and value.strip().upper() in _CANONICAL_STATUSES:
        return value.strip().upper()
    return CollectionStatus.UNKNOWN.value


def combine_statuses(statuses: Iterable[str]) -> str:
    vals = [canonical_status(s) for s in statuses]
    if not vals:
        return CollectionStatus.UNKNOWN.value
    for s in _STATUS_SEVERITY:
        if s in vals:
            return s
    return CollectionStatus.UNKNOWN.value


# ---------------------------------------------------------------------------
# Observation extraction (per scanner; pure)
# ---------------------------------------------------------------------------


def _network_host_status(obs: dict) -> str:
    if obs.get("collection_status"):
        return canonical_status(obs["collection_status"])
    if obs.get("error"):
        return CollectionStatus.FAILED.value
    return CollectionStatus.COMPLETE.value


_OBSERVATION_SPECS: dict[str, tuple[str, str, str]] = {
    # scanner: (payload list key, observation id key, source_type)
    "network_scan": ("hosts", "host", "network_host"),
    "dns_email": ("domains", "domain", "dns_domain"),
    "web_headers": ("targets", "url", "web_target"),
}


def extract_observations(scanner_id: str, payload: dict) -> list[Observation]:
    spec = _OBSERVATION_SPECS.get(scanner_id)
    if spec is None:
        return []
    list_key, id_key, source_type = spec
    items = payload.get(list_key)
    if not isinstance(items, list):
        return []
    out: list[Observation] = []
    seen: set[str] = set()
    for i, obs in enumerate(items):
        if not isinstance(obs, dict):
            continue
        sid = str(obs.get(id_key) or f"#{i}")
        if sid in seen:  # duplicate target in one scan — keep both, distinctly
            sid = f"{sid}#{i}"
        seen.add(sid)
        status = (
            _network_host_status(obs)
            if scanner_id == "network_scan"
            else canonical_status(obs.get("collection_status"))
        )
        out.append(
            Observation(
                source_type=source_type,
                source_id=sid,
                path=f"{list_key}[{i}]",
                payload=obs,
                collection_status=status,
            )
        )
    return out


_PATH_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$")


def resolve_observation(payload: Any, path: str | None) -> dict | None:
    """Locate the digested sub-payload in the stored payload.  None if absent."""
    if not isinstance(payload, dict):
        return None
    if path is None or path == "$":
        return payload
    m = _PATH_RE.match(path)
    if not m:
        return None
    items = payload.get(m.group(1))
    idx = int(m.group(2))
    if not isinstance(items, list) or idx >= len(items):
        return None
    obs = items[idx]
    return obs if isinstance(obs, dict) else None


def _web_key(target: str) -> str:
    t = (target or "").strip()
    return t if t.startswith(("http://", "https://")) else f"https://{t}"


def finding_observation_map(
    scanner_id: str, *, engagement_id: str, scan_result_id: str, payload: dict
) -> dict[str, set[str]]:
    """finding_id → observation source_ids, using each bridge's deterministic id.

    The id formulas mirror network_scan_bridge / dns_email_bridge /
    web_headers_bridge exactly (asserted by the end-to-end tests, which run the
    real bridges).  Findings not resolvable here fall back to the scan-level
    envelope — never to "no evidence".
    """
    raw = payload.get("findings")
    if not isinstance(raw, list) or scanner_id not in TARGET_SCANNERS:
        return {}
    out: dict[str, set[str]] = {}
    for f in raw:
        if not isinstance(f, dict):
            continue
        if scanner_id == "network_scan":
            ftype = str(f.get("finding_type") or "network.finding")
            fid = derive_finding_id(
                ftype, engagement_id, f"network_scan:{scan_result_id}:{ftype}"
            )
            obs = {str(h) for h in (f.get("affected_hosts") or [])}
        elif scanner_id == "dns_email":
            t = str(f.get("type") or "dns_email.finding")
            fid = derive_finding_id(
                f"dns_email.{t}", engagement_id, f"dns_email:{scan_result_id}:{t}"
            )
            obs = {str(f["domain"])} if f.get("domain") else set()
        else:
            t = str(f.get("type") or "web_headers.finding")
            target = f.get("target") or ""
            fid = derive_finding_id(
                f"web_headers.{t}",
                engagement_id,
                f"web_headers:{scan_result_id}:{t}:{target}",
            )
            obs = {_web_key(str(target))} if target else set()
        out.setdefault(fid, set()).update(obs)
    return out


# ---------------------------------------------------------------------------
# Authorization provenance (historical — from worker-start context)
# ---------------------------------------------------------------------------


def _authorization_provenance(
    scanner_id: str,
    payload: dict,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_job_id: str | None,
) -> dict[str, Any]:
    ctx = payload.get("authorization_context")
    if scanner_id not in TARGET_SCANNERS:
        if ctx is not None:
            raise EvidenceCaptureError("AUTHORIZATION_CONTEXT_UNEXPECTED", scanner_id)
        return {
            "authorization_ref": None,
            "authorization_version": None,
            "customer_receipt_id": None,
            "authorization_proof_level": GRAPH_PROOF_LEVEL,
        }
    if not isinstance(ctx, dict):
        # A target scan without worker-start authorization context did not go
        # through the guarded path — refuse to attribute it.
        raise EvidenceCaptureError("AUTHORIZATION_CONTEXT_MISSING", scanner_id)
    if str(ctx.get("tenant_id")) != tenant_id:
        raise EvidenceCaptureError("AUTHORIZATION_TENANT_MISMATCH")
    if str(ctx.get("engagement_id")) != engagement_id:
        raise EvidenceCaptureError("AUTHORIZATION_ENGAGEMENT_MISMATCH")
    if scan_job_id is not None and str(ctx.get("scan_job_id")) != scan_job_id:
        raise EvidenceCaptureError("AUTHORIZATION_SCAN_MISMATCH")
    if str(ctx.get("scanner_type")) != scanner_id:
        raise EvidenceCaptureError("AUTHORIZATION_SCANNER_MISMATCH")
    auth_id = ctx.get("authorization_id")
    receipt = ctx.get("customer_receipt_id")
    for v in (auth_id, receipt):
        if v is not None:
            try:
                uuid.UUID(str(v))
            except ValueError as exc:
                raise EvidenceCaptureError("AUTHORIZATION_REF_MALFORMED") from exc
    if auth_id is None:
        raise EvidenceCaptureError("AUTHORIZATION_REF_MISSING")
    version = ctx.get("authorization_version")
    return {
        "authorization_ref": str(auth_id),
        "authorization_version": int(version) if version is not None else None,
        "customer_receipt_id": str(receipt) if receipt else None,
        "authorization_proof_level": str(ctx.get("proof_level") or "UNKNOWN"),
    }


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


def _load_scan_result(
    db: Session, *, scan_result_id: str, tenant_id: str, engagement_id: str
) -> FaScanResult:
    row = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == scan_result_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()
    if row is None:
        # Same answer for "absent" and "other tenant" — no enumeration.
        raise EvidenceCaptureError("SCAN_RESULT_NOT_FOUND")
    return row


def _assert_ownership(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_job_id: str | None,
    scanner_id: str,
) -> None:
    eng = db.execute(
        select(FaEngagement.id).where(
            FaEngagement.id == engagement_id, FaEngagement.tenant_id == tenant_id
        )
    ).scalar_one_or_none()
    if eng is None:
        raise EvidenceCaptureError("ENGAGEMENT_NOT_FOUND")
    if scan_job_id is not None:
        job = db.execute(
            select(FaScanJob.tenant_id, FaScanJob.engagement_id).where(
                FaScanJob.id == scan_job_id
            )
        ).one_or_none()
        if job is None or job[0] != tenant_id or job[1] != engagement_id:
            raise EvidenceCaptureError("SCAN_JOB_NOT_FOUND")


def _existing_envelopes(
    db: Session, *, tenant_id: str, scan_result_id: str
) -> dict[tuple[str, str], FaScanEvidenceEnvelope]:
    rows = db.execute(
        select(FaScanEvidenceEnvelope).where(
            FaScanEvidenceEnvelope.tenant_id == tenant_id,
            FaScanEvidenceEnvelope.scan_result_id == scan_result_id,
        )
    ).scalars()
    return {(r.source_type, r.source_id or ""): r for r in rows}


def _digest_bounded(payload: dict, limit: int) -> int:
    size = len(canonicalize_payload(payload, schema_version=EVIDENCE_SCHEMA_VERSION))
    if size > limit:
        raise EvidenceCaptureError(
            "EVIDENCE_PAYLOAD_TOO_LARGE", f"{size} > {limit} bytes"
        )
    return size


def _persist_envelope(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_result: FaScanResult,
    scan_job_id: str | None,
    scanner_id: str,
    scanner_version: str | None,
    source_type: str,
    source_id: str,
    path: str,
    payload: dict,
    collection_status: str,
    collected_at: str,
    auth: dict,
    correlation_id: str | None,
    size: int,
) -> FaScanEvidenceEnvelope:
    env = evidence_integrity_svc.build_envelope(
        scan_id=scan_result.id,
        scanner_id=scanner_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload=payload,
        scanner_version=scanner_version,
        authorization_ref=auth["authorization_ref"],
        authorization_version=auth["authorization_version"],
        collected_at=collected_at,
        collection_status=collection_status,
        source_type=source_type,
        source_id=source_id,
        schema_version=EVIDENCE_SCHEMA_VERSION,
        data_sensitivity="confidential",
        correlation_id=correlation_id,
    )
    now = utc_iso8601_z_now()
    row = FaScanEvidenceEnvelope(
        id=env.evidence_id,
        tenant_id=env.tenant_id,
        engagement_id=env.engagement_id,
        scan_result_id=scan_result.id,
        scan_job_id=scan_job_id,
        schema_version=env.schema_version,
        scanner_id=env.scanner_id,
        scanner_version=env.scanner_version,
        authorization_ref=env.authorization_ref,
        authorization_version=env.authorization_version,
        collected_at=env.collected_at,
        collection_status=env.collection_status,
        source_type=env.source_type,
        source_id=env.source_id,
        payload_digest=env.payload_digest,
        canonicalization_ver=env.canonicalization_version,
        provenance_status=env.provenance_status.value,
        signature_ref=env.signature_ref,
        data_sensitivity=env.data_sensitivity,
        correlation_id=env.correlation_id,
        observation_path=path,
        customer_receipt_id=auth["customer_receipt_id"],
        authorization_proof_level=auth["authorization_proof_level"],
        payload_size_bytes=size,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    # Real lifecycle events, atomic with the envelope (commit=False).
    for event_type, to_state in (
        (CustodyEventType.COLLECTED, "collected"),
        (CustodyEventType.INGESTED, "persisted"),
    ):
        custody_svc.record(
            db,
            evidence_id=row.id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type=event_type,
            actor=SYSTEM_ACTOR,
            to_state=to_state,
            reason=f"{scanner_id}:{source_type}:{path}",
            correlation_id=correlation_id,
            digest_ref=row.payload_digest,
            commit=False,
        )
    return row


def _recheck_existing(row: FaScanEvidenceEnvelope, payload: dict) -> bool:
    """A reused envelope must still match the stored payload (never re-baselined)."""
    status = evidence_integrity_svc.verify_envelope(_as_envelope(row), payload)
    return status in (
        ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        ProvenanceStatus.VERIFIED_AUTHENTIC,
    )


def _as_envelope(row: FaScanEvidenceEnvelope) -> ScannerEvidenceEnvelope:
    return ScannerEvidenceEnvelope(
        schema_version=row.schema_version,
        evidence_id=row.id,
        scan_id=row.scan_result_id or "",
        scanner_id=row.scanner_id,
        scanner_version=row.scanner_version,
        tenant_id=row.tenant_id,
        engagement_id=row.engagement_id,
        authorization_ref=row.authorization_ref,
        authorization_version=row.authorization_version,
        collected_at=row.collected_at,
        collection_status=row.collection_status,
        source_type=row.source_type,
        source_id=row.source_id,
        payload_digest=row.payload_digest,
        canonicalization_version=row.canonicalization_ver,
        provenance_status=ProvenanceStatus(row.provenance_status),
        signature_ref=row.signature_ref,
        data_sensitivity=row.data_sensitivity,
        correlation_id=row.correlation_id,
    )


def capture_scan_result_evidence(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_result_id: str,
    scanner_id: str,
    scan_job_id: str | None = None,
    scanner_version: str | None = None,
    correlation_id: str | None = None,
) -> CaptureResult:
    """Capture canonical evidence for one persisted scan result.  Idempotent.

    Does NOT commit: the caller's transaction makes envelope, custody and
    finding links durable together, before the job is marked complete.
    Raises EvidenceCaptureError (fail-closed) — the caller must then record the
    failure and must not present the scan's findings as evidence-backed.
    """
    if scanner_id not in SCANNER_VERIFICATION_METHOD:
        raise EvidenceCaptureError("SCANNER_NOT_SUPPORTED", scanner_id)
    _assert_ownership(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_job_id=scan_job_id,
        scanner_id=scanner_id,
    )
    sr = _load_scan_result(
        db,
        scan_result_id=scan_result_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    payload = sr.raw_payload
    if not isinstance(payload, dict) or not payload:
        raise EvidenceCaptureError("UNSUPPORTED_PAYLOAD", type(payload).__name__)
    auth = _authorization_provenance(
        scanner_id,
        payload,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_job_id=scan_job_id,
    )
    collected_at = str(payload.get("scan_completed_at") or sr.collected_at)
    scan_status = canonical_status(payload.get("collection_status"))
    corr = correlation_id or scan_job_id

    existing = _existing_envelopes(db, tenant_id=tenant_id, scan_result_id=sr.id)
    result = CaptureResult(
        scan_result_id=sr.id, scan_envelope_id="", collection_status=scan_status
    )

    units: list[tuple[str, str, str, dict, str, int]] = [
        ("scan_result", sr.id, "$", payload, scan_status, MAX_SCAN_PAYLOAD_BYTES)
    ]
    for o in extract_observations(scanner_id, payload):
        units.append(
            (
                o.source_type,
                o.source_id,
                o.path,
                o.payload,
                o.collection_status,
                MAX_OBSERVATION_BYTES,
            )
        )

    for source_type, source_id, path, sub, status, limit in units:
        prior = existing.get((source_type, source_id))
        if prior is not None:
            if not _recheck_existing(prior, sub):
                result.integrity_failures.append(prior.id)
            env_id = prior.id
            result.reused += 1
        else:
            size = _digest_bounded(sub, limit)
            row = _persist_envelope(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=sr,
                scan_job_id=scan_job_id,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                source_type=source_type,
                source_id=source_id,
                path=path,
                payload=sub,
                collection_status=status,
                collected_at=collected_at,
                auth=auth,
                correlation_id=corr,
                size=size,
            )
            env_id = row.id
            result.created += 1
        if source_type == "scan_result":
            result.scan_envelope_id = env_id
        else:
            result.observation_envelope_ids[source_id] = env_id

    if result.integrity_failures:
        # Stored payload no longer matches what was captured: never relink or
        # re-baseline; surface it.
        raise EvidenceCaptureError(
            "STORED_EVIDENCE_INTEGRITY_FAILURE", ",".join(result.integrity_failures)
        )

    result.findings_linked = _link_findings(
        db,
        sr=sr,
        scanner_id=scanner_id,
        payload=payload,
        capture=result,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        correlation_id=corr,
    )
    return result


def capture_with_retry(db: Session, **kwargs: Any) -> CaptureResult:
    """Run capture in a SAVEPOINT; a concurrent duplicate insert is retried once
    (the second pass reuses the winner's envelopes).  Any other failure rolls
    back only the savepoint — the scan result already persisted is kept."""
    for attempt in (1, 2):
        sp = db.begin_nested()
        try:
            res = capture_scan_result_evidence(db, **kwargs)
            sp.commit()
            return res
        except IntegrityError:
            sp.rollback()
            if attempt == 2:
                raise EvidenceCaptureError("CONCURRENT_CAPTURE_CONFLICT")
        except Exception:
            sp.rollback()
            raise
    raise EvidenceCaptureError("CONCURRENT_CAPTURE_CONFLICT")  # pragma: no cover


# ---------------------------------------------------------------------------
# Finding ↔ evidence linkage + confidence
# ---------------------------------------------------------------------------


def _scan_findings(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scanner_id: str,
    scan_result_id: str,
) -> list[FaNormalizedFinding]:
    rows = db.execute(
        select(FaNormalizedFinding).where(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.source_attribution.like(f"{scanner_id}:%"),
        )
    ).scalars()
    out = []
    for f in rows:
        refs = f.evidence_ref_ids or []
        if (
            f.source_attribution == f"{scanner_id}:{scan_result_id}"
            or scan_result_id in refs
        ):
            out.append(f)
    return out


def _normalized_event_exists(
    db: Session, *, evidence_id: str, tenant_id: str, finding_id: str
) -> bool:
    from api.db_models_field_assessment import FaEvidenceCustodyEvent

    return (
        db.execute(
            select(FaEvidenceCustodyEvent.id).where(
                FaEvidenceCustodyEvent.evidence_id == evidence_id,
                FaEvidenceCustodyEvent.tenant_id == tenant_id,
                FaEvidenceCustodyEvent.event_type == CustodyEventType.NORMALIZED.value,
                FaEvidenceCustodyEvent.reason == f"finding:{finding_id}",
            )
        ).first()
        is not None
    )


def _link_findings(
    db: Session,
    *,
    sr: FaScanResult,
    scanner_id: str,
    payload: dict,
    capture: CaptureResult,
    tenant_id: str,
    engagement_id: str,
    correlation_id: str | None,
) -> int:
    obs_map = finding_observation_map(
        scanner_id, engagement_id=engagement_id, scan_result_id=sr.id, payload=payload
    )
    statuses = {
        sid: canonical_status(o.collection_status)
        for o in extract_observations(scanner_id, payload)
        for sid in [o.source_id]
    }
    method = SCANNER_VERIFICATION_METHOD[scanner_id]
    linked = 0
    for finding in _scan_findings(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scanner_id=scanner_id,
        scan_result_id=sr.id,
    ):
        if (
            finding.evidence_envelope_id is not None
            or finding.confidence_level is not None
        ):
            continue  # already classified (retry) — never relink or upgrade
        obs_ids = [
            s
            for s in sorted(obs_map.get(finding.id, set()))
            if s in capture.observation_envelope_ids
        ]
        if obs_ids:
            env_ids = [capture.observation_envelope_ids[s] for s in obs_ids]
            coll = combine_statuses(statuses[s] for s in obs_ids)
        else:
            env_ids = [capture.scan_envelope_id]
            coll = capture.collection_status
        level = classify_confidence(
            evidence_present=True,
            collection_complete=coll == CollectionStatus.COMPLETE.value,
            verification_method=method,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        finding.evidence_envelope_id = env_ids[0]
        finding.confidence_level = level.value
        finding.verification_method = method.value
        finding.collection_status = coll
        finding.confidence_justification = (
            f"policy={CONFIDENCE_POLICY_VERSION}; evidence={len(env_ids)}; "
            f"collection={coll}; provenance={ProvenanceStatus.VERIFIED_INTEGRITY_ONLY.value}; "
            f"basis={'observation' if obs_ids else 'scan_result'}"
        )
        for env_id in env_ids:
            if not _normalized_event_exists(
                db, evidence_id=env_id, tenant_id=tenant_id, finding_id=finding.id
            ):
                custody_svc.record(
                    db,
                    evidence_id=env_id,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    event_type=CustodyEventType.NORMALIZED,
                    actor=SYSTEM_ACTOR,
                    to_state="supports_finding",
                    reason=f"finding:{finding.id}",
                    correlation_id=correlation_id,
                    commit=False,
                )
        linked += 1
    db.flush()
    return linked


def mark_findings_evidence_missing(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scanner_id: str,
    scan_result_id: str,
    code: str,
) -> int:
    """After a failed capture: findings are explicitly UNKNOWN, never left to look verified."""
    n = 0
    for f in _scan_findings(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scanner_id=scanner_id,
        scan_result_id=scan_result_id,
    ):
        if f.confidence_level is not None:
            continue
        f.confidence_level = ConfidenceLevel.UNKNOWN.value
        f.verification_method = VerificationMethod.NOT_VERIFIED.value
        f.confidence_justification = (
            f"policy={CONFIDENCE_POLICY_VERSION}; evidence=0; capture_failed={code}"
        )
        n += 1
    db.flush()
    return n


# ---------------------------------------------------------------------------
# Verification against the stored payload
# ---------------------------------------------------------------------------


def verify_stored_evidence(
    db: Session,
    *,
    tenant_id: str,
    evidence_id: str,
    record_custody: bool = False,
    actor: str = SYSTEM_ACTOR,
) -> ProvenanceStatus:
    """Recompute the digest from fa_scan_results and compare.  Fail-closed.

    Cross-tenant or absent → MISSING.  Mismatch → INVALID (sticky: the envelope
    is marked INVALID, the stored digest is never changed).
    """
    env = db.execute(
        select(FaScanEvidenceEnvelope).where(
            FaScanEvidenceEnvelope.id == evidence_id,
            FaScanEvidenceEnvelope.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    if env is None:
        return ProvenanceStatus.MISSING
    if env.provenance_status == ProvenanceStatus.INVALID.value:
        return ProvenanceStatus.INVALID
    if env.scan_result_id is None:
        return ProvenanceStatus.INDETERMINATE
    sr = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == env.scan_result_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == env.engagement_id,
        )
    ).scalar_one_or_none()
    sub = resolve_observation(
        sr.raw_payload if sr is not None else None, env.observation_path
    )
    if sub is None:
        status = (
            ProvenanceStatus.INVALID if sr is not None else ProvenanceStatus.MISSING
        )
    else:
        status = evidence_integrity_svc.verify_envelope(_as_envelope(env), sub)
    if status == ProvenanceStatus.INVALID:
        env.provenance_status = ProvenanceStatus.INVALID.value
        env.updated_at = utc_iso8601_z_now()
        db.flush()
    if record_custody and status in (
        ProvenanceStatus.INVALID,
        ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        ProvenanceStatus.VERIFIED_AUTHENTIC,
    ):
        custody_svc.record(
            db,
            evidence_id=env.id,
            tenant_id=tenant_id,
            engagement_id=env.engagement_id,
            event_type=CustodyEventType.VERIFIED,
            actor=actor,
            to_state=status.value,
            reason="integrity_failure"
            if status == ProvenanceStatus.INVALID
            else "digest_verified",
            digest_ref=env.payload_digest,
            commit=False,
        )
    return status


# ---------------------------------------------------------------------------
# Report-facing evidence manifest (built only from persisted records)
# ---------------------------------------------------------------------------


_CONFIDENCE_RANK = {
    ConfidenceLevel.CONFIRMED.value: 4,
    ConfidenceLevel.PROBABLE.value: 3,
    ConfidenceLevel.SUSPECTED.value: 2,
    ConfidenceLevel.UNKNOWN.value: 1,
    ConfidenceLevel.NOT_ASSESSED.value: 0,
}


def _cap_confidence(stored: str, prov: ProvenanceStatus) -> str:
    """Report-time cap from CURRENT verification (never raises a stored level).

    INVALID / MISSING → max SUSPECTED (rule C-2).  INDETERMINATE / UNVERIFIED —
    evidence exists but cannot be verified now (e.g. source scan result deleted,
    verification error) → max PROBABLE (rule C-8: authoritative method with
    unverified provenance).  Verified provenance keeps the stored level.
    """
    if prov in (
        ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        ProvenanceStatus.VERIFIED_AUTHENTIC,
    ):
        return stored
    cap = (
        ConfidenceLevel.SUSPECTED.value
        if prov in (ProvenanceStatus.INVALID, ProvenanceStatus.MISSING)
        else ConfidenceLevel.PROBABLE.value
    )
    if _CONFIDENCE_RANK.get(stored, 0) > _CONFIDENCE_RANK[cap]:
        return cap
    return stored


def build_evidence_manifest(
    db: Session, *, tenant_id: str, engagement_id: str
) -> dict[str, Any]:
    """Machine-readable, reproducible manifest for report assembly (next PR).

    Every value comes from persisted rows; integrity is re-verified against the
    stored payload at build time (no custody written — read-only).
    """
    from api.db_models_field_assessment import FaEvidenceCustodyEvent

    envs = {
        e.id: e
        for e in db.execute(
            select(FaScanEvidenceEnvelope).where(
                FaScanEvidenceEnvelope.tenant_id == tenant_id,
                FaScanEvidenceEnvelope.engagement_id == engagement_id,
            )
        ).scalars()
    }
    verified_at = utc_iso8601_z_now()
    integrity = {
        eid: verify_stored_evidence(db, tenant_id=tenant_id, evidence_id=eid)
        for eid in envs
    }

    supports: dict[str, list[str]] = {}
    if envs:
        for ev in db.execute(
            select(FaEvidenceCustodyEvent).where(
                FaEvidenceCustodyEvent.tenant_id == tenant_id,
                FaEvidenceCustodyEvent.engagement_id == engagement_id,
                FaEvidenceCustodyEvent.event_type == CustodyEventType.NORMALIZED.value,
            )
        ).scalars():
            reason = ev.reason or ""
            if ev.evidence_id in envs and reason.startswith("finding:"):
                supports.setdefault(reason[len("finding:") :], []).append(
                    ev.evidence_id
                )

    findings_out = []
    for f in db.execute(
        select(FaNormalizedFinding)
        .where(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
        )
        .order_by(FaNormalizedFinding.id)
    ).scalars():
        ev_ids = sorted(
            set(supports.get(f.id, []))
            | ({f.evidence_envelope_id} if f.evidence_envelope_id in envs else set())
        )
        statuses = [integrity[e] for e in ev_ids]
        if not ev_ids:
            prov = ProvenanceStatus.MISSING
        elif ProvenanceStatus.INVALID in statuses:
            prov = ProvenanceStatus.INVALID
        elif all(s == ProvenanceStatus.VERIFIED_AUTHENTIC for s in statuses):
            prov = ProvenanceStatus.VERIFIED_AUTHENTIC
        elif all(
            s
            in (
                ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
                ProvenanceStatus.VERIFIED_AUTHENTIC,
            )
            for s in statuses
        ):
            prov = ProvenanceStatus.VERIFIED_INTEGRITY_ONLY
        else:
            prov = ProvenanceStatus.INDETERMINATE
        stored = f.confidence_level
        if stored is None:
            effective = ConfidenceLevel.UNKNOWN.value  # legacy: never upgraded
        else:
            effective = _cap_confidence(stored, prov)
        env0 = envs.get(ev_ids[0]) if ev_ids else None
        findings_out.append(
            {
                "finding_id": f.id,
                "finding_type": f.finding_type,
                "evidence_ids": ev_ids,
                "source_scanner": env0.scanner_id if env0 else None,
                "collection_status": f.collection_status
                or CollectionStatus.UNKNOWN.value,
                "evidence_integrity_status": "INTEGRITY_VERIFIED"
                if prov
                in (
                    ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
                    ProvenanceStatus.VERIFIED_AUTHENTIC,
                )
                else (
                    "INTEGRITY_FAILED"
                    if prov == ProvenanceStatus.INVALID
                    else "NOT_VERIFIABLE"
                ),
                "provenance_status": prov.value,
                "confidence_stored": stored,
                "confidence_effective": effective,
                "severity": f.severity,
                "legacy_unclassified": stored is None,
                "authorization": {
                    "authorization_id": env0.authorization_ref if env0 else None,
                    "authorization_version": env0.authorization_version
                    if env0
                    else None,
                    "customer_receipt_id": env0.customer_receipt_id if env0 else None,
                    "proof_level": env0.authorization_proof_level if env0 else None,
                },
                "evidence_verified_at": verified_at if ev_ids else None,
            }
        )

    scans: dict[str, dict] = {}
    for e in envs.values():
        if e.source_type == "scan_result":
            scans[e.scan_result_id or e.id] = {
                "scan_result_id": e.scan_result_id,
                "scanner": e.scanner_id,
                "collection_status": e.collection_status,
                "evidence_id": e.id,
                "provenance_status": integrity[e.id].value,
            }
    limitation_set = {
        f"{e.scanner_id}:{e.source_id}:{e.collection_status}"
        for e in envs.values()
        if canonical_status(e.collection_status) != CollectionStatus.COMPLETE.value
    }
    # Reconcile against persisted scan results and jobs: a scan whose capture
    # failed (no envelope) or a job that produced no result is a coverage gap,
    # never silently absent from the coverage decision.
    for sr_id, source_type in db.execute(
        select(FaScanResult.id, FaScanResult.source_type).where(
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).all():
        if source_type in SCANNER_VERIFICATION_METHOD and sr_id not in scans:
            scans[sr_id] = {
                "scan_result_id": sr_id,
                "scanner": source_type,
                "collection_status": CollectionStatus.UNKNOWN.value,
                "evidence_id": None,
                "provenance_status": ProvenanceStatus.MISSING.value,
            }
            limitation_set.add(f"{source_type}:{sr_id}:EVIDENCE_NOT_CAPTURED")
    captured_jobs = {e.scan_job_id for e in envs.values() if e.scan_job_id}
    for job_id, scanner, job_status in db.execute(
        select(FaScanJob.id, FaScanJob.scanner_type, FaScanJob.status).where(
            FaScanJob.tenant_id == tenant_id,
            FaScanJob.engagement_id == engagement_id,
        )
    ).all():
        if job_id not in captured_jobs and job_status != "complete":
            limitation_set.add(f"{scanner}:job:{job_id}:{str(job_status).upper()}")
    limitations = sorted(limitation_set)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "generated_at": verified_at,
        "findings": findings_out,
        "scans": sorted(scans.values(), key=lambda x: str(x["scan_result_id"])),
        "coverage_limitations": limitations,
        "report_constraints": {
            # Never assertable without an authenticated signature (Vault: L14-SCAN-VAULT-001).
            "may_claim_authenticated_evidence": bool(envs)
            and all(
                s == ProvenanceStatus.VERIFIED_AUTHENTIC for s in integrity.values()
            ),
            "may_claim_full_coverage": bool(scans) and not limitations,
            "may_claim_zero_risk": False,
            "confirmed_finding_ids": [
                x["finding_id"]
                for x in findings_out
                if x["confidence_effective"] == ConfidenceLevel.CONFIRMED.value
            ],
            "integrity_failed_evidence_ids": sorted(
                e for e, s in integrity.items() if s == ProvenanceStatus.INVALID
            ),
        },
    }
