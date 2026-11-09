"""Report proof assembly — L14-SCAN-REPORT-PROOF-001.

This module is NOT standalone.  It is a component of the Field Assessment
Engagement Substrate and Governance Platform: it is called ONLY by the
canonical engagement report builder (``api.field_assessment.
_build_engagement_report_json``) and by the canonical export / delivery
routes.  It is not a second report authority, evidence store, severity engine
or release system.

It projects persisted authorities into one signed ``report_proof`` section:

* findings      — ``fa_normalized_findings`` (all eligible rows, explicit
                  exclusions, severity preserved, confidence capped by the
                  PR #813 evidence manifest — never upgraded);
* evidence      — ``runtime_evidence.build_evidence_manifest`` (digests
                  re-verified against stored payloads at assembly time);
* coverage      — persisted scan payload collection status per scan and per
                  observation, unfinished scan jobs and evidence-capture gaps.
                  No percentage is ever invented: no persisted authorized-scope
                  inventory supplies an eligible denominator.

``release_blockers`` feed the canonical result truth gate (generation) and
``_require_production_qualified`` (delivery).  ``evaluate_report_state``
derives the DRAFT / FINAL marking from authoritative state only — it takes no
caller-controlled input.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaNormalizedFinding,
    FaScanEvidenceEnvelope,
    FaScanJob,
    FaScanResult,
)
from services.field_assessment.finding_confidence import ConfidenceLevel
from services.field_assessment.runtime_evidence import (
    SCANNER_VERIFICATION_METHOD,
    TARGET_SCANNERS,
    build_evidence_manifest,
    canonical_status,
    extract_observations,
    finding_observation_map,
    verify_stored_evidence,
)

REPORT_PROOF_SCHEMA_VERSION = "fg.report_proof.v1"
COVERAGE_CALCULATION_VERSION = "fg.coverage.persisted_collection_status.v1"

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")
_SEVERITY_ALIASES = {"info": "informational", "moderate": "medium"}
UNRATED = "unrated"

# Explicit, canonical exclusion rule: only an adjudicated false positive leaves
# the findings register, and it is still counted and listed as excluded.
EXCLUDED_STATUSES: dict[str, str] = {"false_positive": "FALSE_POSITIVE_DISPOSITION"}

_VERIFIED_PROVENANCE = frozenset({"VERIFIED_INTEGRITY_ONLY", "VERIFIED_AUTHENTIC"})
# Non-terminal fa_scan_jobs states (0200 CHECK): cancel_requested is still in
# flight — the worker has not confirmed the stop or persisted its results.
_UNFINISHED_JOB_STATES = frozenset(
    {"queued", "running", "cancel_requested", "pending", "retrying"}
)

MARKING_SYNTHETIC = "DRAFT — SYNTHETIC DATA — NOT VERIFIED"
MARKING_DRAFT = "DRAFT — NOT VERIFIED"
MARKING_FINAL = "FINAL — QA APPROVED"
MARKING_FINAL_LIMITED = "FINAL — QA APPROVED — LIMITED COVERAGE"

COVERAGE_NOT_DETERMINABLE = "Coverage not determinable"
_DENOMINATOR_REASON = (
    "No persisted authorized-scope inventory supplies an eligible denominator; "
    "coverage is reported as recorded per-scan and per-observation collection "
    "status only, never as a percentage."
)


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = _SEVERITY_ALIASES.get(s, s)
    return s if s in SEVERITY_ORDER else UNRATED


def _sev_rank(value: str) -> int:
    return (
        SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )


def _fingerprint(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _is_synthetic_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("synthetic") is True:
        return True
    ctx = payload.get("authorization_context")
    return isinstance(ctx, dict) and str(ctx.get("proof_level") or "").startswith(
        "SYNTHETIC"
    )


def _coverage(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_rows: Iterable[FaScanResult],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, set[str]], list[str]]:
    """Coverage from persisted collection data.  Returns (coverage, resources, synthetic_sources)."""
    scans_out: list[dict[str, Any]] = []
    limitations: set[str] = set(manifest.get("coverage_limitations") or [])
    scan_status_counts: dict[str, int] = {}
    obs_status_counts: dict[str, int] = {}
    resources: dict[str, set[str]] = {}
    synthetic_sources: list[str] = []
    times: list[str] = []
    for sr in sorted(scan_rows, key=lambda r: (str(r.collected_at), r.id)):
        payload = sr.raw_payload if isinstance(sr.raw_payload, dict) else {}
        status = canonical_status(payload.get("collection_status"))
        observations = extract_observations(sr.source_type, payload)
        o_counts: dict[str, int] = {}
        for o in observations:
            o_counts[o.collection_status] = o_counts.get(o.collection_status, 0) + 1
            obs_status_counts[o.collection_status] = (
                obs_status_counts.get(o.collection_status, 0) + 1
            )
            if o.collection_status != "COMPLETE":
                limitations.add(f"{sr.source_type}:{o.source_id}:{o.collection_status}")
        if status != "COMPLETE":
            limitations.add(f"{sr.source_type}:{sr.id}:{status}")
        interrupted = payload.get("interrupted")
        not_started = (
            interrupted.get("remaining_targets_not_started")
            if isinstance(interrupted, dict)
            else None
        )
        if isinstance(not_started, int) and not_started > 0:
            limitations.add(
                f"{sr.source_type}:{sr.id}:TARGETS_NOT_STARTED:{not_started}"
            )
        scan_status_counts[status] = scan_status_counts.get(status, 0) + 1
        if sr.source_type in TARGET_SCANNERS:
            for fid, obs in finding_observation_map(
                sr.source_type,
                engagement_id=engagement_id,
                scan_result_id=sr.id,
                payload=payload,
            ).items():
                resources.setdefault(fid, set()).update(obs)
        if _is_synthetic_payload(payload):
            synthetic_sources.append(sr.id)
        if sr.collected_at:
            times.append(str(sr.collected_at))
        scans_out.append(
            {
                "scan_result_id": sr.id,
                "scanner": sr.source_type,
                "collection_status": status,
                "observation_status_counts": dict(sorted(o_counts.items())),
                "observation_count": len(observations),
                "targets_not_started": not_started
                if isinstance(not_started, int)
                else 0,
                "collected_at": str(sr.collected_at),
                "evidence_supported": sr.source_type in SCANNER_VERIFICATION_METHOD,
            }
        )

    jobs_out: list[dict[str, Any]] = []
    unfinished: list[str] = []
    for job_id, scanner, job_status, coll in db.execute(
        select(
            FaScanJob.id,
            FaScanJob.scanner_type,
            FaScanJob.status,
            FaScanJob.collection_status,
        )
        .where(
            FaScanJob.tenant_id == tenant_id,
            FaScanJob.engagement_id == engagement_id,
        )
        .order_by(FaScanJob.id)
    ).all():
        js = str(job_status or "").lower()
        jobs_out.append(
            {
                "job_id": job_id,
                "scanner": scanner,
                "status": js,
                "collection_status": canonical_status(coll) if coll else None,
            }
        )
        if js != "complete":
            limitations.add(f"{scanner}:job:{job_id}:{js.upper()}")
        if js in _UNFINISHED_JOB_STATES:
            unfinished.append(job_id)

    limitation_list = sorted(limitations)
    full = bool(scans_out) and not limitation_list
    window = {"start": min(times), "end": max(times)} if times else None
    coverage = {
        "calculation_version": COVERAGE_CALCULATION_VERSION,
        "data_source": [
            "fa_scan_results.raw_payload.collection_status",
            "fa_scan_results.raw_payload observations",
            "fa_scan_jobs.status",
            "fa_scan_evidence_envelopes (evidence manifest)",
        ],
        "scans": scans_out,
        "jobs": jobs_out,
        "unfinished_job_ids": unfinished,
        "scan_status_counts": dict(sorted(scan_status_counts.items())),
        "observation_status_counts": dict(sorted(obs_status_counts.items())),
        "limitations": limitation_list,
        "collection_window": window,
        "coverage_percentage": None,
        "coverage_determinable": False,
        "coverage_statement": (
            "NOT_ASSESSED — no persisted collection for this engagement"
            if not scans_out
            else (
                "All recorded collection completed; no limitation recorded"
                if full
                else "Limited — collection incomplete for the recorded scope"
            )
        ),
        "coverage_not_determinable_reason": _DENOMINATOR_REASON,
        "may_claim_full_coverage": full
        and bool(manifest.get("report_constraints", {}).get("may_claim_full_coverage")),
    }
    return coverage, resources, synthetic_sources


def build_report_proof(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    findings: list[FaNormalizedFinding],
    scan_rows: list[FaScanResult],
    data_cutoff: str,
) -> dict[str, Any]:
    """Assemble the signed report proof from persisted authorities only.

    ``findings`` is the builder's paginated read; it is reconciled against an
    independent read by the evidence manifest so a pagination or filter defect
    surfaces as a release blocker instead of a silently shorter report.
    """
    manifest = build_evidence_manifest(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )
    by_id = {m["finding_id"]: m for m in manifest["findings"]}
    coverage, resources, synthetic_sources = _coverage(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_rows=scan_rows,
        manifest=manifest,
    )

    integrity: dict[str, str] = manifest["evidence_integrity"]
    env_rows = (
        {
            e.id: e
            for e in db.execute(
                select(FaScanEvidenceEnvelope).where(
                    FaScanEvidenceEnvelope.tenant_id == tenant_id,
                    FaScanEvidenceEnvelope.engagement_id == engagement_id,
                )
            ).scalars()
        }
        if integrity
        else {}
    )

    blockers: set[str] = set()
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        if f.tenant_id != tenant_id or f.engagement_id != engagement_id:
            blockers.add("CROSS_SCOPE_FINDING_REFERENCE")
            continue
        if f.id in seen:
            blockers.add("DUPLICATE_FINDING_IDENTITY")
            continue
        seen.add(f.id)
        status = str(f.status or "open")
        if status in EXCLUDED_STATUSES:
            excluded.append({"finding_id": f.id, "reason": EXCLUDED_STATUSES[status]})
            continue
        m = by_id.get(f.id)
        if m is None:
            blockers.add("FINDING_NOT_IN_EVIDENCE_MANIFEST")
        prov = m["provenance_status"] if m else "MISSING"
        effective = m["confidence_effective"] if m else ConfidenceLevel.UNKNOWN.value
        coll = canonical_status(
            (m or {}).get("collection_status") or f.collection_status
        )
        ev_ids = list(m["evidence_ids"]) if m else []
        res = sorted(resources.get(f.id, set()))
        if not res:
            res = sorted(
                {
                    str(env_rows[e].source_id)
                    for e in ev_ids
                    if e in env_rows and env_rows[e].observation_path not in (None, "$")
                }
            )
        if not res and f.asset_id:
            res = [f.asset_id]
        limitations: list[str] = []
        if coll != "COMPLETE":
            limitations.append(f"COLLECTION_{coll}")
        if prov == "MISSING":
            limitations.append("EVIDENCE_NOT_CAPTURED")
        elif prov == "INVALID":
            limitations.append("EVIDENCE_INTEGRITY_FAILED")
        elif prov not in _VERIFIED_PROVENANCE:
            limitations.append(f"EVIDENCE_{prov}")
        if f.confidence_level is None:
            limitations.append("CONFIDENCE_UNCLASSIFIED")
        elif f.confidence_level != effective:
            limitations.append(f"CONFIDENCE_CAPPED_FROM_{f.confidence_level}")
        if (
            effective == ConfidenceLevel.CONFIRMED.value
            and prov not in _VERIFIED_PROVENANCE
        ):
            blockers.add("CONFIRMED_WITHOUT_VERIFIED_EVIDENCE")
        auth = (m or {}).get("authorization") or {}
        included.append(
            {
                "finding_id": f.id,
                "title": f.title,
                "finding_type": f.finding_type,
                "severity": normalize_severity(f.severity),
                "severity_recorded": f.severity,
                "status": status,
                "description": f.description,
                "source_attribution": f.source_attribution,
                "affected_resources": res,
                "remediation": (f.remediation_hint or "").strip() or None,
                "confidence_stored": f.confidence_level,
                "confidence_effective": effective,
                "verification_method": f.verification_method,
                "confidence_justification": f.confidence_justification,
                "collection_status": coll,
                "evidence": {
                    "evidence_ids": ev_ids,
                    "provenance_status": prov,
                    "source_scanner": (m or {}).get("source_scanner"),
                    "scan_result_ids": sorted(
                        {
                            str(env_rows[e].scan_result_id)
                            for e in ev_ids
                            if e in env_rows and env_rows[e].scan_result_id
                        }
                        | {str(x) for x in (f.evidence_ref_ids or [])}
                    ),
                    "custody_ref": f"custody:finding:{f.id}" if ev_ids else None,
                    "authorization_ref": auth.get("authorization_id"),
                    "authorization_proof_level": auth.get("proof_level"),
                    "customer_receipt_id": auth.get("customer_receipt_id"),
                },
                "limitations": limitations,
            }
        )
    included.sort(key=lambda x: (_sev_rank(x["severity"]), x["finding_id"]))

    manifest_ids = set(by_id)
    if manifest_ids != seen:
        blockers.add("FINDING_RECONCILIATION_MISMATCH")
    if manifest["report_constraints"].get("integrity_failed_evidence_ids"):
        blockers.add("EVIDENCE_INTEGRITY_FAILED")
    if coverage["unfinished_job_ids"]:
        blockers.add("SCAN_JOBS_IN_PROGRESS")
    if synthetic_sources:
        blockers.add("SYNTHETIC_DATA")

    sev_counts = {s: 0 for s in (*SEVERITY_ORDER, UNRATED)}
    conf_counts: dict[str, int] = {}
    prov_counts: dict[str, int] = {}
    for x in included:
        sev_counts[x["severity"]] += 1
        conf_counts[x["confidence_effective"]] = (
            conf_counts.get(x["confidence_effective"], 0) + 1
        )
        p = x["evidence"]["provenance_status"]
        prov_counts[p] = prov_counts.get(p, 0) + 1

    evidence_index: dict[str, dict[str, Any]] = {
        eid: {
            "scanner": row.scanner_id,
            "scan_result_id": row.scan_result_id,
            "collection_status": canonical_status(row.collection_status),
            "provenance_status": integrity.get(eid),
            "observation": row.source_id
            if row.observation_path not in (None, "$")
            else "$",
        }
        for eid, row in env_rows.items()
    }

    proof: dict[str, Any] = {
        "schema_version": REPORT_PROOF_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "data_cutoff": data_cutoff,
        "evidence_verified_at": manifest["generated_at"],
        "finding_reconciliation": {
            "persisted_total": len(manifest_ids | seen),
            "eligible_total": len(seen) - len(excluded),
            "included_total": len(included),
            "excluded_total": len(excluded),
            "excluded": sorted(excluded, key=lambda x: x["finding_id"]),
            "reconciled": manifest_ids == seen
            and len(included) == len(seen) - len(excluded),
        },
        "severity_counts": sev_counts,
        "confidence_counts": dict(sorted(conf_counts.items())),
        "provenance_counts": dict(sorted(prov_counts.items())),
        "findings": included,
        "coverage": coverage,
        "evidence_index": dict(sorted(evidence_index.items())),
        "report_constraints": {
            **manifest["report_constraints"],
            "may_claim_full_coverage": coverage["may_claim_full_coverage"],
            "may_claim_verified_final": False,  # set only by QA + qualification at export
        },
        "synthetic": {
            "is_synthetic": bool(synthetic_sources),
            "sources": sorted(synthetic_sources),
        },
        "assurance_label": "FULL_RECORDED_COVERAGE"
        if coverage["may_claim_full_coverage"]
        else "LIMITED_COVERAGE",
        "release_blockers": sorted(blockers),
    }
    proof["proof_fingerprint"] = _fingerprint(
        {k: v for k, v in proof.items() if k not in ("evidence_verified_at",)}
    )
    return proof


def recheck_evidence(
    db: Session, *, tenant_id: str, proof: dict[str, Any]
) -> list[str]:
    """Evidence ids whose integrity changed since the proof snapshot (fail-closed)."""
    changed: list[str] = []
    for eid, snap in sorted((proof.get("evidence_index") or {}).items()):
        now = verify_stored_evidence(db, tenant_id=tenant_id, evidence_id=eid).value
        if now != (snap or {}).get("provenance_status"):
            changed.append(eid)
    return changed


def release_blockers_now(
    db: Session, *, tenant_id: str, engagement_id: str, report_json: dict[str, Any]
) -> list[str]:
    """Release blockers for a stored report at decision time (delivery / export)."""
    proof = report_json.get("report_proof") if isinstance(report_json, dict) else None
    if not isinstance(proof, dict):
        return ["REPORT_PROOF_MISSING"]
    out = set(proof.get("release_blockers") or [])
    if (
        proof.get("tenant_id") != tenant_id
        or proof.get("engagement_id") != engagement_id
    ):
        out.add("REPORT_PROOF_SCOPE_MISMATCH")
    if recheck_evidence(db, tenant_id=tenant_id, proof=proof):
        out.add("EVIDENCE_CHANGED_SINCE_GENERATION")
    return sorted(out)


def evaluate_report_state(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    report_json: dict[str, Any],
    qa_approved_by: str | None,
    qa_approved_at: str | None,
    qualified: bool,
) -> dict[str, Any]:
    """Authoritative DRAFT / FINAL marking.  No caller-controlled inputs."""
    proof = report_json.get("report_proof") if isinstance(report_json, dict) else None
    blockers = release_blockers_now(
        db, tenant_id=tenant_id, engagement_id=engagement_id, report_json=report_json
    )
    synthetic = bool(isinstance(proof, dict) and proof["synthetic"]["is_synthetic"])
    limited = not (
        isinstance(proof, dict)
        and proof["report_constraints"]["may_claim_full_coverage"]
    )
    if synthetic:
        state, marking = "DRAFT_SYNTHETIC", MARKING_SYNTHETIC
    elif qa_approved_by is None or not qualified or blockers:
        state, marking = "DRAFT", MARKING_DRAFT
    else:
        state = "FINAL"
        marking = MARKING_FINAL_LIMITED if limited else MARKING_FINAL
    return {
        "state": state,
        "marking": marking,
        "is_draft": state != "FINAL",
        "qa_approved": qa_approved_by is not None,
        "qa_approved_by": qa_approved_by,
        "qa_approved_at": qa_approved_at,
        "production_qualified": qualified,
        "release_blockers": blockers,
        "limited_coverage": limited,
    }
