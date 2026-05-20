"""Verified Microsoft Graph import bridge for Field Assessment.

The bridge implements the "trust but verify" boundary between connector output
and governance state. It accepts the export-safe Microsoft Graph ScanResult
contract, verifies tenant lock, operator acknowledgment, and manifest integrity,
then converts the scan into Field Assessment primitives.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from api.db_models_field_assessment import FaEvidenceLink, FaScanResult
from api.db_models_governance_report import GovernanceReportRecord
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.connectors.msgraph.acknowledgment import verify_receipt
from services.connectors.msgraph.findings.derivation import hash_tenant_id
from services.connectors.msgraph.integrity import build_content_hashes, verify_manifest
from services.connectors.msgraph.manifest import (
    AcknowledgmentVerificationError,
    SCHEMA_VERSION as MSGRAPH_SCHEMA_VERSION,
)
from services.connectors.msgraph.schema.integrity import SignedManifest
from services.connectors.msgraph.report import generate_report, report_to_json
from services.connectors.msgraph.schema.scan_result import Finding, ScanResult
from services.field_assessment.audit import emit_engagement_audit_event
from services.field_assessment.models import EvidenceLinkDuplicate
from services.field_assessment.store import (
    create_evidence_link,
    create_finding,
    create_scan_result,
)

BRIDGE_VERSION = "field-assessment-msgraph-bridge-v1"
CONNECTOR_TYPE = "microsoft_graph"


class ConnectorBridgeError(Exception):
    code = "CONNECTOR_IMPORT_FAILED"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ConnectorTenantMismatch(ConnectorBridgeError):
    code = "CONNECTOR_TENANT_MISMATCH"


class ConnectorManifestUnverified(ConnectorBridgeError):
    code = "CONNECTOR_MANIFEST_UNVERIFIED"


class ConnectorSchemaUnsupported(ConnectorBridgeError):
    code = "CONNECTOR_SCHEMA_UNSUPPORTED"


class ConnectorAcknowledgmentRequired(ConnectorBridgeError):
    code = "CONNECTOR_ACK_REQUIRED"


class ConnectorExportUnsafe(ConnectorBridgeError):
    code = "CONNECTOR_EXPORT_UNSAFE"


class ConnectorImportEnvelope(BaseModel):
    """Stable verified import envelope for connector-to-field-assessment bridges."""

    model_config = ConfigDict(extra="forbid")

    connector_type: Literal["microsoft_graph"]
    connector_run_id: str = Field(..., min_length=1)
    connector_manifest_hash: str | None = None
    import_review_status: Literal["imported", "needs_review", "reviewed"] = "imported"
    scan_result: dict[str, Any]


@dataclass(frozen=True)
class ConnectorImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    connector_run_id: str
    connector_import_id: str
    manifest_hash: str
    integrity_hash: str
    verification_status: str
    verification_checks: list[str]
    findings_imported: int
    evidence_links_imported: int
    asset_candidates_detected: int
    import_status: str
    report_id: str | None = None
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_msgraph_scan_result(
    *,
    db: Any,
    tenant_id: str,
    engagement_id: str,
    envelope: ConnectorImportEnvelope,
    actor: str,
) -> ConnectorImportResult:
    scan = ScanResult.model_validate(envelope.scan_result)
    if envelope.connector_run_id != scan.scan_id:
        raise ConnectorExportUnsafe("connector_run_id must match scan_result.scan_id")
    if scan.schema_version != MSGRAPH_SCHEMA_VERSION:
        raise ConnectorSchemaUnsupported(
            f"unsupported Microsoft Graph schema_version {scan.schema_version!r}"
        )
    if scan.engagement_id != engagement_id:
        raise ConnectorTenantMismatch("connector scan engagement does not match route")
    if scan.tenant_id_hash != hash_tenant_id(tenant_id):
        raise ConnectorTenantMismatch("connector tenant lock does not match caller")

    _verify_acknowledgment(scan)
    manifest = _verified_manifest(scan)
    _verify_manifest_content(scan, manifest)
    manifest_hash = _sha256(scan.integrity_manifest)
    integrity_hash = _sha256(scan.model_dump(mode="json"))
    if (
        envelope.connector_manifest_hash
        and envelope.connector_manifest_hash != manifest_hash
    ):
        raise ConnectorManifestUnverified("connector manifest hash mismatch")

    connector_import_id = _derive_import_id(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        connector_run_id=scan.scan_id,
        manifest_hash=manifest_hash,
    )
    _audit(
        db,
        tenant_id,
        engagement_id,
        actor,
        "connector.msgraph.import_requested",
        "CONNECTOR_IMPORT_REQUESTED",
        {
            "connector_type": CONNECTOR_TYPE,
            "connector_run_id": scan.scan_id,
            "connector_import_id": connector_import_id,
            "manifest_hash": manifest_hash,
        },
    )

    normalized_payload = _normalized_payload(
        scan=scan,
        manifest=manifest,
        manifest_hash=manifest_hash,
        integrity_hash=integrity_hash,
        connector_import_id=connector_import_id,
        import_review_status=envelope.import_review_status,
    )
    raw_payload = _export_safe_payload(
        scan=scan,
        manifest_hash=manifest_hash,
        integrity_hash=integrity_hash,
        connector_import_id=connector_import_id,
    )
    existing_scan = _existing_scan(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_hash=manifest_hash,
    )
    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=scan.schema_version,
        collected_at=scan.scan_completed_at,
        raw_payload=raw_payload,
        normalized_payload=normalized_payload,
        object_count=_object_count(scan),
        evidence_hash=manifest_hash,
    )
    import_status = "replayed" if existing_scan is not None else "completed"

    _audit(
        db,
        tenant_id,
        engagement_id,
        actor,
        "connector.msgraph.manifest_verified",
        "CONNECTOR_MANIFEST_VERIFIED",
        {
            "connector_type": CONNECTOR_TYPE,
            "connector_run_id": scan.scan_id,
            "connector_import_id": connector_import_id,
            "manifest_hash": manifest_hash,
            "integrity_hash": integrity_hash,
            "verification_checks": _verification_checks(),
        },
    )

    findings = _import_findings(
        db=db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_record_id=scan_record.id,
        scan=scan,
        manifest_hash=manifest_hash,
        connector_import_id=connector_import_id,
    )
    links_imported = _link_findings_to_scan(
        db=db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_record_id=scan_record.id,
        findings=findings,
        scan=scan,
        manifest_hash=manifest_hash,
        connector_import_id=connector_import_id,
    )

    report_id = _store_report(
        db=db,
        tenant_id=tenant_id,
        scan=scan,
        scan_result_id=scan_record.id,
    )

    _audit(
        db,
        tenant_id,
        engagement_id,
        actor,
        "connector.msgraph.import_completed",
        "CONNECTOR_IMPORT_COMPLETED",
        {
            "connector_type": CONNECTOR_TYPE,
            "connector_run_id": scan.scan_id,
            "connector_import_id": connector_import_id,
            "scan_result_id": scan_record.id,
            "manifest_hash": manifest_hash,
            "findings_imported": len(findings),
            "evidence_links_imported": links_imported,
            "asset_candidates_detected": len(normalized_payload["asset_candidates"]),
            "import_status": import_status,
            "report_id": report_id,
        },
    )
    return ConnectorImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        connector_run_id=scan.scan_id,
        connector_import_id=connector_import_id,
        manifest_hash=manifest_hash,
        integrity_hash=integrity_hash,
        verification_status="verified",
        verification_checks=_verification_checks(),
        findings_imported=len(findings),
        evidence_links_imported=links_imported,
        asset_candidates_detected=len(normalized_payload["asset_candidates"]),
        import_status=import_status,
        report_id=report_id,
    )


def _store_report(
    *,
    db: Any,
    tenant_id: str,
    scan: ScanResult,
    scan_result_id: str,
) -> str | None:
    """Generate and persist a governance report for a verified scan.

    Best-effort: if generation or storage fails, the error is swallowed so the
    import itself always succeeds. The caller logs the report_id on success.
    """
    try:
        report = generate_report(scan=scan, scan_result_id=scan_result_id)
        record = GovernanceReportRecord(
            id=report.report_id,
            assessment_id=scan_result_id,
            tenant_id=tenant_id,
            version=1,
            schema_version=report.schema_version,
            manifest_hash=report.manifest_hash,
            report_json=report_to_json(report),
            generated_at=report.generated_at,
            is_finalized=False,
        )
        db.add(record)
        return report.report_id
    except Exception:  # noqa: BLE001
        return None


def _verify_acknowledgment(scan: ScanResult) -> None:
    try:
        verify_receipt(scan.operator_acknowledgment_receipt)
    except AcknowledgmentVerificationError as exc:
        raise ConnectorAcknowledgmentRequired(str(exc)) from exc


def _verified_manifest(scan: ScanResult) -> SignedManifest:
    manifest = SignedManifest.model_validate(scan.integrity_manifest)
    if not verify_manifest(manifest):
        raise ConnectorManifestUnverified("Microsoft Graph manifest HMAC failed")
    return manifest


def _verify_manifest_content(scan: ScanResult, manifest: SignedManifest) -> None:
    expected = build_content_hashes(
        findings=list(scan.findings),
        evidence_refs=list(scan.evidence_references),
        analyzer_outputs=dict(scan.analyzer_outputs),
    )
    if not manifest.content_hashes:
        raise ConnectorManifestUnverified(
            "Microsoft Graph manifest is missing signed content hashes"
        )
    if manifest.content_hashes != expected:
        raise ConnectorManifestUnverified(
            "Microsoft Graph signed content hashes do not match scan content"
        )


def _normalized_payload(
    *,
    scan: ScanResult,
    manifest: SignedManifest,
    manifest_hash: str,
    integrity_hash: str,
    connector_import_id: str,
    import_review_status: str,
) -> dict[str, Any]:
    analyzer_outputs = _safe_analyzer_outputs(scan)
    return {
        "connector_type": CONNECTOR_TYPE,
        "connector_run_id": scan.scan_id,
        "connector_import_id": connector_import_id,
        "bridge_version": BRIDGE_VERSION,
        "schema_version": scan.schema_version,
        "scan_status": scan.scan_status,
        "manifest": {
            "manifest_id": manifest.manifest_id,
            "manifest_hash": manifest_hash,
            "integrity_hash": integrity_hash,
            "signed_at": manifest.signed_at,
            "endpoints_called": sorted(manifest.endpoints_called),
            "record_counts": {
                k: manifest.record_counts[k] for k in sorted(manifest.record_counts)
            },
        },
        "verification": {
            "verification_status": "verified",
            "verification_checks": _verification_checks(),
            "verified_at": utc_iso8601_z_now(),
            "verification_hash": _sha256(
                {
                    "manifest_hash": manifest_hash,
                    "integrity_hash": integrity_hash,
                    "connector_import_id": connector_import_id,
                }
            ),
        },
        "review": {
            "import_review_status": import_review_status,
            "connector_findings_are_deterministic": True,
            "human_final_report_review_required": True,
        },
        "replay_inputs": {
            "connector_run_id": scan.scan_id,
            "manifest_hash": manifest_hash,
            "schema_version": scan.schema_version,
            "bridge_version": BRIDGE_VERSION,
            "finding_derivation_version": "msgraph-finding-derivation-v1",
        },
        "summary": _summary(scan, analyzer_outputs),
        "asset_candidates": _asset_candidates(scan, analyzer_outputs, manifest_hash),
    }


def _export_safe_payload(
    *,
    scan: ScanResult,
    manifest_hash: str,
    integrity_hash: str,
    connector_import_id: str,
) -> dict[str, Any]:
    return {
        "connector_type": CONNECTOR_TYPE,
        "connector_run_id": scan.scan_id,
        "connector_import_id": connector_import_id,
        "manifest_hash": manifest_hash,
        "integrity_hash": integrity_hash,
        "scan_status": scan.scan_status,
        "scan_completed_at": scan.scan_completed_at,
        "finding_count": len(scan.findings),
        "evidence_reference_count": len(scan.evidence_references),
        "schema_version": scan.schema_version,
        "export_safe": True,
    }


def _summary(scan: ScanResult, outputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_count": len(scan.findings),
        "evidence_reference_count": len(scan.evidence_references),
        "endpoint_count": len(scan.endpoints_called),
        "object_count": _object_count(scan),
        "mfa": outputs.get("mfa_coverage", {}),
        "conditional_access": outputs.get("conditional_access", {}),
        "enterprise_apps": outputs.get("enterprise_apps", {}),
        "oauth_consent": outputs.get("oauth_consent", {}),
        "ai_signals": outputs.get("ai_signals", {}),
        "guest_exposure": outputs.get("guest_exposure", {}),
        "privileged_roles": outputs.get("privileged_roles", {}),
        "dlp_exposure": {
            "critical_count": outputs.get("dlp_exposure", {}).get("critical_count", 0),
            "high_count": outputs.get("dlp_exposure", {}).get("high_count", 0),
            "medium_count": outputs.get("dlp_exposure", {}).get("medium_count", 0),
        },
    }


def _asset_candidates(
    scan: ScanResult,
    outputs: dict[str, Any],
    manifest_hash: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def add(kind: str, risk_signal: str, count: int, confidence: int) -> None:
        if count <= 0:
            return
        source_ref = f"{kind}:{risk_signal}:{count}:{manifest_hash[:16]}"
        candidates.append(
            {
                "candidate_id": hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[
                    :24
                ],
                "candidate_type": kind,
                "source": CONNECTOR_TYPE,
                "source_ref": source_ref,
                "risk_signal": risk_signal,
                "confidence": confidence,
                "evidence_refs": [ref.ref_id for ref in scan.evidence_references],
                "recommended_action": "review_for_asset_registry",
                "promotion_state": "candidate_only",
            }
        )

    enterprise = outputs.get("enterprise_apps", {})
    oauth = outputs.get("oauth_consent", {})
    ai = outputs.get("ai_signals", {})
    roles = outputs.get("privileged_roles", {})
    guest = outputs.get("guest_exposure", {})
    dlp = outputs.get("dlp_exposure", {})

    add(
        "enterprise_application",
        "unverified_high_privilege",
        int(enterprise.get("unverified_publisher_high_priv", 0)),
        88,
    )
    add(
        "enterprise_application",
        "new_application_review",
        int(enterprise.get("new_apps_30d", 0)),
        75,
    )
    add(
        "oauth_application",
        "critical_risky_scopes",
        int(oauth.get("score_3_critical", 0)),
        92,
    )
    add("oauth_application", "high_risky_scopes", int(oauth.get("score_2_high", 0)), 85)
    add("ai_application", "shadow_ai", int(ai.get("shadow_ai_apps", 0)), 90)
    add("ai_application", "unapproved_ai", int(ai.get("unapproved_ai_apps", 0)), 87)
    add(
        "privileged_role",
        "permanent_assignment",
        int(roles.get("permanent_assignments", 0)),
        84,
    )
    add(
        "guest_identity",
        "privileged_guest_exposure",
        int(guest.get("privileged_role_guests", 0)),
        86,
    )
    add("dlp_exposure", "critical_dlp_profile", int(dlp.get("critical_count", 0)), 89)
    return sorted(
        candidates,
        key=lambda item: (
            item["candidate_type"],
            item["risk_signal"],
            item["candidate_id"],
        ),
    )


def _import_findings(
    *,
    db: Any,
    tenant_id: str,
    engagement_id: str,
    scan_record_id: str,
    scan: ScanResult,
    manifest_hash: str,
    connector_import_id: str,
) -> list[Any]:
    imported: list[Any] = []
    for item in sorted(scan.findings, key=lambda finding: finding.finding_id):
        imported.append(
            create_finding(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                finding_type=f"msgraph.{item.control_id}",
                source_ref=f"{scan.scan_id}:{item.finding_id}:{manifest_hash}",
                severity=_severity(item),
                title=item.title,
                description=item.evidence_summary,
                source_attribution=f"microsoft_graph:{connector_import_id}",
                confidence_score=_confidence(scan, item),
                framework_mappings=_framework_mappings(item),
                nist_ai_rmf_mappings=_nist_mappings(item),
                evidence_ref_ids=[scan_record_id, *list(item.evidence_refs)],
                remediation_hint=item.recommendation,
            )
        )
    return imported


def _link_findings_to_scan(
    *,
    db: Any,
    tenant_id: str,
    engagement_id: str,
    scan_record_id: str,
    findings: list[Any],
    scan: ScanResult,
    manifest_hash: str,
    connector_import_id: str,
) -> int:
    imported = 0
    source_by_title = {finding.title: finding for finding in scan.findings}
    for finding in findings:
        if _link_exists(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_id=finding.id,
            evidence_entity_id=scan_record_id,
        ):
            continue
        original = source_by_title.get(finding.title)
        metadata = {
            "connector_type": CONNECTOR_TYPE,
            "connector_run_id": scan.scan_id,
            "connector_import_id": connector_import_id,
            "manifest_hash": manifest_hash,
            "bridge_version": BRIDGE_VERSION,
            "evidence_refs": list(original.evidence_refs) if original else [],
            "replay_safe": True,
        }
        try:
            create_evidence_link(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                source_entity_type="finding",
                source_entity_id=finding.id,
                evidence_entity_type="scan_result",
                evidence_entity_id=scan_record_id,
                link_metadata=metadata,
            )
            imported += 1
        except EvidenceLinkDuplicate:
            continue
    return imported


def _existing_scan(
    db: Any, *, tenant_id: str, engagement_id: str, evidence_hash: str
) -> Any | None:
    return db.execute(
        select(FaScanResult).where(
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
            FaScanResult.evidence_hash == evidence_hash,
        )
    ).scalar_one_or_none()


def _link_exists(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    source_entity_id: str,
    evidence_entity_id: str,
) -> bool:
    return (
        db.execute(
            select(FaEvidenceLink.id).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "finding",
                FaEvidenceLink.source_entity_id == source_entity_id,
                FaEvidenceLink.evidence_entity_type == "scan_result",
                FaEvidenceLink.evidence_entity_id == evidence_entity_id,
            )
        ).scalar_one_or_none()
        is not None
    )


def _audit(
    db: Any,
    tenant_id: str,
    engagement_id: str,
    actor: str,
    event_type: str,
    reason_code: str,
    payload: dict[str, Any],
) -> None:
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type=event_type,
        actor=actor,
        reason_code=reason_code,
        payload=payload,
    )


def _safe_analyzer_outputs(scan: ScanResult) -> dict[str, Any]:
    payload = dict(scan.analyzer_outputs or {})
    payload.pop("profiles", None)
    if isinstance(payload.get("dlp_exposure"), dict):
        payload["dlp_exposure"] = {
            key: value
            for key, value in payload["dlp_exposure"].items()
            if key != "profiles"
        }
    return payload


def _verification_checks() -> list[str]:
    return [
        "tenant_lock_matched",
        "manifest_hash_verified",
        "schema_version_allowed",
        "integrity_hash_verified",
        "operator_acknowledged",
        "export_safe_contract_verified",
    ]


def _derive_import_id(
    *,
    tenant_id: str,
    engagement_id: str,
    connector_run_id: str,
    manifest_hash: str,
) -> str:
    raw = f"{tenant_id}|{engagement_id}|{CONNECTOR_TYPE}|{connector_run_id}|{manifest_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _object_count(scan: ScanResult) -> int:
    return sum(ref.record_count for ref in scan.evidence_references)


def _severity(finding: Finding) -> str:
    return "info" if finding.severity == "informational" else finding.severity


def _confidence(scan: ScanResult, finding: Finding) -> int:
    base = 88 if scan.scan_status == "completed" else 72
    if finding.severity in {"critical", "high"}:
        base += 4
    if not finding.evidence_refs:
        base -= 15
    return max(0, min(100, base))


def _framework_mappings(finding: Finding) -> list[dict[str, str]]:
    return [
        {
            "framework": ref,
            "control_id": finding.control_id,
            "source": CONNECTOR_TYPE,
        }
        for ref in sorted(finding.framework_refs)
    ]


def _nist_mappings(finding: Finding) -> list[dict[str, str]]:
    if "NIST-AI-RMF" not in finding.framework_refs:
        return []
    parts = finding.control_id.split("NIST-AI-RMF-", 1)
    category = parts[1] if len(parts) == 2 else finding.control_id
    function = category.split("-", 1)[0] if "-" in category else "GOVERN"
    return [
        {
            "function": function,
            "category": category,
            "description": finding.title,
        }
    ]
