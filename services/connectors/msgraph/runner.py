"""Full scan orchestrator — Step 19.

Entry point for a complete Microsoft Graph field assessment scan.
Coordinates credential acquisition, tenant lock, all analyzers,
DLP cross-scoring, manifest signing, and ScanResult assembly.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.acknowledgment import verify_receipt
from services.connectors.msgraph.analyzers import (
    ai_signals,
    conditional_access,
    dlp_scoring,
    enterprise_apps,
    guest_exposure,
    mfa,
    oauth_consent,
    privileged_roles,
)
from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.credential import CredentialContext
from services.connectors.msgraph.export import build_scan_result
from services.connectors.msgraph.integrity import build_manifest
from services.connectors.msgraph.manifest import (
    AUTHORIZED_SCOPES,
    SCAN_TOTAL_TIMEOUT_SECONDS,
    ScanTimeoutError,
)
from services.connectors.msgraph.schema.analyzer_outputs import AnalyzerOutputs
from services.connectors.msgraph.schema.scan_result import (
    AcknowledgmentReceipt,
    EvidenceRef,
    Finding,
    ScanResult,
)
from services.connectors.msgraph.tenant import TenantLock

log = logging.getLogger("frostgate.connectors.msgraph.runner")


def run_scan(
    *,
    tenant_id: str,
    engagement_id: str,
    receipt: AcknowledgmentReceipt,
    baseline_scan_id: str | None = None,
    baseline_finding_ids: set[str] | None = None,
    _test_token: str | None = None,
) -> ScanResult:
    """Execute a full Graph field assessment scan.

    Args:
        tenant_id: The Azure AD tenant ID to scan.
        engagement_id: Engagement UUID linking this scan to an assessment record.
        receipt: Pre-verified operator acknowledgment receipt.
        baseline_scan_id: Optional prior scan ID for delta comparison.
        baseline_finding_ids: Set of finding_ids from the baseline scan.
        _test_token: Inject a mock token in test environments (skips MSAL).

    Returns:
        ScanResult with all findings, evidence refs, and signed manifest.

    Raises:
        AcknowledgmentVerificationError: If receipt HMAC is invalid.
        ScanTimeoutError: If the scan exceeds SCAN_TOTAL_TIMEOUT_SECONDS.
    """
    verify_receipt(receipt)  # raises AcknowledgmentVerificationError on failure

    scan_initiated_at = datetime.now(timezone.utc).isoformat()
    scan_deadline = time.monotonic() + SCAN_TOTAL_TIMEOUT_SECONDS

    all_findings: list[Finding] = []
    all_evidence: list[EvidenceRef] = []
    scan_status = "completed"

    with CredentialContext(tenant_id=tenant_id, _test_token=_test_token) as cred:
        scopes_in_token = cred.scopes_in_token

        with TenantLock(tenant_id=tenant_id) as lock:
            client = GraphClient(
                access_token=cred.access_token,
                tenant_lock=lock,
                scan_deadline=scan_deadline,
            )

            outputs = AnalyzerOutputs()

            try:
                # Step 9: MFA
                mfa_result, mfa_findings, mfa_evidence = mfa.run(client, tenant_id)
                outputs.mfa_coverage = mfa_result
                all_findings.extend(mfa_findings)
                all_evidence.extend(mfa_evidence)

                # Step 10: Conditional Access
                ca_result, ca_findings, ca_evidence = conditional_access.run(
                    client, tenant_id
                )
                outputs.conditional_access = ca_result
                all_findings.extend(ca_findings)
                all_evidence.extend(ca_evidence)

                # Step 11: Enterprise Apps
                app_result, app_findings, app_evidence = enterprise_apps.run(
                    client, tenant_id
                )
                outputs.enterprise_apps = app_result
                all_findings.extend(app_findings)
                all_evidence.extend(app_evidence)

                # Step 12: OAuth Consent
                oauth_result, oauth_findings, oauth_evidence = oauth_consent.run(
                    client, tenant_id
                )
                outputs.oauth_consent = oauth_result
                all_findings.extend(oauth_findings)
                all_evidence.extend(oauth_evidence)

                # Step 13: AI Signals
                ai_result, ai_findings, ai_evidence = ai_signals.run(client, tenant_id)
                outputs.ai_signals = ai_result
                all_findings.extend(ai_findings)
                all_evidence.extend(ai_evidence)

                # Step 14: Guest Exposure
                guest_result, guest_findings, guest_evidence = guest_exposure.run(
                    client, tenant_id
                )
                outputs.guest_exposure = guest_result
                all_findings.extend(guest_findings)
                all_evidence.extend(guest_evidence)

                # Step 15: Privileged Roles
                priv_result, priv_findings, priv_evidence = privileged_roles.run(
                    client, tenant_id
                )
                outputs.privileged_roles = priv_result
                all_findings.extend(priv_findings)
                all_evidence.extend(priv_evidence)

            except ScanTimeoutError:
                log.warning("runner: scan timeout — assembling partial result")
                scan_status = "timeout"

            except Exception as exc:
                log.error("runner: unhandled analyzer error — %s", exc)
                scan_status = "error"

            # Step 16: DLP cross-scoring (runs on accumulated grant data — best-effort)
            try:
                grants_raw = client.get_all(
                    "/oauth2PermissionGrants",
                    params={"$select": "clientId,consentType,scope"},
                )
                sp_ids = {
                    g.get("clientId", "") for g in grants_raw if g.get("clientId")
                }
                sp_map: dict[str, Any] = {}
                for sid in sp_ids:
                    try:
                        sp_map[sid] = client.get_one(
                            f"/servicePrincipals/{sid}?$select=id,appId,verifiedPublisher"
                        )
                    except Exception:
                        sp_map[sid] = {}

                import json as _json
                from pathlib import Path

                _vendor_db = (
                    Path(__file__).parent / "vendor_db" / "approved_vendors.json"
                )
                try:
                    approved_ids = set(
                        _json.loads(_vendor_db.read_text()).get("approved_app_ids", [])
                    )
                except Exception:
                    approved_ids = set()

                dlp_result = dlp_scoring.score_grants(grants_raw, sp_map, approved_ids)
                outputs.dlp_exposure = dlp_result
            except Exception as exc:
                log.warning("runner: DLP scoring failed — %s", exc)

            # Step 17: Signed manifest
            manifest = build_manifest(client)
            pages_fetched = client.pages_fetched
            endpoints_called = client.endpoints_called

    # Step 18: Assemble ScanResult
    return build_scan_result(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        receipt=receipt,
        scopes_authorized=list(AUTHORIZED_SCOPES),
        scopes_in_token=scopes_in_token,
        pages_fetched=pages_fetched,
        endpoints_called=endpoints_called,
        scan_initiated_at=scan_initiated_at,
        all_findings=all_findings,
        all_evidence=all_evidence,
        analyzer_outputs=outputs,
        manifest=manifest,
        baseline_scan_id=baseline_scan_id,
        baseline_finding_ids=baseline_finding_ids,
        scan_status=scan_status,
    )
