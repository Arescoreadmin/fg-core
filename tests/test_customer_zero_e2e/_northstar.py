"""Northstar Manufacturing Group — deterministic SYNTHETIC customer-zero fixture.

L14-CUSTOMER-ZERO-E2E-001.  Everything here is fictional:

* organization, people and hostnames are invented; domains use ``.example``
  (RFC 2606) and addresses use RFC 5737 documentation ranges — nothing is
  ever probed or contacted;
* scanner payloads are persisted through the PRODUCTION bridges and the
  production runtime-evidence adapter; no scanner runs, no network I/O;
* authorization provenance on target-scanner payloads is explicitly
  ``SYNTHETIC_FIXTURE_NO_CUSTOMER_AUTHORIZATION`` — customer consent is never
  fabricated (the real receipt flow is Postgres-only; see
  tests/test_migrations_postgres_replay.py::test_customer_zero_authorization_flow).

Asset representation: the canonical asset authority (``governance_assets``)
models AI/SaaS asset types only, so infrastructure assets (endpoints, servers,
network devices, web apps, domains) exist as scanner observations — the
canonical evidence representation — never in a parallel repository.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

TENANT = "synthetic-northstar-mfg"
OTHER_TENANT = "synthetic-contoso-other"
ORG_NAME = "SYNTHETIC — Northstar Manufacturing Group (NOT A REAL CUSTOMER)"
ENGAGEMENT_MARKER = "customer-zero-e2e-001"
SYNTHETIC_PROOF_LEVEL = "SYNTHETIC_FIXTURE_NO_CUSTOMER_AUTHORIZATION"
SIGNING_KEY_HEX = "cd" * 32
TAMPERED_HOST = "203.0.113.12"

# Persona → canonical tenant_rbac role (→ identity-authority role via
# api.identity_providers.api_key._LEGACY_ROLE_MAP).  No role is invented.
PERSONAS: dict[str, dict[str, str]] = {
    "customer_security_admin": {"role": "tenant_admin", "maps_to": "tenant_admin"},
    "customer_executive": {"role": "read_only", "maps_to": "viewer"},
    "assessor": {"role": "analyst", "maps_to": "assessor"},
    "qa_reviewer": {"role": "auditor", "maps_to": "qa_reviewer"},
    "qualifier": {"role": "governance_admin", "maps_to": "compliance_reviewer"},
    "portal_bff": {"role": "read_only", "maps_to": "viewer"},
}
PERSONA_SCOPES: dict[str, list[str]] = {
    "customer_security_admin": ["governance:read", "governance:write"],
    "customer_executive": ["governance:read"],
    "assessor": ["governance:read", "governance:write"],
    "qa_reviewer": ["governance:read", "governance:qa_approve"],
    "qualifier": ["governance:read", "governance:write"],
    "portal_bff": ["governance:read"],
}

# ── Synthetic environment (fiction) ─────────────────────────────────────────
ENDPOINTS = [f"NSM-WS-{i:03d}" for i in range(1, 16)]  # 15 managed endpoints
SERVERS = {
    "203.0.113.10": "nsm-erp-01 (ERP application server)",
    "203.0.113.11": "nsm-file-01 (file server)",
    "203.0.113.12": "nsm-mes-01 (manufacturing execution server)",
    "203.0.113.13": "nsm-dc-01 (domain controller)",
}
NETWORK_DEVICES = {
    "203.0.113.20": "nsm-fw-01 (perimeter firewall)",
    "203.0.113.21": "nsm-vpn-01 (remote access gateway)",
}
WEB_APPS = [
    ("https://www.northstar-mfg.example", "COMPLETE"),
    ("https://portal.northstar-mfg.example", "COMPLETE"),
    ("https://erp.northstar-mfg.example", "COMPLETE"),
    ("https://mes.northstar-mfg.example", "COMPLETE"),
    ("https://legacy-crm.northstar-mfg.example", "DENIED"),
]
DOMAINS = [
    ("northstar-mfg.example", "COMPLETE"),
    ("mail.northstar-mfg.example", "TIMEOUT"),
]
M365_WORKLOADS = ["Exchange Online", "SharePoint Online"]

# ── Fourteen findings (2 critical, 3 high, 4 medium, 3 low, 2 informational) ─
ENTRA_FINDINGS = [
    (
        "privileged_account_without_mfa",
        "critical",
        "Global administrator account without phishing-resistant MFA",
        "Account it-admin@northstar-mfg.example holds Global Administrator with SMS-only MFA.",
        "Enforce phishing-resistant MFA (FIDO2) for all privileged roles via Conditional Access.",
    ),
    (
        "excessive_cloud_permissions",
        "high",
        "Application granted tenant-wide Mail.ReadWrite",
        "The 'Shop Floor Sync' app registration holds application-level Mail.ReadWrite.",
        "Reduce to delegated, mailbox-scoped permissions and review the app owner.",
    ),
    (
        "unreviewed_external_access",
        "medium",
        "Guest accounts without a recurring access review",
        "41 guest accounts have no access review in the last 180 days.",
        "Create a quarterly access review for guest users and remove stale guests.",
    ),
]
ENDPOINT_FINDINGS = [
    (
        "endpoint.missing_edr",
        "high",
        "Endpoints without active endpoint protection",
        "4 of 15 managed endpoints report no active EDR sensor.",
        "Deploy and enforce the EDR sensor through the device compliance policy.",
    ),
    (
        "endpoint.encryption_evidence_incomplete",
        "medium",
        "Disk encryption status not evidenced for part of the fleet",
        "Intune compliance data was DENIED; encryption could only be confirmed for 9 endpoints.",
        "Grant the assessment read access to Intune compliance or provide BitLocker reports.",
    ),
    (
        "endpoint.stale_inventory",
        "medium",
        "Stale endpoint inventory records",
        "3 devices have not checked in for more than 90 days.",
        "Retire or re-enroll stale devices and set an automatic stale-device policy.",
    ),
    (
        "endpoint.patch_management_incomplete",
        "low",
        "Operating system patch level behind on some endpoints",
        "2 endpoints are more than one feature update behind.",
        "Bring the update ring policy into compliance for all device groups.",
    ),
]
NETWORK_FINDINGS = [
    (
        "network.exposed_admin_service",
        "critical",
        ["203.0.113.10"],
        "Remote administration service exposed to the internet",
        "RDP (3389/tcp) answered on the ERP application server.",
        "Remove public exposure; require VPN plus MFA for administrative access.",
    ),
    (
        "network.unsupported_os",
        "high",
        ["203.0.113.11"],
        "Server running an unsupported operating system",
        "Service banner indicates an end-of-support Windows Server release.",
        "Upgrade or isolate the server; track the exception with an owner and a date.",
    ),
    (
        "network.service_banner_observed",
        "informational",
        [TAMPERED_HOST],
        "Service version banner disclosed",
        "The MES server discloses its web server version in response headers.",
        "Suppress version banners.",
    ),
]
DNS_FINDINGS = [
    (
        "weak_email_authentication",
        "medium",
        "northstar-mfg.example",
        "Weak email authentication policy",
        "DMARC is published with p=none and SPF ends in ?all.",
        "Move DMARC to quarantine/reject after monitoring and end SPF with -all.",
    ),
    (
        "dnssec_absent",
        "low",
        "northstar-mfg.example",
        "DNSSEC not enabled",
        "The corporate domain is not DNSSEC-signed.",
        "Enable DNSSEC at the registrar and DNS host.",
    ),
]
WEB_FINDINGS = [
    (
        "missing_csp",
        "low",
        "https://portal.northstar-mfg.example",
        "Content-Security-Policy header missing",
        "The customer portal does not send a Content-Security-Policy header.",
        "Deploy a restrictive CSP, starting in report-only mode.",
    ),
    (
        "server_header_disclosure",
        "informational",
        "https://www.northstar-mfg.example",
        "Server header discloses technology stack",
        "The public website discloses its server technology in the Server header.",
        None,
    ),
]
EXPECTED_SEVERITY = {
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 3,
    "informational": 2,
}
ALL_COLLECTION_STATES = (
    "COMPLETE",
    "PARTIAL",
    "DENIED",
    "TIMEOUT",
    "FAILED",
    "CANCELLED",
    "UNKNOWN",
    "NOT_ASSESSED",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def synthetic_auth_context(*, engagement_id: str, scanner: str) -> dict[str, Any]:
    """Explicitly synthetic provenance — NOT a customer authorization."""
    return {
        "schema": "fg.scan_authorization_context.v1",
        "tenant_id": TENANT,
        "engagement_id": engagement_id,
        "scanner_type": scanner,
        "operation": scanner,
        "authorization_id": str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"northstar:{engagement_id}:{scanner}")
        ),
        "authorization_version": 1,
        "customer_receipt_id": None,
        "consent_status": "SYNTHETIC_NOT_CUSTOMER_APPROVED",
        "proof_level": SYNTHETIC_PROOF_LEVEL,
        "worker_start_authorized_at": "2026-11-09T08:55:00+00:00",
        "execution_checkpoints_passed": 0,
        "execution_denied_targets": [],
        "interrupted": None,
    }


def _payloads(eid: str) -> dict[str, tuple[str, dict[str, Any]]]:
    """scanner → (bridge scanner id, payload).  Covers all 8 collection states."""
    return {
        "entra_governance": (
            "entra_governance",
            {
                # collection_status deliberately absent → UNKNOWN (never COMPLETE)
                "scan_initiated_at": "2026-11-09T09:00:00Z",
                "role_assignments": [
                    {"role": "Global Administrator", "principal": "it-admin"}
                ],
                "findings": [
                    {
                        "type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {ti}",
                        "description": d,
                        "recommendation": r,
                    }
                    for t, s, ti, d, r in ENTRA_FINDINGS
                ],
                "synthetic": True,
            },
        ),
        "endpoint_inventory": (
            "endpoint_inventory",
            {
                "scan_completed_at": "2026-11-09T09:05:00Z",
                "collection_status": "PARTIAL",
                "intune_collection_status": "DENIED",
                "endpoints": [
                    {"device_name": n, "os": "Windows 11", "managed": True}
                    for n in ENDPOINTS
                ],
                "findings": [
                    {
                        "finding_type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {ti}",
                        "description": d,
                        "recommendation": r,
                    }
                    for t, s, ti, d, r in ENDPOINT_FINDINGS
                ],
                "synthetic": True,
            },
        ),
        "sharepoint_onedrive": (
            "sharepoint_onedrive",
            {
                "scan_completed_at": "2026-11-09T09:06:00Z",
                "collection_status": "NOT_ASSESSED",
                "not_assessed_reason": "Excluded by customer from this assessment window",
                "sites": [],
                "findings": [],
                "synthetic": True,
            },
        ),
        "network_scan": (
            "network_scan",
            {
                "scan_completed_at": "2026-11-09T09:20:00Z",
                "collection_status": "CANCELLED",
                "scan_status": "interrupted",
                "interrupted": {
                    "reason_code": "JOB_CANCELLED",
                    "phase": "target",
                    "remaining_targets_not_started": 3,
                },
                "hosts": [
                    {
                        "host": h,
                        "open_ports": [3389 if h.endswith(".10") else 443],
                        "tls": {},
                    }
                    for h in ("203.0.113.10", "203.0.113.11", TAMPERED_HOST)
                ],
                "findings": [
                    {
                        "finding_type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {ti}",
                        "description": d,
                        "control_id": "NIST-AI-RMF-MANAGE-2.2",
                        "affected_hosts": hosts,
                        "remediation": r,
                    }
                    for t, s, hosts, ti, d, r in NETWORK_FINDINGS
                ],
                "synthetic": True,
                "authorization_context": synthetic_auth_context(
                    engagement_id=eid, scanner="network_scan"
                ),
            },
        ),
        "dns_email": (
            "dns_email",
            {
                "domains": [
                    {"domain": d, "collection_status": st} for d, st in DOMAINS
                ],
                "findings": [
                    {
                        "type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {ti}",
                        "description": de,
                        "domain": d,
                    }
                    for t, s, d, ti, de, _ in DNS_FINDINGS
                ],
                "collection_status": "PARTIAL",
                "synthetic": True,
                # No authorization_context: runtime evidence capture fails closed.
            },
        ),
        "web_headers": (
            "web_headers",
            {
                "targets": [
                    {
                        "url": u,
                        "collection_status": st,
                        "error": None
                        if st == "COMPLETE"
                        else "blocked by scanner policy",
                    }
                    for u, st in WEB_APPS
                ],
                "findings": [
                    {
                        "type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {ti}",
                        "description": d,
                        "target": tgt,
                    }
                    for t, s, tgt, ti, d, _ in WEB_FINDINGS
                ],
                "collection_status": "PARTIAL",
                "synthetic": True,
                "authorization_context": synthetic_auth_context(
                    engagement_id=eid, scanner="web_headers"
                ),
            },
        ),
    }


_REMEDIATION_BY_TITLE = (
    {
        f"[SYNTHETIC] {row[2] if len(row) == 5 else row[3]}": row[-1]
        for row in [*ENTRA_FINDINGS, *ENDPOINT_FINDINGS]
    }
    | {f"[SYNTHETIC] {ti}": r for _, _, _, ti, _, r in NETWORK_FINDINGS}
    | {f"[SYNTHETIC] {ti}": r for _, _, _, ti, _, r in [*DNS_FINDINGS, *WEB_FINDINGS]}
)


def seed_collection(eid: str, *, tamper: bool = True) -> dict[str, str]:
    """Persist all synthetic scans through the production bridges, then run the
    production runtime-evidence adapter for each.  Returns scanner → scan id."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding, FaScanJob
    from api.field_assessment import _c6_capture_runtime_evidence
    from services.field_assessment.connectors import (
        dns_email_bridge,
        endpoint_inventory_bridge,
        entra_governance_bridge,
        network_scan_bridge,
        sharepoint_bridge,
        web_headers_bridge,
    )

    importers = {
        "entra_governance": entra_governance_bridge.import_entra_governance_scan,
        "endpoint_inventory": endpoint_inventory_bridge.import_endpoint_inventory_scan,
        "sharepoint_onedrive": getattr(sharepoint_bridge, "import_sharepoint_scan"),
        "network_scan": network_scan_bridge.import_network_scan,
        "dns_email": dns_email_bridge.import_dns_email_scan,
        "web_headers": web_headers_bridge.import_web_headers_scan,
    }
    from api.db_models_field_assessment import FaScanResult

    ids: dict[str, str] = {}
    db = get_sessionmaker()()
    try:
        # Idempotent: a re-run against the same isolated DB reuses the scans.
        existing = {
            r.source_type: r.id
            for r in db.query(FaScanResult).filter_by(
                tenant_id=TENANT, engagement_id=eid
            )
        }
        if existing:
            return existing
        for name, (scanner, payload) in _payloads(eid).items():
            res = importers[name](
                db=db,
                tenant_id=TENANT,
                engagement_id=eid,
                actor="synthetic-assessor",
                scan_result=payload,
            )
            ids[name] = res.scan_result_id
        db.commit()
        # Canonical remediation column (bridges persist "" when absent).
        for f in db.query(FaNormalizedFinding).filter_by(
            tenant_id=TENANT, engagement_id=eid
        ):
            if not f.remediation_hint and _REMEDIATION_BY_TITLE.get(f.title):
                f.remediation_hint = _REMEDIATION_BY_TITLE[f.title]
        db.commit()
        for name, sr in ids.items():
            _c6_capture_runtime_evidence(
                db,
                tenant_id=TENANT,
                engagement_id=eid,
                scan_result_id=sr,
                scanner_type=_payloads(eid)[name][0],
                scan_job_id=None,
                actor="synthetic-assessor",
            )
            db.commit()
        # A scan job that failed before producing any result (FAILED state).
        db.add(
            FaScanJob(
                id=f"nsm-failed-{eid[:12]}",
                tenant_id=TENANT,
                engagement_id=eid,
                verified_target_ids="[]",
                scanner_type="oauth_inventory",
                status="failed",
                failure_reason="SYNTHETIC: Graph throttling exhausted retries before collection",
                actor="synthetic-assessor",
                created_at=now_iso(),
            )
        )
        db.commit()
    finally:
        db.close()
    if tamper:
        tamper_host(ids["network_scan"])
    return ids


def tamper_host(scan_result_id: str, host: str = TAMPERED_HOST) -> None:
    """Out-of-band edit of stored evidence — the attack evidence proof must catch."""
    from api.db import get_engine

    with get_engine().begin() as conn:
        raw = conn.execute(
            text("SELECT raw_payload FROM fa_scan_results WHERE id = :i"),
            {"i": scan_result_id},
        ).scalar_one()
        payload = json.loads(raw) if isinstance(raw, str) else raw
        for h in payload["hosts"]:
            if h["host"] == host:
                h["open_ports"] = [443, 8443]
        conn.execute(
            text("UPDATE fa_scan_results SET raw_payload = :p WHERE id = :i"),
            {"p": json.dumps(payload), "i": scan_result_id},
        )
