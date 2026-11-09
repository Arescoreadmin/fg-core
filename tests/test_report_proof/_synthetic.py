"""Deterministic synthetic customer engagement for report-proof tests.

L14-SCAN-REPORT-PROOF-001.  Everything here is SYNTHETIC:

* the organization is fictional (``*.example`` / RFC 5737 addresses);
* scanner payloads are persisted through the PRODUCTION bridges — nothing is
  scanned and no network is touched;
* authorization provenance is explicitly SYNTHETIC: the embedded context uses
  proof level ``SYNTHETIC_FIXTURE_NO_CUSTOMER_AUTHORIZATION`` and carries no
  customer receipt — no customer consent is fabricated;
* runtime evidence capture runs through the production adapter
  (``api.field_assessment._c6_capture_runtime_evidence``).

Scenario (14 distinct findings: 2 critical, 3 high, 4 medium, 3 low, 2 info):

* web headers  — PARTIAL scan (one DENIED target); evidence captured → findings
                 on COMPLETE targets are CONFIRMED by integrity-checked evidence;
* DNS / email  — PARTIAL scan (one TIMEOUT domain); evidence capture FAILS
                 (no worker-start authorization context) → findings UNKNOWN,
                 evidence MISSING;
* network      — CANCELLED scan (4 targets not started); evidence captured,
                 then host 203.0.113.12 is altered out of band → INVALID;
* one FAILED scan job (no result) — a coverage gap.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

TENANT = "tenant-synthetic-preview"
CLIENT_NAME = "SYNTHETIC DEMO - Northwind Analytics (NOT A REAL CUSTOMER)"
SIGNING_KEY_HEX = "ab" * 32
SYNTHETIC_PROOF_LEVEL = "SYNTHETIC_FIXTURE_NO_CUSTOMER_AUTHORIZATION"
TAMPERED_HOST = "203.0.113.12"

WEB = [
    (
        "missing_hsts",
        "critical",
        "app.northwind.example",
        "Enable HSTS with max-age >= 31536000 and includeSubDomains.",
    ),
    (
        "missing_csp",
        "critical",
        "portal.northwind.example",
        "Deploy a restrictive Content-Security-Policy; start in report-only mode.",
    ),
    (
        "missing_x_frame",
        "high",
        "app.northwind.example",
        "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    ),
    (
        "weak_referrer_policy",
        "high",
        "portal.northwind.example",
        "Set Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    (
        "missing_permissions_policy",
        "medium",
        "app.northwind.example",
        "Define a Permissions-Policy disabling unused browser features.",
    ),
]
DNS = [
    (
        "missing_dmarc",
        "high",
        "northwind.example",
        "Publish a DMARC record, starting at p=none with reporting, then enforce.",
    ),
    (
        "spf_permissive",
        "medium",
        "northwind.example",
        "Replace +all/?all with -all and enumerate authorized senders.",
    ),
    ("dkim_not_found", "medium", "mail.northwind.example", None),
    (
        "mx_single_provider",
        "low",
        "northwind.example",
        "Consider a secondary MX for delivery resilience.",
    ),
    (
        "dnssec_absent",
        "low",
        "northwind.example",
        "Enable DNSSEC signing at the registrar and DNS provider.",
    ),
]
NET = [
    (
        "network.plain_http_exposed",
        "medium",
        ["203.0.113.10"],
        "Redirect HTTP to HTTPS or close port 80.",
    ),
    (
        "network.legacy_tls",
        "low",
        ["203.0.113.11"],
        "Disable TLS 1.0/1.1 on the listener.",
    ),
    ("network.ai_port_observed", "informational", [TAMPERED_HOST], None),
    (
        "network.service_banner_observed",
        "informational",
        [TAMPERED_HOST],
        "Suppress version banners.",
    ),
]
EXPECTED_SEVERITY = {
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 3,
    "informational": 2,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def synthetic_auth_context(
    *,
    engagement_id: str,
    scanner: str,
    tenant: str = TENANT,
    proof_level: str = SYNTHETIC_PROOF_LEVEL,
) -> dict[str, Any]:
    """Explicitly synthetic provenance — NOT a customer authorization."""
    return {
        "schema": "fg.scan_authorization_context.v1",
        "tenant_id": tenant,
        "engagement_id": engagement_id,
        "scanner_type": scanner,
        "operation": scanner,
        "authorization_id": str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"synthetic:{engagement_id}:{scanner}")
        ),
        "authorization_version": 1,
        "customer_receipt_id": None,
        "consent_status": "SYNTHETIC_NOT_CUSTOMER_APPROVED",
        "proof_level": proof_level,
        "worker_start_authorized_at": "2026-11-08T11:55:00+00:00",
        "execution_checkpoints_passed": 0,
        "execution_denied_targets": [],
        "interrupted": None,
    }


def issue_key(tenant_id: str, *scopes: str, role: str = "analyst") -> str:
    from sqlalchemy.orm import Session

    from api.credential_authority import issue_credential
    from api.db import get_engine
    from api.tenant_rbac import assign_role

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state) VALUES (:t, 'active')"
            ),
            {"t": tenant_id},
        )
    res = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"proof:{uuid.uuid4()}",
        scopes=list(scopes),
    )
    assert res.plaintext_secret is not None
    with Session(engine) as db:
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="proof",
            credential_id=res.record.credential_id,
            role_name=role,
        )
        db.commit()
    return res.plaintext_secret


def create_engagement(client: Any, name: str = CLIENT_NAME) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": name,
            "assessor_id": "synthetic-assessor",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _web_payload(
    eid: str, *, synthetic: bool, tenant: str, proof_level: str
) -> dict[str, Any]:
    return {
        "targets": [
            {
                "url": "https://app.northwind.example",
                "collection_status": "COMPLETE",
                "error": None,
            },
            {
                "url": "https://portal.northwind.example",
                "collection_status": "COMPLETE",
                "error": None,
            },
            {
                "url": "https://legacy.northwind.example",
                "collection_status": "DENIED",
                "error": "target blocked by scanner policy",
                "blocked": True,
            },
        ],
        "findings": [
            {
                "type": t,
                "severity": s,
                "title": f"[SYNTHETIC] {t.replace('_', ' ').title()}",
                "description": f"Synthetic demo observation on {tgt}: the response did not include the expected security header.",
                "target": tgt,
                "remediation": rem,
            }
            for t, s, tgt, rem in WEB
        ],
        "collection_status": "PARTIAL",
        "synthetic": synthetic,
        "authorization_context": synthetic_auth_context(
            engagement_id=eid,
            scanner="web_headers",
            tenant=tenant,
            proof_level=proof_level,
        ),
    }


def seed(
    eid: str,
    *,
    synthetic: bool = True,
    tamper: bool = True,
    failed_job: bool = True,
    tenant: str = TENANT,
    proof_level: str = SYNTHETIC_PROOF_LEVEL,
) -> dict[str, Any]:
    """Persist the scenario.  Returns scan ids and the tampered evidence ids."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding, FaScanJob
    from api.field_assessment import _c6_capture_runtime_evidence
    from services.field_assessment.connectors.dns_email_bridge import (
        import_dns_email_scan,
    )
    from services.field_assessment.connectors.network_scan_bridge import (
        import_network_scan,
    )
    from services.field_assessment.connectors.web_headers_bridge import (
        import_web_headers_scan,
    )

    db = get_sessionmaker()()
    try:
        web = import_web_headers_scan(
            db=db,
            tenant_id=tenant,
            engagement_id=eid,
            actor="synthetic-assessor",
            scan_result=_web_payload(
                eid, synthetic=synthetic, tenant=tenant, proof_level=proof_level
            ),
        )
        dns = import_dns_email_scan(
            db=db,
            tenant_id=tenant,
            engagement_id=eid,
            actor="synthetic-assessor",
            scan_result={
                "domains": [
                    {"domain": "northwind.example", "collection_status": "COMPLETE"},
                    {
                        "domain": "mail.northwind.example",
                        "collection_status": "TIMEOUT",
                    },
                ],
                "findings": [
                    {
                        "type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {t.replace('_', ' ').title()}",
                        "description": f"Synthetic demo observation for {d}.",
                        "domain": d,
                        "remediation": rem,
                    }
                    for t, s, d, rem in DNS
                ],
                "collection_status": "PARTIAL",
                "synthetic": synthetic,
                # No authorization_context: capture must FAIL closed.
            },
        )
        net = import_network_scan(
            db=db,
            tenant_id=tenant,
            engagement_id=eid,
            actor="synthetic-assessor",
            scan_result={
                "scan_completed_at": "2026-11-08T12:00:00Z",
                "collection_status": "CANCELLED",
                "scan_status": "interrupted",
                "interrupted": {
                    "reason_code": "JOB_CANCELLED",
                    "phase": "target",
                    "remaining_targets_not_started": 4,
                },
                "hosts": [
                    {"host": h, "open_ports": [80], "tls": {}}
                    for h in ("203.0.113.10", "203.0.113.11", TAMPERED_HOST)
                ],
                "findings": [
                    {
                        "finding_type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {t.split('.')[-1].replace('_', ' ').title()}",
                        "description": "Synthetic demo observation.",
                        "control_id": "NIST-AI-RMF-MANAGE-2.2",
                        "affected_hosts": hosts,
                        "remediation": rem,
                    }
                    for t, s, hosts, rem in NET
                ],
                "synthetic": synthetic,
                "authorization_context": synthetic_auth_context(
                    engagement_id=eid,
                    scanner="network_scan",
                    tenant=tenant,
                    proof_level=proof_level,
                ),
            },
        )
        db.commit()
        ids = {
            "web": web.scan_result_id,
            "dns": dns.scan_result_id,
            "network": net.scan_result_id,
        }
        # Bridges may not carry remediation; record the synthetic guidance on
        # the canonical column (dkim + ai_port deliberately have none).
        rem_by_title = {
            f"[SYNTHETIC] {t.replace('_', ' ').title()}": r for t, _, _, r in WEB + DNS
        } | {
            f"[SYNTHETIC] {t.split('.')[-1].replace('_', ' ').title()}": r
            for t, _, _, r in NET
        }
        for f in db.query(FaNormalizedFinding).filter_by(
            tenant_id=tenant, engagement_id=eid
        ):
            if not f.remediation_hint and rem_by_title.get(f.title):
                f.remediation_hint = rem_by_title[f.title]
        db.commit()
        for scanner, sr in (
            ("web_headers", ids["web"]),
            ("dns_email", ids["dns"]),
            ("network_scan", ids["network"]),
        ):
            _c6_capture_runtime_evidence(
                db,
                tenant_id=tenant,
                engagement_id=eid,
                scan_result_id=sr,
                scanner_type=scanner,
                scan_job_id=None,
                actor="synthetic-assessor",
            )
            db.commit()
        if failed_job:
            db.add(
                FaScanJob(
                    id=uuid.uuid4().hex[:32],
                    tenant_id=tenant,
                    engagement_id=eid,
                    verified_target_ids="[]",
                    scanner_type="web_headers",
                    status="failed",
                    failure_reason="SYNTHETIC: worker failed before producing a result",
                    actor="synthetic-assessor",
                    created_at=now_iso(),
                )
            )
            db.commit()
    finally:
        db.close()
    if tamper:
        tamper_host(ids["network"])
    return ids


def tamper_host(scan_result_id: str, host: str = TAMPERED_HOST) -> None:
    """Out-of-band edit of stored evidence (the attack the proof must detect)."""
    from api.db import get_engine

    with get_engine().begin() as conn:
        raw = conn.execute(
            text("SELECT raw_payload FROM fa_scan_results WHERE id = :i"),
            {"i": scan_result_id},
        ).scalar_one()
        payload = json.loads(raw) if isinstance(raw, str) else raw
        for h in payload["hosts"]:
            if h["host"] == host:
                h["open_ports"] = [80, 443, 8443]
        conn.execute(
            text("UPDATE fa_scan_results SET raw_payload = :p WHERE id = :i"),
            {"p": json.dumps(payload), "i": scan_result_id},
        )


def generate_report(client: Any, eid: str) -> dict[str, Any]:
    rep = client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert rep.status_code == 201, rep.text
    return rep.json()


def export(client: Any, eid: str, version: int, fmt: str) -> Any:
    return client.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": fmt},
    )


def persisted_findings(eid: str, tenant: str = TENANT) -> list[Any]:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding

    db = get_sessionmaker()()
    try:
        rows = (
            db.query(FaNormalizedFinding)
            .filter_by(tenant_id=tenant, engagement_id=eid)
            .all()
        )
        db.expunge_all()
        return rows
    finally:
        db.close()


def persisted_scan_id(eid: str, source_type: str, tenant: str = TENANT) -> str:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaScanResult

    db = get_sessionmaker()()
    try:
        return (
            db.query(FaScanResult.id)
            .filter_by(tenant_id=tenant, engagement_id=eid, source_type=source_type)
            .scalar()
        )
    finally:
        db.close()


_SEVERITIES = ("critical", "high", "medium", "low", "informational")


def seed_bulk_findings(eid: str, count: int, tenant: str = TENANT) -> None:
    """Dense synthetic register: long titles, verbose text, long asset ids."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding

    db = get_sessionmaker()()
    try:
        for i in range(count):
            db.add(
                FaNormalizedFinding(
                    id=f"bulk{i:05d}{uuid.uuid4().hex[:7]}",
                    tenant_id=tenant,
                    engagement_id=eid,
                    finding_type="manual.synthetic_bulk",
                    findings_hash=uuid.uuid4().hex,
                    severity=_SEVERITIES[i % 5],
                    title=f"[SYNTHETIC] Bulk finding {i} with a deliberately long title "
                    "that exercises wrapping in the severity header bar",
                    description=(
                        "Synthetic verbose description sentence. "
                        * (40 if i % 7 == 0 else 3)
                    ).strip(),
                    source_attribution="manual",
                    asset_id=("asset-" + "x" * 50)[:64],
                    remediation_hint="Synthetic remediation guidance. " * 4,
                    created_at=now_iso(),
                    updated_at=now_iso(),
                )
            )
        db.commit()
    finally:
        db.close()


def pdf_layout_checks(pdf_bytes: bytes, *, marking: str) -> dict[str, Any]:
    """Per-page layout facts from the PDF itself (pypdf text positions).

    marking on every page; "Page i of N" on page i; footer present; no body
    text inside the footer band; no horizontal overlap between footer items on
    the same line (widths measured with reportlab's Helvetica 7pt metrics).
    """
    import io
    import re

    import pypdf
    from reportlab.pdfbase.pdfmetrics import stringWidth

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    n = len(reader.pages)
    footer_top = 0.66 * 72
    pages: list[dict[str, Any]] = []
    for i, page in enumerate(reader.pages, start=1):
        items: list[tuple[float, float, str]] = []

        def visit(text, cm, tm, _font, _size, _items=items):
            if text.strip():
                _items.append((tm[4] * cm[0] + cm[4], tm[5] * cm[3] + cm[5], text))

        flat = re.sub(r"\s+", " ", page.extract_text(visitor_text=visit) or "")
        footer = [it for it in items if it[1] < footer_top]
        intrusions = [it for it in items if footer_top <= it[1] < 1.2 * 72]
        overlaps = []
        rows: dict[int, list[tuple[float, float, str]]] = {}
        for it in footer:
            rows.setdefault(round(it[1]), []).append(it)
        for row in rows.values():
            row.sort()
            for a, b in zip(row, row[1:]):
                if a[0] + stringWidth(a[2], "Helvetica", 7) > b[0] + 0.5:
                    overlaps.append([a[2], b[2]])
        pages.append(
            {
                "page": i,
                "marking": marking in flat,
                "page_x_of_y": f"Page {i} of {n}" in flat,
                "footer_lines": len(rows),
                "body_in_footer_band": len(intrusions),
                "footer_overlaps": overlaps,
            }
        )
    return {
        "pages": n,
        "per_page": pages,
        "all_ok": all(
            p["marking"]
            and p["page_x_of_y"]
            and p["footer_lines"] == 2
            and not p["body_in_footer_band"]
            and not p["footer_overlaps"]
            for p in pages
        ),
    }
