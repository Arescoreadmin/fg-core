"""Synthetic customer report preview through EXISTING infrastructure.

L14-SCAN-RUNNER-INTEGRITY-001 addendum (customer-zero report preview readiness).

Isolated: the conftest ``build_app`` SQLite app, a synthetic tenant and
engagement, synthetic scanner payloads persisted through the SAME bridge
functions the scanner workers call (no scanning, no network), then the real
report routes:  POST /engagements/{id}/reports → GET …/reports/{v}/export?format=pdf.

No authorization is fabricated: no customer receipt exists, so runtime evidence
capture is NOT run and every finding stays unclassified (confidence UNKNOWN).
The preview is DRAFT / SYNTHETIC / NOT VERIFIED; no QA approval or delivery
route is called.

Set FG_REPORT_PREVIEW_OUT=<dir> to keep the generated PDF + JSON for visual QA.
"""

from __future__ import annotations

import io
import json
import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SIGNING_KEY_HEX = "ab" * 32
_TENANT = "tenant-synthetic-preview"
CLIENT_NAME = "SYNTHETIC DEMO - Northwind Analytics (NOT A REAL CUSTOMER)"

# Severity mix required by the preview dataset (demo fixture, not real findings).
_WEB = [
    ("missing_hsts", "critical", "app.northwind.example"),
    ("missing_csp", "critical", "portal.northwind.example"),
    ("missing_x_frame", "high", "app.northwind.example"),
    ("weak_referrer_policy", "high", "portal.northwind.example"),
    ("missing_permissions_policy", "medium", "app.northwind.example"),
]
_DNS = [
    ("missing_dmarc", "high", "northwind.example"),
    ("spf_permissive", "medium", "northwind.example"),
    ("dkim_not_found", "medium", "mail.northwind.example"),
    ("mx_single_provider", "low", "northwind.example"),
    ("dnssec_absent", "low", "northwind.example"),
]
_NET = [
    ("network.plain_http_exposed", "medium", ["203.0.113.10"]),
    ("network.legacy_tls", "low", ["203.0.113.11"]),
    ("network.ai_port_observed", "informational", ["203.0.113.12"]),
    ("network.service_banner_observed", "informational", ["203.0.113.12"]),
]


def _issue_key(tenant_id: str, *scopes: str) -> tuple[str, str]:
    from sqlalchemy import text as sa_text

    from api.credential_authority import issue_credential
    from api.db import get_engine

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            sa_text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state) VALUES (:t, 'active')"
            ),
            {"t": tenant_id},
        )
    res = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"preview:{uuid.uuid4()}",
        scopes=list(scopes),
    )
    assert res.plaintext_secret is not None
    return res.plaintext_secret, res.record.credential_id


def _assign(tenant_id: str, credential_id: str, role: str) -> None:
    from sqlalchemy.orm import Session

    from api.db import get_engine
    from api.tenant_rbac import assign_role

    with Session(get_engine()) as db:
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="preview",
            credential_id=credential_id,
            role_name=role,
        )
        db.commit()


def _seed_findings(engagement_id: str) -> dict[str, str]:
    """Persist synthetic scanner payloads through the production bridges."""
    from api.db import get_sessionmaker
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
            tenant_id=_TENANT,
            engagement_id=engagement_id,
            actor="synthetic-assessor",
            scan_result={
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
                        "description": f"Synthetic demo observation on {tgt}.",
                        "target": tgt,
                    }
                    for t, s, tgt in _WEB
                ],
                "collection_status": "PARTIAL",
                "synthetic": True,
            },
        )
        dns = import_dns_email_scan(
            db=db,
            tenant_id=_TENANT,
            engagement_id=engagement_id,
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
                    }
                    for t, s, d in _DNS
                ],
                "collection_status": "PARTIAL",
                "synthetic": True,
            },
        )
        net = import_network_scan(
            db=db,
            tenant_id=_TENANT,
            engagement_id=engagement_id,
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
                    for h in ("203.0.113.10", "203.0.113.11", "203.0.113.12")
                ],
                "findings": [
                    {
                        "finding_type": t,
                        "severity": s,
                        "title": f"[SYNTHETIC] {t.split('.')[-1].replace('_', ' ').title()}",
                        "description": "Synthetic demo observation.",
                        "control_id": "NIST-AI-RMF-MANAGE-2.2",
                        "affected_hosts": hosts,
                    }
                    for t, s, hosts in _NET
                ],
                "synthetic": True,
            },
        )
        db.commit()
        return {
            "web": web.scan_result_id,
            "dns": dns.scan_result_id,
            "network": net.scan_result_id,
        }
    finally:
        db.close()


@pytest.fixture()
def client(build_app, monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key, cred = _issue_key(_TENANT, "governance:read", "governance:write")
    _assign(_TENANT, cred, "analyst")
    return TestClient(app, headers={"X-API-Key": key})


def test_synthetic_report_preview_renders(client):
    pypdf = pytest.importorskip("pypdf")
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": CLIENT_NAME,
            "assessor_id": "synthetic-assessor",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    eid = resp.json()["id"]
    scans = _seed_findings(eid)

    findings = client.get(
        f"/field-assessment/engagements/{eid}/findings", params={"limit": 100}
    )
    assert findings.status_code == 200, findings.text
    items = findings.json().get("findings") or findings.json().get("items") or []
    sev = {}
    for f in items:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    # Bridges dedupe per (finding_type, scan) — the counts are what persisted.
    assert sum(sev.values()) >= 10, sev

    rep = client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert rep.status_code == 201, rep.text
    version = rep.json()["version"]

    js = client.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "json"},
    )
    assert js.status_code == 200, js.text
    pdf = client.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "pdf"},
    )
    if pdf.status_code == 501:
        pytest.skip("reportlab unavailable: PDF_EXPORT_UNAVAILABLE")
    assert pdf.status_code == 200, pdf.text[:500]
    assert pdf.content[:5] == b"%PDF-"

    reader = pypdf.PdfReader(io.BytesIO(pdf.content))
    text = "\n".join((p.extract_text() or "") for p in reader.pages)
    assert len(reader.pages) >= 2
    assert "SYNTHETIC" in text  # customer identity marks the preview as synthetic

    out = os.getenv("FG_REPORT_PREVIEW_OUT")
    if out:
        d = Path(out)
        d.mkdir(parents=True, exist_ok=True)
        (d / "synthetic_report_preview.pdf").write_bytes(pdf.content)
        (d / "synthetic_report_preview.json").write_text(
            json.dumps(js.json(), indent=2, default=str)
        )
        (d / "synthetic_report_preview_text.txt").write_text(text)
        (d / "preview_meta.json").write_text(
            json.dumps(
                {
                    "engagement_id": eid,
                    "report_version": version,
                    "pages": len(reader.pages),
                    "severity_counts_persisted": sev,
                    "scan_result_ids": scans,
                    "pdf_bytes": len(pdf.content),
                    "status": "DRAFT / SYNTHETIC / NOT VERIFIED",
                },
                indent=2,
            )
        )
