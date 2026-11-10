"""Customer-zero end-to-end journey — L14-CUSTOMER-ZERO-E2E-001.

One synthetic customer (Northstar Manufacturing Group) is driven through the
platform as it exists: canonical admin provisioning, role-bound personas,
engagement creation, synthetic collection through the production bridges and
evidence capture, finding normalization, report assembly and PDF rendering,
QA, qualification, delivery, the customer-portal access path and audit.

Hard controls are asserted (the test fails if one is broken).  Product gaps
are probed and recorded in the acceptance matrix as findings — never hidden,
never forced to pass.  Set FG_CUSTOMER_ZERO_OUT=<dir> to keep the matrix,
PDF, page PNGs, evidence manifest and reconciliation record.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from tests._assurance_actors import reviewer
from tests.test_customer_zero_e2e import _northstar as N
from tests.test_customer_zero_e2e._acceptance import Acceptance

pypdf = pytest.importorskip("pypdf")
pytest.importorskip("reportlab")

PORTAL = {"X-Portal-Source": "client-portal"}
QA_HUMAN = "auth0|northstar-independent-qa"
SYNTH_MARK = "DRAFT — SYNTHETIC DATA — NOT VERIFIED"


def _items(resp: Any) -> list[Any]:
    """Collection payload from a list or an {items|events|findings|engagements} envelope."""
    if resp.status_code != 200:
        return []
    body = resp.json()
    if isinstance(body, list):
        return body
    for key in ("items", "events", "findings", "engagements"):
        if isinstance(body.get(key), list):
            return body[key]
    return []


def _flat(s: str) -> str:
    return re.sub(r"\s+", " ", s)


def _db_tenant_row(tenant_id: str) -> None:
    """SQLite-only seam: the canonical Postgres tenant repository (R7) is
    absent on SQLite, so POST /admin/tenants writes only the transition JSON
    registry.  Insert the tenants row the repository would have written —
    the same seam existing tests use.  Recorded as a limitation."""
    from api.db import get_engine

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state) VALUES (:t, 'active')"
            ),
            {"t": tenant_id},
        )


def provision(
    platform, acc: Acceptance | None, tenant_id: str = N.TENANT, name: str = N.ORG_NAME
) -> None:
    """Idempotent provisioning through the admin plane."""
    first = platform.admin().post(
        "/admin/tenants", json={"tenant_id": tenant_id, "name": name}
    )
    assert first.status_code in (201, 409), first.text
    _db_tenant_row(tenant_id)
    again = platform.admin().post(
        "/admin/tenants", json={"tenant_id": tenant_id, "name": name}
    )
    assert again.status_code == 409, again.text
    got = platform.admin().get(f"/admin/tenants/{tenant_id}")
    assert got.status_code == 200 and got.json()["tenant_id"] == tenant_id
    if acc is not None:
        acc.record(
            step_id="CZ-01",
            area="backend_workflow",
            capability="Tenant creation and lookup",
            executed_path="POST /admin/tenants; GET /admin/tenants/{id}",
            expected="201 then lookup; duplicate create rejected",
            actual=f"create={first.status_code}, duplicate={again.status_code}, lookup=200",
            status="PARTIAL",
            evidence={"tenant": got.json()},
            limitations=[
                "SQLite: the canonical Postgres tenant repository (R7) is not exercised; "
                "the route wrote the transition JSON registry and the harness inserted the "
                "tenants row (seam). Postgres provisioning is exercised in CI "
                "(test_customer_zero_postgres_provisioning_and_authorization).",
            ],
        )
    for persona, spec in N.PERSONAS.items():
        slot = f"{N.ENGAGEMENT_MARKER}:{persona}"
        cred = platform.admin(tenant_id).post(
            f"/admin/tenants/{tenant_id}/credentials",
            json={
                "credential_slot": slot,
                "scopes": N.PERSONA_SCOPES[persona],
                "idempotency_key": slot,
            },
        )
        assert cred.status_code in (200, 201), cred.text
        body = cred.json()
        cid = body["credential_id"]
        if body.get("plaintext_secret"):
            platform.keys[persona] = body["plaintext_secret"]
        role = platform.admin(tenant_id).post(
            f"/admin/tenants/{tenant_id}/credentials/{cid}/role",
            json={"role": spec["role"]},
        )
        assert role.status_code in (200, 201), role.text
        platform.credential_ids[persona] = cid


def _engagement(platform) -> str:
    """Idempotent: reuse the marked engagement if it already exists."""
    c = platform.client("assessor")
    listed = c.get("/field-assessment/engagements", params={"limit": 100}).json()
    for e in listed.get("items") or listed.get("engagements") or []:
        if e.get("client_name") == N.ORG_NAME:
            return e["id"]
    resp = c.post(
        "/field-assessment/engagements",
        json={
            "client_name": N.ORG_NAME,
            "client_domain": "northstar-mfg.example",
            "assessor_id": "synthetic-assessor",
            "assessment_type": "comprehensive",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _out() -> Path | None:
    o = os.getenv("FG_CUSTOMER_ZERO_OUT")
    if not o:
        return None
    p = Path(o)
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_customer_zero_end_to_end_journey(platform, monkeypatch):  # noqa: PLR0915 — an acceptance script
    acc = Acceptance()
    out = _out()

    # ── 1. Tenant, lifecycle, personas ──────────────────────────────────────
    provision(platform, acc)
    admin = platform.admin(N.TENANT)
    sus = admin.post(f"/admin/tenants/{N.TENANT}/suspend")
    during = platform.client("assessor").get("/field-assessment/engagements")
    act = admin.post(f"/admin/tenants/{N.TENANT}/activate")
    hist = admin.get(f"/admin/tenants/{N.TENANT}/lifecycle-history").json()
    assert sus.status_code == 200 and act.status_code == 200
    from api.db import get_engine

    enforced = get_engine().dialect.name == "postgresql"
    acc.record(
        step_id="CZ-02",
        area="security",
        capability="Tenant lifecycle enforcement (suspend/activate)",
        executed_path="POST /admin/tenants/{id}/suspend → tenant key request → /activate",
        expected="suspended tenant credentials denied; restored on activation",
        actual=(
            f"suspend={sus.status_code} (body says suspended), request while 'suspended'={during.status_code}, "
            f"activate={act.status_code}, history transitions={len(hist.get('transitions') or [])}"
        ),
        status="PASS"
        if enforced and during.status_code in (401, 403)
        else "NOT_TESTED",
        evidence={"lifecycle_history": hist, "dialect": get_engine().dialect.name},
        limitations=[]
        if enforced
        else [
            "The R3 lifecycle authority (_lifecycle_transition) is a no-op on non-Postgres: on this SQLite "
            "harness the route reports 'suspended' but nothing is enforced and no history is written. "
            "Enforcement is proven on real Postgres in CI "
            "(test_customer_zero_postgres_provisioning_and_authorization).",
        ],
        follow_up=None
        if enforced
        else "Consider failing loudly (not 200) when lifecycle authority is unavailable",
    )
    acc.record(
        step_id="CZ-03",
        area="backend_workflow",
        capability="Personas and role assignment",
        executed_path="POST /admin/tenants/{id}/credentials; POST .../credentials/{cid}/role",
        expected="each persona bound to a canonical role; no invented roles",
        actual=", ".join(
            f"{p}→{s['role']}→{s['maps_to']}" for p, s in N.PERSONAS.items()
        ),
        status="SYNTHETIC_EXECUTED",
        evidence={"credential_ids": dict(platform.credential_ids)},
        limitations=[
            "Personas authenticate with role-bound tenant API keys (supported identity adapter). "
            "Interactive OIDC login (Auth0/Keycloak) is NOT_TESTED.",
            "client_executive / client_security_owner exist only as OIDC roles; the API-key "
            "path maps the executive to viewer and the security admin to tenant_admin.",
        ],
    )

    # ── 2. Engagement ───────────────────────────────────────────────────────
    eid = _engagement(platform)
    assert _engagement(platform) == eid  # idempotent
    viewer_create = platform.client("customer_executive").post(
        "/field-assessment/engagements",
        json={
            "client_name": "x",
            "assessor_id": "x",
            "assessment_type": "comprehensive",
        },
    )
    assert viewer_create.status_code == 403
    acc.record(
        step_id="CZ-04",
        area="backend_workflow",
        capability="Engagement creation (tenant-bound, idempotent)",
        executed_path="POST /field-assessment/engagements (assessor)",
        expected="201; re-run reuses the engagement; customer executive cannot create",
        actual=f"engagement {eid}; re-run reused; executive create={viewer_create.status_code}",
        status="PASS",
        evidence={"engagement_id": eid},
    )
    acc.record(
        step_id="CZ-05",
        area="security",
        capability="Customer scan authorization (consent receipt)",
        executed_path="services.field_assessment.customer_authorization (Postgres-only SQL)",
        expected="receipt request → authenticated customer approval → scope → execution check",
        actual="not executable on the SQLite harness; exercised on real Postgres in CI",
        status="NOT_TESTED",
        limitations=[
            "Receipt persistence uses Postgres types (uuid, jsonb). Covered by "
            "tests/test_migrations_postgres_replay.py::test_customer_zero_postgres_provisioning_and_authorization "
            "(CI Migrations Replay job) with a simulated authenticated approver (no real OIDC).",
        ],
        follow_up="Interactive customer approval through the portal (OIDC) remains unverified",
    )

    # ── 3. Synthetic collection, evidence, findings ─────────────────────────
    ids = N.seed_collection(eid)
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaEvidenceCustodyEvent,
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
    )

    db = get_sessionmaker()()
    try:
        envs = (
            db.query(FaScanEvidenceEnvelope)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .all()
        )
        custody = (
            db.query(FaEvidenceCustodyEvent)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .all()
        )
        findings = (
            db.query(FaNormalizedFinding)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .all()
        )
        db.expunge_all()
    finally:
        db.close()
    env_by_scan = {e.scan_result_id for e in envs}
    assert ids["dns_email"] not in env_by_scan  # capture failed closed
    assert {
        ids[k]
        for k in (
            "web_headers",
            "network_scan",
            "entra_governance",
            "endpoint_inventory",
        )
    } <= env_by_scan
    assert {c.evidence_id for c in custody} >= {e.id for e in envs}
    assert all(e.tenant_id == N.TENANT and e.engagement_id == eid for e in envs)
    assert len(findings) == 14
    acc.record(
        step_id="CZ-06",
        area="evidence_integrity",
        capability="Synthetic collection through canonical persistence",
        executed_path="production bridges (6 collectors) + _c6_capture_runtime_evidence",
        expected="scan results, envelopes and custody persisted; failed capture fails closed",
        actual=f"{len(ids)} scan results, {len(envs)} envelopes, {len(custody)} custody events; DNS capture failed closed",
        status="SYNTHETIC_EXECUTED",
        evidence={
            "scan_result_ids": ids,
            "envelopes": len(envs),
            "custody_events": len(custody),
        },
        limitations=[
            "No scanner executed; payloads are synthetic. Target-scanner provenance is "
            f"{N.SYNTHETIC_PROOF_LEVEL} (no customer receipt).",
            "Graph-family collectors (Entra, endpoint, SharePoint) produce scan-level evidence only.",
        ],
    )

    # ── 4. Report assembly ──────────────────────────────────────────────────
    assessor = platform.client("assessor")
    rep = assessor.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert rep.status_code == 201, rep.text
    rid, version = rep.json()["report_id"], rep.json()["version"]
    exported = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "json"},
    )
    assert exported.status_code == 200
    report = exported.json()
    proof = report["report"]["report_proof"]
    rec = proof["finding_reconciliation"]
    assert (rec["persisted_total"], rec["included_total"], rec["reconciled"]) == (
        14,
        14,
        True,
    )
    assert {
        k: v for k, v in proof["severity_counts"].items() if v
    } == N.EXPECTED_SEVERITY
    assert {f["finding_id"] for f in proof["findings"]} == {f.id for f in findings}
    states = (
        set(proof["coverage"]["scan_status_counts"])
        | set(proof["coverage"]["observation_status_counts"])
        | {c.split(":")[-1] for c in proof["coverage"]["limitations"]}
    )
    missing_states = [s for s in N.ALL_COLLECTION_STATES if s not in states]
    assert not missing_states, missing_states
    assert (
        proof["coverage"]["may_claim_full_coverage"] is False
        and proof["coverage"]["coverage_percentage"] is None
    )
    prov = proof["provenance_counts"]
    assert prov.get("INVALID", 0) >= 1 and prov.get("MISSING", 0) >= 1
    for f in proof["findings"]:
        if f["confidence_effective"] == "CONFIRMED":
            assert f["evidence"]["provenance_status"] in (
                "VERIFIED_INTEGRITY_ONLY",
                "VERIFIED_AUTHENTIC",
            )
    assert "VERIFIED_AUTHENTIC" not in prov
    acc.record(
        step_id="CZ-07",
        area="report_correctness",
        capability="Finding reconciliation (14)",
        executed_path="POST /reports → report_proof",
        expected="14 persisted = 14 rendered; 2/3/4/3/2 severity",
        actual=f"persisted {rec['persisted_total']}, included {rec['included_total']}, severity {proof['severity_counts']}",
        status="SYNTHETIC_EXECUTED",
        evidence={
            "severity": proof["severity_counts"],
            "confidence": proof["confidence_counts"],
        },
    )
    acc.record(
        step_id="CZ-08",
        area="evidence_integrity",
        capability="Evidence proof and confidence separation",
        executed_path="evidence manifest re-verification inside report_proof",
        expected="integrity-only never shown as authentic; INVALID/MISSING disclosed; confidence capped, severity untouched",
        actual=f"provenance {prov}; confidence {proof['confidence_counts']}",
        status="SYNTHETIC_EXECUTED",
        evidence={
            "provenance": prov,
            "integrity_failed": proof["report_constraints"][
                "integrity_failed_evidence_ids"
            ],
        },
        limitations=[
            "Source authenticity is never established (no Vault Transit signature): L14-SCAN-VAULT-001."
        ],
    )
    acc.record(
        step_id="CZ-09",
        area="report_correctness",
        capability="Coverage truth (all 8 collection states)",
        executed_path="report_proof.coverage",
        expected="COMPLETE/PARTIAL/DENIED/TIMEOUT/FAILED/CANCELLED/UNKNOWN/NOT_ASSESSED disclosed; no %",
        actual=f"{len(proof['coverage']['limitations'])} limitations; percentage=None; full coverage claim=False",
        status="SYNTHETIC_EXECUTED",
        evidence={"limitations": proof["coverage"]["limitations"]},
    )

    # ── 5. Remediation roadmap and PDF ──────────────────────────────────────
    roadmap = assessor.get(f"/field-assessment/engagements/{eid}/remediation-roadmap")
    acc.record(
        step_id="CZ-10",
        area="report_correctness",
        capability="Remediation recommendations",
        executed_path="GET /engagements/{id}/remediation-roadmap; report_proof.findings[].remediation",
        expected="remediation for each finding where recorded; none invented",
        actual=f"roadmap route={roadmap.status_code}; {sum(1 for f in proof['findings'] if f['remediation'])}/14 findings carry guidance",
        status="SYNTHETIC_EXECUTED" if roadmap.status_code == 200 else "PARTIAL",
        evidence={
            "roadmap_status": roadmap.status_code,
            "roadmap_keys": sorted(roadmap.json())[:12]
            if roadmap.status_code == 200
            else roadmap.text[:200],
        },
        limitations=[
            "No remediation ownership field exists on findings (ownership is not represented)."
        ],
    )
    pdf = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "pdf"},
    )
    assert pdf.status_code == 200, pdf.text[:300]
    from tests.test_report_proof._synthetic import pdf_layout_checks

    layout = pdf_layout_checks(pdf.content, marking=SYNTH_MARK)
    reader = pypdf.PdfReader(io.BytesIO(pdf.content))
    pdf_text = _flat("\n".join(p.extract_text() or "" for p in reader.pages))
    nospace = re.sub(r"\s+", "", pdf_text)
    sections = [
        "Executive Summary",
        "Findings Summary",
        "Scope and Methodology",
        "Detailed Findings",
        "Remediation Roadmap",
        "Appendix A — Evidence and Coverage",
        "Verification and Quality Review",
    ]
    pdf_checks = {
        "all_14_ids": all(f["finding_id"] in pdf_text for f in proof["findings"]),
        "finding_blocks_14": pdf_text.count("Finding ID") == 14,
        "sections_present": all(s in pdf_text for s in sections),
        "no_100_percent": "100%" not in pdf_text,
        "coverage_not_determinable": "Coverage percentage: not determinable"
        in pdf_text,
        "signed_hash_present": report["manifest_hash"] in nospace,
        "evidence_ids_match_proof": all(e in nospace for e in proof["evidence_index"]),
        "layout_every_page": layout["all_ok"],
        "state_draft_synthetic": pdf.headers.get("X-Report-State") == "DRAFT_SYNTHETIC",
    }
    raster = _rasterize(pdf.content, out)
    if raster.get("performed"):
        pdf_checks["no_blank_pages"] = raster["all_non_blank"]
    assert all(pdf_checks.values()), {k: v for k, v in pdf_checks.items() if not v}
    acc.record(
        step_id="CZ-11",
        area="report_correctness",
        capability="Executive PDF (canonical renderer)",
        executed_path="GET /reports/{v}/export?format=pdf → pypdf + layout geometry + pdftoppm",
        expected="all sections, 14 findings, truthful marking, no overlap/blank pages",
        actual=f"{len(reader.pages)} pages; checks {pdf_checks}",
        status="SYNTHETIC_EXECUTED",
        evidence={
            "pages": len(reader.pages),
            "layout": layout["all_ok"],
            "raster": raster,
        },
    )

    # ── 6. QA, qualification, delivery ──────────────────────────────────────
    base = f"/field-assessment/engagements/{eid}/reports/{rid}"
    self_qa = assessor.post(f"{base}/qa-approve", json={"reviewer_name": "assessor"})
    assert self_qa.status_code == 403, self_qa.text
    # L14-ASSESSMENT-ASSURANCE-001: a role-bound QA *key* is still a key.
    qa_key = platform.client("qa_reviewer").post(
        f"{base}/qa-approve", json={"reviewer_name": "Independent QA"}
    )
    assert qa_key.status_code == 403, qa_key.text
    qa_human = platform.client("qa_reviewer", **reviewer(QA_HUMAN)).post(
        f"{base}/qa-approve", json={"reviewer_name": "Independent QA"}
    )
    # The deliberately tampered host makes approval impossible in every mode.
    assert qa_human.status_code == 422, qa_human.text
    assert qa_human.json()["detail"]["code"] == "ASSURANCE_PROVENANCE_BLOCKED"
    state_after_qa = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "json"},
    ).json()["report_state"]
    assert (
        state_after_qa["state"] == "DRAFT_SYNTHETIC"
        and state_after_qa["qa_approved"] is False
    )
    acc.record(
        step_id="CZ-12",
        area="security",
        capability="Independent QA (named human, no contribution, provenance-gated)",
        executed_path="POST /reports/{id}/qa-approve as assessor key, QA role key, then a named independent human",
        expected="keys refused; independent human refused while evidence integrity fails",
        actual=(
            f"assessor={self_qa.status_code}, qa_key={qa_key.status_code}, "
            f"named_reviewer={qa_human.status_code} "
            f"({qa_human.json()['detail']['code']}), state={state_after_qa['state']}"
        ),
        status="PASS",
        limitations=[
            "Named reviewer simulated through the test OIDC resolution seam; interactive OIDC login NOT_TESTED.",
            "Reviewer qualification (credentials/competence) remains policy-only (FVA-05).",
        ],
    )
    dual = _dual_role_self_approval_probe(platform, eid)
    acc.record(**dual)

    qualifier = platform.client("qualifier")
    req = qualifier.post(f"{base}/qualify/request")
    qual_status: Any = req.status_code
    fin = None
    if req.status_code == 201:
        qid = req.json().get("qual_request_id") or req.json().get("id")
        for gate in (
            "PRODUCTION_DEPENDENCY_SECURITY",
            "PRODUCTION_SCHEMA_AND_RLS",
            "CANONICAL_ASSESSMENT_PROOF",
            "DURABLE_EXECUTION_AND_RECOVERY",
        ):
            qualifier.post(
                f"{base}/qualify/{qid}/attest",
                json={"gate_name": gate, "attested": True},
            )
        fin = qualifier.post(
            f"{base}/qualify/{qid}/finalize",
            json={"reason": "customer-zero acceptance"},
        )
        qual_status = fin.status_code
    assert qual_status == 422, (req.text, fin.text if fin is not None else "")
    acc.record(
        step_id="CZ-13",
        area="security",
        capability="Production qualification of a synthetic report",
        executed_path="qualify/request → attest ×4 → finalize (qualifier persona)",
        expected="QUALIFIED refused: truth gate FAIL (synthetic data, invalid evidence)",
        actual=f"request={req.status_code}, finalize={qual_status}",
        status="PASS",
        evidence={"finalize": (fin.json() if fin is not None else req.json())},
    )

    from tests.test_governed_delivery import _governed_delivery

    vid = assessor.post(f"{base}/versions")
    assert vid.status_code == 201, vid.text
    vid = vid.json()["id"]
    submit = assessor.post(f"{base}/versions/{vid}/submit-for-review")
    approve = platform.client("qa_reviewer", **reviewer(QA_HUMAN)).post(
        f"{base}/versions/{vid}/approve",
        json={
            "reviewer_name": "Independent QA",
            "reviewer_role": "QA Lead",
            "approval_notes": "synthetic",
            "signature_placeholder": "n/a",
        },
    )
    deliver = assessor.post(f"{base}/versions/{vid}/deliver")
    gov = _governed_delivery(assessor, eid, rid, vid)
    assert deliver.status_code in (403, 409, 422) and gov.status_code in (403, 409, 422)
    acc.record(
        step_id="CZ-14",
        area="security",
        capability="Delivery of a synthetic report",
        executed_path="versions → submit → approve → deliver / governed-delivery",
        expected="delivery refused; never FINAL",
        actual=f"submit={submit.status_code}, approve={approve.status_code}, deliver={deliver.status_code}, governed={gov.status_code}",
        status="PASS",
        evidence={"deliver": deliver.json(), "governed": gov.json()},
    )

    reject = platform.client("qa_reviewer", **reviewer(QA_HUMAN)).post(
        f"{base}/qa-reject",
        json={
            "reason_code": "EVIDENCE_INTEGRITY",
            "explanation": "Host 203.0.113.12 evidence fails digest re-verification.",
        },
    )
    assert reject.status_code == 200, reject.text
    after_reject = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "json"},
    ).json()["report_state"]
    revive = assessor.post(f"{base}/versions")
    late_approve = platform.client(
        "qa_reviewer", **reviewer("auth0|northstar-second-qa")
    ).post(f"{base}/qa-approve", json={})
    assert after_reject["state"] == "REJECTED"
    assert revive.status_code == 409 and late_approve.status_code == 409
    acc.record(
        step_id="CZ-12C",
        area="security",
        capability="QA rejection and rework",
        executed_path="POST /reports/{id}/qa-reject (named reviewer) → export state → new version / late approval",
        expected="rejection recorded with reason; REJECTED state; no revival, no late approval",
        actual=(
            f"reject={reject.status_code} ({reject.json()['reason_code']}), "
            f"state={after_reject['state']}, new_version={revive.status_code}, "
            f"late_approve={late_approve.status_code}"
        ),
        status="PASS",
        evidence={"rejection": reject.json()},
    )

    # ── 7. Customer portal access path (backend) ────────────────────────────
    portal = _portal_probe(platform, eid, version)
    for step in portal:
        acc.record(**step)

    # ── 8. Audit trail ──────────────────────────────────────────────────────
    audit = assessor.get(
        f"/field-assessment/engagements/{eid}/audit-events", params={"limit": 100}
    )
    types = sorted({e.get("event_type") for e in _items(audit)})
    needed = {"engagement_report_created", "report.qa_rejected"}
    acc.record(
        step_id="CZ-20",
        area="operational_readiness",
        capability="Audit trail",
        executed_path="GET /engagements/{id}/audit-events",
        expected="report creation, QA decision and evidence capture audited",
        actual=f"status={audit.status_code}; event types={types}",
        status="PASS" if needed <= set(types) else "PARTIAL",
        evidence={"event_types": types},
        limitations=[]
        if needed <= set(types)
        else [f"missing from engagement audit feed: {sorted(needed - set(types))}"],
    )

    trust_events = [
        e
        for e in _items(audit)
        if e.get("event_type") in ("trust_chain_failure", "report_link_failure")
    ]
    monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
    strict_export = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": "json"},
    )
    monkeypatch.setenv("FG_PROVENANCE_MODE", "warn")
    from services.field_assessment.assessment_assurance import (
        evaluate_engagement_provenance,
    )
    from api.db import get_sessionmaker as _sm

    _db = _sm()()
    try:
        prov_decision = evaluate_engagement_provenance(
            _db, tenant_id=N.TENANT, engagement_id=eid
        ).summary()
    finally:
        _db.close()
    strict_detail = (
        strict_export.json() if strict_export.status_code != 200 else "allowed"
    )
    # Canonical evidence is evaluated (no legacy rows needed); the only failure is
    # the deliberately tampered host, so strict mode blocks for the right reason.
    assert prov_decision["evidence_count"] > 0
    assert prov_decision["legacy_record_count"] == 0
    assert prov_decision["reason_codes"] == ["PROVENANCE_INTEGRITY_FAILED"]
    acc.record(
        step_id="CZ-23",
        area="operational_readiness",
        capability="Canonical provenance for runtime scanner evidence",
        executed_path="evaluate_engagement_provenance → derive_engagement_trust_inputs → export/QA gates",
        expected="trust gates read the runtime envelope + custody chain; strict blocks only on real integrity failures",
        actual=(
            f"evidence={prov_decision['evidence_count']}, legacy_rows=0, "
            f"classifications={prov_decision['classification_counts']}, "
            f"reason_codes={prov_decision['reason_codes']}; strict export={strict_export.status_code} "
            f"(tampered host); trust failure audit events={len(trust_events)}"
        ),
        status="PASS",
        evidence={
            "provenance": prov_decision,
            "strict_export_status": strict_export.status_code,
            "strict_export_detail": strict_detail,
        },
        limitations=[
            "Clean-evidence strict acceptance is proven in tests/test_assessment_assurance/test_provenance.py "
            "(this journey keeps the deliberately tampered host).",
            "Scanner evidence is VERIFIED_INTEGRITY_ONLY: source authenticity is not established (disclosed).",
        ],
    )

    # ── 9. Not executable here ──────────────────────────────────────────────
    acc.record(
        step_id="CZ-21",
        area="browser_ui",
        capability="Customer portal browser experience",
        executed_path="apps/portal (Next.js) — not launched by this harness",
        expected="dashboard, engagement, findings, report preview, download, access denied",
        actual="see docs/assurance/L14_CUSTOMER_ZERO_E2E_ACCEPTANCE.md §14 for the separate browser run",
        status="NOT_TESTED",
        limitations=[
            "Browser-level acceptance is recorded separately and is not implied by API results."
        ],
    )
    acc.record(
        step_id="CZ-22",
        area="commercial_readiness",
        capability="Billing and entitlements",
        executed_path="none (no billing mutation permitted)",
        expected="entitlement to the assessment offer; invoice / payment",
        actual="not exercised; build_app runs entitlement enforcement in audit-only mode",
        status="NOT_TESTED",
        limitations=["No subscription, invoice or payment was created (safety rule)."],
    )

    # ── Artifacts ───────────────────────────────────────────────────────────
    if out is not None:
        (out / "northstar_report.pdf").write_bytes(pdf.content)
        (out / "report_export.json").write_text(
            json.dumps(report, indent=2, default=str)
        )
        (out / "evidence_manifest.json").write_text(
            json.dumps(
                {
                    "evidence_index": proof["evidence_index"],
                    "provenance_counts": prov,
                    "report_constraints": proof["report_constraints"],
                    "coverage": proof["coverage"],
                },
                indent=2,
                default=str,
            )
        )
        (out / "finding_reconciliation.json").write_text(
            json.dumps(
                {
                    "reconciliation": rec,
                    "findings": [
                        {
                            k: f[k]
                            for k in (
                                "finding_id",
                                "title",
                                "severity",
                                "confidence_effective",
                                "collection_status",
                                "affected_resources",
                                "limitations",
                            )
                        }
                        | {
                            "provenance": f["evidence"]["provenance_status"],
                            "evidence_ids": f["evidence"]["evidence_ids"],
                        }
                        for f in proof["findings"]
                    ],
                },
                indent=2,
                default=str,
            )
        )
        (out / "audit_events.json").write_text(
            json.dumps(_items(audit), indent=2, default=str)
        )
        (out / "report_validation.json").write_text(
            json.dumps(
                {"checks": pdf_checks, "layout": layout, "raster": raster}, indent=2
            )
        )
    acc.write()
    fails = [s for s in acc.steps if s.status == "FAIL"]
    # Recorded findings are expected product gaps; every FAIL must carry a blocking level.
    assert all(s.blocking in ("P0", "P1", "P2") for s in fails), fails


def _dual_role_self_approval_probe(platform, eid: str) -> dict[str, Any]:
    """Gap probe (FVA-05): can one credential both author and QA-approve?"""
    from api.auth_scopes import mint_key

    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=N.TENANT,
    )
    c = platform.client(**{"X-API-Key": key})
    rep = c.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    rid = rep.json().get("report_id") if rep.status_code == 201 else None
    qa = (
        c.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve",
            json={"reviewer_name": "same actor"},
        )
        if rid
        else None
    )
    accepted = qa is not None and qa.status_code == 200
    return dict(
        step_id="CZ-12B",
        area="security",
        capability="Self-approval by a dual-scope legacy credential",
        executed_path="legacy key (governance:write + governance:qa_approve, no RBAC role): generate then qa-approve",
        expected="author cannot QA-approve own report",
        actual=f"generate={rep.status_code}, self qa-approve={qa.status_code if qa else 'n/a'}",
        status="FAIL" if accepted else "PASS",
        blocking="P1" if accepted else "none",
        limitations=[]
        if not accepted
        else ["A dual-scope API key self-approved: independence not enforced."],
        follow_up="L14-ASSESSMENT-ASSURANCE-001: enforce author≠reviewer for every actor type"
        if accepted
        else None,
    )


def _portal_probe(platform, eid: str, version: int) -> list[dict[str, Any]]:
    """Customer access through the real core routes the portal BFF calls."""
    assessor = platform.client("assessor")
    grant = assessor.post(
        f"/field-assessment/engagements/{eid}/portal-grants", json={"ttl_days": 14}
    )
    assert grant.status_code == 201, grant.text
    secret = grant.json()["raw_secret"]
    bff = platform.client("portal_bff")
    auth = bff.post("/portal/authenticate", json={"secret": secret})
    assert auth.status_code == 200, auth.text
    session = auth.json()["session_id"]
    assert eid in auth.json()["engagement_ids"]
    cust = platform.client("portal_bff", **PORTAL, **{"X-FG-Portal-Session": session})
    reads = {
        "summary": cust.get(f"/field-assessment/engagements/{eid}/summary"),
        "findings": cust.get(
            f"/field-assessment/engagements/{eid}/findings", params={"limit": 100}
        ),
        "reports": cust.get(f"/field-assessment/engagements/{eid}/reports"),
        "roadmap": cust.get(f"/field-assessment/engagements/{eid}/remediation-roadmap"),
        "pdf": cust.get(
            f"/field-assessment/engagements/{eid}/reports/{version}/export",
            params={"format": "pdf"},
        ),
    }
    codes = {k: v.status_code for k, v in reads.items()}
    for k in ("findings", "reports"):
        assert codes[k] == 200, (k, reads[k].text[:200])
    report_items = reads["reports"].json().get("items", [])
    current_report = next(
        (item for item in report_items if item["version"] == version), None
    )
    assert current_report is not None, (
        "canonical report missing from customer workspace list"
    )
    assert current_report["status"] in {
        "draft",
        "synthetic_draft",
        "pending_qa",
        "release_blocked",
        "rejected",
        "unknown",
    }
    assert current_report.get("compiled_by") is None
    assert current_report["report_id"]
    assert current_report.get("manifest_hash")
    # L14-ASSESSMENT-ASSURANCE-001 (CZ-17): unreleased content is internal.
    assert codes["pdf"] == 403, reads["pdf"].text[:200]
    assert reads["pdf"].json()["detail"]["code"] == "REPORT_DRAFT_ACCESS_DENIED"
    items = (
        reads["findings"].json().get("findings")
        or reads["findings"].json().get("items")
        or []
    )

    # Denials
    other_eng = assessor.post(
        "/field-assessment/engagements",
        json={
            "client_name": "SYNTHETIC — Northstar second engagement",
            "assessor_id": "synthetic-assessor",
            "assessment_type": "comprehensive",
        },
    ).json()["id"]
    cross_engagement = cust.get(f"/field-assessment/engagements/{other_eng}/findings")
    no_session = platform.client("portal_bff", **PORTAL).get(
        f"/field-assessment/engagements/{eid}/findings"
    )
    forged = platform.client(
        "portal_bff", **PORTAL, **{"X-FG-Portal-Session": "forged-session-id"}
    ).get(f"/field-assessment/engagements/{eid}/findings")
    write_attempt = cust.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    qa_attempt = cust.post(
        f"/field-assessment/engagements/{eid}/reports/x/qa-approve", json={}
    )
    provision(
        platform,
        None,
        tenant_id=N.OTHER_TENANT,
        name="SYNTHETIC — Contoso Other (NOT A REAL CUSTOMER)",
    )
    other_bff = platform.client(
        "portal_bff", **PORTAL, **{"X-FG-Portal-Session": session}
    )
    cross_tenant = other_bff.get(f"/field-assessment/engagements/{eid}/findings")
    enumerate_all = cust.get("/field-assessment/engagements", params={"limit": 100})
    listed = (
        [
            e["id"]
            for e in (
                enumerate_all.json().get("items")
                or enumerate_all.json().get("engagements")
                or []
            )
        ]
        if enumerate_all.status_code == 200
        else []
    )
    assert listed == [eid], (
        f"grant-scoped list exposed {listed!r}; expected only {eid!r}"
    )
    for name, r in (
        ("cross_engagement", cross_engagement),
        ("no_session", no_session),
        ("forged", forged),
        ("write", write_attempt),
        ("qa", qa_attempt),
        ("cross_tenant", cross_tenant),
    ):
        assert r.status_code in (401, 403, 404), (name, r.status_code, r.text[:200])
    denials = {
        n: r.status_code
        for n, r in (
            ("cross_engagement", cross_engagement),
            ("no_session", no_session),
            ("forged_session", forged),
            ("write_via_portal", write_attempt),
            ("qa_via_portal", qa_attempt),
            ("other_tenant_key_same_session", cross_tenant),
        )
    }
    steps: list[dict[str, Any]] = [
        dict(
            step_id="CZ-15",
            area="backend_workflow",
            capability="Customer portal access (grant → session)",
            executed_path="POST portal-grants → POST /portal/authenticate → portal-scoped GETs (BFF key + X-FG-Portal-Session)",
            expected="customer reads findings, reports, roadmap and the PDF for the granted engagement",
            actual=f"grant=201, session ok, reads {codes}, findings listed={len(items)}",
            status="SYNTHETIC_EXECUTED",
            evidence={"reads": codes},
            limitations=[
                "Exercises the C7 grant-session path the BFF uses; the pnu1 named-user OIDC path is NOT_TESTED."
            ],
        ),
        dict(
            step_id="CZ-16",
            area="security",
            capability="Portal access controls",
            executed_path="cross-engagement, no/forged session, write/QA via portal, other-tenant key",
            expected="all denied",
            actual=f"{denials}",
            status="PASS",
            evidence={"denials": denials},
        ),
        dict(
            step_id="CZ-17",
            area="security",
            capability="Customer download of an unapproved draft",
            executed_path="portal-scoped GET /reports/{v}/export?format=pdf before any FINAL decision",
            expected="policy decision: customers see drafts only if explicitly allowed",
            actual=f"portal-scoped draft PDF export={codes['pdf']} (REPORT_DRAFT_ACCESS_DENIED)",
            status="PASS",
            limitations=[
                "Engagement policy report_access_policy.customer_draft_review can opt customers in "
                "(tests/test_assessment_assurance/test_draft_access.py)."
            ],
        ),
        dict(
            step_id="CZ-18",
            area="security",
            capability="Grant-scoped engagement enumeration",
            executed_path="portal-scoped GET /field-assessment/engagements (list, no id)",
            expected="only granted engagements visible",
            actual=f"status={enumerate_all.status_code}; listed {len(listed)} engagements (granted 1)",
            status="FAIL" if len(listed) > 1 else "PASS",
            blocking="P2" if len(listed) > 1 else "none",
            limitations=[
                "The legacy grant-session path validates only /engagements/{id}/* paths; the list route "
                "returns every engagement of the tenant to a single-engagement grant."
            ]
            if len(listed) > 1
            else [],
            follow_up="Scope the engagement list for portal-origin grant sessions"
            if len(listed) > 1
            else None,
        ),
    ]
    from api.auth_scopes import mint_key

    ws_key = mint_key("portal:read", "governance:read", tenant_id=N.TENANT)
    ep = platform.client(**{"X-API-Key": ws_key}).get(
        "/portal/engagement/reports", params={"engagement_id": eid}
    )
    canonical_ids = {
        (item["report_id"], item["version"], item.get("manifest_hash"))
        for item in reads["reports"].json().get("items", [])
    }
    workspace_ids = {
        (item["report_id"], item["version"], item.get("manifest_hash"))
        for item in ep.json().get("items", [])
    }
    assert ep.status_code == 200, ep.text
    assert workspace_ids == canonical_ids
    steps.append(
        dict(
            step_id="CZ-19",
            area="backend_workflow",
            capability="Engagement-portal workspace API (/portal/engagement/*)",
            executed_path="GET /portal/engagement/reports",
            expected="field-assessment report visible in the portal workspace",
            actual=f"status={ep.status_code}; workspace/canonical identities match={workspace_ids == canonical_ids}",
            status="PASS",
            blocking="none",
            limitations=[],
            follow_up=None,
        )
    )
    return steps


def _rasterize(pdf_bytes: bytes, out: Path | None) -> dict[str, Any]:
    if shutil.which("pdftoppm") is None:
        return {"performed": False}
    import tempfile

    from PIL import Image

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "r.pdf"
        src.write_bytes(pdf_bytes)
        subprocess.run(
            ["pdftoppm", "-r", "80", "-png", str(src), str(Path(tmp) / "page")],
            check=True,
            timeout=180,
        )
        spans = []
        for img in sorted(Path(tmp).glob("page-*.png")):
            with Image.open(img) as im:
                extrema: Any = im.convert("L").getextrema()
                spans.append(int(extrema[1]) - int(extrema[0]))
            if out is not None:
                shutil.copy(img, out / img.name)
    return {
        "performed": True,
        "pages": len(spans),
        "contrast_span_per_page": spans,
        "all_non_blank": bool(spans) and all(x > 100 for x in spans),
    }
