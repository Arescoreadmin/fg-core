"""Real report routes + real PDF — L14-SCAN-REPORT-PROOF-001.

Synthetic engagement (``_synthetic``) persisted through the production
bridges and evidence capture; report generated, exported, QA-approved and
delivered through the canonical routes.  The PDF is parsed with pypdf and its
footer geometry checked; pages are rasterized with pdftoppm when available.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_report_proof import _synthetic as S

pypdf = pytest.importorskip("pypdf")
pytest.importorskip("reportlab")

FORBIDDEN_CLAIMS = (
    "100%",
    "100.0%",
    "zero risk",
    "no risk",
    "certified",
    "compliant with",
    "verified critical",
    "verified assessment",
    "VERIFIED_AUTHENTIC —",
)


@pytest.fixture()
def client(build_app, monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    return TestClient(
        app,
        headers={
            "X-API-Key": S.issue_key(S.TENANT, "governance:read", "governance:write")
        },
    )


@pytest.fixture()
def scenario(client):
    eid = S.create_engagement(client)
    ids = S.seed(eid)
    rep = S.generate_report(client, eid)
    js = S.export(client, eid, rep["version"], "json")
    pdf = S.export(client, eid, rep["version"], "pdf")
    assert js.status_code == 200, js.text
    assert pdf.status_code == 200, pdf.text[:500]
    reader = pypdf.PdfReader(io.BytesIO(pdf.content))
    pages = [pg.extract_text() or "" for pg in reader.pages]
    return {
        "client": client,
        "eid": eid,
        "ids": ids,
        "report": rep,
        "json": js.json(),
        "pdf": pdf,
        "reader": reader,
        "pages": pages,
        "text": "\n".join(pages),
    }


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


# ── Finding completeness ────────────────────────────────────────────────────


def test_all_fourteen_findings_reconcile_to_persisted_authority(scenario):
    proof = scenario["json"]["report"]["report_proof"]
    persisted = {f.id: f for f in S.persisted_findings(scenario["eid"])}
    assert len(persisted) == 14
    assert {f["finding_id"] for f in proof["findings"]} == set(persisted)
    rec = proof["finding_reconciliation"]
    assert (rec["persisted_total"], rec["included_total"], rec["excluded_total"]) == (
        14,
        14,
        0,
    )
    assert rec["reconciled"] is True
    assert {
        k: v for k, v in proof["severity_counts"].items() if v
    } == S.EXPECTED_SEVERITY
    for f in proof["findings"]:
        assert (
            f["severity"] == persisted[f["finding_id"]].severity
        )  # severity preserved
    assert len(scenario["json"]["report"]["normalized_findings"]) == 14


def test_scenario_classifications_are_represented_truthfully(scenario):
    proof = scenario["json"]["report"]["report_proof"]
    prov = proof["provenance_counts"]
    assert prov == {"VERIFIED_INTEGRITY_ONLY": 7, "MISSING": 5, "INVALID": 2}
    for f in proof["findings"]:
        p = f["evidence"]["provenance_status"]
        if p == "INVALID":
            assert f["confidence_effective"] == "SUSPECTED"
            assert S.TAMPERED_HOST in f["affected_resources"]
        if p == "MISSING":  # failed DNS capture
            assert f["confidence_effective"] == "UNKNOWN"
            assert "EVIDENCE_NOT_CAPTURED" in f["limitations"]
        if f["confidence_effective"] == "CONFIRMED":
            assert p == "VERIFIED_INTEGRITY_ONLY"
    assert proof["report_constraints"]["may_claim_authenticated_evidence"] is False
    assert sum(1 for f in proof["findings"] if f["remediation"]) == 12


def test_coverage_truth_is_disclosed(scenario):
    cov = scenario["json"]["report"]["report_proof"]["coverage"]
    lim = cov["limitations"]
    for marker in (
        ":DENIED",
        ":TIMEOUT",
        ":CANCELLED",
        ":PARTIAL",
        ":FAILED",
        "EVIDENCE_NOT_CAPTURED",
        "TARGETS_NOT_STARTED:4",
    ):
        assert any(marker in c for c in lim), marker
    assert cov["may_claim_full_coverage"] is False
    assert cov["coverage_percentage"] is None
    text = _flat(scenario["text"])
    for word in ("DENIED", "TIMEOUT", "CANCELLED", "PARTIAL", "FAILED"):
        assert word in text, word
    assert "Coverage percentage: not determinable" in text
    assert "Limited" in text


def test_release_blocked_for_synthetic_and_tampered_evidence(scenario):
    report = scenario["json"]["report"]
    gate = report["result_truth_gate"]
    assert gate["decision"] == "FAIL"
    assert {
        "REPORT_PROOF_BLOCKED:SYNTHETIC_DATA",
        "REPORT_PROOF_BLOCKED:EVIDENCE_INTEGRITY_FAILED",
    } <= set(gate["failure_reasons"])
    state = scenario["json"]["report_state"]
    assert state["state"] == "DRAFT_SYNTHETIC" and state["is_draft"] is True
    assert scenario["pdf"].headers["X-Report-State"] == "DRAFT_SYNTHETIC"


# ── Real PDF validation ─────────────────────────────────────────────────────


def test_pdf_contains_every_finding_and_reconciles(scenario):
    text = _flat(scenario["text"])
    proof = scenario["json"]["report"]["report_proof"]
    for f in proof["findings"]:
        assert f["finding_id"] in text, f["finding_id"]
    assert text.count("Finding ID") == 14
    assert "Detailed Findings (14)" in text
    assert "14 finding(s): 2 critical, 3 high, 4 medium, 3 low, 2 informational" in text
    assert "14 included of 14 eligible" in text
    # Evidence appendix lists exactly the proof's evidence index.
    for eid in proof["evidence_index"]:
        assert eid in text, eid


def test_every_page_marked_numbered_and_identified(scenario):
    pages = scenario["pages"]
    n = len(pages)
    assert n >= 6
    rid = scenario["json"]["report"]["report_id"]
    for i, page in enumerate(pages, start=1):
        flat = _flat(page)
        assert S_MARK in flat, f"page {i} lacks draft/synthetic marking"
        assert f"Page {i} of {n}" in flat
        assert rid in flat and "Revision v" in flat and "CONFIDENTIAL" in flat
        assert flat.strip(), f"page {i} blank"


S_MARK = "DRAFT — SYNTHETIC DATA — NOT VERIFIED"


def test_no_unsupported_claims(scenario):
    low = _flat(scenario["text"]).lower()
    for phrase in FORBIDDEN_CLAIMS:
        assert phrase.lower() not in low, phrase
    # Compliance framework mapping is not rendered for a scanner assessment.
    assert "Framework Coverage" not in scenario["text"]


def test_footer_geometry_has_no_collisions(scenario):
    from reportlab.pdfbase.pdfmetrics import stringWidth

    footer_top = 0.66 * 72
    for i, page in enumerate(scenario["reader"].pages, start=1):
        items: list[tuple[float, float, str, float]] = []

        def visit(text, cm, tm, font, size, _items=items):
            if text.strip():
                x, y = tm[4] * cm[0] + cm[4], tm[5] * cm[3] + cm[5]
                _items.append((x, y, text, float(size or 0) * (cm[0] or 1)))

        page.extract_text(visitor_text=visit)
        footer = [it for it in items if it[1] < footer_top]
        body = [it for it in items if footer_top <= it[1] < 0.95 * 72 + 0.25 * 72]
        assert footer, f"page {i}: no footer"
        assert not body, f"page {i}: body text intrudes into footer band: {body[:2]}"
        rows: dict[int, list[tuple[float, float, str, float]]] = {}
        for it in footer:
            rows.setdefault(round(it[1]), []).append(it)
        for row in rows.values():
            row.sort()
            for a, b in zip(row, row[1:]):
                width = stringWidth(a[2], "Helvetica", 7)
                assert a[0] + width <= b[0] + 0.5, (
                    f"page {i}: footer overlap {a[2]!r} / {b[2]!r}"
                )


def test_pages_render_to_non_blank_images(scenario, tmp_path):
    if shutil.which("pdftoppm") is None:
        pytest.skip("pdftoppm not installed")
    Image = pytest.importorskip("PIL.Image")
    src = tmp_path / "r.pdf"
    src.write_bytes(scenario["pdf"].content)
    subprocess.run(
        ["pdftoppm", "-r", "40", "-png", str(src), str(tmp_path / "pg")],
        check=True,
        timeout=120,
    )
    images = sorted(tmp_path.glob("pg-*.png"))
    assert len(images) == len(scenario["pages"])
    for img in images:
        with Image.open(img) as im:
            lo, hi = im.convert("L").getextrema()
            assert hi - lo > 100, f"{img.name} looks blank"


# ── Release enforcement through the real delivery path ──────────────────────


@pytest.fixture()
def release_client(build_app, monkeypatch):
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=RELEASE_TENANT,
    )
    return TestClient(app, headers={"X-API-Key": key})


RELEASE_TENANT = "tenant-proof-release"


def _approved_clean_version(c: TestClient):
    from tests.test_governed_delivery import (
        _approve_version,
        _create_version,
        _qa_approve,
        _submit,
    )

    eid = S.create_engagement(c, "Release Test Org (test fixture)")
    S.seed(
        eid,
        synthetic=False,
        tamper=False,
        failed_job=False,
        tenant=RELEASE_TENANT,
        proof_level="TEST_FIXTURE_ONLY",
    )
    rep = S.generate_report(c, eid)
    rid = rep["report_id"]
    _qa_approve(c, eid, rid)
    vid = _create_version(c, eid, rid)
    _submit(c, eid, rid, vid)
    _approve_version(c, eid, rid, vid)
    return eid, rid, vid, rep["version"]


def test_limited_scope_report_releases_with_limitation_label_then_blocks_on_evidence_change(
    release_client,
):
    from tests.test_governed_delivery import _governed_delivery, _inject_qualification

    c = release_client
    eid, rid, vid, version = _approved_clean_version(c)
    report = S.export(c, eid, version, "json").json()
    assert report["report"]["report_proof"]["release_blockers"] == []
    assert report["report"]["result_truth_gate"]["decision"] == "PASS"

    # No qualification yet: draft marking, delivery refused.
    assert report["report_state"]["marking"] == "DRAFT — NOT VERIFIED"
    assert _governed_delivery(c, eid, rid, vid).status_code == 422

    _inject_qualification(RELEASE_TENANT, eid, rid, vid)
    final = S.export(c, eid, version, "json").json()["report_state"]
    assert final["state"] == "FINAL"
    assert final["marking"] == "FINAL — QA APPROVED — LIMITED COVERAGE"
    ok = _governed_delivery(c, eid, rid, vid, idempotency_key=uuid.uuid4().hex)
    assert ok.status_code == 200, ok.text
    pdf = S.export(c, eid, version, "pdf")
    assert pdf.headers["X-Report-State"] == "FINAL"
    assert "LIMITED COVERAGE" in _flat(
        pypdf.PdfReader(io.BytesIO(pdf.content)).pages[0].extract_text()
    )

    # Stored evidence altered after QA approval and qualification.
    S.tamper_host(S.persisted_scan_id(eid, "network_scan", tenant=RELEASE_TENANT))
    blocked = _governed_delivery(c, eid, rid, vid, idempotency_key=uuid.uuid4().hex)
    assert blocked.status_code == 422
    assert "EVIDENCE_CHANGED_SINCE_GENERATION" in blocked.text
    after = S.export(c, eid, version, "json").json()["report_state"]
    assert (
        after["state"] == "DRAFT"
        and "EVIDENCE_CHANGED_SINCE_GENERATION" in after["release_blockers"]
    )


def test_report_changed_after_qa_blocks_export(release_client):
    from api.db import get_sessionmaker
    from api.db_models_governance_report import GovernanceReportRecord

    c = release_client
    eid, rid, vid, version = _approved_clean_version(c)
    db = get_sessionmaker()()
    try:
        rec = db.get(GovernanceReportRecord, rid)
        doc = dict(rec.report_json)
        doc["report_proof"] = {**doc["report_proof"], "release_blockers": []}
        doc["report_proof"]["findings"] = doc["report_proof"]["findings"][:1]
        rec.report_json = doc
        db.commit()
    finally:
        db.close()
    resp = S.export(c, eid, version, "pdf")
    assert resp.status_code == 403
    assert "REPORT_CONTENT_INTEGRITY_FAILED" in resp.text


# ── Tenant isolation and access control ─────────────────────────────────────


def test_cross_tenant_and_unauthorized_access_denied(scenario, build_app):
    c, eid, version = scenario["client"], scenario["eid"], scenario["report"]["version"]
    other = TestClient(
        c.app,
        headers={
            "X-API-Key": S.issue_key(
                "tenant-proof-other", "governance:read", "governance:write"
            )
        },
    )
    assert S.export(other, eid, version, "pdf").status_code == 404
    assert S.export(other, eid, version, "json").status_code == 404
    assert (
        other.post(
            f"/field-assessment/engagements/{eid}/reports",
            json={"report_type": "full_assessment"},
        ).status_code
        == 404
    )
    reader_only = TestClient(
        c.app,
        headers={
            "X-API-Key": S.issue_key(S.TENANT, "governance:read", role="read_only")
        },
    )
    assert (
        reader_only.post(
            f"/field-assessment/engagements/{eid}/reports",
            json={"report_type": "full_assessment"},
        ).status_code
        == 403
    )
    rid = scenario["report"]["report_id"]
    assert (
        reader_only.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve", json={}
        ).status_code
        == 403
    )
    no_key = TestClient(c.app)
    assert S.export(no_key, eid, version, "pdf").status_code in (401, 403)


def test_marking_cannot_be_removed_by_request_parameters(scenario):
    c, eid, version = scenario["client"], scenario["eid"], scenario["report"]["version"]
    resp = c.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={
            "format": "pdf",
            "draft": "false",
            "marking": "FINAL",
            "watermark": "0",
            "state": "FINAL",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["X-Report-State"] == "DRAFT_SYNTHETIC"
    first = _flat(pypdf.PdfReader(io.BytesIO(resp.content)).pages[0].extract_text())
    assert S_MARK in first


# ── Revisions ───────────────────────────────────────────────────────────────


def test_revisions_preserved_and_distinct(scenario):
    c, eid = scenario["client"], scenario["eid"]
    v1 = scenario["json"]
    S.tamper_host(
        scenario["ids"]["network"], host="203.0.113.10"
    )  # later evidence change
    v2r = S.generate_report(c, eid)
    assert v2r["version"] == v1["version"] + 1
    v2 = S.export(c, eid, v2r["version"], "json").json()
    old = S.export(c, eid, v1["version"], "json").json()
    assert old["manifest_hash"] == v1["manifest_hash"]  # earlier revision untouched
    assert v2["report_id"] != v1["report_id"]
    assert (
        v2["report"]["report_proof"]["proof_fingerprint"]
        != v1["report"]["report_proof"]["proof_fingerprint"]
    )
    assert (
        v2["report"]["report_proof"]["provenance_counts"]["INVALID"]
        > v1["report"]["report_proof"]["provenance_counts"]["INVALID"]
    )


# ── Failure safety ──────────────────────────────────────────────────────────


def test_empty_engagement_renders_not_assessed_draft(client):
    eid = S.create_engagement(client, "Empty Engagement (test fixture)")
    rep = S.generate_report(client, eid)
    js = S.export(client, eid, rep["version"], "json").json()
    proof = js["report"]["report_proof"]
    assert proof["findings"] == [] and proof["coverage"][
        "coverage_statement"
    ].startswith("NOT_ASSESSED")
    assert js["report"]["result_truth_gate"]["decision"] == "FAIL"
    pdf = S.export(client, eid, rep["version"], "pdf")
    text = _flat(
        "\n".join(
            p.extract_text() or ""
            for p in pypdf.PdfReader(io.BytesIO(pdf.content)).pages
        )
    )
    assert "No eligible finding was recorded" in text and "DRAFT — NOT VERIFIED" in text


def test_render_failure_is_a_controlled_error(scenario, monkeypatch):
    import services.governance.report.pdf_layout as layout

    def boom(**_kw):
        raise RuntimeError("corrupt template")

    monkeypatch.setattr(layout, "proof_story", boom)
    resp = S.export(
        scenario["client"], scenario["eid"], scenario["report"]["version"], "pdf"
    )
    assert resp.status_code == 501
    assert not resp.content.startswith(b"%PDF")


# ── Scale ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("count", [100, 500])
def test_large_engagement_renders_every_finding(client, count, tmp_path):
    eid = S.create_engagement(client, "Scale Test Org (test fixture)")
    S.seed_bulk_findings(eid, count)
    t0 = time.perf_counter()
    rep = S.generate_report(client, eid)
    t1 = time.perf_counter()
    pdf = S.export(client, eid, rep["version"], "pdf")
    t2 = time.perf_counter()
    assert pdf.status_code == 200
    reader = pypdf.PdfReader(io.BytesIO(pdf.content))
    text = _flat("\n".join(p.extract_text() or "" for p in reader.pages))
    ids = [f.id for f in S.persisted_findings(eid)]
    assert len(ids) == count
    missing = [i for i in ids if i not in text]
    assert not missing, missing[:5]
    assert text.count("Finding ID") == count
    Path(tmp_path / "timing.txt").write_text(
        f"{count}: generate={t1 - t0:.2f}s render={t2 - t1:.2f}s pages={len(reader.pages)}"
    )
    print(
        f"\n[report-proof perf] findings={count} generate={t1 - t0:.2f}s export_pdf={t2 - t1:.2f}s pages={len(reader.pages)} bytes={len(pdf.content)}"
    )
    assert t2 - t0 < 120
