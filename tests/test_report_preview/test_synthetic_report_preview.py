"""Synthetic customer report preview through the canonical report pipeline.

L14-SCAN-RUNNER-INTEGRITY-001 addendum; upgraded by L14-SCAN-REPORT-PROOF-001.

Isolated ``build_app`` SQLite app; the deterministic synthetic engagement from
``tests/test_report_proof/_synthetic.py`` (production bridges, production
evidence capture, explicitly SYNTHETIC authorization provenance, no scanning,
no network); then the real routes:
POST /engagements/{id}/reports → GET …/reports/{v}/export?format=json|pdf.

The preview is DRAFT / SYNTHETIC / NOT VERIFIED on every page.  No QA approval
or delivery route is called.

Set FG_REPORT_PREVIEW_OUT=<dir> to keep the PDF, JSON, extracted text and (when
pdftoppm is installed) one PNG per page for visual QA.
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
from fastapi.testclient import TestClient

from tests.test_report_proof import _synthetic as S


@pytest.fixture()
def client(build_app, monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = S.issue_key(S.TENANT, "governance:read", "governance:write")
    return TestClient(app, headers={"X-API-Key": key})


def test_synthetic_report_preview_renders(client):
    pypdf = pytest.importorskip("pypdf")
    eid = S.create_engagement(client)
    scans = S.seed(eid)
    rep = S.generate_report(client, eid)
    version = rep["version"]

    js = S.export(client, eid, version, "json")
    assert js.status_code == 200, js.text
    pdf = S.export(client, eid, version, "pdf")
    if pdf.status_code == 501:
        pytest.skip("reportlab unavailable: PDF_EXPORT_UNAVAILABLE")
    assert pdf.status_code == 200, pdf.text[:500]
    assert pdf.content[:5] == b"%PDF-"

    reader = pypdf.PdfReader(io.BytesIO(pdf.content))
    pages = [p.extract_text() or "" for p in reader.pages]
    text = re.sub(r"\s+", " ", "\n".join(pages))
    proof = js.json()["report"]["report_proof"]
    assert proof["finding_reconciliation"]["included_total"] == 14
    for f in proof["findings"]:
        assert f["finding_id"] in text
    flat_pages = [re.sub(r"\s+", " ", p) for p in pages]
    nospace = re.sub(r"\s+", "", text)
    sev = proof["severity_counts"]
    checks = {
        "all_14_finding_ids_in_pdf": all(
            f["finding_id"] in text for f in proof["findings"]
        ),
        "finding_id_blocks_eq_14": text.count("Finding ID") == 14,
        "severity_totals_2_3_4_3_2": [
            sev[k] for k in ("critical", "high", "medium", "low", "informational")
        ]
        == [2, 3, 4, 3, 2],
        "reconciled": proof["finding_reconciliation"]["reconciled"] is True,
        "no_full_coverage_claim": proof["coverage"]["may_claim_full_coverage"] is False
        and proof["coverage"]["coverage_percentage"] is None
        and "100%" not in text,
        "partial_denied_cancelled_failed_disclosed": all(
            any(c.endswith(s_) for c in proof["coverage"]["limitations"])
            for s_ in (":PARTIAL", ":DENIED", ":CANCELLED", ":FAILED")
        ),
        "synthetic_marking_every_page": all(
            "DRAFT — SYNTHETIC DATA — NOT VERIFIED" in p for p in flat_pages
        ),
        "page_x_of_y_every_page": all(
            f"Page {i} of {len(pages)}" in p for i, p in enumerate(flat_pages, start=1)
        ),
        "signed_hash_in_pdf": js.json()["manifest_hash"] in nospace,
        "proof_fingerprint_in_pdf": proof["proof_fingerprint"] in nospace,
        "release_blocked": bool(proof["release_blockers"])
        and js.json()["report"]["result_truth_gate"]["decision"] == "FAIL",
        "state_draft_synthetic": js.json()["report_state"]["state"]
        == "DRAFT_SYNTHETIC",
    }
    layout = S.pdf_layout_checks(
        pdf.content, marking="DRAFT — SYNTHETIC DATA — NOT VERIFIED"
    )
    checks["layout_every_page_marking_numbering_footer"] = layout["all_ok"]
    raster: dict[str, object] = {"performed": False}
    if shutil.which("pdftoppm"):
        raster = _raster_check(pdf.content)
        checks["raster_every_page_non_blank"] = raster["all_non_blank"]
    assert all(checks.values()), {k: v for k, v in checks.items() if not v}

    out = os.getenv("FG_REPORT_PREVIEW_OUT")
    if out:
        d = Path(out)
        d.mkdir(parents=True, exist_ok=True)
        pdf_path = d / "synthetic_report_preview.pdf"
        pdf_path.write_bytes(pdf.content)
        (d / "synthetic_report_preview.json").write_text(
            json.dumps(js.json(), indent=2, default=str)
        )
        (d / "synthetic_report_preview_text.txt").write_text("\n".join(pages))
        if shutil.which("pdftoppm"):
            subprocess.run(
                ["pdftoppm", "-r", "110", "-png", str(pdf_path), str(d / "page")],
                check=True,
                timeout=120,
            )
        import hashlib

        import importlib.metadata as md
        import platform
        from datetime import datetime, timezone

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        )
        (d / "validation_record.json").write_text(
            json.dumps(
                {
                    "work_item": "L14-SCAN-REPORT-PROOF-001",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "test": os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0],
                    "outcome": "PASS" if all(checks.values()) else "FAIL",
                    "artifact": {
                        "file": pdf_path.name,
                        "sha256": hashlib.sha256(pdf.content).hexdigest(),
                        "bytes": len(pdf.content),
                        "pages": len(pages),
                    },
                    "snapshot": {
                        "report_id": rep["report_id"],
                        "report_version": version,
                        "engagement_id": eid,
                        "signed_report_sha256": js.json()["manifest_hash"],
                        "proof_fingerprint": proof["proof_fingerprint"],
                        "proof_schema": proof["schema_version"],
                        "data_cutoff": proof["data_cutoff"],
                        "evidence_verified_at": proof["evidence_verified_at"],
                        "finding_ids": [f["finding_id"] for f in proof["findings"]],
                        "severity_counts": proof["severity_counts"],
                        "coverage_limitations": proof["coverage"]["limitations"],
                        "release_blockers": proof["release_blockers"],
                        "truth_gate": js.json()["report"]["result_truth_gate"][
                            "decision"
                        ],
                        "report_state": js.json()["report_state"]["state"],
                    },
                    "checks": checks,
                    "layout": layout,
                    "raster": raster,
                    "verification_basis": {
                        "data": "Synthetic engagement persisted through production "
                        "bridges and production evidence capture in an isolated "
                        "SQLite test app (build_app); no scanning, no network.",
                        "routes": [
                            "POST /field-assessment/engagements",
                            "POST /field-assessment/engagements/{id}/reports",
                            "GET .../reports/{v}/export?format=json",
                            "GET .../reports/{v}/export?format=pdf",
                        ],
                        "text": "pypdf text extraction of every page",
                        "layout": "pypdf text positions + reportlab Helvetica "
                        "7pt string widths (footer band and per-line overlap)",
                        "raster": "pdftoppm 40 dpi per page, grayscale "
                        "extrema (non-blank)"
                        if raster.get("performed")
                        else "not performed (pdftoppm unavailable)",
                        "not_verified": [
                            "human visual review is separate from this record",
                            "evidence provenance is SHA-256 integrity only; "
                            "source authenticity is not attested",
                            "no QA approval or production qualification exists",
                        ],
                    },
                    "environment": {
                        "git_head": head,
                        "working_tree_dirty": dirty,
                        "python": platform.python_version(),
                        "reportlab": md.version("reportlab"),
                        "pypdf": md.version("pypdf"),
                    },
                    "status": "DRAFT / SYNTHETIC / NOT VERIFIED — not client-deliverable",
                },
                indent=2,
            )
        )
        (d / "preview_meta.json").write_text(
            json.dumps(
                {
                    "engagement_id": eid,
                    "report_version": version,
                    "report_id": rep["report_id"],
                    "pages": len(pages),
                    "severity_counts": proof["severity_counts"],
                    "confidence_counts": proof["confidence_counts"],
                    "provenance_counts": proof["provenance_counts"],
                    "coverage_limitations": proof["coverage"]["limitations"],
                    "release_blockers": proof["release_blockers"],
                    "scan_result_ids": scans,
                    "pdf_bytes": len(pdf.content),
                    "report_state": js.json()["report_state"],
                },
                indent=2,
            )
        )


def _raster_check(pdf_bytes: bytes) -> dict[str, object]:
    import tempfile

    from PIL import Image

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "r.pdf"
        src.write_bytes(pdf_bytes)
        subprocess.run(
            ["pdftoppm", "-r", "40", "-gray", "-png", str(src), str(Path(tmp) / "p")],
            check=True,
            timeout=120,
        )
        spans: list[int] = []
        for img in sorted(Path(tmp).glob("p-*.png")):
            with Image.open(img) as im:
                extrema: Any = im.convert("L").getextrema()
                spans.append(int(extrema[1]) - int(extrema[0]))
    return {
        "performed": True,
        "pages": len(spans),
        "contrast_span_per_page": spans,
        "all_non_blank": bool(spans) and all(x > 100 for x in spans),
    }
