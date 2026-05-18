from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from api.report_exports import (
    ExportValidationError,
    build_hashed_manifest,
    canonical_json,
    manifest_sha256,
    render_html_export,
    render_pdf_export,
)


def _content() -> dict:
    return {
        "executive_summary": "Advisory narrative only.",
        "findings": [
            {
                "id": "finding-2",
                "title": "Logging gap",
                "evidence_ids": ["evidence-2"],
                "framework_mapping_ids": ["map-2"],
                "confidence_score": 0.83,
            },
            {
                "id": "finding-1",
                "title": "Access review gap",
                "evidence_ids": ["evidence-1"],
                "framework_mapping_ids": ["map-1"],
                "confidence_score": 0.91,
            },
        ],
        "evidence": [
            {
                "id": "evidence-2",
                "lineage": "collector:log-review",
                "provenance": "signed-import",
                "validation_state": "validated",
                "freshness": "2026-05-01",
                "source_metadata": {"system": "siem"},
                "linked_findings": ["finding-2"],
                "linked_controls": ["AU-6"],
            },
            {
                "id": "evidence-1",
                "lineage": "collector:iam-review",
                "provenance": "signed-import",
                "validation_state": "validated",
                "freshness": "2026-05-01",
                "source_metadata": {"system": "iam"},
                "linked_findings": ["finding-1"],
                "linked_controls": ["AC-2"],
            },
        ],
        "framework_mappings": [
            {
                "id": "map-2",
                "finding_id": "finding-2",
                "framework": "SOC2",
                "control": "CC7.2",
            },
            {
                "id": "map-1",
                "finding_id": "finding-1",
                "framework": "SOC2",
                "control": "CC6.3",
            },
        ],
        "remediations": [
            {
                "id": "rem-2",
                "finding_id": "finding-2",
                "owner": "secops",
                "due": "2026-06-15",
            },
            {
                "id": "rem-1",
                "finding_id": "finding-1",
                "owner": "iam",
                "due": "2026-06-01",
            },
        ],
        "confidence": {"method": "evidence-weighted", "score": 0.87},
    }


def _report(**overrides):
    data = {
        "id": "report-1",
        "tenant_id": "tenant-a",
        "assessment_id": "assessment-1",
        "org_id": "org-1",
        "org_profile_id": 7,
        "status": "complete",
        "content": _content(),
        "created_at": datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 5, 1, 12, 5, tzinfo=timezone.utc),
        "manifest_version": "governance-export-manifest-v1",
        "export_version": "governance-export-v1",
        "report_version": 1,
        "reviewer_ref": None,
        "approval_status": "unapproved",
        "finalized_at": None,
        "finalized_manifest_hash": None,
        "previous_report_id": None,
        "superseded_by_report_id": None,
        "evidence_snapshot_version": "evidence-snapshot-v1",
        "scoring_contract_version": "assessment-scoring-v1",
        "framework_mapping_version": "framework-mapping-v1",
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _assessment():
    return SimpleNamespace(
        status="scored",
        overall_score=82.5,
        risk_band="medium",
        scores={"security_posture": 82.5},
    )


def test_identical_inputs_produce_identical_hashes_and_canonical_json() -> None:
    first = build_hashed_manifest(_report(), _assessment())
    second = build_hashed_manifest(_report(), _assessment())

    assert first["manifest_hash"] == second["manifest_hash"]
    assert canonical_json(first["manifest"]) == canonical_json(second["manifest"])
    assert first["manifest_hash"] == manifest_sha256(first["manifest"])


def test_exports_are_deterministic_for_identical_manifest() -> None:
    hashed = build_hashed_manifest(_report(), _assessment())
    manifest = hashed["manifest"]
    digest = hashed["manifest_hash"]

    assert render_pdf_export(manifest, digest) == render_pdf_export(manifest, digest)
    assert render_html_export(manifest, digest) == render_html_export(manifest, digest)
    assert digest.encode("utf-8") in render_pdf_export(manifest, digest)
    assert digest.encode("utf-8") in render_html_export(manifest, digest)


def test_evidence_appendix_ordering_is_deterministic() -> None:
    report_a = _report()
    report_b = _report(content=deepcopy(_content()))
    report_b.content["evidence"].reverse()
    report_b.content["findings"].reverse()
    report_b.content["framework_mappings"].reverse()
    report_b.content["remediations"].reverse()

    manifest_a = build_hashed_manifest(report_a, _assessment())["manifest"]
    manifest_b = build_hashed_manifest(report_b, _assessment())["manifest"]

    assert [item["id"] for item in manifest_a["evidence"]] == [
        "evidence-1",
        "evidence-2",
    ]
    assert manifest_a == manifest_b


def test_missing_required_sections_fail_closed() -> None:
    content = _content()
    content.pop("evidence")

    with pytest.raises(ExportValidationError, match="missing required sections"):
        build_hashed_manifest(_report(content=content), _assessment())


def test_replay_mismatch_detection_uses_canonical_hash() -> None:
    hashed = build_hashed_manifest(_report(), _assessment())
    mutated = _report()
    mutated.content["confidence"] = {"method": "evidence-weighted", "score": 0.42}

    replay_hash = build_hashed_manifest(mutated, _assessment())["manifest_hash"]

    assert replay_hash != hashed["manifest_hash"]


def test_finalized_lineage_and_reviewer_metadata_are_preserved() -> None:
    finalized_at = datetime(2026, 5, 2, 9, 30, tzinfo=timezone.utc)
    report = _report(
        reviewer_ref="user:reviewer-1",
        approval_status="finalized",
        finalized_at=finalized_at,
        previous_report_id="report-0",
        superseded_by_report_id="report-2",
        report_version=2,
    )

    manifest = build_hashed_manifest(report, _assessment())["manifest"]

    assert manifest["reviewer"]["reviewer_ref"] == "user:reviewer-1"
    assert manifest["reviewer"]["approval_status"] == "finalized"
    assert manifest["metadata"]["finalized_at"] == "2026-05-02T09:30:00Z"
    assert manifest["lineage"]["prior_report_id"] == "report-0"
    assert manifest["lineage"]["following_report_id"] == "report-2"
    assert manifest["report"]["report_version"] == 2


def test_ai_narrative_is_advisory_and_separate_from_deterministic_sections() -> None:
    manifest = build_hashed_manifest(_report(), _assessment())["manifest"]

    assert manifest["ai_narrative"]["advisory_only"] is True
    assert "executive_summary" not in manifest["findings"][0]
