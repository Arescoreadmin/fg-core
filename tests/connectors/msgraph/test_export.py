"""Tests for ScanResult assembly and delta classification."""

from __future__ import annotations


from services.connectors.msgraph.export import build_scan_result, _apply_delta
from services.connectors.msgraph.schema.analyzer_outputs import AnalyzerOutputs
from services.connectors.msgraph.schema.integrity import SignedManifest
from services.connectors.msgraph.schema.scan_result import (
    AcknowledgmentReceipt,
    Finding,
)


def _make_receipt() -> AcknowledgmentReceipt:
    return AcknowledgmentReceipt(
        operator_name="Alice",
        operator_org="Acme",
        client_org_name="Corp",
        scopes_acknowledged=["User.Read.All"],
        scan_authorized_at="2026-01-01T00:00:00+00:00",
        engagement_id="eng-001",
        receipt_hmac="aa" * 32,
    )


def _make_manifest() -> SignedManifest:
    return SignedManifest(
        manifest_id="abc",
        endpoints_called=["/users"],
        record_counts={"/users": 10},
        call_timestamps={"/users": "2026-01-01T00:00:00+00:00"},
        response_structure_hashes={"/users": "hash1"},
        manifest_hmac="bb" * 32,
        signed_at="2026-01-01T00:00:00+00:00",
    )


def _make_finding(fid: str) -> Finding:
    return Finding(
        finding_id=fid,
        control_id="CTRL-001",
        framework_refs=[],
        severity="high",
        title="Test Finding",
        evidence_summary="summary",
        affected_count=1,
        affected_entities=[],
        recommendation="fix it",
        remediation_effort="low",
        remediation_owner="IT",
        evidence_refs=[],
    )


def test_scan_result_tenant_id_not_plaintext():
    tenant_id = "my-secret-tenant-id"
    result = build_scan_result(
        tenant_id=tenant_id,
        engagement_id="eng-001",
        receipt=_make_receipt(),
        scopes_authorized=["User.Read.All"],
        scopes_in_token=["User.Read.All"],
        pages_fetched={},
        endpoints_called=[],
        scan_initiated_at="2026-01-01T00:00:00+00:00",
        all_findings=[],
        all_evidence=[],
        analyzer_outputs=AnalyzerOutputs(),
        manifest=_make_manifest(),
    )
    assert tenant_id not in result.tenant_id_hash
    assert len(result.tenant_id_hash) == 64  # sha256 hex


def test_delta_new_finding_marked():
    finding = _make_finding("fid1")
    annotated = _apply_delta(
        [finding], baseline_finding_ids=set(), baseline_scan_id="scan0"
    )
    assert annotated[0].delta_status == "new"


def test_delta_persisted_finding_marked():
    finding = _make_finding("fid1")
    annotated = _apply_delta(
        [finding], baseline_finding_ids={"fid1"}, baseline_scan_id="scan0"
    )
    assert annotated[0].delta_status == "persisted"
    assert annotated[0].first_seen_scan_id == "scan0"


def test_scan_result_has_schema_version():
    result = build_scan_result(
        tenant_id="tid",
        engagement_id="eng",
        receipt=_make_receipt(),
        scopes_authorized=[],
        scopes_in_token=[],
        pages_fetched={},
        endpoints_called=[],
        scan_initiated_at="2026-01-01T00:00:00+00:00",
        all_findings=[],
        all_evidence=[],
        analyzer_outputs=AnalyzerOutputs(),
        manifest=_make_manifest(),
    )
    assert result.schema_version == "1.0"
    assert result.scan_type == "msgraph_v1"
