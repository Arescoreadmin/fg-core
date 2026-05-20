"""Tests for msgraph scan report generator."""

from __future__ import annotations

import json


from services.connectors.msgraph.report import (
    REPORT_TYPE,
    VERIFY_BASE_URL,
    generate_report,
    report_to_json,
)
from services.connectors.msgraph.schema.scan_result import (
    AcknowledgmentReceipt,
    Finding,
    ScanResult,
)


def _make_receipt(hmac: str = "deadbeef" * 8) -> AcknowledgmentReceipt:
    return AcknowledgmentReceipt(
        operator_name="Test Operator",
        operator_org="TestOrg",
        client_org_name="ClientOrg",
        scopes_acknowledged=["User.Read.All", "Policy.Read.All"],
        scan_authorized_at="2026-05-20T00:00:00+00:00",
        engagement_id="eng-0001",
        receipt_hmac=hmac,
    )


def _make_finding(
    severity: str = "high",
    finding_id: str = "f001",
    title: str = "Test Finding",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        control_id="NIST-AI-RMF-GOVERN-1.2",
        framework_refs=["NIST-AI-RMF", "HIPAA-164.312(d)"],
        severity=severity,  # type: ignore[arg-type]
        title=title,
        evidence_summary="1 account affected",
        affected_count=1,
        recommendation="Enforce MFA immediately",
        remediation_effort="low",
        remediation_owner="IT",
        delta_status="new",
    )


def _make_scan(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scan_id="scan-abc123",
        tenant_id_hash="a" * 64,
        engagement_id="eng-0001",
        operator_acknowledgment_receipt=_make_receipt(),
        scan_initiated_at="2026-05-20T00:00:00+00:00",
        scan_completed_at="2026-05-20T00:05:00+00:00",
        scan_duration_seconds=300,
        scopes_authorized=["User.Read.All", "Policy.Read.All"],
        scopes_in_token=["User.Read.All", "Policy.Read.All"],
        findings=findings or [],
    )


class TestGenerateReport:
    def test_report_contains_posture_score(self) -> None:
        scan = _make_scan([_make_finding("critical")])
        report = generate_report(scan, scan_result_id="sr-001")
        assert 0 <= report.posture_overall <= 100
        assert report.posture_band in ("good", "fair", "poor", "critical")

    def test_verification_url_contains_manifest_hash(self) -> None:
        scan = _make_scan()
        report = generate_report(scan, scan_result_id="sr-002")
        assert report.verification_url == f"{VERIFY_BASE_URL}/{report.manifest_hash}"
        assert len(report.manifest_hash) == 64  # sha256 hex

    def test_no_plaintext_tenant_id_in_report(self) -> None:
        raw_tenant_id = "00000000-0000-0000-0000-000000000001"
        scan = _make_scan()
        report = generate_report(scan, scan_result_id="sr-003")
        report_str = json.dumps(report_to_json(report))
        assert raw_tenant_id not in report_str
        assert report.tenant_id_hash == "a" * 64  # hash only

    def test_findings_sorted_critical_first(self) -> None:
        findings = [
            _make_finding("low", finding_id="f-low", title="Low finding"),
            _make_finding("critical", finding_id="f-crit", title="Critical finding"),
            _make_finding("high", finding_id="f-high", title="High finding"),
        ]
        scan = _make_scan(findings)
        report = generate_report(scan, scan_result_id="sr-004")
        severities = [f["severity"] for f in report_to_json(report)["findings"]]
        assert severities[0] == "critical"
        assert severities[1] == "high"
        assert severities[2] == "low"

    def test_report_is_deterministic(self) -> None:
        scan = _make_scan([_make_finding("high")])
        report1 = generate_report(scan, scan_result_id="sr-005")
        report2 = generate_report(scan, scan_result_id="sr-005")
        # manifest_hash must be identical across runs (generated_at excluded)
        assert report1.manifest_hash == report2.manifest_hash
        assert report1.report_id == report2.report_id
        assert report1.posture_overall == report2.posture_overall

    def test_operator_receipt_hmac_present(self) -> None:
        hmac = "cafebabe" * 8
        scan = _make_scan()
        scan = scan.model_copy(
            update={"operator_acknowledgment_receipt": _make_receipt(hmac=hmac)}
        )
        report = generate_report(scan, scan_result_id="sr-006")
        assert report.operator_receipt_hmac == hmac

    def test_framework_refs_deduplicated(self) -> None:
        findings = [
            _make_finding("high", finding_id="f1"),
            _make_finding("medium", finding_id="f2"),
        ]
        scan = _make_scan(findings)
        report = generate_report(scan, scan_result_id="sr-007")
        # "NIST-AI-RMF" and "HIPAA-164.312(d)" appear in both findings → deduplicated
        assert len(report.framework_refs) == len(set(report.framework_refs))

    def test_report_type_is_correct(self) -> None:
        scan = _make_scan()
        report = generate_report(scan, scan_result_id="sr-008")
        assert report.report_type == REPORT_TYPE

    def test_report_to_json_serializable(self) -> None:
        scan = _make_scan([_make_finding("critical")])
        report = generate_report(scan, scan_result_id="sr-009")
        d = report_to_json(report)
        # Must be JSON-serializable without error
        serialized = json.dumps(d)
        assert "manifest_hash" in serialized
        assert "verification_url" in serialized
        assert "posture_overall" in serialized

    def test_different_scan_result_ids_produce_different_report_ids(self) -> None:
        scan = _make_scan()
        report1 = generate_report(scan, scan_result_id="sr-a")
        report2 = generate_report(scan, scan_result_id="sr-b")
        assert report1.report_id != report2.report_id
        assert report1.manifest_hash != report2.manifest_hash
