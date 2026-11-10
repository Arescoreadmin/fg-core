"""Regression tests for customer-safe mapping of canonical report states."""

from api.field_assessment import _customer_report_status


def test_unapproved_and_blocked_reports_are_never_finalized() -> None:
    assert _customer_report_status({"state": "DRAFT", "qa_approved": False}) == "pending_qa"
    assert (
        _customer_report_status(
            {"state": "DRAFT", "qa_approved": True, "release_blockers": ["PROVENANCE"]}
        )
        == "release_blocked"
    )


def test_synthetic_rejected_unknown_and_limited_states_are_explicit() -> None:
    assert _customer_report_status({"state": "DRAFT_SYNTHETIC"}) == "synthetic_draft"
    assert _customer_report_status({"state": "REJECTED"}) == "rejected"
    assert _customer_report_status({"state": "MYSTERY"}) == "unknown"
    assert (
        _customer_report_status(
            {"state": "FINAL", "marking": "FINAL — QA APPROVED — LIMITED COVERAGE"}
        )
        == "finalized_limited"
    )


def test_only_authoritative_final_state_maps_to_finalized() -> None:
    assert _customer_report_status({"state": "FINAL"}) == "finalized"
    assert _customer_report_status({"state": "DRAFT", "has_pdf": True}) == "pending_qa"
