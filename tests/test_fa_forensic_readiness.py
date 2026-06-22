from __future__ import annotations

import json

from tests.fa_forensic_helpers import SCAN_BODY, create_engagement, make_context


def test_execution_state_is_deterministic_bounded_and_schema_complete(
    build_app: object,
) -> None:
    """Repeated execution-state reads must be identical, bounded, and contain complete gate records."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    url = f"/field-assessment/engagements/{engagement['id']}/execution-state"
    first = ctx.client_a.get(url)
    second = ctx.client_a.get(url)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    state = first.json()
    repeated_state = second.json()
    assert state.pop("generated_at")
    assert repeated_state.pop("generated_at")
    assert json.dumps(state, sort_keys=True) == json.dumps(
        repeated_state, sort_keys=True
    )
    assert 0 <= state["readiness_score"] <= 100
    assert state["schema_version"] == "1.0"
    for gate in state["gates"]:
        assert {
            "gate_id",
            "status",
            "title",
            "explanation",
            "evidence_required",
            "evidence_present",
            "missing_items",
            "blocks_status_transition",
        } <= gate.keys()


def test_required_scan_gate_switches_to_passed_with_specific_evidence(
    build_app: object,
) -> None:
    """Adding the required Microsoft Graph scan must populate and pass its gate without decreasing readiness."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    state_url = f"/field-assessment/engagements/{engagement['id']}/execution-state"
    before = ctx.client_a.get(state_url).json()
    scan = ctx.client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/scan-results", json=SCAN_BODY
    )
    after = ctx.client_a.get(state_url).json()
    assert scan.status_code == 201, scan.text
    gate = next(
        item
        for item in after["gates"]
        if item["gate_id"] == "scan.microsoft_graph.required"
    )
    assert gate["status"] == "passed"
    assert gate["evidence_present"]
    assert after["readiness_score"] >= before["readiness_score"]
