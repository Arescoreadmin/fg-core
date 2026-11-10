from types import SimpleNamespace

from api.field_assessment import _questionnaire_coverage_metrics


def test_coverage_percentage_uses_applicable_controls_only() -> None:
    responses = [
        SimpleNamespace(control_id="GOVERN-1.1", response_status="implemented"),
        SimpleNamespace(control_id="GOVERN-1.2", response_status="partial"),
        SimpleNamespace(control_id="MAP-1.1", response_status="not_assessed"),
        SimpleNamespace(control_id="MAP-1.2", response_status="not_applicable"),
    ]

    denominator, percentage, controls, implemented = _questionnaire_coverage_metrics(
        responses
    )

    assert denominator == 3
    assert percentage == 33.3
    assert controls == {"GOVERN-1.1", "GOVERN-1.2", "MAP-1.1"}
    assert implemented == {"GOVERN-1.1"}


def test_empty_or_all_not_applicable_coverage_is_unavailable() -> None:
    for responses in (
        [],
        [SimpleNamespace(control_id="GOVERN-1.1", response_status="not_applicable")],
    ):
        assert _questionnaire_coverage_metrics(responses) == (0, None, set(), set())
