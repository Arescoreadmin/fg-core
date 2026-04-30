from __future__ import annotations

from services.phi_classifier.minimizer import minimize_prompt


def test_prompt_minimization_replaces_required_phi_types() -> None:
    text = (
        "Patient John Smith DOB 01/02/1980 has MRN 4872910, SSN 123-45-6789. "
        "Contact jane@example.com or 555-123-4567."
    )

    result = minimize_prompt(text)

    assert result.minimized_text == (
        "Patient [PATIENT_NAME] DOB [DATE] has MRN [MRN], SSN [SSN]. "
        "Contact [EMAIL] or [PHONE]."
    )
    assert result.changed is True
    assert result.replacement_count == 6
    assert result.placeholder_types == [
        "DATE",
        "EMAIL",
        "MRN",
        "PATIENT_NAME",
        "PHONE",
        "SSN",
    ]
    assert result.minimization_version == "prompt_minimization_v1"


def test_prompt_minimization_clean_text_unchanged() -> None:
    result = minimize_prompt("Summarize quarterly report")

    assert result.minimized_text == "Summarize quarterly report"
    assert result.changed is False
    assert result.replacements == ()
    assert result.replacement_count == 0
    assert result.placeholder_types == []


def test_prompt_minimization_repeated_values_are_deterministic() -> None:
    text = "SSN 123-45-6789 repeats 123-45-6789"

    first = minimize_prompt(text)
    second = minimize_prompt(text)

    assert first == second
    assert first.minimized_text == "SSN [SSN] repeats [SSN]"
    assert first.replacement_count == 2


def test_prompt_minimization_overlapping_and_adjacent_spans_are_safe() -> None:
    text = "MRN:4872910 123-45-6789.555-123-4567"

    result = minimize_prompt(text)

    assert result.minimized_text == "MRN:[MRN] [SSN].[PHONE]"
    assert result.replacement_count == 3


def test_prompt_minimization_metadata_excludes_raw_values() -> None:
    text = "Patient Jane Doe DOB 03/22/1990 has SSN 987-65-4321"

    result = minimize_prompt(text)
    metadata_payload = str(result.replacements)

    assert "Jane Doe" not in metadata_payload
    assert "03/22/1990" not in metadata_payload
    assert "987-65-4321" not in metadata_payload
    assert "Jane Doe" not in result.minimized_text
    assert "03/22/1990" not in result.minimized_text
    assert "987-65-4321" not in result.minimized_text


def test_prompt_minimization_non_string_fails_closed() -> None:
    result = minimize_prompt(None)  # type: ignore[arg-type]

    assert result.minimized_text == ""
    assert result.changed is True
    assert result.replacement_count == 0
    assert result.reason_code == "PROMPT_MINIMIZATION_NON_STRING"


def test_prompt_minimization_empty_string_unchanged() -> None:
    result = minimize_prompt("")

    assert result.minimized_text == ""
    assert result.changed is False
    assert result.reason_code == "PROMPT_MINIMIZATION_EMPTY"
