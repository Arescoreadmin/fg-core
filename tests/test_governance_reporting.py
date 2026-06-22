from __future__ import annotations

from services.framework_authority.schemas import ControlFrameworkMappingResponse


def test_reporting_fields_present_on_mapping_response_model() -> None:
    fields = ControlFrameworkMappingResponse.model_fields
    for required in (
        "framework_key",
        "framework_version",
        "control_ref",
        "coverage_level",
        "mapping_type",
        "confidence",
        "rationale",
        "mapped_at",
        "mapped_by",
    ):
        assert required in fields
