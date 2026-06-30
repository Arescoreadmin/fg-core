"""services/report_authority/validators.py — Pure validation functions for Report Authority.

No database access. No side effects. All functions raise ValueError with clear,
actionable messages on invalid input.

These validators are called by the engine before any state mutation and are
individually unit-testable without infrastructure.
"""

from __future__ import annotations


def validate_tenant_id(tenant_id: str) -> None:
    """Raise ValueError if *tenant_id* is not a non-empty string.

    The tenant_id must be a non-whitespace string of at most 255 characters.
    It is the caller's responsibility to ensure the value actually exists in
    the tenant registry — this validator only checks the structural contract.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty string.")
    if len(tenant_id) > 255:
        raise ValueError(
            f"tenant_id must be at most 255 characters; got {len(tenant_id)}."
        )


def validate_report_request(request: object) -> None:
    """Validate a GenerateReportRequest for internal consistency.

    Pydantic enforces structural contracts (types, min/max length). This
    function enforces semantic invariants that cannot be expressed in Pydantic
    field constraints.

    Raises ValueError with a descriptive message on any violation.
    """
    from services.report_authority.schemas import GenerateReportRequest

    if not isinstance(request, GenerateReportRequest):
        raise ValueError(
            f"Expected GenerateReportRequest; got {type(request).__name__}."
        )

    # assessor and reviewer must be different actors for independence
    if request.assessor_id == request.reviewer_id:
        raise ValueError(
            "assessor_id and reviewer_id must be different — "
            "the same actor cannot both assess and review a report."
        )

    # title must not be only whitespace
    if not request.title.strip():
        raise ValueError("Report title must not be blank.")

    # scope must not be only whitespace
    if not request.scope.strip():
        raise ValueError("Report scope must not be blank.")

    # objectives must not be only whitespace
    if not request.objectives.strip():
        raise ValueError("Report objectives must not be blank.")


def validate_manifest_integrity(manifest: dict[str, object]) -> bool:
    """Return True if *manifest* contains all required fields with non-None values.

    Required fields: report_id, schema_version, manifest_schema_version,
    report_hash_sha256, report_hash_sha512, generation_timestamp,
    generator_version.

    Returns False (not raises) so callers can handle partial manifests gracefully
    during imports and legacy data processing.
    """
    required_fields = (
        "report_id",
        "schema_version",
        "manifest_schema_version",
        "report_hash_sha256",
        "report_hash_sha512",
        "generation_timestamp",
        "generator_version",
    )
    for field in required_fields:
        if not manifest.get(field):
            return False
    return True


def validate_bundle_integrity(bundle_checksums: dict[str, str]) -> bool:
    """Return True if *bundle_checksums* is a non-empty dict of non-blank strings.

    Each key is a filename/artifact name; each value is a hex digest.
    Returns False (not raises) for graceful handling of corrupted export bundles.
    """
    if not bundle_checksums:
        return False
    for key, value in bundle_checksums.items():
        if not isinstance(key, str) or not key.strip():
            return False
        if not isinstance(value, str) or not value.strip():
            return False
    return True
