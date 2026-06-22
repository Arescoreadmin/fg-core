from __future__ import annotations

from services.framework_authority.schemas import MappingAuditEventType


def test_framework_authority_audit_events_cover_mapping_lifecycle() -> None:
    values = {member.value for member in MappingAuditEventType}
    assert values >= {
        "CREATED",
        "UPDATED",
        "ACTIVATED",
        "SUPERSEDED",
        "REJECTED",
        "RETIRED",
    }
