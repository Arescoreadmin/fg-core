"""Timeline Authority — PR 14.6.2: Canonical Governance Ledger."""

from __future__ import annotations

_SCHEMA_EXPORTS = {
    "TimelineSourceSystem",
    "TimelineEntityType",
    "TimelineSeverity",
    "TimelineActorType",
    "TimelineAuthorityLevel",
    "TimelineAuthorityError",
    "TimelineEventNotFound",
    "TimelineConflict",
    "TimelineIntegrityError",
    "TimelineTenantViolation",
    "TimelineEventRecordRequest",
    "TimelineEventResponse",
    "TimelineReplayResponse",
    "TimelineExportResponse",
    "TimelineIntegrityResponse",
    "TimelineStatisticsResponse",
}

_ENGINE_EXPORTS = {
    "TimelineAuthorityEngine",
    "SOURCE_REGISTRY",
}

_REPOSITORY_EXPORTS = {
    "TimelineAuthorityRepository",
    "derive_event_id",
    "compute_event_hash",
}

_ALL = _SCHEMA_EXPORTS | _ENGINE_EXPORTS | _REPOSITORY_EXPORTS


def __getattr__(name: str):
    if name in _SCHEMA_EXPORTS:
        from services.timeline_authority import schemas as _schemas

        return getattr(_schemas, name)
    if name in _ENGINE_EXPORTS:
        from services.timeline_authority import engine as _engine

        return getattr(_engine, name)
    if name in _REPOSITORY_EXPORTS:
        from services.timeline_authority import repository as _repository

        return getattr(_repository, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_ALL)
