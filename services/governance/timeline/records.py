"""Lightweight domain records for EXPORT and REPLAY timeline adapters.

These dataclasses carry only what the adapters need to build a TimelineEvent.
They are constructed at the wiring site (reports_engine.py) and passed to
export_to_timeline_event() / replay_verify_to_timeline_event().
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExportTimelineEntry:
    """Snapshot of a governance report export at the moment it was produced."""

    tenant_id: str
    export_id: str  # e.g. "export-{manifest_hash[:16]}"
    report_id: str
    assessment_id: str | None
    export_format: str  # "pdf" | "html"
    manifest_hash: str
    export_version: str
    exported_at_iso: str  # ISO 8601 UTC


@dataclass(frozen=True)
class ReplayTimelineEntry:
    """Snapshot of a governance report replay-verify run."""

    tenant_id: str
    replay_id: str  # e.g. "replay-{actual_manifest_hash[:16]}"
    report_id: str
    assessment_id: str | None
    actual_manifest_hash: str
    expected_manifest_hash: str | None
    verified: bool
    replayed_at_iso: str  # ISO 8601 UTC
    replay_contract_version: str
