"""api/identity_governance/snapshots/meta.py — Canonical SnapshotMeta envelope."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SnapshotMeta:
    """Canonical metadata envelope required on every governance snapshot.

    tenant_id           — tenant scope (required, non-empty)
    generated_at        — UTC generation timestamp; EXCLUDED from fingerprint
    fingerprint         — SHA-256 hex of canonical data payload (non-meta fields)
    schema_version      — public shape version e.g. "identity/1.0", "risk/1.0"
    replay_version      — hash of input set; changes iff inputs change
    source_version      — evaluator version e.g. "identity/1.0.0", "risk/1.0.0"
    snapshot_id         — opaque stable identifier (empty = not tracked)
    generated_by        — service/agent that generated snapshot
    correlation_id      — request correlation (empty = not tracked)
    classification      — "internal" | "confidential" | "restricted"
    retention_class     — "standard" | "extended" | "permanent"
    integrity_algorithm — always "sha256" in this implementation
    """

    tenant_id: str
    generated_at: datetime
    fingerprint: str
    schema_version: str
    replay_version: str
    source_version: str
    snapshot_id: str = ""
    generated_by: str = ""
    correlation_id: str = ""
    classification: str = "internal"
    retention_class: str = "standard"
    integrity_algorithm: str = "sha256"
