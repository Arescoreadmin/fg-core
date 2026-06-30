"""services/report_authority/metadata.py — Platform version constants and UTC helpers.

Bump version constants on any breaking change to the report schema, manifest
format, or export bundle layout. These values are embedded in every manifest
and export bundle for offline verification and must be treated as part of the
public API surface.

_now_utc() is intentionally separate from hashing utilities — it is used only
for metadata timestamps, never inside deterministic hash payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Increment on any breaking change to the report generation pipeline.
GENERATOR_VERSION: str = "1.0.0"

# Increment on any change to the export bundle format or file layout.
EXPORT_VERSION: str = "1.0.0"

# Identifies the FrostGate core provider version embedded in manifests.
PROVIDER_VERSION: str = "frostgate-core-1.0.0"


def _now_utc() -> str:
    """Return the current UTC time as an ISO 8601 string.

    Use this for metadata fields only — never inside a payload that will be
    hashed deterministically, since the result changes on every call.
    """
    return datetime.now(tz=timezone.utc).isoformat()
