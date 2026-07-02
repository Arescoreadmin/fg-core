"""External event abstraction for the Governance Intelligence Authority.

Provider abstraction only. No vendor implementations. No I/O.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import ExternalEventType
from services.governance_intelligence.schemas import GovernanceIntelligenceValidationError


SUPPORTED_EVENT_TYPES: frozenset[str] = frozenset(
    {e.value for e in ExternalEventType}
)


def validate_external_event(
    event_type: str, source: str, payload: dict[str, Any]
) -> None:
    """Raise GovernanceIntelligenceValidationError if the event is invalid."""
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise GovernanceIntelligenceValidationError(
            f"Unsupported event_type '{event_type}'. "
            f"Supported: {sorted(SUPPORTED_EVENT_TYPES)}"
        )
    if not isinstance(source, str) or not source.strip():
        raise GovernanceIntelligenceValidationError(
            "source must be a non-empty string"
        )
    if not isinstance(payload, dict):
        raise GovernanceIntelligenceValidationError(
            "payload must be a dict"
        )


def normalize_event(
    event_type: str, source: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Normalize an event to a canonical structure."""
    validate_external_event(event_type, source, payload)
    return {
        "event_type": event_type,
        "source": source,
        "normalized_payload": {
            k: v for k, v in payload.items()
        },
        "schema_version": "1.0",
    }


class ExternalEventProviderBase:
    """Abstract base class for external event providers.

    Subclasses must implement validate_connection and fetch_events.
    No vendor implementations here — this is an abstraction layer only.
    """

    def validate_connection(self) -> bool:
        raise NotImplementedError(
            f"{type(self).__name__}.validate_connection() must be implemented by subclass"
        )

    def fetch_events(self, since: str) -> list[dict[str, Any]]:
        raise NotImplementedError(
            f"{type(self).__name__}.fetch_events() must be implemented by subclass"
        )
