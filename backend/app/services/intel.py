"""Intel-related helpers for the Frostgate API."""

from ..schemas import IntelReport


def list_reports() -> list[IntelReport]:
    """Return a curated set of intel reports for the MVP."""

    return [
        IntelReport(
            id="intel-001",
            title="Perimeter fluctuations",
            threat_level="medium",
            details="Sensors detect intermittent breaches near the northern lattice.",
        ),
        IntelReport(
            id="intel-002",
            title="Aether surge",
            threat_level="high",
            details="Energy spikes predicted within the next 12 hours require standby teams.",
        ),
        IntelReport(
            id="intel-003",
            title="Relay disruption",
            threat_level="low",
            details="Communications relay epsilon is experiencing delays; reroute traffic.",
        ),
    ]
