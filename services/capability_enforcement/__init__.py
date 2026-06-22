"""services/capability_enforcement — P1.3 Runtime Capability Enforcement Engine.

Provides:
    validate_graph_at_startup() — cycle detection + registry validation at boot
    get_required_capabilities() — transitive dep resolution for a capability
    DEPENDENCY_GRAPH           — authoritative capability prerequisite map
"""

from services.capability_enforcement.graph import (
    DEPENDENCY_GRAPH,
    detect_cycles,
    get_required_capabilities,
    validate_graph,
)

__all__ = [
    "DEPENDENCY_GRAPH",
    "detect_cycles",
    "get_required_capabilities",
    "validate_graph",
]
