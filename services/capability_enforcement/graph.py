"""services/capability_enforcement/graph.py — Capability dependency graph (P1.3).

Authoritative prerequisite graph. Mirrors _CAP_DEPENDENCIES in seeder.py — both
must be kept in sync. The graph here is the runtime enforcement copy; the seeder
copy populates the capability_dependencies DB table.

Format: { capability: [direct_prerequisites, ...] }
"""

from __future__ import annotations

from collections import deque

# Authoritative dependency graph — mirrors seeder._CAP_DEPENDENCIES.
# Update both when adding new dependencies.
DEPENDENCY_GRAPH: dict[str, list[str]] = {
    "portal.ai": ["ai.workspace"],
    "portal.rag": ["ai.rag"],
    "ai.rag": ["ai.workspace"],
    "ai.document_ingestion": ["ai.workspace"],
    "ai.agent_builder": ["ai.workspace"],
    "ai.multi_agent": ["ai.agent_builder"],
    "ai.governance": ["ai.workspace"],
    "ai.compliance_assistant": ["ai.workspace"],
    "ai.executive_advisor": ["ai.workspace"],
    "identity.scim": ["identity.sso"],
    "msp.cross_tenant_reporting": ["msp.multi_tenant"],
    "msp.tenant_switching": ["msp.multi_tenant"],
}


def get_required_capabilities(capability: str) -> list[str]:
    """Return all transitive prerequisites for *capability* (BFS, excludes self).

    For ai.multi_agent → [ai.agent_builder, ai.workspace]
    For ai.rag → [ai.workspace]
    For portal.access → []
    """
    visited: set[str] = set()
    queue: deque[str] = deque(DEPENDENCY_GRAPH.get(capability, []))
    while queue:
        dep = queue.popleft()
        if dep not in visited:
            visited.add(dep)
            queue.extend(DEPENDENCY_GRAPH.get(dep, []))
    return list(visited)


def detect_cycles() -> list[list[str]]:
    """Return all cycles in DEPENDENCY_GRAPH using DFS.

    Each returned list is one cycle in path order. Empty list means no cycles.
    """
    cycles: list[list[str]] = []
    # track: 0=unvisited, 1=in-stack, 2=done
    state: dict[str, int] = {}
    path: list[str] = []

    def _dfs(node: str) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            # found a cycle — extract the cycle from path
            idx = path.index(node)
            cycles.append(path[idx:] + [node])
            return
        state[node] = 1
        path.append(node)
        for dep in DEPENDENCY_GRAPH.get(node, []):
            _dfs(dep)
        path.pop()
        state[node] = 2

    for cap in DEPENDENCY_GRAPH:
        _dfs(cap)
    return cycles


def validate_graph() -> None:
    """Validate DEPENDENCY_GRAPH at startup.

    Raises ValueError on:
    - Any cycle
    - Any capability or dependency not in CAPABILITY_REGISTRY
    """
    from api.entitlements import CAPABILITY_REGISTRY

    cycles = detect_cycles()
    if cycles:
        raise ValueError(
            f"Capability dependency cycles detected: {cycles}. "
            "Fix DEPENDENCY_GRAPH in services/capability_enforcement/graph.py"
        )

    missing: list[str] = []
    for cap, deps in DEPENDENCY_GRAPH.items():
        if cap not in CAPABILITY_REGISTRY:
            missing.append(f"source:{cap}")
        for dep in deps:
            if dep not in CAPABILITY_REGISTRY:
                missing.append(f"target:{dep}")

    if missing:
        raise ValueError(
            f"Capability dependency graph references unknown capabilities: {missing}. "
            "Register them in CAPABILITY_REGISTRY (api/entitlements.py)"
        )
