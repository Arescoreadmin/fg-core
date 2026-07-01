"""Dependency graph helpers.

Detects cycles in a proposed dependency graph and computes reachability.
Everything here is pure and deterministic.
"""

from __future__ import annotations

from services.remediation_authority.schemas import RemediationDependencyError


Edge = tuple[str, str]


def would_create_cycle(
    existing_edges: list[Edge],
    new_edge: Edge,
) -> bool:
    """Return True if adding ``new_edge`` to ``existing_edges`` creates a cycle.

    Uses DFS from the target of the new edge; if the DFS reaches the source
    following existing edges, a cycle would be formed.
    """
    source, target = new_edge
    if source == target:
        return True
    adjacency: dict[str, list[str]] = {}
    for src, dst in existing_edges:
        adjacency.setdefault(src, []).append(dst)
    stack: list[str] = list(adjacency.get(target, []))
    seen: set[str] = set()
    while stack:
        node = stack.pop()
        if node == source:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(adjacency.get(node, []))
    return False


def check_no_cycle(existing_edges: list[Edge], new_edge: Edge) -> None:
    """Raise RemediationDependencyError if the new edge would create a cycle."""
    if would_create_cycle(existing_edges, new_edge):
        raise RemediationDependencyError(
            f"Dependency {new_edge[0]} -> {new_edge[1]} would create a cycle"
        )


def blockers_of(task_id: str, edges: list[Edge]) -> list[str]:
    """Return the sorted list of task ids that directly block ``task_id``."""
    return sorted({src for src, dst in edges if dst == task_id})


def dependents_of(task_id: str, edges: list[Edge]) -> list[str]:
    """Return the sorted list of task ids that depend on ``task_id`` directly."""
    return sorted({dst for src, dst in edges if src == task_id})


def critical_path(edges: list[Edge], starts: list[str]) -> list[str]:
    """Return the deterministic longest path forward from ``starts``.

    Ties broken by lexicographic task id. Returns nodes in traversal order.
    """
    adjacency: dict[str, list[str]] = {}
    for src, dst in edges:
        adjacency.setdefault(src, []).append(dst)
    for node in adjacency:
        adjacency[node] = sorted(set(adjacency[node]))
    best: list[str] = []

    def dfs(node: str, path: list[str], seen: set[str]) -> None:
        nonlocal best
        if node in seen:
            return
        path.append(node)
        seen.add(node)
        children = adjacency.get(node, [])
        if not children and len(path) > len(best):
            best = list(path)
        for child in children:
            dfs(child, path, seen)
        path.pop()
        seen.discard(node)

    for start in sorted(set(starts)):
        dfs(start, [], set())
    return best
