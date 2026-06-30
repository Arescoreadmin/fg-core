"""Transparency store protocol and in-memory implementation.

Protocol: append-only; no updates, no deletes.
Duplicate entry_id raises ValueError immediately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from services.cgin.transparency.entry import TransparencyEntry
    from services.cgin.transparency.root import TransparencyRoot


@runtime_checkable
class TransparencyStore(Protocol):
    """Protocol for append-only transparency log storage."""

    def append_entry(self, entry: "TransparencyEntry") -> None: ...

    def append_root(self, root: "TransparencyRoot") -> None: ...

    def get_entry(self, entry_id: str) -> "TransparencyEntry | None": ...

    def get_root(self, root_id: str) -> "TransparencyRoot | None": ...

    def get_latest_root(self) -> "TransparencyRoot | None": ...

    def all_entries(self) -> "list[TransparencyEntry]": ...

    def all_roots(self) -> "list[TransparencyRoot]": ...

    def entry_count(self) -> int: ...

    def root_count(self) -> int: ...


class MemoryTransparencyStore:
    """In-memory append-only store. History cannot be mutated."""

    def __init__(self) -> None:

        self._entries: dict[str, TransparencyEntry] = {}
        self._roots: dict[str, TransparencyRoot] = {}
        self._entry_order: list[str] = []  # insertion order
        self._root_order: list[str] = []

    def append_entry(self, entry: "TransparencyEntry") -> None:
        if entry.entry_id in self._entries:
            raise ValueError(f"Duplicate entry_id: {entry.entry_id}")
        self._entries[entry.entry_id] = entry
        self._entry_order.append(entry.entry_id)

    def append_root(self, root: "TransparencyRoot") -> None:
        if root.root_id in self._roots:
            raise ValueError(f"Duplicate root_id: {root.root_id}")
        self._roots[root.root_id] = root
        self._root_order.append(root.root_id)

    def get_entry(self, entry_id: str) -> "TransparencyEntry | None":
        return self._entries.get(entry_id)

    def get_root(self, root_id: str) -> "TransparencyRoot | None":
        return self._roots.get(root_id)

    def get_latest_root(self) -> "TransparencyRoot | None":
        if not self._root_order:
            return None
        return self._roots[self._root_order[-1]]

    def all_entries(self) -> "list[TransparencyEntry]":
        return [self._entries[eid] for eid in self._entry_order]

    def all_roots(self) -> "list[TransparencyRoot]":
        return [self._roots[rid] for rid in self._root_order]

    def entry_count(self) -> int:
        return len(self._entries)

    def root_count(self) -> int:
        return len(self._roots)
