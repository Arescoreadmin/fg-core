"""Immutable helpers for Governance Digital Twin payloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, NoReturn


class FrozenDict(dict[str, Any]):
    """JSON-serializable immutable mapping."""

    def _immutable_error(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("FrozenDict is immutable")

    def __setitem__(self, key: str, value: Any) -> None:
        self._immutable_error(key, value)

    def __delitem__(self, key: str) -> None:
        self._immutable_error(key)

    def clear(self) -> None:
        self._immutable_error()

    def pop(self, key: str, default: Any = None) -> Any:
        self._immutable_error(key, default)

    def popitem(self) -> tuple[str, Any]:
        self._immutable_error()

    def setdefault(self, key: str, default: Any = None) -> Any:
        self._immutable_error(key, default)

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._immutable_error(*args, **kwargs)


def deep_freeze(payload: Any) -> Any:
    if isinstance(payload, FrozenDict):
        return payload
    if isinstance(payload, Mapping):
        return FrozenDict(
            {
                str(key): deep_freeze(value)
                for key, value in sorted(payload.items(), key=lambda item: str(item[0]))
            }
        )
    if isinstance(payload, Sequence) and not isinstance(
        payload, (str, bytes, bytearray)
    ):
        return tuple(deep_freeze(item) for item in payload)
    return payload
