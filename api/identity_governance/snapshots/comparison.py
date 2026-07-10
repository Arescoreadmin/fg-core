"""api/identity_governance/snapshots/comparison.py — Deterministic snapshot comparison."""
from __future__ import annotations

import dataclasses
import json
import logging
import warnings
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("frostgate.identity_governance.snapshots.comparison")


class SnapshotVersionError(Exception):
    """Raised when schema versions are incompatible for comparison."""


class SnapshotSourceVersionWarning(UserWarning):
    """Emitted when source versions differ (comparison may not be meaningful)."""


@dataclass(frozen=True)
class FieldChange:
    field: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class SnapshotDiff:
    snapshot_type: str
    schema_version: str
    fields_added: tuple[str, ...]
    fields_removed: tuple[str, ...]
    fields_changed: tuple[FieldChange, ...]
    is_compatible: bool
    same_source_version: bool


class SnapshotComparisonEngine:
    """Compare two snapshots of the same type deterministically.

    Rules:
    - Raises SnapshotVersionError if schema_versions differ
    - Warns if source_versions differ
    - Raises TypeError if snapshot types differ
    - Produces SnapshotDiff with deterministic (sorted) field lists
    """

    def compare(self, a: Any, b: Any) -> SnapshotDiff:
        if type(a) is not type(b):
            raise TypeError(
                f"Cannot compare snapshots of different types: "
                f"{type(a).__name__} vs {type(b).__name__}"
            )

        if not dataclasses.is_dataclass(a) or isinstance(a, type):
            raise TypeError(f"Expected dataclass instances, got {type(a)}")

        meta_a = getattr(a, "meta", None)
        meta_b = getattr(b, "meta", None)

        schema_a = getattr(meta_a, "schema_version", "") if meta_a else ""
        schema_b = getattr(meta_b, "schema_version", "") if meta_b else ""
        source_a = getattr(meta_a, "source_version", "") if meta_a else ""
        source_b = getattr(meta_b, "source_version", "") if meta_b else ""

        if schema_a != schema_b:
            raise SnapshotVersionError(
                f"Incompatible schema versions: {schema_a!r} vs {schema_b!r}"
            )

        same_source = source_a == source_b
        if not same_source:
            warnings.warn(
                f"Source versions differ: {source_a!r} vs {source_b!r}; "
                "comparison may not be semantically meaningful.",
                SnapshotSourceVersionWarning,
                stacklevel=2,
            )

        # Extract data fields (exclude meta) from both snapshots
        fields_a = self._extract_data_fields(a)
        fields_b = self._extract_data_fields(b)

        keys_a = set(fields_a)
        keys_b = set(fields_b)

        added = sorted(keys_b - keys_a)
        removed = sorted(keys_a - keys_b)

        changed: list[FieldChange] = []
        for key in sorted(keys_a & keys_b):
            val_a = self._serialize_value(fields_a[key])
            val_b = self._serialize_value(fields_b[key])
            if val_a != val_b:
                changed.append(FieldChange(field=key, old_value=val_a, new_value=val_b))

        # Sort changes deterministically by field name
        changed.sort(key=lambda c: c.field)

        return SnapshotDiff(
            snapshot_type=type(a).__name__,
            schema_version=schema_a,
            fields_added=tuple(added),
            fields_removed=tuple(removed),
            fields_changed=tuple(changed),
            is_compatible=True,  # schema versions matched (otherwise we'd have raised)
            same_source_version=same_source,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_data_fields(self, snapshot: Any) -> dict[str, Any]:
        """Return non-meta fields as a dict."""
        return {
            f.name: getattr(snapshot, f.name)
            for f in dataclasses.fields(snapshot)
            if f.name != "meta"
        }

    def _serialize_value(self, value: Any) -> str:
        """Serialize a single field value to a canonical string for comparison."""
        from api.identity_governance.snapshots.serializer import _to_serializable

        serializable = _to_serializable(value)
        return json.dumps(serializable, sort_keys=True, separators=(",", ":"))
