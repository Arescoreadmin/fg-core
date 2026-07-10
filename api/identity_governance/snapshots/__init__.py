"""api/identity_governance/snapshots — Canonical governance snapshot contract.

Every future FrostGate subsystem snapshot must use this contract.
"""

from api.identity_governance.snapshots.meta import SnapshotMeta
from api.identity_governance.snapshots.types import (
    DigitalTwinSnapshot,
    GraphSnapshot,
    IdentitySnapshot,
    PolicySnapshot,
    RiskSnapshot,
)
from api.identity_governance.snapshots.serializer import (
    deserialize_snapshot,
    fingerprint_snapshot,
    serialize_snapshot,
    compute_replay_version,
)
from api.identity_governance.snapshots.registry import (
    SnapshotRegistration,
    SnapshotRegistry,
    SnapshotRegistryError,
    get_snapshot_registry,
)
from api.identity_governance.snapshots.comparison import (
    FieldChange,
    SnapshotComparisonEngine,
    SnapshotDiff,
    SnapshotSourceVersionWarning,
    SnapshotVersionError,
)
from api.identity_governance.snapshots.validator import (
    SecretValidator,
    SnapshotValidationError,
)

__all__ = [
    "SnapshotMeta",
    "DigitalTwinSnapshot",
    "GraphSnapshot",
    "IdentitySnapshot",
    "PolicySnapshot",
    "RiskSnapshot",
    "serialize_snapshot",
    "deserialize_snapshot",
    "fingerprint_snapshot",
    "compute_replay_version",
    "SnapshotRegistration",
    "SnapshotRegistry",
    "SnapshotRegistryError",
    "get_snapshot_registry",
    "FieldChange",
    "SnapshotComparisonEngine",
    "SnapshotDiff",
    "SnapshotSourceVersionWarning",
    "SnapshotVersionError",
    "SecretValidator",
    "SnapshotValidationError",
]
