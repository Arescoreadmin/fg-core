# Governance Snapshot Contract

**Package:** `api.identity_governance.snapshots`
**Schema versions:** identity/1.0, risk/1.0, graph/1.0, policy/1.0, digital_twin/1.0

---

## Overview

Every FrostGate subsystem snapshot must use the canonical snapshot contract defined in `api/identity_governance/snapshots/`. This contract guarantees:

- Deterministic serialization (byte-for-byte identical across calls)
- Tamper-evident fingerprinting (SHA-256 of data fields, excluding meta)
- Secret detection before storage or transmission
- Schema-version-aware comparison with deterministic diffs
- A single registry mapping types to their schema/source versions

---

## Canonical Snapshot Types

| Type | Schema Version | Source Version |
|---|---|---|
| `IdentitySnapshot` | identity/1.0 | identity/1.0.0 |
| `RiskSnapshot` | risk/1.0 | risk/1.0.0 |
| `GraphSnapshot` | graph/1.0 | graph/1.0.0 |
| `PolicySnapshot` | policy/1.0 | policy/1.0.0 |
| `DigitalTwinSnapshot` | digital_twin/1.0 | digital_twin/1.0.0 |

Every snapshot type starts with `meta: SnapshotMeta` as its first field.

---

## SnapshotMeta Envelope

```python
@dataclass(frozen=True)
class SnapshotMeta:
    tenant_id: str           # Required: tenant scope
    generated_at: datetime   # UTC; EXCLUDED from fingerprint
    fingerprint: str         # SHA-256 hex of data fields
    schema_version: str      # e.g. "identity/1.0"
    replay_version: str      # hash of inputs (16-char hex)
    source_version: str      # e.g. "identity/1.0.0"
    snapshot_id: str = ""
    generated_by: str = ""
    correlation_id: str = ""
    classification: str = "internal"
    retention_class: str = "standard"
    integrity_algorithm: str = "sha256"
```

---

## Fingerprint Contract

The fingerprint is a SHA-256 hex digest of the **data fields only** (all non-meta fields). This means:

- Two snapshots with identical data but different `generated_at` timestamps have the **same fingerprint**.
- Any change to a data field changes the fingerprint.
- The meta envelope is excluded from the fingerprint computation.

```python
from api.identity_governance.snapshots import fingerprint_snapshot

fp = fingerprint_snapshot(my_snapshot)  # 64-char hex string
```

---

## Canonical Serialization

```python
from api.identity_governance.snapshots import serialize_snapshot, deserialize_snapshot

raw = serialize_snapshot(snap)               # canonical JSON, sorted keys, no whitespace
restored = deserialize_snapshot(raw, MySnapshotType)
assert restored == snap                      # round-trip equality
```

Serialization rules:
- `datetime` → UTC ISO 8601 with Z suffix, microsecond precision (`2026-07-10T12:00:00.000000Z`)
- `Enum` → `.value` (string), never the Python repr
- `tuple` → JSON array; deserialization reconstructs tuples from type hints
- `dataclass` → dict with sorted keys
- `None` → `null`

---

## Replay Version

```python
from api.identity_governance.snapshots import compute_replay_version

rv = compute_replay_version(subject, tenant_id, evaluated_at)  # 16-char hex
```

The replay version is a 16-char hex prefix of SHA-256(canonical JSON of inputs). It changes iff the inputs change, enabling detection of re-processed snapshots with identical results.

---

## Secret Validation

Before storing or transmitting any snapshot, validate it:

```python
from api.identity_governance.snapshots import SecretValidator, SnapshotValidationError

validator = SecretValidator()

try:
    validator.validate(snapshot)
except SnapshotValidationError as exc:
    # snapshot contains secret-shaped data at exc.field_path
    ...

# Or: non-raising check
if not validator.is_safe(snapshot):
    ...
```

Detected patterns:
- Key names: `password`, `token`, `secret`, `api_key`, `private_key`, `refresh_token`, `authorization`, `cookie`, `credential(s)`, `access_token`, `client_secret`, and normalized variants
- Value prefixes: `eyJ` (JWT), `sk-` (API key), `bearer `, `basic `
- Value shape: 3-segment base64url strings longer than 50 chars (JWT shape)
- Safe exceptions: `fingerprint`, `event_hash`, `previous_hash`, `fingerprint_hash`, `user_agent_hash`

---

## Snapshot Comparison

```python
from api.identity_governance.snapshots import SnapshotComparisonEngine, SnapshotVersionError

engine = SnapshotComparisonEngine()
diff = engine.compare(snapshot_a, snapshot_b)

# diff.fields_changed — sorted list of FieldChange(field, old_value, new_value)
# diff.is_compatible  — True if schema_versions matched
# diff.same_source_version — False if source versions differ (warning emitted)
```

Comparison rules:
- `SnapshotVersionError` raised if `schema_version` differs between snapshots
- `TypeError` raised if snapshot types differ
- `SnapshotSourceVersionWarning` issued if `source_version` differs
- All field lists (added, removed, changed) are sorted for determinism

---

## Registry

```python
from api.identity_governance.snapshots import get_snapshot_registry

reg = get_snapshot_registry()
entry = reg.lookup(IdentitySnapshot)
# entry.schema_version == "identity/1.0"
# entry.source_version == "identity/1.0.0"
```

Custom snapshot types can register with a local `SnapshotRegistry` instance.

---

## Compatibility with Legacy Types

`models.DigitalTwinSnapshot` (legacy, no meta) remains unchanged. The new `snapshots.DigitalTwinSnapshot` is a separate class with `SnapshotMeta`. Import from `api.identity_governance.snapshots` for all new code.

In `api/identity_governance/__init__.py`, the canonical type is imported as `CanonicalDigitalTwinSnapshot` to avoid shadowing.
