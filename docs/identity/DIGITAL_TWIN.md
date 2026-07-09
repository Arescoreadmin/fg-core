# Identity Digital Twin

`IdentityDigitalTwinExporter` (`api/identity_governance/digital_twin.py`)
emits a deterministic, tenant-scoped snapshot of everything the
governance plane knows about a subject. The snapshot is intended for
downstream use in audit exports, dashboards, and forensic replay.

## Schema

`DigitalTwinSnapshot` carries:

- `subject`, `tenant_id`, `generated_at`
- `identity_summary` — sorted `(key, value)` pairs, secret-shaped keys
  dropped
- `lifecycle_state` — from `IdentityLifecycleState`
- `roles`, `permissions`, `capabilities` — sorted tuples of strings
- `device_records` — one entry per tenant-matched device (with
  `device_id`, `trust_state`, `risk_score`, `user_agent_hash`,
  `registered_at`, `updated_at`). Raw fingerprints and fingerprint hashes
  are **never** included.
- `active_sessions_count`
- `risk_score` — optional `RiskScore` reference
- `active_break_glass_count`
- `recent_timeline_events` — up to 20 most-recent tenant-scoped events
- `assessments_count`, `evidence_count`
- `fingerprint` — SHA-256 over the structural content (see below)

## Fingerprinting

The `fingerprint` field is a SHA-256 over the concatenated structural
content of the snapshot. It **excludes** `generated_at` so identical
structural content always produces identical fingerprints across
snapshots.

## No-secrets rule

The exporter drops any key in `identity_summary` whose lowercase name is
one of:

```
token, secret, password, key, access_token, refresh_token,
id_token, client_secret, authorization, cookie, fingerprint
```

`test_digital_twin.py::test_no_secrets_in_summary` and
`test_no_raw_fingerprint_in_device_records` enforce this at test time.

## Tenant isolation

The exporter accepts arbitrary iterables of devices and timeline events
but internally filters both to `tenant_id`. A snapshot for `tenant-a`
never contains `tenant-b` data even if the caller mistakenly passes both.

## Deterministic ordering

Roles, permissions, and capabilities are sorted. Device records are
sorted by `device_id`. Timeline events preserve chronological order,
capped at the last 20. Identity-summary attributes are sorted by key.
