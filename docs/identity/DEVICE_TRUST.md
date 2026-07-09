# Device Trust Registry

`DeviceTrustRegistry` (`api/identity_governance/devices.py`) tracks
registered devices, their trust state, and a deterministic risk score
computed from the state alone.

## Trust states and risk scores

| State         | Risk score |
|---------------|-----------:|
| `TRUSTED`     |       0.00 |
| `KNOWN`       |       0.10 |
| `UNKNOWN`     |       0.40 |
| `SUSPICIOUS`  |       0.70 |
| `COMPROMISED` |       0.95 |
| `REVOKED`     |       1.00 |

Scores are pure functions of the trust state — `_compute_risk_score` never
consults external state, so identical inputs always yield identical scores.

## Fingerprint policy

Raw device fingerprints are **never** stored, transmitted, or logged by the
registry. Callers must hash the fingerprint (SHA-256 with an appropriate
per-tenant pepper) before invoking `register_device()`. The registry stores
the hash verbatim in `DeviceRecord.fingerprint_hash`.

The digital-twin exporter (`IdentityDigitalTwinExporter`) drops any
`fingerprint`/`fingerprint_hash` key from `identity_summary` and never
serializes `DeviceRecord.fingerprint_hash` to the snapshot output.

## Tenant isolation

Every read and write requires an explicit `tenant_id`. Cross-tenant reads
return `None`; cross-tenant updates raise `ValueError`. Devices are stored
in a `(tenant_id, device_id)` keyed map so tenant contamination is
impossible by construction.

## Revocation

`revoke_device()` transitions the device to `REVOKED` and records a
`reason` + `actor`. The session evaluator (`SessionEvaluator.evaluate`)
short-circuits to `DENY` on any `REVOKED` device and to `STEP_UP_REQUIRED`
on `COMPROMISED` devices before any MFA or risk checks are performed.

## Persistence

Phase 1 is in-memory. Migration `0148_identity_governance.sql` provisions
the `identity_devices` table with `tenant_id`, `subject`,
`fingerprint_hash`, `user_agent_hash`, and `trust_state` columns, plus RLS
on `tenant_id = current_setting('app.tenant_id', true)`.
