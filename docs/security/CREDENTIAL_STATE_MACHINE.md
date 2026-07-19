# Credential State Machine

Diagrams only. Implementation details belong in `CREDENTIAL_AUTHORITY.md`.

---

## Credential lifecycle

```
             issued
               │
               ▼
           ┌───────┐
           │pending│  (activation deadline = expires_at)
           └───────┘
               │
       activated│         expires_at passed
               │◄────────────────────────────┐
               ▼                             │
           ┌──────┐                     ┌─────────┐
           │active│────────────────────►│ expired │
           └──────┘    expires_at       └─────────┘
               │       passed
               │
       ┌───────┼───────────┐
       │                   │
       ▼                   ▼
  ┌─────────┐         ┌─────────┐
  │ rotated │         │ revoked │
  └─────────┘         └─────────┘

pending, rotated, revoked, expired — terminal states.
No transition back to active from any terminal state.

If a credential class requires no activation step,
issue directly as active (skip pending).
```

---

## Rotation — generation sequence

```
  Slot: production-primary
  Type: tenant_api_key

  ┌─────────────────────────────────────┐
  │  Generation 3          (rotated)    │
  │  valid_from:  T₀                    │
  │  valid_until: T₁  ◄── set at       │
  │  status:      rotated    rotation   │
  │  replaced_by: gen-4-id             │
  └─────────────────────────────────────┘
               │ replaced_by
               ▼
  ┌─────────────────────────────────────┐
  │  Generation 4          (active)     │
  │  valid_from:  T₁                    │
  │  valid_until: T₁ + TTL             │
  │  status:      active                │
  │  replaced_by: null                  │
  └─────────────────────────────────────┘

  Immediate cutover (default):
    old valid_until = now()
    new valid_from  = now()
    no overlap window

  Bounded overlap (explicit, audited):
    old valid_until = now() + grace_period
    new valid_from  = now()
    max 2 active generations per slot
    grace_period is bounded and logged
```

---

## Slot serialization — concurrency

```
  Thread A              credential_slots row          Thread B
  ────────              ────────────────────          ────────

  SELECT FOR UPDATE ──► [locked]
                        current_generation = 3
  insert gen 4
  UPDATE slots
    SET current_generation = 4
    WHERE current_generation = 3
                        current_generation = 4        SELECT FOR UPDATE
  COMMIT                [released]                    [acquired]
                                                      current_generation = 4
                                                      insert gen 5
                                                      UPDATE slots
                                                        SET current_generation = 5
                                                        WHERE current_generation = 4
                                                      COMMIT

  Concurrent rotation attempt (rowcount = 0 on UPDATE):
    raise CredentialConflictError → caller retries
```

---

## Validation path

```
  presented raw credential
          │
          ▼
  parse secret_part
  (last dot-segment of fgk.<payload>.<secret>)
          │
          ▼
  compute lookup_fingerprint
  HMAC-SHA256(secret_part, pepper)
          │
          ▼
  indexed lookup
  SELECT tenant_credentials JOIN tenants
  WHERE lookup_fingerprint = :fingerprint
          │
          ├── not found ──► reject (constant-time)
          │
          ▼
  verify secret_hash
  Argon2id constant-time compare
          │
          ├── mismatch ──► reject
          │
          ▼
  enforce status
  status = 'active'
  AND (expires_at IS NULL OR expires_at > now())
          │
          ├── inactive / expired ──► reject
          │
          ▼
  enforce tenant lifecycle
  t.lifecycle_state ∈ {active}  (suspended/archived/deleted → reject)
          │
          ├── denied ──► reject + emit denied_tenant_state telemetry
          │
          ▼
  return CredentialPrincipal
  (never the raw row, never the hash)
```

---

## Expiration enforcement — two layers

```
  Request time (primary, always enforced):

    expires_at IS NULL  ──► allow (no expiry)
           │
    expires_at > now()  ──► allow
           │
    expires_at ≤ now()  ──► reject immediately
                            (row status may still read 'active')

  Scheduled sweep (normalization, not enforcement):

    SELECT WHERE status = 'active'
             AND expires_at ≤ now()
          ──► UPDATE status = 'expired'
          ──► emit 'expired' audit event
          ──► idempotent: skip rows already expired
```

---

## Audit event flow

```
  Authoritative lifecycle events          Security telemetry
  (tenant_credential_events table)        (structured logs / pipeline)
  ─────────────────────────────           ──────────────────────────
  issued                                  validated
  activated                               validation_failed
  rotated
  revoked
  expired
  denied_tenant_state

  Lifecycle events: one per state change.
  Telemetry: one per request (high volume — not written to audit table).
```
