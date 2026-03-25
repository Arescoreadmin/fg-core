# FrostGate Canonical Audit Event Model

## 1) Global Audit Event Contract

Every audit event MUST include:
- `event_id` (globally unique)
- `tenant_id` (required for tenant-owned action; explicit `global` class only for approved global admin ops)
- `actor_id` (human principal id or service/device id)
- `actor_type` (`human|service|agent|system`)
- `timestamp` (UTC ISO8601)
- `action` (stable action code)
- `metadata` (object with type-specific fields)
- `request_id` (trace correlation id)
- `outcome` (`allowed|denied|success|failure`)

Optional integrity fields (recommended canonical):
- `prev_hash`, `entry_hash`, `signature_key_id`, `schema_version`

---

## 2) Required Event Families

### A) Auth events
**Examples**: login success/failure, session established, session revoked, authz denied.

**Metadata minimum**
- auth method
- source ip/hash
- user agent hash
- denial reason or policy id (when denied)

### B) File ingest events
**Examples**: ingest accepted, ingest rejected, ingest completed.

**Metadata minimum**
- artifact id/path/hash
- source connector or upload channel
- content class/type
- policy decisions (allow/block/review)

### C) Retrieval events
**Examples**: retrieval requested, retrieval filtered, retrieval served.

**Metadata minimum**
- retrieval/query id
- namespace/index id
- result count
- policy filters applied

### D) Provider call events
**Examples**: external model call start/end, provider failure, retry exhausted.

**Metadata minimum**
- provider name/model
- token/usage counts (if applicable)
- latency/cost class
- error code and retry count

### E) Admin actions
**Examples**: policy change, key rotation, tenant config update, break-glass action.

**Metadata minimum**
- target resource type/id
- before/after summary hash
- reason/ticket reference
- approval marker when required

### F) Agent lifecycle events
**Examples**: agent enrolled, heartbeat accepted, command issued, command acked, device revoked.

**Metadata minimum**
- device id
- agent version/ring
- command id (if applicable)
- attestation or trust state

---

## 3) Audit Enforcement Rules

1. No security-relevant action without an audit event.
2. Audit writes are fail-closed for privileged/admin operations.
3. Audit queries are tenant-scoped by default; global scope requires explicit elevated path and audit.
4. Event schemas are versioned; unknown schema versions are rejected or quarantined.
5. Time source must be UTC and monotonic-safe in pipeline ordering logic.

---

## 4) Retention and Access

1. Retention policy must be configurable per compliance tier but never below minimum regulatory baseline.
2. Redaction must preserve forensic usefulness (hash/tokenization instead of destructive deletion where possible).
3. Audit export artifacts must remain tenant-scoped unless explicit approved global export flow is used.
