# FrostGate Canonical Service Boundary Map

## 1) Service Topology

This map defines responsibility and trust boundaries for the multi-tenant AI platform foundation.

## 2) Services

### A) admin-gateway
**Responsibility**
- Human authentication + session boundary.
- Tenant/actor context establishment.
- Admin action authorization.

**Inputs**
- Browser/console requests.
- Identity provider responses.

**Outputs**
- Authorized service-to-service calls to core-api.
- Auth/admin audit events.

**Trust boundary**
- Internet-facing human boundary.
- Trusted by core only as identity assertion source, not as data authority.

---

### B) core-api
**Responsibility**
- Business logic, tenant-scoped data access, policy enforcement.
- No human authentication.

**Inputs**
- Trusted service requests from admin-gateway and internal services.
- Worker callbacks/events.

**Outputs**
- Tenant-scoped state mutations/read responses.
- Domain/audit events.

**Trust boundary**
- Internal control/data plane boundary.
- Must verify tenant/actor context on every operation.

---

### C) ingestion workers
**Responsibility**
- Process ingest jobs and normalize artifacts per tenant.

**Inputs**
- Ingestion tasks with explicit `tenant_id` and actor provenance.

**Outputs**
- Tenant-scoped stored artifacts, indexing tasks, ingest audit events.

**Trust boundary**
- Internal async boundary; no direct human auth.
- Must reject unscoped tasks.

---

### D) connector workers
**Responsibility**
- Execute outbound connector sync/fetch/push workflows per tenant policy.

**Inputs**
- Tenant-bound connector jobs + connector credentials.

**Outputs**
- Tenant-scoped retrieved data and connector audit/provider-call events.

**Trust boundary**
- External integration edge.
- Must preserve tenant namespace isolation for credentials, rate limits, and idempotency keys.

---

### E) agent control
**Responsibility**
- Agent enrollment, command/control lifecycle, receipts, policy fetch/ack state.

**Inputs**
- Device/service-authenticated agent requests.
- Admin-issued commands from admin-gateway/core.

**Outputs**
- Tenant-scoped agent lifecycle state transitions.
- Command and receipt audit events.

**Trust boundary**
- Device-to-platform boundary.
- Never used for human login/authentication.

---

### F) audit pipeline
**Responsibility**
- Collect, normalize, persist, and export immutable/tamper-evident audit records.

**Inputs**
- Auth/admin/core/worker/provider/agent events.

**Outputs**
- Tenant-scoped audit ledger and compliance export artifacts.

**Trust boundary**
- Forensic integrity boundary.
- Must enforce append-only semantics and tenant-aware query constraints.

---

## 3) Inter-Service Flow Rules

1. Human-originated admin actions: `console -> admin-gateway -> core-api -> workers/services`.
2. Workers call core/internal services with service identity, never human credentials.
3. Every service boundary handoff must carry `tenant_id`, `actor_id`, `request_id`.
4. Any service receiving unscoped tenant-owned operation must reject (fail closed).
