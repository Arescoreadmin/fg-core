# FrostGate Core — Data Plane Next-Level Hardening Plan

## Authoritative scope, non-goals, and assumptions

### Scope (authoritative)
- Ingest endpoint and ingress contract enforcement.
- Agent → Core channel (REST/gRPC) request integrity and replay handling.
- Redis queueing/rate-limit coordination path.
- Postgres write/read path with tenant isolation.
- Artifact generation and evidence storage path.
- Contract generation and CI contract authority path.
- Admin read plane and privileged observability surfaces.

### Non-goals
- Not redesigning the entire control plane architecture in this document.
- Not changing the auth model in this document.
- Not redefining policy doctrine content or business policy outcomes.
- Not introducing runtime code in this step (doc-only spine hardening step).

### Assumptions
- Container-per-feature boundaries remain in effect.
- REST/gRPC is primary edge protocol; NATS/Redis remains backbone queue/coordination layer.
- Auditable structured logs, health probes, and CI/CD already exist.
- Security-first fail-closed behavior is mandatory for production profile.
- Multi-tenant isolation baseline exists and is extended here with verifiable gates.

---

## Contracts: required fields, error semantics, versioning

### Required fields at ingest
`/ingest` request contract requires these fields at minimum:
- `tenant_id`
- `event_id`
- `trace_id`
- `agent_id`
- `schema_version`
- `created_at`
- `source`
- `integrity_hash` (required when payload signing/hashing mode is enabled)

### Idempotency rule
- `event_id` is client-generated and stable for the logical event.
- Deduplication key is `(tenant_id, event_id)`.
- On duplicate ingest, the service returns deterministic replay of the first persisted response (no second write side effect).

### Error semantics (stable machine codes)
- Missing `tenant_id` → HTTP 400 with `TENANT_ID_REQUIRED`.
- Missing `event_id` → HTTP 400 with `EVENT_ID_REQUIRED`.
- Missing `trace_id` → HTTP 400 with `TRACE_ID_REQUIRED`.
- Missing `schema_version` → HTTP 400 with `SCHEMA_VERSION_REQUIRED`.
- Missing `agent_id` → HTTP 400 with `AGENT_ID_REQUIRED`.
- Missing `created_at` → HTTP 400 with `CREATED_AT_REQUIRED`.
- Missing `source` → HTTP 400 with `SOURCE_REQUIRED`.
- Missing `integrity_hash` when integrity mode is enabled → HTTP 400 with `INTEGRITY_HASH_REQUIRED`.

### Versioning rule
- `schema_version` follows `major.minor` semantics.
- Accept same major with equal-or-higher minor only when fields are backward-compatible.
- Reject unknown major versions with HTTP 400 `SCHEMA_VERSION_UNSUPPORTED`.
- Rollout policy: add new version in dual-read mode, verify in DP-G-003, then switch default writer.

---

## PHASE 1 — Data Plane Threat Model

| Attack surface | Exploit scenario | Blast radius | Current mitigation | Missing mitigation | Severity (1-10) |
|---|---|---|---|---|---:|
| Ingest endpoint (`POST /ingest`) | Tenant sends valid API key but floods high-cardinality payloads + unique event IDs to exhaust CPU/DB and bypass cache locality. | Tenant-local at first, then shared DB saturation causing cross-tenant latency. | Scope enforcement and tenant binding; event ID validation; idempotent replay support; path-level rate limiting exists. | Per-tenant dynamic budgets tied to plan tier; payload-size ceiling with hard reject; p95-aware adaptive throttling; WAF signatures for malformed JSON bombs. | 9 |
| Agent → Core channel (REST/gRPC) | MITM or replay against weak client pinning path; request ID spoofing to poison trace lineage. | Single tenant plus forensic corruption if logs become ambiguous. | Client retry + request ID reuse for retries; optional TLS fingerprint support in client; auth scopes. | mTLS mandatory in prod; signed request envelope (`event_id + tenant + ts + nonce`); anti-replay nonce cache in Redis; strict clock skew policy. | 8 |
| Redis queues / coordination | Redis unavailable/partitioned causes fail-open behavior in controls that rely on Redis (rate limit, queues), or hot key DoS. | Multi-tenant service degradation + potential bypass of fairness controls. | Redis backend supported; fail-open requires explicit acknowledgement; memory fallback exists. | Remove memory fallback in prod profile; queue-depth hard-stop thresholds; Redis ACL/TLS + client certs; per-tenant queue shards + hot-key detection metric. | 9 |
| Postgres write path | Partial commit under network jitter causes decision persisted without artifact/evidence link; RLS misconfiguration leaks rows. | Cross-tenant confidentiality/integrity failure if RLS disabled; audit gap for affected tenant if partial write. | Transactional writes + unique idempotency index; tenant context setter exists. | `SET LOCAL app.tenant_id` guard trigger per tx; mandatory RLS policy test gate; outbox pattern for artifact emission atomicity; statement_timeout + lock_timeout per request class. | 10 |
| Artifact generation path | Path traversal or object key collision writes artifact outside tenant namespace; tampered artifact hash chain insertion. | Tenant evidence compromise; auditor trust failure. | Evidence artifact rows append-only; hash chain fields stored; evidence export endpoint exists. | Canonical artifact envelope signed with key ID; immutable object-lock policy; deterministic storage key format (`tenant/date/event/hash`); verify-before-serve on export. | 8 |
| Contract generation / enforcement | Undocumented endpoint added without contract update; schema changes drift and break downstream consumers silently. | Platform-wide integration break + compliance drift. | Contract authority check + drift/align gates in CI. | Consumer-driven contract tests per tier; breaking-change classifier gate; schema backward-compatibility diff gate with allowlist approvals only. | 7 |
| Admin read plane (`/admin`, dashboards) | Privileged token exfiltration exposes cross-tenant telemetry and security posture; overbroad query paths bypass tenant scoping. | Full multi-tenant metadata disclosure. | Auth/session controls in admin gateway; some scoped endpoints + audit logs. | Just-in-time elevation with expiry; row-level tenancy checks for admin queries using explicit `tenant_scope`; field-level redaction policy; immutable admin access evidence stream. | 9 |

---

## PHASE 2 — Resilience Engineering Plan

### 2.1 Backpressure strategy

#### A) Config flags
```bash
# Ingest fairness
FG_DP_INGEST_RPS_BASE=20                    # floor per tenant
FG_DP_INGEST_RPS_BURST=120
FG_DP_INGEST_RPS_TIER_OVERRIDE_JSON='{"free":10,"pro":40,"enterprise":120}'

# Queue protection
FG_DP_REDIS_QUEUE_WARN_DEPTH=5000
FG_DP_REDIS_QUEUE_SHED_DEPTH=8000
FG_DP_REDIS_QUEUE_HARDSTOP_DEPTH=12000
FG_DP_QUEUE_KEY_TEMPLATE='fg:q:{tenant_id}:{lane}'

# Circuit breaker
FG_DP_CB_ERROR_RATE_THRESHOLD=0.08          # 8% over rolling window
FG_DP_CB_LATENCY_P95_MS=350
FG_DP_CB_OPEN_SECONDS=30
FG_DP_CB_HALF_OPEN_PROBE=25

# Retry / DLQ
FG_DP_RETRY_BUDGET_PER_EVENT=5
FG_DP_RETRY_BUDGET_WINDOW_SEC=900
FG_DP_DLQ_MAX_AGE_SEC=86400
FG_DP_DLQ_ALERT_DEPTH=200
```

#### B) Metrics to track
- `frostgate_ingest_requests_total{tenant_id,plan,outcome}`
- `frostgate_ingest_rejected_total{tenant_id,reason=rate_limit|queue_hardstop|cb_open}`
- `frostgate_redis_queue_depth{tenant_id,lane}` (Gauge)
- `frostgate_circuit_state{component,tenant_id}` (0 closed / 1 half-open / 2 open)
- `frostgate_retry_budget_remaining{tenant_id,event_class}`
- `frostgate_dlq_events_total{tenant_id,reason}`

#### C) Failure behavior (fail-closed)
- Queue depth >= `SHED_DEPTH`: return `429` with deterministic retry-after derived from depth slope.
- Queue depth >= `HARDSTOP_DEPTH`: return `503` + `error_code=INGEST_BACKPRESSURE_HARDSTOP`; no enqueue.
- Circuit open: only health probes + half-open sample admitted; all other requests short-circuited.
- Retry budget depleted: event moved to DLQ with immutable evidence reason `retry_budget_exhausted`.
- Redis unavailable in prod profile: deny ingest (`503`) unless explicit emergency override signed by break-glass policy.

#### D) Code touchpoints
- `api/ratelimit.py`: add tenant-tier aware limit resolver + hard fail-closed prod mode.
- `api/ingest.py`: integrate queue-depth gate + retry-budget headers + deterministic 429/503 error envelope.
- `api/admin.py`: expose breaker + queue depth + DLQ stats API.
- `agent/core_client.py`: honor `Retry-After` + budget reason codes; bounded jitter and budget accounting.
- `jobs/*`: add DLQ reprocessor job requiring human approval token for replay.

---

### 2.2 Latency budgets

| SLO domain | Target | Hard threshold | Alert trigger | Instrumentation point | Prometheus metric |
|---|---:|---:|---|---|---|
| Agent ingest p95 | <= 120ms | 200ms | p95 > 120ms for 10m (warn), >200ms for 5m (page) | Around `/ingest` handler before/after auth + validation | `frostgate_ingest_latency_ms_bucket{phase=total}` |
| Decision pipeline p95 | <= 80ms | 150ms | p95 > 80ms for 15m, >150ms for 5m | `engine.pipeline.evaluate` phase timers (`features`, `policy`, `scoring`) | `frostgate_pipeline_phase_latency_ms_bucket{phase}` |
| DB write latency p95 | <= 40ms | 90ms | p95 > 40ms for 15m, >90ms for 5m | DB session commit wrapper in ingest/defend persistence | `frostgate_db_write_latency_ms_bucket{table}` |
| Contract validation time p95 | <= 2s in CI | 5s hard fail | >2s trend over 20 PRs (warn), >5s immediate fail | CI contract authority + drift check steps | `frostgate_ci_contract_validation_seconds_bucket{job}` |

Implementation detail: emit exemplars with `trace_id` on high-latency buckets for forensic join.

---

### 2.3 Multi-node horizontal scale

```text
                        +-------------------------------+
Agent Pods ---> LB ---> | Ingest API Pods (stateless)  | --+
                        |  - auth/tenant bind          |   |
                        |  - idempotency precheck       |   |
                        +-------------------------------+   |
                                                            v
                                                   +----------------+
                                                   | Redis Cluster  |
                                                   | shard by tenant|
                                                   +----------------+
                                                            |
                                                            v
                                                   +----------------+
                                                   | Worker Pods    |
                                                   | decision/evidence
                                                   +----------------+
                                                            |
                                                            v
                                                   +----------------+
                                                   | PgBouncer      |
                                                   +----------------+
                                                            |
                                                            v
                                                   +----------------+
                                                   | Postgres + RLS |
                                                   +----------------+
```

#### Routing strategy
- Ingest: non-sticky routing (stateless) to maximize utilization.
- Queue/worker: sticky by `tenant_id hash` for cache locality and fairness.
- gRPC internal calls: round-robin with outlier ejection.

#### Idempotency under scale
- Keep deterministic `event_id` from agent.
- Enforce unique index on `(tenant_id,event_id)` (already present in Postgres migration) and return replayed response on conflict.
- Add Redis short-lived idempotency hint cache (`SETNX` 30s) to cut duplicate DB pressure; DB remains source of truth.

#### Redis clustering strategy
- 3 master / 3 replica topology; keyslot stable hash tag by tenant: `fg:{tenant_id}:...`.
- Separate logical lanes: `ingest`, `retry`, `dlq`, `nonce`.
- Enable ACL + TLS + command renaming for dangerous ops.

#### Postgres pooling strategy
- PgBouncer transaction pooling for API pods; session pooling for migration/admin tooling.
- `max_connections` budget split by service class (`ingest`, `worker`, `admin`).
- Prepared statement strategy compatible with transaction pooling (`server_reset_query=DISCARD ALL`).

#### Scaling failure modes
- Hot tenant saturates shard: detect by queue depth skew metric; auto-throttle tenant only.
- Redis slot migration lag: temporary latency spike; breaker prevents cascade by shedding new ingest.
- Pool exhaustion: API returns 503 before timeouts via connection-acquire deadline.

#### Consistency guarantees
- Decision writes: exactly-once effect per `(tenant_id,event_id)` (idempotent exactly-once semantics).
- Queue processing: at-least-once delivery + dedupe on event ID.
- Evidence chain: append-only, per-tenant hash continuity; tamper evident.

---

## PHASE 3 — Cross-Module Telemetry Correlation

### Trace propagation design
- Canonical headers across REST/gRPC:
  - `X-Trace-Id` (UUIDv7)
  - `X-Span-Id`
  - `X-Parent-Span-Id`
  - `X-Request-Id` (logical request chain; reused across retries)
  - `X-Tenant-Id`
  - `X-Event-Id`
- Binding rule: `trace_id` immutable across all module hops for one decision path.

### Unified request envelope
```json
{
  "trace_id": "uuidv7",
  "request_id": "logical-chain-id",
  "tenant_id": "tenant-123",
  "event_id": "deterministic-event-id",
  "ingest_ts": "2026-01-01T00:00:00Z",
  "policy_hash": "sha256...",
  "config_hash": "sha256..."
}
```

### Required log correlation format
- JSON log line with stable keys (no freeform-only logs):
  - `ts`, `level`, `service`, `module`, `trace_id`, `span_id`, `request_id`, `tenant_id`, `event_id`, `decision_id`, `policy_hash`, `config_hash`, `route`, `status_code`, `latency_ms`, `error_code`, `cb_state`, `queue_depth`, `retry_budget_remaining`.

### Hash chain extension
- Extend `api/evidence_chain.py` payload inputs to include:
  - `trace_id`
  - `request_id`
  - `policy_hash`
  - `config_hash`
- Result: each evidence chain entry cryptographically binds execution telemetry to decision content.

### Evidence export linkage
- `evidence_bundles.bundle_json` includes `trace_bundle` section:
  - first span timestamp, final span timestamp, span count, and SHA-256 over normalized trace list.
- Export API adds optional `include_trace=true` to package signed trace manifest.

---

## PHASE 4 — Chaos & Failure Injection

| Chaos scenario | Expected behavior | Required guardrail | Test script outline | CI integration plan |
|---|---|---|---|---|
| Redis outage | Ingest fails closed with 503 in prod profile; no silent memory fallback. | `FG_ENV=prod` fail-closed behavior is required and verified by DP-G-007 once implemented. | Bring down Redis container during ingest load; assert 503 + structured error + no writes without queue ack. | New CI job `chaos_redis_outage` nightly + pre-release required. |
| Postgres partial write failure | No orphan decision/evidence rows; transaction rollback complete; retries bounded. | DB transaction boundary + outbox check. | Inject fault between decision insert and artifact emit; assert atomic rollback or compensating outbox entry only. | `chaos_pg_partial_write` weekly required; fail on invariant break. |
| OPA unavailable | Deny by default when `FG_OPA_ENFORCE=1`; allow only explicit observe mode in non-prod. | Startup guard that forbids prod + enforce off. | Blackhole OPA endpoint; run defend/ingest requests; assert deny code `OPA_UNAVAILABLE_DENY`. | Add to `prod-profile-check` and chaos lane. |
| Contract schema mismatch | Build fails before merge; runtime rejects mismatched payloads with explicit error code. | Contract diff + schema compatibility gate. | Modify generated schema to incompatible field; run CI; assert contract job fails. | Extend `contract_authority` with backward-compat matrix. |
| Rate-limit exhaustion | Offending tenant throttled; other tenants remain within SLO. | Per-tenant keyed limits + fairness metrics. | Fire burst from tenant A and steady traffic from tenant B; assert only A receives 429 and B p95 unchanged. | New integration test + chaos test in PR for ingest/rate-limit touched files. |

---

## Monetization: billable meters and pricing levers (ROI-backed)

### Billable meters (contract for billing pipeline)
- `ingest_events_total` (counter): billable ingest event units.
- `ingest_bytes_total` (counter): billable data volume.
- `artifacts_bytes_stored_total` (counter): billable retained evidence storage volume.
- `retention_days_configured` (gauge): contracted retention obligation per tenant.
- `realtime_stream_subscriptions` (gauge): concurrent premium stream seats.
- `correlation_queries_total` (counter): billable forensic correlation query units.
- `advanced_trace_enabled` (boolean feature flag, 0/1): enables premium trace bundle and replay-depth features.

### Tier mapping and pricing levers

| Meter/Capability | Free | Pro | Enterprise | Upsell lever |
|---|---|---|---|---|
| `ingest_events_total` | Included low monthly cap | Higher cap + overage | Contracted high cap + discounted overage | Higher RPS / event pack |
| `ingest_bytes_total` | Small payload quota | Mid payload quota | Large payload quota | Data-volume overage bundles |
| `artifacts_bytes_stored_total` + `retention_days_configured` | 7 days retention | 30-90 days retention | 365+ days retention | Longer retention |
| `correlation_queries_total` | Basic filters only | Advanced joins quota | High-throughput forensic joins | Premium correlation |
| Compliance export package | Not included | Scheduled exports | Signed auditor-grade exports | Compliance export |
| `realtime_stream_subscriptions` | 1 dashboard stream | Team streams | Org-wide streams with SLA | Real-time seats |
| `advanced_trace_enabled` | Disabled | Optional add-on | Included + replay-depth controls | Advanced trace & replay |
| Chaos certification report | Not included | Quarterly report | Monthly report + attestation pack | Chaos-certified badge |

### ROI table (execution-driven)

| Feature | Customer value | Cost to implement | Monetization lever |
|---|---|---|---|
| Higher ingest throughput controls | Prevent dropped telemetry at growth stage | M | RPS tier upgrade + overage |
| Extended evidence retention | Satisfy audit/legal hold requirements | M | Retention add-on |
| Premium correlation queries | Faster incident triage and RCA | S | Query pack or Enterprise-only feature |
| Compliance export bundle | Reduce compliance prep labor | M | Per-export fee or annual compliance SKU |
| Chaos-certified badge package | Procurement trust + risk reduction evidence | L | Premium certification add-on |

---

## Definition of Done (verifiable, testable)

- [ ] **A) Backpressure behavior is deterministic under sustained queue pressure.**
  - Requirement: Ingest returns HTTP 429 + `Retry-After` when queue depth exceeds threshold window (DP-G-001).
  - Proof: `dp-backpressure-gate` (**NOT IMPLEMENTED**) via intended test `tests/chaos/test_backpressure_429_retry_after.py`.
  - Evidence artifact: `artifacts/reports/data_plane/backpressure_report.json` + metrics `queue_depth` (`frostgate_redis_queue_depth`) and `backpressure_429_total` (`frostgate_backpressure_429_total`).

- [ ] **B) Latency SLO is enforced with explicit thresholds.**
  - Requirement: Ingest p95 remains below target at configured RPS; alert thresholds are validated (DP-G-002).
  - Proof: `dp-slo-gate` (**NOT IMPLEMENTED**) via intended load test `tests/perf/test_ingest_p95_budget.py`.
  - Evidence artifact: `artifacts/reports/data_plane/slo_report.json` + metric `ingest_latency_ms_bucket` (`frostgate_ingest_latency_ms_bucket`).

- [ ] **C) Trace propagation contract is fail-closed.**
  - Requirement: `trace_id` is required end-to-end; missing trace must return HTTP 400 `TRACE_ID_REQUIRED` (DP-G-003).
  - Proof: `dp-trace-contract-gate` (**NOT IMPLEMENTED**) via intended contract test `tests/contracts/test_trace_id_required.py`.
  - Evidence artifact: `artifacts/reports/data_plane/trace_contract_report.json` + structured logs containing `trace_id` at each hop.

- [ ] **D) Telemetry correlation fields are complete and stable.**
  - Requirement: Every data-plane log event includes required correlation keys (DP-G-004).
  - Proof: `dp-telemetry-fields-gate` (**NOT IMPLEMENTED**) via intended checker `tools/ci/check_telemetry_required_fields.py`.
  - Evidence artifact: `artifacts/reports/data_plane/telemetry_fields_report.json` and sample log JSON:

```json
{
  "ts": "2026-01-01T00:00:00Z",
  "service": "fg-core-api",
  "trace_id": "2f6f7e20-6d6f-7e20-a3f1-9eb6b7a1f112",
  "request_id": "req-01",
  "tenant_id": "tenant-123",
  "event_id": "evt-123",
  "decision_id": 991,
  "route": "/ingest",
  "status_code": 429,
  "latency_ms": 37,
  "error_code": "INGEST_BACKPRESSURE_HARDSTOP"
}
```

- [ ] **E) Hash-chain extension is verifiable and tamper-evident.**
  - Requirement: Decisions/artifacts contain `prev_hash` and `chain_hash`; tamper produces verification failure (DP-G-005).
  - Proof: `dp-hashchain-gate` (**NOT IMPLEMENTED**) via intended verifier `scripts/verify_data_plane_hashchain.py` and test `tests/invariants/test_hashchain_integrity.py`.
  - Evidence artifact: `artifacts/reports/data_plane/hashchain_verification.json` + metric `frostgate_hashchain_verification_fail_total`.

- [ ] **F) Multi-tenant isolation invariants hold under negative tests.**
  - Requirement: Cross-tenant reads are impossible; unauthorized cross-tenant lookup returns no-leak semantics (`404`/empty as contract requires) (DP-G-006).
  - Proof: `dp-tenant-isolation-gate` (**NOT IMPLEMENTED**) via intended invariant test `tests/security/test_tenant_rls_isolation.py`.
  - Evidence artifact: `artifacts/reports/data_plane/tenant_isolation_report.json` + intended Postgres RLS invariant result `artifacts/reports/data_plane/rls_attestation.txt`.

---

## Gate Register (Option B: declared now, implemented later)

| Gate ID | Make target name (intended) | Intended file path(s) | What it enforces (1 sentence) | STATUS |
|---|---|---|---|---|
| DP-G-001 | `dp-backpressure-gate` | `tools/ci/check_backpressure_contract.py`, `tests/chaos/test_backpressure_429_retry_after.py` | Validates sustained queue-depth threshold yields deterministic HTTP 429 + `Retry-After`. | NOT IMPLEMENTED |
| DP-G-002 | `dp-slo-gate` | `tools/ci/check_ingest_slo.py`, `tests/perf/test_ingest_p95_budget.py` | Fails when ingest p95 exceeds declared target/alert budget under fixed workload profile. | NOT IMPLEMENTED |
| DP-G-003 | `dp-trace-contract-gate` | `tools/ci/check_trace_contract.py`, `tests/contracts/test_trace_id_required.py` | Ensures `trace_id` and required ingest contract fields are mandatory with stable 400 error codes. | NOT IMPLEMENTED |
| DP-G-004 | `dp-telemetry-fields-gate` | `tools/ci/check_telemetry_required_fields.py`, `tests/contracts/test_telemetry_log_schema.py` | Ensures required correlation keys are present in structured logs for ingest/decision/artifact hops. | NOT IMPLEMENTED |
| DP-G-005 | `dp-hashchain-gate` | `scripts/verify_data_plane_hashchain.py`, `tests/invariants/test_hashchain_integrity.py` | Ensures decision/artifact chain hashes verify and tamper conditions are detected. | NOT IMPLEMENTED |
| DP-G-006 | `dp-tenant-isolation-gate` | `tools/ci/check_tenant_isolation.py`, `tests/security/test_tenant_rls_isolation.py` | Ensures tenant isolation invariants and no cross-tenant data leakage semantics. | NOT IMPLEMENTED |
| DP-G-007 | `dp-chaos-plan-gate` | `tools/ci/check_chaos_plan_registration.py`, `tests/chaos/test_chaos_scenarios_registered.py` | Ensures all declared chaos scenarios are present and referenced by CI workflow config. | NOT IMPLEMENTED |

---

## PHASE 6 — Required Deliverables

### Data Plane Maturity Score (0–100)
- **Current: 63/100**
  - Security defaults: 14/20
  - Isolation: 13/15
  - Scalability: 10/15
  - Resilience/backpressure: 8/15
  - Observability/forensics: 10/15
  - CI/governance rigor: 8/10

### 10 critical upgrades
1. Enforce prod fail-closed Redis dependency for rate limit/queue controls.
2. Add tenant-tier dynamic ingest budgets with deterministic deny envelopes.
3. Implement queue depth shed/hard-stop gates at ingest edge.
4. Introduce per-component circuit breakers with open/half-open telemetry.
5. Add retry budget + DLQ policy as compliance invariant.
6. Extend evidence chain payload to bind trace/request/policy/config metadata.
7. Enforce Postgres RLS policy test gate + startup guard for tenant context.
8. Add distributed trace propagation contract across REST/gRPC boundaries.
9. Add chaos lanes for Redis/PG/OPA/rate-limit failures with invariant assertions.
10. Add contract backward-compatibility gate beyond drift detection.

### 5 revenue-leveraged enhancements
1. Tier-aware throttling and burst credits.
2. Premium forensic export package with signed trace manifest.
3. Live compliance/audit dashboard with SLA-backed freshness.
4. Automated compliance report generator with evidence deep links.
5. Forensic replay and incident timeline reconstruction SKU.

### 5 security hardening gaps
1. mTLS not mandatory end-to-end for agent/core in prod.
2. Missing anti-replay nonce cache for signed request envelopes.
3. RLS enforcement not continuously attested in CI/runtime startup checks.
4. Artifact path immutability/object-lock controls not explicitly guaranteed.
5. Admin cross-tenant data minimization/redaction controls incomplete.

### 90-day execution plan

#### Days 1-30 (Foundation hardening)
- Implement fail-closed redis + queue depth gates.
- Add new ingest/retry/DLQ metrics and alert rules.
- Land latency instrumentation for ingest/pipeline/db.
- Deliver chaos test harness skeleton in `tests/chaos/`.

#### Days 31-60 (Isolation + forensic depth)
- Add trace propagation contract and middleware for REST/gRPC.
- Extend evidence chain schema + migrations for trace binding fields.
- Add RLS CI attestation tests with tenant-context assertions.
- Launch tier-based rate-limit config service.

#### Days 61-90 (Scale + monetization)
- Roll out Redis cluster sharding and PgBouncer profiles.
- Ship premium evidence export and dashboard upsell APIs.
- Add forensic replay API (enterprise-flagged).
- Finalize CI gates and publish SLO/error-budget dashboard.

### Required schema changes
1. `decisions` table:
   - add `trace_id VARCHAR(36) NOT NULL`
   - add `request_id VARCHAR(64) NOT NULL`
   - add `ingest_latency_ms INTEGER NULL`
   - add index `(tenant_id, trace_id)`
2. `decision_evidence_artifacts` table:
   - add `trace_hash CHAR(64) NULL`
   - add `artifact_class VARCHAR(32) NOT NULL DEFAULT 'decision'`
3. New `ingest_dlq` table:
   - `id BIGSERIAL PK`, `tenant_id`, `event_id`, `reason_code`, `payload_json`, `retry_count`, `first_seen_at`, `last_seen_at`, `trace_id`
   - unique `(tenant_id,event_id,reason_code)`
4. New `tenant_runtime_limits` table:
   - `tenant_id PK`, `plan_tier`, `ingest_rps`, `burst`, `updated_at`, `updated_by`

### Required new metrics
1. `frostgate_ingest_latency_ms_bucket{phase,tenant_id}`
2. `frostgate_pipeline_phase_latency_ms_bucket{phase}`
3. `frostgate_db_write_latency_ms_bucket{table,operation}`
4. `frostgate_redis_queue_depth{tenant_id,lane}`
5. `frostgate_circuit_state{component,tenant_id}`
6. `frostgate_retry_budget_remaining{tenant_id,event_class}`
7. `frostgate_dlq_events_total{tenant_id,reason}`
8. `frostgate_trace_propagation_failures_total{hop}`
9. `frostgate_contract_breaking_changes_total{surface}`
10. `frostgate_rls_denied_queries_total{service}`

### Required new CI gates
1. `chaos_redis_outage_gate`: fail if prod profile ever fails open.
2. `chaos_pg_atomicity_gate`: fail on decision/evidence atomicity break.
3. `opa_enforcement_gate`: fail if `FG_OPA_ENFORCE=1` does not deny on OPA outage.
4. `contract_backward_compat_gate`: fail on breaking OpenAPI/schema/event changes.
5. `trace_propagation_gate`: fail if required trace fields missing across ingest→decision→artifact logs.
6. `rls_attestation_gate`: run tenant A/B read/write isolation tests on Postgres with RLS enabled.
7. `latency_budget_gate`: fail PR if benchmark regression breaches set p95 thresholds.
8. `retry_budget_gate`: fail if retries exceed configured budget without DLQ handoff.

---

## Alignment non-regression guard
- Add `BP-C-005` and `BP-M3-005/BP-M3-006` mapping entries for each new gate in `tools/align_score.py` so data-plane hardening increases (never decreases) blueprint alignment.


---

## PR checklist
- [x] Doc-only change (no Python/TS/Makefile edits).
- [x] Added authoritative scope, non-goals, and assumptions section.
- [x] Added contract-required fields, error semantics, and versioning rules.
- [x] Added Step 1 Definition of Done with proof + evidence artifacts.
- [x] Added Gate Register Option B with STATUS `NOT IMPLEMENTED` for all declared gates.
- [x] Added monetization billable meters and tier-to-upsell mapping.
- [x] Added conservative ROI table with execution-oriented sizing.
- [x] Kept existing architecture sections intact except where proof hooks were required.
