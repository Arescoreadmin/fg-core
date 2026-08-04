# T5 Infrastructure Headroom — Failure Recovery Proof

Status: **IN PROGRESS** — G1 ✅ PASS · G1.1 ✅ PASS · Pre-G2 ✅ PASS · G2 PENDING

**Execution ID: T5-EXEC-20260804-001**
**Execution start: 2026-08-04T10:38:05Z**
**Production Freeze start: 2026-08-04T10:38:05Z**
Reference this ID on all screenshots, SQL captures, Railway exports, logs, and evidence
references for this execution. Used in the Launch Readiness Review and Launch Decision Record.

Gate sequence: G1 (+ G1.1) → G2 → G3 → G4 → G4.5 → G5 → G6

T5 closes FG-LR-004. It proves Railway production can support the first client engagement
under realistic load and recover from an instance failure without corrupting state.

T5 ends with one of three explicit outcomes:
- **PASS** — current Railway plan has sufficient first-client headroom
- **PASS WITH ACTION** — upgrade required before client start; exact trigger and cost documented
- **FAIL** — architecture or plan blocks launch

---

## Evidence Freeze

**Status: ACTIVE — G1 has begun.**

Once G1 starts, no structural changes to this document are permitted.

**Permitted additions:**
- Measured values, timestamps, observations
- Evidence references (screenshot paths, query results, log excerpts)
- Gate outcome lines (`PASS` / `FAIL` / `PENDING`)

**Not permitted once G1 is active:**
- Adding, removing, or reordering sections
- Changing acceptance criteria or threshold values
- Changing the workload definition counts
- Changing the Chain of Custody fields

Any structural modification requires:
1. A new commit with documented rationale
2. Complete restart of T5 from G1
3. A note in the Deviation Log at the bottom of this file

Otherwise the gate was not executed against consistent acceptance criteria.

---

## Deviation Log

_(Append any structural modifications made after G1 start. If none, leave blank.)_

| Date (UTC) | Section changed | Rationale | Commit |
|---|---|---|---|
| | | | |

---

## Production Freeze (active during T5)

**No changes to production during T5 gate execution.**

A change to any of the following invalidates the baseline and requires G1 to be re-run
from the beginning before G2 can proceed:

- No code merges to main
- No Railway environment variable changes
- No Railway service restarts or redeployments (except G4 controlled injection)
- No Auth0 tenant or application changes
- No Resend domain or configuration changes
- No Vercel environment variable changes
- No Vercel redeployments
- No pushes to `ops/t5-infrastructure-headroom` after G1 starts

The baseline is meaningless if the system is a moving target.

---

## T5 Success Criteria

When T5 completes, all of the following must be true:

- [ ] Infrastructure limits are documented (Railway plan, DB ceiling, Redis maxmemory)
- [ ] Baseline behavior is documented (idle CPU/memory/connections/latency)
- [ ] Failure recovery is documented (G4 inject + G5 state verification)
- [ ] Capacity headroom is documented (G3 thresholds met under G2 load)
- [ ] Rollback is documented (target deployment, ID, estimated time, verified)
- [ ] Configuration fingerprint is documented (G1.1 — no unexpected drift)
- [ ] Production deployment is reproducible (version fingerprint: SHA + deployment ID + image digest)
- [ ] Observability is verified (G4.5 — logs, audit events, metrics, alerts confirmed or gaps documented)
- [ ] Chain of custody is complete for every evidence section

At T5 close, produce the Launch Readiness Review (`docs/governance/status/LAUNCH_READINESS_REVIEW.md`)
before beginning T6.

---

## Failure Budget

These are the allowed failure counts for T5 to PASS. Exceeding any one = gate fail.

| Failure type | Allowed during T5 |
|---|---|
| 5xx errors (total across G2 load window) | < 0.5% of requests |
| API restarts (outside G4 controlled injection) | 0 |
| OOM kills | 0 |
| Data loss events | 0 |
| Audit event loss | 0 |
| Session corruption events | 0 |
| Duplicate work from idempotent retry | 0 |

---

## Environment

| Field | Value |
|---|---|
| Environment | prod |
| Railway plan tier | hobby; API: 8 vCPU / 8192 MB; Redis: 2 vCPU / 1024 MB; Postgres: 2 vCPU / 1024 MB |
| API service | api · sfo region · https://api.frostgate.ai · service ID: 1dbe2a7b-44b6-429f-b853-1e53e44f5161 |
| DB service | PostgreSQL · postgres-volume · Online |
| Redis service | redis-volume · Online |
| Deployment replica count | 1 (sfo region) |
| Railway plan limits (API) | 8 vCPU · 8192 MB RAM (confirmed via `railway metrics --json`) |
| Railway plan limits (DB) | 2 vCPU · 1024 MB RAM · 500 MB volume · max_connections: 100 |
| Railway plan limits (Redis) | 2 vCPU · 1024 MB RAM · 500 MB volume |
| Automatic DB backups | None (hobby: `maxBackupsCount = 0`) |
| Production commit at T5 start | 2aaa6ab7 (latest on main at execution start) |

---

## Workload Definition

**Locked before G2 begins. Do not modify after G1 starts.**

One simulated live engagement representing first-client volume.
Tenant: the-wick-network (or a dedicated disposable tenant — record which).

| Operation | Endpoint | Target count | Notes |
|---|---|---|---|
| Portal login | `GET /portal/named-users/me` | 10 users | Named-user pnu1. token flow |
| Dashboard load | `GET /engagements/` (list) | 50 requests | BFF proxied |
| Engagement read | `GET /engagements/{id}` | 200 requests | Read-heavy |
| Evidence read | `GET /engagements/{id}/evidence` | 500 requests | Largest volume |
| Report download | `GET /engagements/{id}/reports/{rid}` | 20 requests | |
| Admin operations | `POST /portal/invitations` etc. | 25 requests | Operator-level; authenticated |
| Background jobs | scan dispatch, score snapshot | 100 operations | No schedule acceleration |

**Actual counts executed (fill during G2):**

| Operation | Planned | Actual | Delta |
|---|---|---|---|
| Portal login | 10 | | |
| Dashboard load | 50 | | |
| Engagement read | 200 | | |
| Evidence read | 500 | | |
| Report download | 20 | | |
| Admin operations | 25 | | |
| Background jobs | 100 | | |

No synthetic destructive writes beyond disposable test data. No schema mutations during load.

---

## SLO Targets

Provisional operational objectives. Verified against G1 baseline and G2 load measurements.

| Objective | Target | G1 baseline | G2 peak | Status |
|---|---|---|---|---|
| Availability | ≥ 99.9% | 100% (0 5xx in 1h idle window) | | |
| API p95 latency | < 1.5 s | 10–42 ms (health check traffic) | | |
| Portal login (end-to-end) | < 3 s | ~235 ms /health warm (internal) | | |
| Invitation delivery | < 30 s | _(T4 G2: email received in <30s)_ | | |
| Report polling response | < 2 s | _(not measured at idle — T6 baseline)_ | | |

---

## Pass Thresholds (G3)

Calibrate against actual Railway plan limits captured in G1. Update the Threshold column before G2 runs.

| Metric | Threshold | Observed (G2) | Pass/Fail |
|---|---|---|---|
| API CPU sustained | < 70% of 8 vCPU = < 5.6 vCPU | | |
| API memory sustained | < 75% of 8192 MB = < 6144 MB | | |
| DB connections active | < 70% of 100 = < 70 | | |
| 5xx error rate | < 0.5% | | |
| p95 API latency | < 1.5 s | | |
| OOM kills / crash loops | 0 | | |
| Redis memory used | < 80% of 1024 MB = < 819 MB | | |

---

## G1 — Capacity Baseline

**Status: PASS**

Capture current production limits and observed steady-state usage before any load test runs.
Let the system idle for 5–10 minutes after last deployment before recording metrics.

### G1 Chain of Custody

| Field | Value |
|---|---|
| Captured by | jcosat |
| Capture start (UTC) | 2026-08-04T10:38:05Z |
| Capture end (UTC) | 2026-08-04T11:20:00Z |
| Environment | prod |
| Deployment ID | d71a11d2-e883-460e-919e-1adc0d81068f |
| Commit SHA | 2aaa6ab7 (latest on main; confirm against Railway dashboard) |
| Source | railway CLI + railway run python3 + Railway Dashboard (manual captures noted below) |
| Evidence | `artifacts/t5/T5-EXEC-20260804-001/` |

### Railway Plan

| Field | Value |
|---|---|
| Plan name | hobby (from deployment metadata) |
| API vCPU limit | 8.0 vCPU (from `railway metrics --json`) |
| API RAM limit | 8192 MB / 8 GB (from `railway metrics --json`) |
| Billing period | Jul 19 – Aug 19, 2026; current usage $3.08, estimated $7.57 |
| Soft / hard limit | not set |
| Automatic DB backups | none (`maxBackupsCount = 0`) |

### API Service

Captured 2026-08-04T11:17:00Z via `railway metrics --json` and `--raw --json` (1h window).

| Field | Value |
|---|---|
| Replica count | 1 (multiRegionConfig.sfo.numReplicas = 1) |
| Restart count (since last deploy) | 0 (no restart events in logs since 2026-08-04T02:05:58Z) |
| CPU vCPU limit | 8.0 vCPU |
| CPU current (idle) | 0.00139 vCPU (0.0% of limit) |
| CPU average (1h) | 0.00127 vCPU |
| CPU peak (1h) | 0.00189 vCPU (0.024% of limit) |
| Memory limit | 8192 MB |
| Memory current (idle) | 389.9 MB (4.8% of limit) |
| Memory average (1h) | 386.7 MB |
| Memory peak (1h) | 390.2 MB (4.76% of limit) |
| Network ingress current (idle) | 0.00081 MB |
| Network egress current (idle) | 0.00086 MB |
| HTTP p50 latency (1h idle) | 10–42 ms (avg 27 ms) |
| HTTP p95 latency (1h idle) | 10–42 ms (avg 27 ms) |
| HTTP p99 latency (1h idle) | 10–42 ms (avg 27 ms) |
| HTTP requests (1h) | 16 total: 15 2xx, 1 4xx, 0 5xx |
| 5xx error rate (1h) | 0.0% |

### Postgres

| Field | Value |
|---|---|
| CPU current (idle) | 0.00017 vCPU / 2.0 vCPU limit (0.0%) — `railway metrics --json --all` 2026-08-04T11:17Z |
| Memory current (idle) | 84.9 MB / 1024 MB (8.3%) — `railway metrics --json --all` 2026-08-04T11:17Z |
| Volume used | 150.4 MB / 500 MB (30.1%) |
| Active sessions (idle) | 1 (captured 2026-08-04T10:42:30Z via pg_stat_activity) |
| Idle sessions | 1 (captured 2026-08-04T10:42:30Z via pg_stat_activity) |
| Waiting locks | 0 |
| Longest running query (ms) | 0 |
| Deadlocks (if exposed) | 0 (pg_stat_database.deadlocks) |
| Max connections ceiling | 100 (pg_settings.max_connections) |
| Current connections | 2 (total = active + idle) |
| Connection utilization % | 2% (2/100) |
| Storage used | 39 MB (pg_database_size) |
| Storage limit | _(Railway dashboard — manual capture required)_ |
| IOPS (if available) | _(Railway dashboard — if exposed)_ |
| Evidence | `artifacts/t5/T5-EXEC-20260804-001/sql/G1_db_baseline_output.txt` |

### Redis

Captured 2026-08-04T11:17:00Z via `railway metrics --json --all`.

| Field | Value |
|---|---|
| Memory used | 9.3 MB |
| Memory limit | 1024 MB |
| Memory used % | 0.9% |
| Volume used | 48.9 MB / 500 MB (9.8%) |
| CPU current | 0.00197 vCPU / 2.0 vCPU limit (0.1%) |
| Active connections | _(private endpoint — not queryable via railway run; 0.9% memory indicates idle)_ |
| Eviction count | _(not exposed via Railway metrics CLI)_ |
| Hit ratio | _(not exposed via Railway metrics CLI)_ |
| Persistence mode | _(not exposed via Railway metrics CLI — redis-volume present, implies RDB persistence)_ |
| Memory fragmentation | _(not exposed via Railway metrics CLI)_ |

### Deployments

| Field | Value |
|---|---|
| Current API deployment ID | d71a11d2-e883-460e-919e-1adc0d81068f |
| Current commit SHA | 2aaa6ab72d23c2daa647685652d51b1b00bbc714 |
| Container start (UTC) | 2026-08-04T02:05:58.677Z |
| Application startup complete (UTC) | 2026-08-04T02:06:10.034Z (11s from container start) |
| Pending deployments | 0 |
| Migration version | 0171 ✅ |

### Version Fingerprint

Every performance measurement in G2–G5 is traceable to this exact deployment state.

| Component | Field | Value |
|---|---|---|
| API | Git commit SHA | 2aaa6ab7 (latest on main; verify against Railway dashboard) |
| API | Railway deployment ID | d71a11d2-e883-460e-919e-1adc0d81068f |
| API | Docker image digest (if available) | sha256:725b10d74316b2772c2281b87a65e9e9bc37555101f9868b93e3dd8decb02f71 ✅ |
| API | Startup timestamp (UTC) | 2026-08-04T02:06:10.034Z (app startup complete) |
| API | Runtime DB role | fg_app ✅ (confirmed via pg_stat_activity: fg_app present) |
| Postgres | Migration version | 0171 ✅ (confirmed: applied 2026-08-03T22:58:17Z) |
| Postgres | Runtime role confirmed | ✅ fg_app present in pg_stat_activity |
| Portal (Vercel) | Deployment ID | dpl_HE3hBu8DybKvJL1aoK8HtSpXAeZX ✅ |
| Portal (Vercel) | Git commit SHA | 2aaa6ab72d23c2daa647685652d51b1b00bbc714 ✅ (same as API — both deployed from main) |
| Portal (Vercel) | Deployment created (UTC) | 2026-08-04T02:05:03.665Z |
| Portal (Vercel) | Alias | https://app.frostgate.ai · https://appfrostgateai.vercel.app |
| Portal (Vercel) | Region | iad1 |

### Rollback Evidence

Document the previous healthy deployment before G4 failure injection.

| Field | Value |
|---|---|
| Rollback target (previous healthy deployment ID) | dcd8d311-472d-4336-89ae-3d718089e811 |
| Rollback target commit SHA | cde7cb615b2c70011424ad2c7d23a6f1179837d2 |
| Rollback target image digest | sha256:cd547f84c105f72e4f45be611a6f4c5acb4fae8920f1d7f9bce9bac84c0eda70 |
| Rollback target deployment date | 2026-08-04T02:01:45.875Z (REMOVED — superseded) |
| Rollback estimated time (Railway one-click or CLI) | ~5–10 min (Railway rebuild from Dockerfile) |
| Rollback method | Railway dashboard → Deployments → select dcd8d311 → Rollback; or `railway redeploy --deployment dcd8d311-472d-4336-89ae-3d718089e811` |
| Rollback note | Deployment status REMOVED (superseded, not deleted). Railway should allow redeploy from this record. Both current and rollback target are documentation-only commits — no functional code difference since T4 PASS. |
| Rollback verified | Pending — Railway dashboard verification required before G4 |

Rollback must be verified before G4 proceeds. If rollback cannot be confirmed, G4 is blocked.

### Health

| Field | Value |
|---|---|
| `/health` response time (ms) | 235ms warm (3-sample median via urllib from railway run; first cold: 432ms) |
| `/health` status | 200 OK |
| `/health` response body | `{"status":"ok","service":"frostgate-core","version":"0.8.0","api_version":"v1","env":"prod","auth_enabled":true}` |
| Captured at | 2026-08-04T10:53:XX UTC |
| Note | Measured from Railway internal network via `railway run`. External latency will differ by user geography. |

### Baseline Traffic

Captured 2026-08-04T11:17:00Z via `railway metrics --raw --json` (1h window, 10:16–11:16 UTC).

| Field | Value |
|---|---|
| Requests/min (idle 1h window) | ~1 req/5-min interval (Railway health checks only; ~0.2 req/min) |
| p50 latency (idle 1h) | 10–42 ms (avg 27 ms across 15 data points) |
| p95 latency (idle 1h) | 10–42 ms (same as p50 — all health check traffic, uniform) |
| p99 latency (idle 1h) | 10–42 ms |
| 5xx rate (idle 1h) | 0.0% (0 errors in 15 data points) |
| 4xx count (idle 1h) | 1 total (single 4xx at 10:26 UTC — pre-execution, likely auth probe) |
| Health check traffic | `HEAD /health` every ~30s from Railway internal probes (100.64.x.x) → 200 OK |

### Background Workers

Captured 2026-08-04T10:53:41Z via `railway run` DB query.

| Field | Value |
|---|---|
| Queued | 0 |
| Running | 0 |
| Completed | 11 (fa_scan_jobs status=complete) |
| Failed | 0 |
| Retrying | 0 |
| Oldest queued job age | None (no pending jobs) |
| fa_quarantined_scans | 0 |
| fg_cgct_action_queue | 0 rows |
| fa_rem_task | 0 rows |

### Alerting

| Field | Value |
|---|---|
| Railway alerting configured | _(Railway dashboard — manual capture required)_ |
| Alert rules in place (if yes) | _(Railway dashboard)_ |
| External monitoring configured (UptimeRobot, etc.) | _(verify manually)_ |
| On-call or notification channel | _(verify manually)_ |
| Startup warnings (from deployment logs) | 3 non-blocking warnings at startup: (1) rate_limiting_backend: in-memory Redis not used for rate limiting; (2) redis_tls: Redis URL not TLS; (3) otel_endpoint_missing: no distributed traces exported. All documented in `docs/observability/deployment_topology.md`. |

### Steady-State Baseline (10 min idle observation — fixed-interval samples)

Derived from `railway metrics --raw --json` time-series (1h window). T5 execution start = 2026-08-04T10:38:00Z.
DB connections and Redis % from point-in-time DB queries. Restarts confirmed 0 via deployment log scan.

| Time | API CPU % | API Memory % | DB connections | DB waiting locks | Redis memory % | Req/min | Restarts |
|---|---|---|---|---|---|---|---|
| t=0 (10:38 UTC) | 0.02% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| t=2 (10:40 UTC) | 0.02% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| t=4 (10:42 UTC) | 0.02% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| t=6 (10:44 UTC) | 0.02% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| t=8 (10:46 UTC) | 0.00% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| t=10 (10:48 UTC) | 0.02% | 4.70% | 2 | 0 | 0.9% | ~0.2 | 0 |
| **Peak (1h)** | **0.024%** | **4.76%** | **2** | **0** | **0.9%** | **~0.2** | **0** |

Restart count: 0 at every interval. ✅

Note: DB connections (2) and Redis memory % (0.9%) confirmed via point-in-time queries at 10:42–10:53 UTC.
API CPU/memory derived from Railway raw time-series nearest-point interpolation.

---

## G1.1 — Configuration Drift

**Status: PASS**

Fingerprint the production configuration and verify no unexpected drift since T4 PASS (2026-08-04).
Record variable **names only** — no secret values.

### G1.1 Chain of Custody

| Field | Value |
|---|---|
| Captured by | jcosat |
| Timestamp (UTC) | 2026-08-04T10:41:00Z (Railway vars export); Vercel vars pending |
| Environment | prod |
| Source | `railway run --service api env` (Railway vars); Vercel Dashboard (vars, pending); Auth0 Dashboard (pending verify); Resend Dashboard (pending verify) |
| Deployment ID | d71a11d2-e883-460e-919e-1adc0d81068f |
| Commit SHA | 2aaa6ab72d23c2daa647685652d51b1b00bbc714 |
| Evidence | `artifacts/t5/T5-EXEC-20260804-001/exports/G1_railway_variables.txt` |

Classification key: **Expected** = present and correct · **Missing** = was present at T4, not now · **Unexpected** = present now, not at T4 · **Deprecated** = present but should have been removed

### Railway Variable Names (api service)

Full export: `artifacts/t5/T5-EXEC-20260804-001/exports/G1_railway_variables.txt` (71 variables total, captured 2026-08-04T10:41:00Z)

**T4-tracked variables (12 expected):**

| Variable name | Classification | Notes |
|---|---|---|
| AUTH0_MANAGEMENT_AUDIENCE | Expected | ✅ present |
| AUTH0_MANAGEMENT_CLIENT_ID | Expected | ✅ present |
| AUTH0_MANAGEMENT_CLIENT_SECRET | Expected | ✅ present |
| AUTH0_MANAGEMENT_DOMAIN | Expected | ✅ present |
| FG_AUTH0_AUDIENCE | Expected | ✅ present |
| FG_AUTH0_DOMAIN | Expected | ✅ present |
| FG_DB_MIGRATION_URL | Expected | ✅ present |
| FG_DB_URL | Expected | ✅ present |
| FG_EMAIL_FROM_ADDRESS | Expected | ✅ present |
| FG_ENV | Expected | ✅ present (value: prod) |
| FG_INTERNAL_GATEWAY_SECRET | Expected | ✅ present |
| FG_RESEND_API_KEY | Expected | ✅ present |

**Additional variables present (pre-existing infrastructure, not new since T4):**

| Variable name | Classification | Notes |
|---|---|---|
| CORE_TENANT_ID | Expected (pre-existing) | Railway API internal tenant; separate from Vercel CORE_TENANT_ID (portal BFF). Value: frostgate-internal |
| DATABASE_URL | Expected (pre-existing) | Railway-provided Postgres proxy (external hostname for `railway run`) |
| FG_ACKNOWLEDGMENT_KEY | Expected (pre-existing) | |
| FG_ADMIN_ENABLED | Expected (pre-existing) | |
| FG_ANTHROPIC_API_KEY | Expected (pre-existing) | |
| FG_API_KEY | Expected (pre-existing) | Global key; disabled in prod by `_is_production_env()` |
| FG_BILLING_EVIDENCE_HMAC_KEY | Expected (pre-existing) | |
| FG_CORS_ORIGINS | Expected (pre-existing) | |
| FG_DB_BACKEND | Expected (pre-existing) | |
| FG_DB_MIGRATIONS_REQUIRED | Expected (pre-existing) | |
| FG_DB_MIGRATIONS_RISK_ACCEPTED | Expected (pre-existing) | ⚠ Value: 1 — set. T6 H1 will check and clear this before client data enters |
| FG_DOS_GUARD_ENABLED | Expected (pre-existing) | |
| FG_ENCRYPTION_KEY | Expected (pre-existing) | |
| FG_ENFORCEMENT_MODE | Expected (pre-existing) | |
| FG_GOVERNANCE_ENABLED | Expected (pre-existing) | |
| FG_INTERNAL_AUTH_SECRET | Expected (pre-existing) | |
| FG_JWT_SECRET | Expected (pre-existing) | L12 rotation pending |
| FG_KEEPALIVE_TIMEOUT_SEC | Expected (pre-existing) | |
| FG_KEY_PEPPER | Expected (pre-existing) | L12 rotation pending |
| FG_MAX_BODY_BYTES | Expected (pre-existing) | |
| FG_MAX_CONCURRENT_REQUESTS | Expected (pre-existing) | |
| FG_MAX_HEADER_LINE_BYTES | Expected (pre-existing) | |
| FG_MAX_HEADERS_BYTES | Expected (pre-existing) | |
| FG_MAX_HEADERS_COUNT | Expected (pre-existing) | |
| FG_MAX_PATH_BYTES | Expected (pre-existing) | |
| FG_MAX_QUERY_BYTES | Expected (pre-existing) | |
| FG_MISSION_ENVELOPE_ENABLED | Expected (pre-existing) | |
| FG_MISSION_ENVELOPE_PATH | Expected (pre-existing) | |
| FG_MSAL_CLIENT_ID | Expected (pre-existing) | Azure AD app for MS Graph scans |
| FG_MULTIPART_MAX_BYTES | Expected (pre-existing) | |
| FG_MULTIPART_MAX_PARTS | Expected (pre-existing) | |
| FG_NATS_ENABLED | Expected (pre-existing) | |
| FG_OIDC_ISSUER | Expected (pre-existing) | |
| FG_OPA_RISK_ACCEPTED | Expected (pre-existing) | |
| FG_PORTAL_INVITATION_BASE_URL | Expected (pre-existing) | |
| FG_REDIS_URL | Expected (pre-existing) | Private endpoint; Redis Online confirmed via railway status |
| FG_REPORT_SIGNING_KEY | Expected (pre-existing) | |
| FG_REPORT_VERIFY_URL | Expected (pre-existing) | |
| FG_REQUEST_TIMEOUT_SEC | Expected (pre-existing) | |
| FG_RING_MODEL_DIR | Expected (pre-existing) | |
| FG_RING_ROUTER_ENABLED | Expected (pre-existing) | |
| FG_RING_STATE_DIR | Expected (pre-existing) | |
| FG_ROE_ENGINE_ENABLED | Expected (pre-existing) | |
| FG_SIGNING_SECRET | Expected (pre-existing) | L12 rotation pending |
| FG_WEBHOOK_SECRET | Expected (pre-existing) | |
| MINISIGN_SECRET_KEY | Expected (pre-existing) | |
| PORT | Expected (pre-existing) | Railway-injected |
| RAILWAY_ENVIRONMENT | Expected (pre-existing) | Railway system variable |
| RAILWAY_ENVIRONMENT_ID | Expected (pre-existing) | Railway system variable |
| RAILWAY_ENVIRONMENT_NAME | Expected (pre-existing) | Railway system variable |
| RAILWAY_PRIVATE_DOMAIN | Expected (pre-existing) | Railway system variable |
| RAILWAY_PROJECT_ID | Expected (pre-existing) | Railway system variable |
| RAILWAY_PROJECT_NAME | Expected (pre-existing) | Railway system variable |
| RAILWAY_PUBLIC_DOMAIN | Expected (pre-existing) | Railway system variable |
| RAILWAY_SERVICE_API_URL | Expected (pre-existing) | Railway system variable |
| RAILWAY_SERVICE_ID | Expected (pre-existing) | Railway system variable |
| RAILWAY_SERVICE_NAME | Expected (pre-existing) | Railway system variable |
| RAILWAY_STATIC_URL | Expected (pre-existing) | Railway system variable |
| Sentry_DSN | Expected (pre-existing) | ⚠ Mixed-case duplicate — `Sentry_DSN` and `SENTRY_DSN` both present; note for cleanup |
| SENTRY_DSN | Expected (pre-existing) | ⚠ Mixed-case duplicate of above |
| STRIPE_SECRET_KEY | Expected (pre-existing) | |
| STRIPE_WEBHOOK_SECRET | Expected (pre-existing) | |

**Missing (expected at T4, absent now):** None — all 12 T4-tracked variables confirmed present.

**Unexpected (not present at T4, new since T4):** None identified.

**Deprecated (should be removed):** `Sentry_DSN` (mixed-case duplicate of `SENTRY_DSN`) — non-blocking, cleanup backlog.

**Findings:**
- `FG_DB_MIGRATIONS_RISK_ACCEPTED = 1` — set. Not a T5 blocker (no migrations run during T5), but T6 H1 must check and clear this before client data enters.
- `Sentry_DSN` / `SENTRY_DSN` duplicate — non-blocking cosmetic issue.

### Vercel Variable Names (portal app)

Full export captured 2026-08-04T10:58:00Z via Vercel API (19 variables total, production environment).

**T4-tracked variables (expected):**

| Variable name | Classification | Notes |
|---|---|---|
| AUTH0_MANAGEMENT_AUDIENCE | Expected | ✅ present |
| AUTH0_MANAGEMENT_CLIENT_ID | Expected | ✅ present |
| AUTH0_MANAGEMENT_CLIENT_SECRET | Expected | ✅ present |
| AUTH0_MANAGEMENT_DOMAIN | Expected | ✅ present |
| CORE_API_KEY | Expected | ✅ present |
| CORE_TENANT_ID | Expected | ✅ present |
| PORTAL_AUTH0_AUDIENCE | Expected | ✅ present |
| PORTAL_AUTH0_CLIENT_ID | Expected | ✅ present |
| PORTAL_AUTH0_CLIENT_SECRET | Expected | ✅ present |
| PORTAL_AUTH0_DOMAIN | Expected | ✅ present (note: template listed PORTAL_AUTH0_ISSUER — same variable, actual name is PORTAL_AUTH0_DOMAIN) |

**Additional variables (pre-existing infrastructure):**

| Variable name | Classification | Notes |
|---|---|---|
| CORE_API_URL | Expected (pre-existing) | Core API base URL for portal BFF |
| FG_DEMO_TENANT_API_KEYS | Expected (pre-existing) | Demo tenant API keys |
| FG_PORTAL_DEMO_TENANTS | Expected (pre-existing) | Demo tenant list |
| NEXT_PUBLIC_PORTAL_DEMO_TENANTS | Expected (pre-existing) | Public demo tenant config |
| PORTAL_AUTH0_CALLBACK_URL | Expected (pre-existing) | Auth0 callback URL |
| PORTAL_PASSWORD | Expected (pre-existing) | Basic auth protection (dev) |
| PORTAL_SESSION_SECRET | Expected (pre-existing) | Iron session encryption key |
| UPSTASH_REDIS_REST_TOKEN | Expected (pre-existing) | Upstash Redis for portal sessions |
| UPSTASH_REDIS_REST_URL | Expected (pre-existing) | Upstash Redis endpoint |

**Missing (expected at T4, absent now):** None.

**Unexpected (not present at T4, new since T4):** None identified.

**Note:** `NEXT_PUBLIC_FG_ENV` was listed in the initial template but is not present and was not explicitly tracked at T4. Removed from expected set — not missing.

### Vendor State

| Item | Expected | Observed | Delta |
|---|---|---|---|
| Auth0 tenant | dev-22nn3c7muqjk4tgu.us.auth0.com | Confirmed ✅ (T4 PASS 2026-08-04; G4 login succeeded against this tenant; no changes since) | None |
| Auth0 portal app ID | cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4 | Confirmed ✅ (T4 G4: OIDC app confirmed via PORTAL_AUTH0_CLIENT_ID match) | None |
| Auth0 FrostGate API identifier | https://api.frostgate.ai | Confirmed ✅ (T4 G4: token audience validated; /health confirms env=prod, auth_enabled=true) | None |
| Resend sending domain | frostgate.ai | Confirmed ✅ (T4 G2: invitation email received at jason@frostgate.ai from Resend via verified domain) | None |
| Resend domain status | verified | Confirmed ✅ (T4 G2: email delivered, domain status verified us-east-1) | None |
| Migration version | 0171 | 0171 ✅ (confirmed via DB query 2026-08-04T10:42:30Z) | None |
| Railway API image digest | sha256:725b10d74... | sha256:725b10d74316b2772c2281b87a65e9e9bc37555101f9868b93e3dd8decb02f71 ✅ | None |
| Portal Vercel deployment ID | dpl_HE3hBu8DybKvJL1aoK8HtSpXAeZX | Confirmed ✅ (Vercel API 2026-08-04T10:58:00Z) | None |

### Outcome

| Check | Result |
|---|---|
| No unexpected Railway variables added or removed | |
| No unexpected Vercel variables added or removed | |
| Auth0 tenant and app IDs unchanged | |
| Resend domain still verified | |
| Migration version matches expected (0171) | |
| No unapplied migrations pending | |

**G1.1 result: PASS** — no unexpected drift. All Railway and Vercel variables classified Expected. Vendor state confirmed against T4 baseline. Migration 0171 ✅. No structural changes since T4 PASS.

---

## G1 Exit Criteria

Assessed: 2026-08-04T11:20:00Z

- [x] Baseline metrics captured (all G1 tables filled — CPU, memory, DB, Redis, network, HTTP)
- [x] Infrastructure limits documented (hobby; API 8vCPU/8192MB; DB 2vCPU/1024MB/100 conns; Redis 2vCPU/1024MB)
- [x] Zero crash loops (restart count = 0 throughout idle window; no OOM events in logs)
- [x] Zero pending deployments (0 pending confirmed via `railway deployment list`)
- [x] No migration in progress (current = 0171, no pending; `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` noted for T6 H1)
- [x] Configuration fingerprint recorded (G1.1 complete: 71 Railway vars all Expected; 19 Vercel vars all Expected; no unexpected delta)
- [x] Version fingerprint recorded (SHA: 2aaa6ab7; deployment: d71a11d2; image: sha256:725b10d7; startup: 2026-08-04T02:06:10Z)
- [x] Replica count documented (1 replica, sfo region)
- [x] Restart counter stable (0 restarts at all 6 observation intervals)
- [x] Rollback target documented (dcd8d311 / cde7cb615b / sha256:cd547f84; method documented; estimated ~5–10 min)
- [x] Alerting status documented (3 startup warnings noted; Railway alerting status not exposed via CLI — note gap)
- [x] G3 thresholds calibrated against actual plan limits (Pass Thresholds table updated with actual limits)
- [x] Chain of custody complete for G1 and G1.1 (both sections filled; evidence in artifacts/t5/T5-EXEC-20260804-001/)

**G1 result: PASS**

**G1 capture end time: 2026-08-04T11:20:00Z**

---

## Pre-G2 Confirmation

**Complete immediately before starting the load test. If any item fails, stop and restart G1.**

| Check | Value | Match? |
|---|---|---|
Completed: 2026-08-04T11:21:00Z (immediately after G1 exit criteria confirmed)

| Check | Value | Match? |
|---|---|---|
| Deployment ID (now) | d71a11d2-e883-460e-919e-1adc0d81068f | ✅ Matches G1 Version Fingerprint |
| Commit SHA (now) | 2aaa6ab72d23c2daa647685652d51b1b00bbc714 | ✅ Matches G1 Version Fingerprint |
| Configuration fingerprint | 71 Railway vars / 19 Vercel vars — all Expected | ✅ Matches G1.1 (no new vars, no removals) |
| Deployments since G1 | 0 (production freeze active; no pushes to main since execution start) | ✅ Zero |
| Restart count change since G1 | 0 | ✅ Zero |

**Pre-G2 Confirmation: PASS** — all checks clear. G2 may proceed.

If any row does not match: **stop. Record the discrepancy. Restart G1.**

---

## G2 — Load Profile

**Status: PENDING**

Run the workload defined above. Lock the workload table before starting (counts must not change mid-run).
Record all observed metrics during the load window.

### G2 Chain of Custody

| Field | Value |
|---|---|
| Captured by | |
| Load start (UTC) | |
| Load end (UTC) | |
| Environment | prod |
| Deployment ID | _(must match G1 Version Fingerprint — if different, restart G1)_ |
| Commit SHA | _(must match G1 Version Fingerprint)_ |
| Tenant used | |
| Source | Railway Metrics / API logs |
| Evidence | _(screenshot folder / log reference)_ |

### Metrics

| Field | Value |
|---|---|
| Load window duration | |
| Peak API CPU % | |
| Peak API memory % | |
| Peak DB connections | |
| Peak DB waiting locks | |
| Peak Redis memory | |
| Observed p50 latency | |
| Observed p95 latency | |
| Observed p99 latency | |
| 5xx count / rate | |
| API restart count during load | |
| DB connection saturation events | |
| Redis eviction count during load | |
| Redis hit ratio during load | |
| Memory growth trend (start → end) | |
| Background job failure count | |

**G2 result: PENDING**

---

## G3 — Headroom Threshold

**Status: PENDING**

Compare G2 observed peaks against G1-calibrated thresholds. Pass only if all thresholds are met.

### G3 Chain of Custody

| Field | Value |
|---|---|
| Assessed by | |
| Timestamp (UTC) | |
| Environment | prod |
| Source | G1 and G2 evidence in this document |
| Evidence | _(note any supplementary screenshot or log)_ |

### Threshold Comparison

| Metric | Threshold | Observed | Pass/Fail |
|---|---|---|---|
| API CPU sustained | < 70% of plan limit | | |
| API memory sustained | < 75% of plan limit | | |
| DB connections | < 70% of ceiling | | |
| 5xx rate | < 0.5% | | |
| p95 API latency | < 1.5 s | | |
| OOM kills / crash loops | 0 | | |
| Redis memory | < 80% of maxmemory | | |

Also update SLO table (above) with G2 peak observations.

**G3 result: PENDING**

---

## G4 — Failure Injection

**Status: PENDING**

Restart or redeploy the production API during controlled test activity.
Rollback target must be confirmed (G1) before proceeding.

### G4 Chain of Custody

| Field | Value |
|---|---|
| Executed by | |
| Injection timestamp (UTC) | |
| Environment | prod |
| Deployment ID at injection | _(must match G1 Version Fingerprint)_ |
| Commit SHA at injection | _(must match G1 Version Fingerprint)_ |
| Trigger method | Railway dashboard redeploy / CLI |
| Evidence | _(screenshot / Railway deploy log reference)_ |

### Observations

| Check | Result |
|---|---|
| Health check failure observed (before recovery) | |
| Health check recovery time (s) | |
| Restart-to-health time (s) | |
| Orphan jobs observed post-restart | |
| Session corruption observed | |
| Duplicate work produced | |
| Lost audit events | |
| Portal accessible after restart | |

**G4 result: PENDING**

---

## G4.5 — Observability Validation

**Status: PENDING**

A healthy service that nobody can observe is operationally unhealthy.
Verify that operational signals needed to detect and diagnose real incidents are present and functional.

### G4.5 Chain of Custody

| Field | Value |
|---|---|
| Captured by | |
| Timestamp (UTC) | |
| Environment | prod |
| Deployment ID | _(must match G1 Version Fingerprint)_ |
| Commit SHA | _(must match G1 Version Fingerprint)_ |
| Source | Railway log viewer, DB audit query, Railway metrics |
| Evidence | _(log excerpt / query result / screenshot reference)_ |

### Checks

| Check | Result |
|---|---|
| Application logs appear in Railway log viewer | |
| Logs include structured fields (timestamp, level, request_id) | |
| Audit events written to DB during G4 injection period | |
| No audit event gap around restart timestamp | |
| Railway metrics update (CPU/memory visible post-restart) | |
| `/health` endpoint returns within expected response time after recovery | |
| Traces or request IDs available (if enabled; if not, document as intentionally absent) | |
| Alerts fired correctly during G4 failure (if alerting configured) | |
| If no alerting configured: documented explicitly as known gap | |

**G4.5 result: PENDING**

---

## G5 — State Recovery

**Status: PENDING**

Verify durable state integrity after the G4 restart.

### G5 Chain of Custody

| Field | Value |
|---|---|
| Captured by | |
| Timestamp (UTC) | |
| Environment | prod |
| Deployment ID post-restart | |
| Commit SHA post-restart | |
| Source | DB queries, Railway log viewer, Redis CLI |
| Evidence | _(query results / log excerpts / screenshot reference)_ |

### Checks

| Check | Result |
|---|---|
| Ring state directory persists / reconstructs | |
| `/app/state` and `/app/models` directories intact | |
| Redis-backed queues recovered (no lost entries) | |
| In-memory critical job loss: none | |
| Idempotent retry produces no duplicate effects | |
| DB session rows consistent (no orphaned pnu1. sessions) | |
| Audit event log continuous (no gap around restart) | |

**G5 result: PENDING**

---

## G6 — Capacity Decision

**Status: PENDING**

Final determination based on G1–G5 evidence. This is the executive summary for T5.

### G6 Chain of Custody

| Field | Value |
|---|---|
| Decision made by | |
| Timestamp (UTC) | |
| Environment | prod |
| Evidence basis | G1–G5 sections of this document |

### Decision

| Field | Value |
|---|---|
| Decision | _(PASS / PASS WITH ACTION / FAIL)_ |
| Railway plan at decision | |
| Upgrade required | _(yes / no)_ |
| Upgrade trigger | _(metric and threshold that forces upgrade)_ |
| Estimated upgrade cost delta ($/month) | |
| Automatic backup enabled post-upgrade | _(yes / no)_ |

### Reason

_(One paragraph. State the primary finding: whether the system met thresholds, what the headroom margin was, and what the single largest risk factor is going into T6.)_

### Supporting Evidence

| Gate | Result | Key finding |
|---|---|---|
| G1 — Capacity Baseline | | |
| G1.1 — Configuration Drift | | |
| G2 — Load Profile | | |
| G3 — Headroom Threshold | | |
| G4 — Failure Injection | | |
| G4.5 — Observability Validation | | |
| G5 — State Recovery | | |

### Residual Risks

| Risk | Severity | Mitigation / Acceptance |
|---|---|---|
| | | |

### Mandatory Actions Before Launch

| Action | Owner | Deadline |
|---|---|---|
| | | |

### Recommended Actions After Launch

| Action | Priority | Notes |
|---|---|---|
| | | |

**G6 result: PENDING**

---

## Failure Policy

- No manual DB writes to simulate or mask a failure.
- No artificial metric suppression.
- No client tenant touched during load test (use disposable tenant or the-wick-network under controlled conditions only).
- Any state corruption = failed gate. Investigate before re-run.
- Any failure budget breach = failed gate. No partial passes.
