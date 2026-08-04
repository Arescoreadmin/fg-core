# T5 Infrastructure Headroom — Failure Recovery Proof

Status: **PENDING** — gates not yet executed

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
| Railway plan tier | hobby (as of T1, 2026-07-30) |
| API service | api (Railway internal: `api.railway.internal`) |
| DB service | PostgreSQL 18.4 (`postgres.railway.internal`) |
| Redis service | _(fill: service name and region)_ |
| Deployment replica count | _(fill from G1)_ |
| Railway plan limits (API) | _(fill: vCPU, RAM, egress ceiling from G1)_ |
| Railway plan limits (DB) | _(fill: connections ceiling, storage ceiling from G1)_ |
| Railway plan limits (Redis) | _(fill: maxmemory, connection limit from G1)_ |
| Automatic DB backups | None (hobby: `maxBackupsCount = 0`) |
| Production commit at T5 start | _(fill)_ |

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
| Availability | ≥ 99.9% | | | |
| API p95 latency | < 1.5 s | | | |
| Portal login (end-to-end) | < 3 s | | | |
| Invitation delivery | < 30 s | | | |
| Report polling response | < 2 s | | | |

---

## Pass Thresholds (G3)

Calibrate against actual Railway plan limits captured in G1. Update the Threshold column before G2 runs.

| Metric | Threshold | Observed (G2) | Pass/Fail |
|---|---|---|---|
| API CPU sustained | < 70% of plan limit | | |
| API memory sustained | < 75% of plan limit | | |
| DB connections active | < 70% of ceiling | | |
| 5xx error rate | < 0.5% | | |
| p95 API latency | < 1.5 s | | |
| OOM kills / crash loops | 0 | | |
| Redis memory used | < 80% of maxmemory | | |

---

## G1 — Capacity Baseline

**Status: PENDING**

Capture current production limits and observed steady-state usage before any load test runs.
Let the system idle for 5–10 minutes after last deployment before recording metrics.

### G1 Chain of Custody

| Field | Value |
|---|---|
| Captured by | |
| Capture start (UTC) | |
| Capture end (UTC) | |
| Environment | prod |
| Deployment ID | _(from Version Fingerprint below)_ |
| Commit SHA | _(from Version Fingerprint below)_ |
| Source | Railway Dashboard / CLI |
| Evidence | _(screenshot folder / log reference)_ |

### Railway Plan

| Field | Value |
|---|---|
| Plan name | |
| API vCPU limit | |
| API RAM limit | |
| Included usage / overage pricing | |

### API Service

| Field | Value |
|---|---|
| Replica count | |
| Restart count (since last deploy) | |
| CPU % (idle steady-state) | |
| Memory % (idle steady-state) | |
| Network in (idle) | |
| Network out (idle) | |

### Postgres

| Field | Value |
|---|---|
| CPU % (idle) | |
| Memory % (idle) | |
| Active sessions (idle) | |
| Idle sessions | |
| Waiting locks | |
| Longest running query (ms) | |
| Deadlocks (if exposed) | |
| Max connections ceiling | |
| Current connections | |
| Connection utilization % | |
| Storage used | |
| Storage limit | |
| IOPS (if available) | |

### Redis

| Field | Value |
|---|---|
| Memory used | |
| maxmemory limit | |
| Memory used % | |
| Memory fragmentation ratio | |
| Active connections | |
| Eviction count | |
| Hit ratio | |
| Persistence mode (RDB / AOF / none) | |

### Deployments

| Field | Value |
|---|---|
| Current API deployment ID | |
| Current commit SHA | |
| Pending deployments | |
| Migration version | |

### Version Fingerprint

Every performance measurement in G2–G5 is traceable to this exact deployment state.

| Component | Field | Value |
|---|---|---|
| API | Git commit SHA | |
| API | Railway deployment ID | |
| API | Docker image digest (if available) | |
| API | Startup timestamp (UTC) | |
| API | Runtime DB role | fg_app (expected) |
| Postgres | Migration version | 0171 (expected) |
| Postgres | Runtime role confirmed | |
| Portal (Vercel) | Deployment ID | |
| Portal (Vercel) | Git commit SHA | |

### Rollback Evidence

Document the previous healthy deployment before G4 failure injection.

| Field | Value |
|---|---|
| Rollback target (previous healthy deployment ID) | |
| Rollback target commit SHA | |
| Rollback estimated time (Railway one-click or CLI) | |
| Rollback method (Railway dashboard / `railway redeploy`) | |
| Rollback verified | YES / NO |

Rollback must be verified before G4 proceeds. If rollback cannot be confirmed, G4 is blocked.

### Health

| Field | Value |
|---|---|
| `/health` response time (ms) | |
| `/health` status | |

### Baseline Traffic

| Field | Value |
|---|---|
| Requests/min (idle 10-min window) | |
| p50 latency | |
| p95 latency | |
| p99 latency | |
| 5xx rate (idle 24h window) | |

### Background Workers

| Field | Value |
|---|---|
| Queued | |
| Running | |
| Completed | |
| Failed | |
| Retrying | |
| Oldest queued job age | |

### Alerting

| Field | Value |
|---|---|
| Railway alerting configured | yes / no |
| Alert rules in place (if yes) | |
| External monitoring configured (UptimeRobot, etc.) | yes / no |
| On-call or notification channel | |

### Steady-State Baseline (5–10 min idle observation)

| Metric | Start | End | Peak |
|---|---|---|---|
| API CPU % | | | |
| API Memory % | | | |
| Open DB connections | | | |
| DB waiting locks | | | |
| Redis memory % | | | |
| Request rate (req/min) | | | |
| Restart count | 0 (required) | 0 (required) | 0 (required) |

---

## G1.1 — Configuration Drift

**Status: PENDING**

Fingerprint the production configuration and verify no unexpected drift since T4 PASS (2026-08-04).
Record variable **names only** — no secret values.

### G1.1 Chain of Custody

| Field | Value |
|---|---|
| Captured by | |
| Timestamp (UTC) | |
| Environment | prod |
| Source | Railway Dashboard (vars), Vercel Dashboard (vars), Auth0 Dashboard, Resend Dashboard |
| Deployment ID | _(from G1 Version Fingerprint)_ |
| Commit SHA | _(from G1 Version Fingerprint)_ |
| Evidence | _(screenshot folder / export reference)_ |

### Railway Variable Names (api service)

| Variable name | Present at T4 | Present now | Delta |
|---|---|---|---|
| FG_ENV | yes | | |
| FG_DB_URL | yes | | |
| FG_DB_MIGRATION_URL | yes | | |
| FG_RESEND_API_KEY | yes | | |
| FG_EMAIL_FROM_ADDRESS | yes | | |
| FG_AUTH0_DOMAIN | yes | | |
| FG_AUTH0_AUDIENCE | yes | | |
| FG_INTERNAL_GATEWAY_SECRET | yes | | |
| AUTH0_MANAGEMENT_DOMAIN | yes | | |
| AUTH0_MANAGEMENT_CLIENT_ID | yes | | |
| AUTH0_MANAGEMENT_CLIENT_SECRET | yes | | |
| AUTH0_MANAGEMENT_AUDIENCE | yes | | |
| _(any additions)_ | no | | |

### Vercel Variable Names (portal app)

| Variable name | Present at T4 | Present now | Delta |
|---|---|---|---|
| CORE_TENANT_ID | yes | | |
| CORE_API_KEY | yes | | |
| PORTAL_AUTH0_CLIENT_ID | yes | | |
| PORTAL_AUTH0_CLIENT_SECRET | yes | | |
| PORTAL_AUTH0_ISSUER | yes | | |
| NEXT_PUBLIC_FG_ENV | yes | | |
| _(any additions)_ | no | | |

### Vendor State

| Item | Expected | Observed | Delta |
|---|---|---|---|
| Auth0 tenant | dev-22nn3c7muqjk4tgu.us.auth0.com | | |
| Auth0 portal app ID | cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4 | | |
| Auth0 FrostGate API identifier | https://api.frostgate.ai | | |
| Resend sending domain | frostgate.ai | | |
| Resend domain status | verified | | |
| Migration version | 0171 | | |
| Railway API service version / image | _(fill from G1)_ | | |

### Outcome

| Check | Result |
|---|---|
| No unexpected Railway variables added or removed | |
| No unexpected Vercel variables added or removed | |
| Auth0 tenant and app IDs unchanged | |
| Resend domain still verified | |
| Migration version matches expected (0171) | |
| No unapplied migrations pending | |

**G1.1 result: PENDING**

---

## G1 Exit Criteria

Do not start G2 until all are true:

- [ ] Baseline metrics captured (all G1 tables filled)
- [ ] Infrastructure limits documented (plan name, vCPU, RAM, DB connections ceiling, Redis maxmemory)
- [ ] Zero crash loops (restart count stable, zero during idle observation)
- [ ] Zero pending deployments
- [ ] No migration in progress
- [ ] Configuration fingerprint recorded (G1.1 complete, no unexpected delta)
- [ ] Version fingerprint recorded (commit SHA, deployment ID, image digest, startup timestamp)
- [ ] Replica count documented
- [ ] Restart counter stable (zero during idle observation window)
- [ ] Rollback target documented and verified
- [ ] Alerting status documented
- [ ] G3 thresholds calibrated against actual plan limits (Pass Thresholds table updated above)
- [ ] Chain of custody complete for G1 and G1.1

**G1 result: PENDING**

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
