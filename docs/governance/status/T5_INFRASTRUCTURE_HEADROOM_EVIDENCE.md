# T5 Infrastructure Headroom — Failure Recovery Proof

Status: **PENDING** — gates not yet executed

Gate sequence: G1 (+ G1.1) → G2 → G3 → G4 → G5 → G6

T5 closes FG-LR-004. It proves Railway production can support the first client engagement
under realistic load and recover from an instance failure without corrupting state.

T5 ends with one of three explicit outcomes:
- **PASS** — current Railway plan has sufficient first-client headroom
- **PASS WITH ACTION** — upgrade required before client start; exact trigger and cost documented
- **FAIL** — architecture or plan blocks launch

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

At T5 close, T6 becomes a business workflow validation, not another infrastructure investigation.

---

## Environment

| Field | Value |
|---|---|
| Environment | prod |
| Railway plan tier | hobby (as of T1, 2026-07-30) |
| API service | api (Railway internal: `api.railway.internal`) |
| DB service | PostgreSQL 18.4 (`postgres.railway.internal`) |
| Redis service | _(fill: service name and region)_ |
| Deployment replica count | _(fill from Railway during G1)_ |
| Railway plan limits (API) | _(fill: vCPU, RAM, egress ceiling during G1)_ |
| Railway plan limits (DB) | _(fill: connections ceiling, storage ceiling during G1)_ |
| Railway plan limits (Redis) | _(fill: maxmemory, connection limit during G1)_ |
| Automatic DB backups | None (hobby: `maxBackupsCount = 0`) |
| Production commit at T5 start | _(fill)_ |

---

## Workload Definition

One simulated live engagement (the-wick-network, or a dedicated disposable tenant):

| Operation | Frequency | Notes |
|---|---|---|
| Portal login (`GET /portal/named-users/me`) | ~30 req/min | Named-user pnu1. token flow |
| Engagement reads (`GET /engagements/...`) | ~20 req/min | Read-heavy; BFF proxied |
| Evidence reads (`GET /engagements/{id}/evidence`) | ~15 req/min | |
| Report polling (`GET /engagements/{id}/reports`) | ~10 req/min | |
| Admin operations (`POST /portal/invitations`, etc.) | ~2 req/min | Operator-level; authenticated |
| Background jobs (scan dispatch, score snapshot) | per-schedule | No acceleration |

No synthetic destructive writes beyond disposable test data. No schema mutations during load.

---

## Pass Thresholds (G3)

Set during G1 from actual Railway plan limits. Candidates based on typical engagement volume:

| Metric | Threshold | Rationale |
|---|---|---|
| API CPU sustained | < 70% | _(calibrate against Railway limit from G1)_ |
| API memory sustained | < 75% | _(calibrate against Railway limit from G1)_ |
| DB connections active | < 70% of ceiling | _(calibrate against ceiling from G1)_ |
| 5xx error rate | < 0.5% over load window | |
| p95 API latency | < 1.5 s | Portal-facing; portal UX threshold |
| OOM kills / crash loops | 0 | Absolute |
| Redis memory used | < 80% of maxmemory | |

Thresholds are updated in G3 once G1 captures actual plan limits.

---

## G1 — Capacity Baseline

**Status: PENDING**

Capture current production limits and observed steady-state usage before any load test runs.
Let the system idle for 5–10 minutes after last deployment before recording metrics.

### Railway Plan

| Field | Value |
|---|---|
| Date/time captured (UTC) | |
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
| Active connections (idle) | |
| Max connections ceiling | |
| Storage used | |
| Storage limit | |
| IOPS (if available) | |

### Redis

| Field | Value |
|---|---|
| Memory used | |
| maxmemory limit | |
| Memory used % | |
| Active connections | |
| Eviction count | |

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
| Queue depth | |
| Active jobs | |
| Idle jobs | |

### Steady-State Baseline (5–10 min idle observation)

| Metric | Value |
|---|---|
| CPU (start / end / peak) | |
| Memory (start / end / peak) | |
| Open DB connections (start / end / peak) | |
| Redis memory (start / end / peak) | |
| Request rate (avg over window) | |
| Restart count (must be zero) | |

---

## G1.1 — Configuration Drift

**Status: PENDING**

Fingerprint the production configuration and verify no unexpected drift since T4 PASS (2026-08-04).
Record variable **names only** — no secret values.

### Railway Variable Names (api service)

_(List all variable names present; flag any not present at T4 close or any unexpected additions.)_

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
- [ ] Alerting status documented (Railway alerting configured: yes/no; if yes, note alert rules in place)
- [ ] G3 thresholds calibrated against actual plan limits (update Pass Thresholds table above)

**G1 result: PENDING**

---

## G2 — Load Profile

**Status: PENDING**

Run the bounded production-safe load test (workload definition above). Record all observed metrics during the load window.

| Field | Value |
|---|---|
| Date/time (UTC) | |
| Load window duration | |
| Disposable tenant used | |
| Peak API CPU % | |
| Peak API memory % | |
| Peak DB connections | |
| Peak Redis memory | |
| Observed p50 latency | |
| Observed p95 latency | |
| Observed p99 latency | |
| 5xx count / rate | |
| API restart count during load | |
| DB connection saturation events | |
| Redis eviction count | |
| Memory growth trend | |

**G2 result: PENDING**

---

## G3 — Headroom Threshold

**Status: PENDING**

Compare G2 observed peaks against G1-calibrated thresholds. Pass only if all thresholds are met.

| Metric | Threshold | Observed | Pass/Fail |
|---|---|---|---|
| API CPU sustained | < 70% | | |
| API memory sustained | < 75% | | |
| DB connections | < 70% of ceiling | | |
| 5xx rate | < 0.5% | | |
| p95 API latency | < 1.5 s | | |
| OOM kills / crash loops | 0 | | |
| Redis memory | < 80% of maxmemory | | |

**G3 result: PENDING**

---

## G4 — Failure Injection

**Status: PENDING**

Restart or redeploy the production API during controlled test activity. Verify recovery.

| Check | Result |
|---|---|
| Date/time of restart injection (UTC) | |
| Trigger method (Railway redeploy / kill) | |
| Health check failure observed (before recovery) | |
| Health check recovery time (s) | |
| Orphan jobs observed post-restart | |
| Session corruption observed | |
| Duplicate work produced | |
| Lost audit events | |
| Portal accessible after restart | |
| Restart-to-health time (s) | |

**G4 result: PENDING**

---

## G5 — State Recovery

**Status: PENDING**

Verify durable state integrity after the G4 restart.

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

Final determination based on G1–G5 evidence.

| Field | Value |
|---|---|
| Decision | _(PASS / PASS WITH ACTION / FAIL)_ |
| Railway plan at decision | |
| Upgrade required | _(yes / no)_ |
| Upgrade trigger | _(metric and threshold that forces upgrade)_ |
| Estimated upgrade cost delta | |
| Automatic backup enabled post-upgrade | _(yes / no)_ |
| Residual risks documented | |

**G6 result: PENDING**

---

## Failure Policy

- No manual DB writes to simulate or mask a failure.
- No artificial metric suppression.
- No client tenant touched during load test (use disposable tenant or the-wick-network under controlled conditions only).
- Any state corruption = failed gate. Investigate before re-run.
