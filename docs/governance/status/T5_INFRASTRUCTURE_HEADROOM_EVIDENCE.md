# T5 Infrastructure Headroom — Failure Recovery Proof

Status: **PENDING** — gates not yet executed

Gate sequence: G1 → G2 → G3 → G4 → G5 → G6

T5 closes FG-LR-004. It proves Railway production can support the first client engagement
under realistic load and recover from an instance failure without corrupting state.

T5 ends with one of three explicit outcomes:
- **PASS** — current Railway plan has sufficient first-client headroom
- **PASS WITH ACTION** — upgrade required before client start; exact trigger and cost documented
- **FAIL** — architecture or plan blocks launch

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

Capture current production limits and observed idle/baseline usage before any load test runs.

| Field | Value |
|---|---|
| Date/time (UTC) | |
| Railway API plan: vCPU | |
| Railway API plan: RAM | |
| Railway DB plan: max connections | |
| Railway DB plan: storage limit | |
| Railway Redis plan: maxmemory | |
| Railway Redis plan: max connections | |
| Deployment replica count | |
| Observed baseline API CPU % | |
| Observed baseline API memory % | |
| Observed baseline DB connections | |
| Observed baseline Redis memory | |
| p50 / p95 / p99 API latency (idle) | |
| 5xx rate (idle, 24h window) | |
| First-client safety margin (documented) | |

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
