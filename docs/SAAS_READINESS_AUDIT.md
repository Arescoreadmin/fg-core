# FrostGate Core — SaaS Readiness Audit

**Auditor Role:** Senior Principal Engineer / Startup CTO / Enterprise Security Architect
**Date:** 2026-02-09
**Repo Commit:** Current HEAD on `main`
**Verdict:** Not SaaS-ready. Strong security DNA. Significant structural and commercial gaps.

---

## Executive Summary

FrostGate Core is a security-decision engine with unusually mature security testing and
contract discipline for its stage. It has the skeleton of a multi-tenant SaaS product but
is missing the muscle and organs. The codebase is approximately 283 Python files, 10
TypeScript files, 1 Go file, ~111 scripts, and 100+ test files with 706 test functions.

**Current state:** MVP1 (Partial), self-assessed at 27% blueprint alignment (`STATUS.md:10`).

**Bottom line:** An enterprise security buyer would evaluate this for 30 minutes and defer.
Not because the security posture is weak — it is genuinely above average — but because there
is no self-service onboarding, no billing, no SLA tooling, no data retention policy, and the
admin console is a scaffold. The product cannot be purchased, provisioned, or operated without
an engineer in the loop.

---

## Phase 1: Structural Assessment

### 1.1 Current Architectural Spine

```
                    ┌─────────────────────┐
                    │   Console (Next.js)  │  Port 13000
                    │   3 test files, 39   │
                    │   lines of test code │
                    └─────────┬───────────┘
                              │ HTTP
                    ┌─────────▼───────────┐
                    │  Admin Gateway       │  Port 18001
                    │  FastAPI, OIDC,      │
                    │  RBAC, CSRF, Audit   │
                    │  12 test files       │
                    └─────────┬───────────┘
                              │ HTTP proxy
┌──────────┐      ┌──────────▼───────────┐      ┌─────────┐
│  Agent   │─────>│  FrostGate Core API  │<─────│   OPA   │
│ (stub)   │      │  FastAPI, v0.8.0     │      │  v0.64  │
│ heartbeat│      │  57+ test files      │      │ ENFORCE │
│ only     │      │  5 middleware layers  │      │ =false  │
└──────────┘      └──┬─────┬─────┬───────┘      └─────────┘
                     │     │     │
               ┌─────▼┐ ┌─▼───┐ ┌▼──────┐
               │Postgr│ │Redis│ │ NATS  │
               │  16  │ │  7  │ │ 2.10  │
               └──────┘ └─────┘ └───────┘
```

**Services (5 Dockerfiles):**

| Service | Dockerfile | Profile | Status |
|---------|-----------|---------|--------|
| frostgate-core | `Dockerfile` | default | Primary service, functional |
| admin-gateway | `admin_gateway/Dockerfile` | `admin` | Functional, proxies to core |
| console | `console/Dockerfile` | `admin` | Scaffold, minimal testing |
| agent | `agent/Dockerfile` | `agent` | Stub — heartbeat only |
| supervisor-sidecar | `supervisor-sidecar/Dockerfile` | (Go) | Health/restart sidecar |

**Infrastructure:**

| Component | Version | Purpose | Auth |
|-----------|---------|---------|------|
| PostgreSQL | 16-alpine | Primary datastore | Password required (no default) |
| Redis | 7-alpine | Rate limiting, caching | Password required (no default) |
| NATS | 2.10-alpine | Ingestion bus | **No auth configured** |
| OPA | 0.64.1 | Policy evaluation | **No auth, healthcheck disabled** |

### 1.2 Weak Joints

**W1. NATS has no authentication** (`docker-compose.yml:20-21`)
NATS is exposed on port 4222 with JetStream enabled but zero auth. Any container on the
Docker network can publish/subscribe. In a multi-tenant system, this is a lateral movement
vector.

**W2. OPA healthcheck is disabled** (`docker-compose.yml:64`)
`healthcheck: disable: true` means Docker won't track OPA liveness. If OPA crashes, core
continues with `FG_OPA_ENFORCE=false` as default — silently degrading policy enforcement.

**W3. OPA enforcement is OFF by default** (`docker-compose.yml:120`)
`FG_OPA_ENFORCE: ${FG_OPA_ENFORCE:-false}` — The entire policy engine is a no-op in default
configuration. This means a misconfigured deployment has zero policy enforcement and
won't even know it.

**W4. Agent is a stub** (`agent/Dockerfile`)
The agent service exists but only produces heartbeats. No real telemetry collection, no
endpoint integration, no detection capabilities. This is the product's data ingestion
surface and it's empty.

**W5. Console has 39 lines of test code** (`console/tests/`)
The customer-facing UI has essentially no functional testing. Three files that do string
matching on file contents, not component or integration testing.

**W6. Admin Gateway uses mocked core in tests** (`admin_gateway/tests/conftest.py`)
All 12 admin gateway test files mock the core proxy, meaning the actual admin→core integration
path is untested.

**W7. `api/main.py` has 15 try/except import blocks** (`api/main.py:28-114`)
Every spine module (governance, mission_envelope, ring_router, roe_engine, startup_validation,
graceful_shutdown, admin) is wrapped in a fail-soft import. This means the system can boot
with none of its advertised features and report "healthy." A production deployment could
silently lack governance, forensics, or ring routing and nobody would know unless they hit
those endpoints.

**W8. No database migration tooling for core**
Admin gateway has Alembic (`admin_gateway/alembic.ini`) with 1 migration. Core has zero
migration tooling. `api/db.py` does `create_all()` which is SQLite-only and cannot handle
schema evolution in PostgreSQL. The `CONTRACT.md:386` explicitly acknowledges this:
"Postgres requires explicit migrations." They don't exist.

### 1.3 Missing Vertebrae

| Missing Component | Impact | Evidence |
|-------------------|--------|----------|
| Database migrations (core) | Cannot upgrade production DB schema | No alembic.ini in root |
| Secrets manager integration | Secrets in files/env only | `grep vault` returns 0 Python hits |
| Encryption at rest | DB data unencrypted | No encrypt_at_rest anywhere |
| Log aggregation/export | Logs to stdout only | No Loki/ELK/Datadog integration |
| Metrics export | No Prometheus/StatsD | No `/metrics` endpoint |
| Distributed tracing | No OpenTelemetry | No trace correlation headers |
| Billing/payment system | Cannot charge money | `api/tenant_usage.py` has tier stubs, no Stripe |
| Identity provider | OIDC stubs in admin-gw, no real IdP | Mock-only in tests |
| Multi-region | Single-region only | No replication config |
| Backup/restore | No backup procedures | No pg_dump scripts, no PITR config |
| Rate limiting at edge | Redis-backed in-app only | No CDN/WAF/edge rate limiting |
| WebSocket/SSE for real-time | No push capability | Feed is polling-only |
| API versioning strategy | `/v1` prefix exists but no v2 path | No version negotiation |
| Tenant data isolation (physical) | Logical isolation only (tenant_id column) | No per-tenant schemas/DBs |
| Feature flag system | Env vars only | No LaunchDarkly/Unleash/internal |

### 1.4 Accidental Coupling

**C1. 111 scripts in `scripts/`**
This directory has accumulated 111 shell and Python scripts, many of which are one-time fixes
(`fg_fix_decisions_diff_duplicate_kw.sh`, `fg_fix_defend_diff_indent.sh`,
`fg_fix_defend_diff_indent_v2.sh`). At least 40 of these are "fix" scripts that were used
once and never cleaned up. They create the illusion of operational tooling while actually
being dead code that confuses onboarding.

**C2. auth logic split across 4 locations**
- `api/main.py` (lines 134-467) — inline auth with `require_status_auth`
- `api/auth.py` — auth module with tenant registry
- `api/auth_scopes.py` — scoped key validation
- `api/middleware/auth_gate.py` — middleware layer

A new developer cannot answer "where is auth enforced?" without reading all four files.
Line 461-467 of `api/main.py` actually monkey-patches `api.auth` at runtime:
```python
if not hasattr(auth_mod, "require_status_auth"):
    setattr(auth_mod, "require_status_auth", require_status_auth)
```

**C3. SQLite/PostgreSQL dual-mode creates hidden divergence**
Tests run on SQLite. Production runs on PostgreSQL. The `DecisionRecord` model
(`api/db_models.py:131`) uses `create_all()` for SQLite auto-migration but explicitly
says Postgres needs manual migrations (which don't exist). Any schema change passes tests
but breaks production.

**C4. `_SINGLE_USE_EXACT` paths hardcoded in main.py** (`api/main.py:284-286`)
UI single-use token enforcement is implemented as inline middleware in `build_app()` with
hardcoded path sets. This should be in a middleware module with configurable paths.

### 1.5 Tech Debt Traps

**T1. The 27% alignment score is self-inflicted drift**
`STATUS.md` reports 27% blueprint alignment with HIGH drift on API, events, and artifacts.
The project has a `BLUEPRINT_STAGED.md` that defines requirements, but the implementation
has diverged so far that the blueprint is aspirational fiction.

**T2. Fail-soft imports mask missing features in production**
Every try/except import in `api/main.py` means CI can pass while production runs a gutted
version of the application. There is no CI gate that verifies all spine modules actually
load.

**T3. `COPY . /app` in Dockerfile** (`Dockerfile:43`)
The Dockerfile copies the entire repo into the image including tests, scripts, docs,
`.git`, etc. No `.dockerignore` was found to exclude these. This bloats images and leaks
source code.

**T4. In-memory usage tracking** (`api/tenant_usage.py:74-80`)
`TenantUsageTracker` stores usage in a Python dict (`self._usage = {}`). This means:
- Usage data is lost on every restart
- Multiple replicas don't share usage data
- Quotas cannot be enforced across horizontal scaling

**T5. Hardcoded rate limits** (`docker-compose.yml:141`)
`FG_RL_RATE_PER_SEC: 2` and `FG_RL_BURST: 60` — per-tenant rate limits are global env vars,
not per-tenant configuration. Every tenant gets the same limits regardless of tier.

---

## Phase 2: MVP Maturity Scoring

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **Core functionality completeness** | 5/10 | Decision pipeline works (`POST /defend`), feed works, key management works. But: agent is stub, console is scaffold, OPA enforcement is off, governance is feature-flagged-off. Half the advertised surface is dormant. |
| **Stability** | 6/10 | 706 test functions, contract tests, core invariant tests (INV-001 through INV-007) gate CI. But: no load testing, no chaos testing, no failover testing. SQLite↔Postgres divergence is a stability landmine. |
| **Security posture** | 7/10 | Best dimension. 15 dedicated security test files, AST-based crypto verification, timing attack prevention, tenant isolation tests, evidence chain with Merkle anchoring, DoS guard middleware, CORS hardening, CSRF in admin-gw. Deductions: NATS unauthenticated, OPA unenforced, no encryption at rest, no secrets vault. |
| **CI reliability** | 7/10 | 10 CI lanes (guard → unit → integration → postgres → admin → console → PT → hardening → compliance → evidence). Path filtering with dorny/paths-filter. Concurrency groups. Artifact collection. Deduction: no load/performance gate, no container scan, no DAST. |
| **Deployment repeatability** | 4/10 | Docker Compose works for dev. No Helm charts, no Terraform, no K8s manifests (k8s-dev-cluster.sh exists as a script, not IaC). No blue/green or canary. No rollback procedure. Production deployment is undocumented. |
| **Operator usability** | 3/10 | 111 scripts with no documentation on which ones matter. No runbook. No alerting. No dashboards. `fg_doctor.sh` exists but is a diagnostic script, not an operator tool. Console is a scaffold. An operator cannot manage this system without reading source code. |
| **Incident recovery** | 2/10 | No backup/restore procedures. No PITR configuration. No disaster recovery plan. No runbook. Merkle anchor provides tamper detection but not recovery. Evidence chain proves what happened but doesn't help fix it. |
| **Documentation adequacy** | 5/10 | `CONTRACT.md` is excellent — precise, testable, maintained. `GAP_MATRIX.md` and `GAP_SCORECARD.md` show disciplined tracking. But: no API reference beyond OpenAPI, no operator guide, no architecture decision records, no onboarding guide, no deployment guide. |
| **Monitoring coverage** | 2/10 | `/health/ready` checks DB and Redis. `/health/detailed` exists behind auth. No Prometheus metrics, no distributed tracing, no log aggregation, no alerting, no SLO definitions, no error budget tracking. |
| **Revenue readiness** | 1/10 | `api/tenant_usage.py` has tier definitions (free/starter/pro/enterprise) and quota stubs. `api/admin.py` has tenant management endpoints. But: no billing integration, no payment processing, no invoice generation, no usage export, no self-service signup, no pricing page. The in-memory usage tracker loses data on restart. |

**Composite Score: 4.2/10**

---

## Phase 3: Commercial Viability Audit

### 3.1 Who Would Pay Today

**Nobody.** Specifically:

The closest buyer profile is a security team at a mid-market company (200-2000 employees)
that wants an AI-augmented decision engine for their SOC. But:

1. They cannot self-provision. There is no signup flow.
2. They cannot integrate without engineering help. The agent is a stub.
3. They cannot demonstrate compliance. No SOC 2 Type II, no ISO 27001, no GDPR DPA.
4. They cannot get an SLA. No SLA tooling, no uptime guarantees, no error budgets.
5. They cannot get an invoice. No billing system.

### 3.2 Why They Would Hesitate

| Hesitation | Root Cause | File/Evidence |
|-----------|------------|---------------|
| "Is this production-ready?" | STATUS.md says 27% alignment, "MVP 1 (Partial)" | `STATUS.md:10-11` |
| "Can I try it myself?" | No self-service. Docker Compose only. | No signup endpoint exists |
| "What happens to my data?" | No data retention policy, no encryption at rest | No DPA document |
| "What's your uptime?" | No SLA tooling, no status page, no incident history | No monitoring stack |
| "Can I see a dashboard?" | Console is scaffold with 39 lines of test code | `console/tests/` |
| "Is this SOC 2 compliant?" | SBOM/provenance exist, but no SOC 2 report | Missing audit report |
| "What integrations exist?" | Agent is a heartbeat stub | `agent/` directory |
| "How do I pay?" | No billing system | `api/tenant_usage.py` — in-memory only |

### 3.3 What Blocks Procurement

1. **No security questionnaire answers.** Enterprise procurement requires completed SIG/CAIQ.
2. **No DPA/BAA.** GDPR/HIPAA buyers need data processing agreements.
3. **No penetration test report.** CI has a PT lane but no third-party pentest report.
4. **No SOC 2 Type II.** The compliance gate scripts (`cis_check.py`, `scap_scan.py`) are
   internal only — they're not externally audited attestations.
5. **No vendor risk assessment materials.** No SBOM published to customers. Internal only.

### 3.4 What Blocks Scale

1. **In-memory usage tracking** (`api/tenant_usage.py`) — cannot survive restarts or replicas.
2. **No horizontal scaling strategy.** Rate limiting uses Redis (good), but usage/quotas are in-process memory (bad).
3. **No connection pooling configuration.** Core uses SQLAlchemy but no pooling tuning.
4. **No caching layer beyond Redis rate limits.** Feed queries hit DB every time.
5. **Single PostgreSQL instance.** No read replicas, no connection proxy (PgBouncer).
6. **No CDN/edge caching.** Console serves from container directly.

### 3.5 What Blocks Compliance

1. No data residency controls (no region selection).
2. No audit log export (audit logs exist internally but no customer-facing export).
3. No right-to-erasure implementation (GDPR Article 17).
4. No data classification labels on stored fields.
5. Append-only decision records (by design) conflict with deletion requirements without
   a crypto-erasure strategy.

### 3.6 What Blocks Onboarding

1. No self-service tenant provisioning.
2. No API key generation UI (admin gateway has endpoints, console doesn't wire them).
3. No getting-started guide.
4. No SDK or client library.
5. No example integrations.
6. Agent stub means customers must build their own data pipeline.

### 3.7 What Blocks Retention

1. No dashboards showing value delivered (blocked threats, decisions made).
2. No usage analytics visible to customers.
3. No alerting when threats are detected.
4. No weekly/monthly security reports.
5. No comparison benchmarks ("you blocked X more threats than average").
6. The feed endpoint is the only way to see decisions — it's a JSON list, not a dashboard.

---

## Phase 4: Spine Reinforcement Plan

### Stage A: MVP2 Hardening (30-45 days)

**Goal:** A deployable, demonstrable product that one pilot customer can use.

#### A1. Database Migration System for Core (Week 1-2)

**Deliverables:**
- Alembic configuration in repo root (`alembic.ini`, `migrations/`)
- Initial migration from current `create_all()` schema
- Migration for all missing Postgres columns (chain columns, key hash columns)
- CI gate: `make db-migrate-check` verifies pending migrations

**Kill-switch:** `FG_DB_AUTO_MIGRATE=false` (default off in prod, require explicit migration runs)

**Tests:**
- `tests/test_migration_safety.py` — verify up/down migrations are idempotent
- Add to `db_postgres_verify` CI lane

**Files to create/modify:**
- `alembic.ini` (new)
- `migrations/env.py` (new)
- `migrations/versions/001_initial_schema.py` (new)
- `Makefile` — add `db-migrate`, `db-migrate-check` targets

#### A2. Eliminate Fail-Soft Imports (Week 1)

**Deliverables:**
- New CI gate: `make verify-spine-modules` that imports all spine modules and fails if any
  raise ImportError
- Convert `api/main.py` try/except blocks to explicit feature flags
- Feature flags checked at startup, logged, and exposed via `/health/detailed`

**Kill-switch:** Each module gets `FG_<MODULE>_ENABLED` env var (already partially exists)

**Tests:**
- `tests/test_spine_module_loading.py` — verify all modules import cleanly
- Add to `fg_guard` CI lane

**Files to modify:**
- `api/main.py` — remove 15 try/except blocks, replace with explicit checks

#### A3. Persistent Usage Tracking (Week 2-3)

**Deliverables:**
- Move `TenantUsageTracker` from in-memory dict to Redis or PostgreSQL
- Usage records survive restarts and work across replicas
- Usage export endpoint: `GET /admin/usage/export?format=csv`

**Tests:**
- `tests/test_tenant_usage_persistent.py` — verify persistence across tracker instances
- `tests/test_usage_export.py` — verify CSV export

**Files to modify:**
- `api/tenant_usage.py` — replace dict with Redis/Postgres backend
- `api/admin.py` — add export endpoint

#### A4. NATS Authentication (Week 1)

**Deliverables:**
- NATS configured with token or NKey authentication
- Connection credentials from Docker secret or env
- Health check re-enabled

**Files to modify:**
- `docker-compose.yml` — add NATS auth config, enable healthcheck for OPA
- `api/ingest_bus.py` — pass credentials when connecting

#### A5. Dockerfile Hardening (Week 1)

**Deliverables:**
- `.dockerignore` excluding tests, scripts, docs, .git, .env
- Multi-stage build already exists (good), but verify no secrets in image layers
- Pin base image digests for supply chain security

**Files to create/modify:**
- `.dockerignore` (new or update)
- `Dockerfile` — pin `python:3.12-slim@sha256:...`

#### A6. Console Functional Testing (Week 2-4)

**Deliverables:**
- Playwright or Cypress E2E test suite for console
- Minimum: login flow, dashboard render, feed display, key management
- CI gate: `make ci-console-e2e`

**Tests:**
- `console/tests/e2e/` directory with at least 10 test cases

#### A7. Auth Consolidation (Week 3-4)

**Deliverables:**
- Single `api/auth/` package with clear layers:
  - `api/auth/gate.py` — middleware
  - `api/auth/keys.py` — key validation
  - `api/auth/scopes.py` — scope enforcement
  - `api/auth/tenant.py` — tenant validation
- Remove monkey-patching from `api/main.py:461-467`
- Remove inline `require_status_auth` from `api/main.py`

**Tests:**
- Existing auth tests must pass without modification (refactor, not rewrite)

---

### Stage B: Enterprise Spine (90 days)

#### B1. Identity Provider Integration

- OIDC integration with Okta, Azure AD, Google Workspace
- SAML 2.0 support (enterprise requirement)
- JIT provisioning (create tenant on first login)
- Admin gateway already has OIDC stubs — make them real

#### B2. Policy Engine Enforcement

- Set `FG_OPA_ENFORCE=true` by default
- Policy library: 10 pre-built policies for common use cases
- Policy editor in console
- Policy versioning and rollback
- Policy simulation mode (what-if analysis)

#### B3. Billing Integration

- Stripe integration for usage-based billing
- Webhook endpoint for Stripe events
- Invoice generation from usage records
- Self-service plan upgrade/downgrade in console
- Metered billing from persistent usage tracker (Stage A3)

#### B4. Multi-Tenant Hardening

- PostgreSQL Row-Level Security (RLS) policies
- Per-tenant connection strings (optional physical isolation)
- Tenant provisioning API (self-service)
- Tenant suspension with data preservation
- Tenant data export (GDPR portability)

#### B5. Audit System

- Customer-facing audit log viewer in console
- Audit log export (CSV, JSON, SIEM formats)
- Audit log retention policy with configurable TTL
- Audit log integrity verification (Merkle anchor integration)
- Audit webhook for external SIEM integration

#### B6. SLA Tooling

- Public status page (using existing health endpoints)
- SLO definitions: availability, latency p99, decision throughput
- Error budget tracking
- Incident management integration (PagerDuty/OpsGenie)
- Monthly SLA reports

#### B7. Monitoring Stack

- Prometheus metrics endpoint (`/metrics`)
- Grafana dashboards (pre-built)
- OpenTelemetry integration for distributed tracing
- Log aggregation (structured JSON → Loki/CloudWatch)
- Alerting rules for: error rate, latency, queue depth, quota exhaustion

---

### Stage C: Moat Layer (6-12 months)

#### C1. Data Flywheel

The decision engine gets better with more data. Each `/defend` call produces a
`DecisionRecord` with threat classification, rules triggered, and anomaly scores.

- **Anonymized threat intelligence sharing:** Aggregate anonymized threat patterns across
  tenants → publish community threat feed → free tier gets delayed access, paid gets
  real-time.
- **Model retraining pipeline:** Decision feedback loop → retrain anomaly scoring models →
  customers who use it longer get better detection.
- **Benchmark database:** "Your organization blocked 340% more brute-force attempts than
  the industry average this month."

#### C2. Network Effects

- **Integration marketplace:** Agent templates for common platforms (AWS CloudTrail,
  Azure Sentinel, Splunk, CrowdStrike).
- **Community policy library:** User-contributed OPA policies, vetted and ranked.
- **Cross-tenant threat correlation:** Anonymized patterns from Tenant A's incidents
  automatically protect Tenant B (with consent).

#### C3. Vendor Lock-In (Ethical)

- **Custom policy language:** Domain-specific policy syntax that's easier than raw Rego.
- **Evidence chain format:** Proprietary chain verification format that exports to
  standard formats but is most powerful in-platform.
- **Decision replay:** Only FrostGate can replay decisions with full context (forensics
  endpoint). Historical decisions become an asset that's expensive to migrate.

#### C4. IP Defensibility

- **Decision engine algorithms:** Patent the TieD (Threat Impact Estimate for Decisions)
  framework. It's novel — doctrine-aware impact estimation with service/user impact scoring.
- **Evidence chain:** Patent the per-tenant Merkle chain with policy hash propagation.
- **ROE gating:** Patent the Rules of Engagement gating for security automation
  (guardian/persona model).

#### C5. Platform Leverage

- **API-first platform:** Everything in FrostGate is an API. The console is just one
  client. SDKs for Python, Go, JS, Rust.
- **Webhook ecosystem:** Tripwire delivery system (`api/tripwires.py`) already exists.
  Expand to full event-driven platform.
- **Embeddable widget:** Security posture widget that customers embed in their dashboards.

---

## Phase 5: ROI Prioritization Matrix

| Rank | Work Item | Revenue Impact | Risk Reduction | Competitive Leverage | Time to Implement | Priority Score |
|------|-----------|---------------|----------------|---------------------|-------------------|---------------|
| 1 | Persistent usage tracking (A3) | **HIGH** — enables billing | **MED** — data loss on restart | LOW | 1 week | **9.5** |
| 2 | Database migrations for core (A1) | **HIGH** — blocks all upgrades | **HIGH** — schema drift breaks prod | LOW | 2 weeks | **9.0** |
| 3 | Billing integration (B3) | **CRITICAL** — no revenue without it | LOW | MED | 4 weeks | **9.0** |
| 4 | Self-service tenant provisioning | **HIGH** — blocks all sales | MED | MED | 2 weeks | **8.5** |
| 5 | Eliminate fail-soft imports (A2) | LOW | **HIGH** — silent feature loss | LOW | 3 days | **8.0** |
| 6 | NATS authentication (A4) | LOW | **HIGH** — lateral movement vector | LOW | 2 days | **8.0** |
| 7 | Console E2E testing (A6) | MED — demo quality | **MED** — UI regression risk | MED | 3 weeks | **7.5** |
| 8 | OPA enforcement on by default | LOW | **HIGH** — policy bypass | **HIGH** — core differentiator | 1 week | **7.5** |
| 9 | Identity provider integration (B1) | **HIGH** — enterprise requirement | MED | MED | 4 weeks | **7.5** |
| 10 | Auth consolidation (A7) | LOW | **MED** — audit surface confusion | LOW | 2 weeks | **6.5** |
| 11 | Monitoring stack (B7) | LOW | **HIGH** — blind operations | LOW | 3 weeks | **6.5** |
| 12 | Dockerfile hardening (A5) | LOW | **MED** — image bloat, code leak | LOW | 2 days | **6.0** |
| 13 | SLA tooling (B6) | MED | MED | MED | 4 weeks | **6.0** |
| 14 | Audit log export (B5) | MED | LOW | **HIGH** — compliance differentiator | 3 weeks | **6.0** |
| 15 | Multi-tenant RLS (B4) | MED | **HIGH** — isolation is app-level only | MED | 4 weeks | **6.0** |
| 16 | Backup/restore procedures | LOW | **CRITICAL** — no disaster recovery | LOW | 1 week | **5.5** |
| 17 | Agent implementation | **HIGH** — enables data ingestion | LOW | **HIGH** — integration surface | 8 weeks | **5.5** |
| 18 | Script cleanup | LOW | LOW | LOW | 1 week | **3.0** |
| 19 | Data flywheel (C1) | **HIGH** (long-term) | LOW | **CRITICAL** | 6 months | **2.5** (now) |

**Scoring formula:** `(Revenue × 3 + Risk × 2 + Competitive × 1) / (Time × 0.5)`
Items scored higher when they unblock other items (e.g., billing unblocks revenue).

---

## Phase 6: Kill Analysis (Failure Modes)

### Scenario: FrostGate fails in 24 months

**Cause of death:** The product never achieved product-market fit because it couldn't
complete the journey from "security engine" to "security product."

**Timeline of failure:**

**Months 1-6 (Now → Mid-2026):**
The team ships technical improvements: migrations, monitoring, auth consolidation.
These are necessary but invisible to customers. No billing system ships. The pilot
customer uses FrostGate with white-glove support. Revenue: $0.

**Warning sign #1:** The 111 scripts in `scripts/` keep growing. Each fix spawns
another script instead of being absorbed into the core. This is a cultural problem:
the team builds scaffolding instead of structures.

**Months 6-12 (Mid → Late 2026):**
The console gets real. Billing ships via Stripe. Three customers sign up for the free
tier. One upgrades to Starter ($99/mo). The agent is still a stub, so customers must
build their own data pipelines. Onboarding takes 2 weeks of engineering time per customer.

**Warning sign #2:** Customer acquisition cost is $5,000+ per customer (engineering
time for onboarding) against $99/mo revenue. LTV:CAC is underwater.

**Warning sign #3:** The SQLite↔Postgres divergence causes a production schema mismatch
that takes 4 days to diagnose. Tests passed. Production broke. Trust erodes.

**Months 12-18 (Early → Mid 2027):**
A competitor (LimaCharlie, Torq, or a Wiz feature expansion) ships a similar decision
engine with a working agent ecosystem and marketplace integrations. They have 50+ data
source integrations. FrostGate has 0.

**Warning sign #4:** The `STATUS.md` alignment score never reached 60%. The blueprint
and the implementation continued diverging because there was no mechanism to enforce
convergence.

**Months 18-24 (Mid → Late 2027):**
The remaining customers churn because:
1. No SOC 2 report (procurement blocks renewals).
2. Agent still requires custom integration work.
3. Dashboard is functional but not competitive with incumbents.
4. No threat intelligence sharing (no data flywheel).

**Fatal decisions:**

1. **Building the engine before the product.** The decision pipeline, evidence chain,
   and Merkle anchor are technically impressive. But customers don't buy engines — they
   buy products. The time spent on cryptographic tamper detection should have been split
   50/50 with billing, onboarding, and agent implementation.

2. **Dual-mode SQLite/Postgres without migration tooling.** This saved time in month 1
   and created a permanent tax. Every schema change required manual intervention in
   production while silently passing in CI.

3. **111 scripts instead of operational tooling.** The scripts directory is a graveyard
   of one-time fixes. Each script represents a problem that was patched instead of
   fixed. The operational surface became untestable.

4. **OPA enforcement off by default.** The policy engine — the core differentiator —
   was disabled by default. This meant most deployments never used it. When it was
   finally turned on, policies were stale and mismatched.

5. **Agent as afterthought.** A security product without data ingestion is a decision
   engine without decisions. The agent should have been the first service built, not
   the last.

---

## Phase 7: Execution Checklist

### Next 14 Days

| # | Task | Testable | Verifiable | Monetizable |
|---|------|----------|------------|-------------|
| 1 | Create `.dockerignore` excluding tests, docs, scripts, .git, .env, *.md | `docker build` produces image < 200MB | Image layer inspection | Faster deployments for customers |
| 2 | Add NATS authentication to `docker-compose.yml` | `nats-cli` connection without token fails | CI integration test | Security posture for enterprise sales |
| 3 | Enable OPA healthcheck in `docker-compose.yml` | `docker compose ps` shows OPA healthy/unhealthy | Health endpoint returns OPA status | Reliability claim |
| 4 | Create `make verify-spine-modules` target that imports all spine modules | `make verify-spine-modules` exits 0 in CI | Add to `fg_guard` lane | Prevents silent feature loss in production |
| 5 | Write `alembic.ini` and initial migration for core DB | `alembic upgrade head` on fresh Postgres succeeds | `alembic check` shows no pending migrations | Enables production upgrades |
| 6 | Pin Docker base images to digest | `Dockerfile` references `@sha256:` | `docker inspect` shows pinned digest | Supply chain security for enterprise |
| 7 | Delete dead scripts from `scripts/` (identify ≥40 one-time fix scripts) | `ls scripts/fg_fix_*.sh \| wc -l` decreases by ≥30 | Git diff shows only deletions in scripts/ | Reduces onboarding confusion |
| 8 | Create backup/restore documentation with `pg_dump` procedure | Document exists at `docs/BACKUP_RESTORE.md` | Procedure tested on fresh Postgres | Disaster recovery claim |
| 9 | Set `FG_OPA_ENFORCE=true` as default in `docker-compose.yml` | Deploy without explicit override → OPA evaluates | Test with failing policy → request blocked | Core product differentiator |
| 10 | Add Prometheus metrics endpoint (`/metrics`) using `prometheus_client` | `curl /metrics` returns Prometheus text format | Grafana can scrape and display | Monitoring sales enablement |

### Next 30 Days

| # | Task | Testable | Verifiable | Monetizable |
|---|------|----------|------------|-------------|
| 11 | Move `TenantUsageTracker` to Redis-backed persistence | Restart server → usage data persists | `redis-cli` shows usage keys | Enables billing |
| 12 | Implement Stripe billing integration (usage-based) | Create Stripe test customer → meter usage → invoice generated | Stripe dashboard shows metered events | **Direct revenue** |
| 13 | Build self-service tenant provisioning API | `POST /admin/tenants` creates tenant with API key | Tenant can call `/defend` immediately | Removes onboarding engineering cost |
| 14 | Implement Playwright E2E tests for console (10 tests minimum) | `make ci-console-e2e` exits 0 | Coverage report shows tested paths | Demo reliability |
| 15 | Consolidate auth into `api/auth/` package | All 4 auth locations → 1 package | Existing auth tests pass unchanged | Audit-ready auth surface |
| 16 | Add structured JSON logging with correlation IDs | Every log line has `request_id`, `tenant_id` | Grep logs by tenant | Enterprise logging requirement |
| 17 | Create customer-facing API documentation site | Docs hosted at `/docs` with examples | Non-engineer can understand API | Self-service onboarding |
| 18 | Build getting-started guide with example integration | Guide at `docs/GETTING_STARTED.md` with curl examples | New developer can send first `/defend` in < 5 minutes | Onboarding time reduction |
| 19 | Implement audit log export endpoint | `GET /admin/audit/export?format=csv` returns CSV | CSV opens in Excel correctly | Compliance sales enablement |
| 20 | Add PostgreSQL RLS policies for tenant isolation | `SET fg.tenant_id = 'X'; SELECT * FROM decision_records;` returns only X's data | Bypass attempt returns empty result | Security posture for enterprise |

### Next 90 Days

| # | Task | Testable | Verifiable | Monetizable |
|---|------|----------|------------|-------------|
| 21 | Implement real OIDC with Okta/Azure AD | Login with Okta account → session created | Okta audit log shows login event | Enterprise SSO requirement |
| 22 | Build agent for AWS CloudTrail | Agent ingests CloudTrail events → `/defend` decisions appear | Feed shows AWS-sourced events | First real integration |
| 23 | Build agent for Splunk HEC | Agent receives Splunk HEC events → decisions appear | Splunk customer can connect in < 1 hour | Second integration |
| 24 | Implement data retention policy with crypto-erasure | Tenant deletion → crypto-erase all records | Verification shows records unrecoverable | GDPR compliance |
| 25 | Deploy monitoring stack (Prometheus + Grafana + alerting) | Alert fires on error rate > 5% | PagerDuty receives alert | SLA tooling |
| 26 | Complete SOC 2 Type I evidence collection | Evidence package contains all required artifacts | External auditor accepts package | Procurement unblock |
| 27 | Build policy editor in console | Create policy in UI → OPA evaluates it | Policy test mode shows expected results | Product differentiator |
| 28 | Implement status page | `status.frostgate.io` shows uptime | Historical uptime data visible | Trust signal |
| 29 | Ship SDK for Python and JavaScript | `pip install frostgate` / `npm install frostgate` works | SDK example sends first event in 3 lines | Developer onboarding |
| 30 | Implement weekly security report emails | Tenant receives email with threat summary | Email contains actionable metrics | Retention mechanism |

---

## Appendix A: File Reference Index

| File | Relevance to Audit |
|------|-------------------|
| `STATUS.md:10` | Self-assessment: MVP1 Partial, 27% alignment |
| `docker-compose.yml:20-21` | NATS exposed without auth |
| `docker-compose.yml:64` | OPA healthcheck disabled |
| `docker-compose.yml:120` | OPA enforcement off by default |
| `api/main.py:28-114` | 15 fail-soft import blocks |
| `api/main.py:284-286` | Hardcoded single-use paths |
| `api/main.py:461-467` | Runtime monkey-patching of auth module |
| `api/tenant_usage.py:74-80` | In-memory usage dict |
| `api/db_models.py:131` | DecisionRecord model (no migrations) |
| `Dockerfile:43` | `COPY . /app` without .dockerignore |
| `CONTRACT.md:386` | Acknowledges Postgres migration gap |
| `GAP_SCORECARD.md:14` | Launch Readiness: 0% |
| `console/tests/` | 3 files, 39 lines total |
| `admin_gateway/alembic.ini` | Only service with migrations |
| `scripts/` | 111 scripts, ~40 are one-time fixes |

## Appendix B: Strengths Worth Preserving

These are genuinely good and should not be lost in the rush to ship:

1. **Contract-driven development** (`CONTRACT.md`) — This is rare. Keep it.
2. **Security test suite** (15 files, AST-based crypto verification) — Best-in-class for this stage.
3. **Core invariant tests** (INV-001 through INV-007 as CI gates) — Hard to retroactively add.
4. **Evidence chain with Merkle anchoring** — Real IP. Patent it.
5. **Gap matrix with machine-enforced severity** (`scripts/gap_audit.py`) — Disciplined tracking.
6. **Fail-closed in production** (`api/main.py:232-233`) — Correct default posture.
7. **Docker secrets for API keys** (`docker-compose.yml:248-250`) — Not env vars.
8. **Non-root container user** (`Dockerfile:56`) — Security baseline.
9. **DoS guard middleware** with configurable limits — Enterprise-grade defense.
10. **Per-tenant Merkle chains** — Novel and defensible.
