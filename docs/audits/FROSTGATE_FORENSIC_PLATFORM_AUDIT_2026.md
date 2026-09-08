# FrostGate Forensic Platform Audit 2026

**Principle:** Trust, but Verify.
**Audit date:** 2026-09-08
**Decision target:** shortest safe and defensible path to customer usage, first revenue, and recurring revenue.

## 1. Executive Verdict

FrostGate is a large, security-conscious platform with a credible field-assessment core, meaningful evidence lineage, deterministic governance artifacts, and unusually broad automated testing. It is not, however, a production-ready autonomous governance platform or a supportable multi-customer recurring service today.

The shortest sellable wedge is a **service-led, fixed-scope AI governance assessment**: operator-created engagement, no-auth and manual evidence collection, questionnaire/interviews, deterministic findings, human report QA, signed delivery, and a controlled remediation plan. Microsoft 365 scans must be excluded from the contractual scope until exercised against a real tenant. The customer-facing Console and Portal must not be exposed until critical dependency findings, reproducible builds, current-schema backup/restore proof, and current-HEAD identity onboarding proof are closed.

There is no proven P0 cross-tenant exploit in the audited paths. There are multiple P1 conditions that make unconditional external use indefensible: vulnerable authentication/frontend dependencies, absent enforced branch rules, a Portal lockfile that cannot clean-install, process-local job execution presented as durable, current production proofs still pending, migration/RLS closed-world gaps, stale deployment branch authority, and contradictory backup evidence.

**Verdict:** charge conditionally for a tightly operated assessment after the Customer-One preflight below; do not sell continuous autonomous governance or self-service MRR yet.

### A. System Health

| Subsystem | Status | Confidence | Customer Ready | MRR Ready | Blocker |
| --- | --- | ---: | ---: | ---: | --- |
| Core API and middleware | ACTIVE / PARTIAL | High | Conditional | No | Production proof and runtime DDL model |
| Canonical identity and membership | ACTIVE / PARTIAL | High | Conditional | No | P-113.9 live proof pending; worker deployment drift |
| Authorization and tenant binding | ACTIVE | High | Conditional | Conditional | Compatibility authority and incomplete RLS universe |
| Field assessment | ACTIVE | High | Conditional | Conditional | Jobs are not durably executed |
| Evidence and signed reports | ACTIVE / DUPLICATED | High | Conditional | Conditional | Parallel authorities; worker recovery gap |
| Microsoft connectors | PARTIAL | High | No | No | No real Microsoft tenant proof |
| No-auth scanners | ACTIVE | High | Yes with operator control | Conditional | Restart/retry handling |
| Console | ACTIVE / PARTIAL | High | No | No | Critical Auth.js advisories; release gates |
| Portal | PARTIAL | High | No | No | Critical Next.js advisories; unreproducible clean install |
| Billing/subscriptions | PARTIAL | High | No | No | No consumer/proof; schema authority gap |
| Continuous governance | PARTIAL / UNPROVEN | High | No | No | Manual reassessment; unwired readiness inputs |
| Autonomous governance | PARTIAL / MARKETING CLAIM | High | No | No | Key inputs explicitly unwired |
| Backup/restore | PARTIAL | High | No | No | Freshest artifact critical; restore proof at 0172 only |
| CI/release governance | PARTIAL | Proven | No | No | Main unprotected; no rulesets |
| Observability/operations | PARTIAL | High | Conditional | No | No worker health/SLO alert proof |

## 2. Repository Identity

| Item | Recorded value |
| --- | --- |
| Repository | `/home/jcosat/Projects/fg-core` |
| Initial branch | `feat/p1140-invitation-authorized-identity-enrollment` |
| Initial HEAD | `e7450077e396e4f8ccec4308778acc5da7e867a4` |
| Analysis baseline after invitation commit | `194e669fbe759930b0e3628fca0279e912ffebab` |
| Closeout branch | `main` |
| Final audited HEAD | `c231a5e6d4962c4dd855c7e461bf31efa5e18b55` |
| `origin/main` at closeout | `c231a5e6d4962c4dd855c7e461bf31efa5e18b55` |
| Final worktree before report | Clean |
| Python | 3.12.3 |
| Node | v22.22.2 |
| npm | 10.9.7 |
| Railway CLI | 5.49.3 |
| Production access | Not used |

**Evidence preservation note:** the audit began with three modified files: `api/identity_acceptance.py`, `apps/console/app/api/core/[...path]/route.ts`, and `apps/console/app/identity/invitations/[token]/page.tsx`. During the audit, an external actor committed those changes plus a test as `194e669f`; this auditor did not create that commit. During final validation, PR #682 moved the worktree to `main` at `c231a5e6`. The delta from `194e669f` was reviewed in full: it normalizes `login_hint`, adds two invitation tests, and updates the fix log. Both new tests passed in the repository virtual environment, and no audit conclusion changed. No tracked file was changed by this auditor before this requested report.

**Environment assumptions:** static and local test evidence was used. No claim is made about current Railway/Vercel values, live database contents, Auth0 state, Microsoft tenant state, Redis durability, Stripe state, or production traffic beyond committed artifacts and read-only GitHub metadata.

## 3. Audit Methodology

1. Captured branch, SHAs, worktree state, toolchain, tracked-file census, route inventory, migration head, and dependency manifests.
2. Started from process entry points (`api.main:app`, `admin_gateway.asgi:app`, identity worker, three Next.js apps), then traced request/auth/tenant/service/persistence paths.
3. Compared runtime AST routes, committed OpenAPI, BFF allowlists, UI consumers, authority manifest, SQL migrations, SQLAlchemy metadata, tests, runbooks, CI, deployment definitions, and production-proof artifacts.
4. Ran non-mutating or local-only gates. No production connections or secret values were used.
5. Classified statements as **PROVEN FACT**, **INFERENCE**, **RISK**, or **RECOMMENDATION**. A passing structural test was not treated as live proof.

Verification performed:

- `make -s check-core-rls check-connectors-rls check-credential-authority route-inventory-audit authority-integration-check`: passed; authority check emitted billing, governance-workflow, and subscription warnings.
- `pytest tests/security -m 'not slow'`: `1,234 passed, 1 skipped`.
- Current identity-focused suite: `96 passed, 3 skipped`; skips are live production proofs.
- Closeout delta at `c231a5e6`: both newly added invitation preflight tests passed.
- Full collection: `22,500 tests collected`. A non-gating full run was stopped at 12% after 11m13s: `2,906 passed, 14 skipped`, no failures observed.
- Console tests: `2,957 passed`; Console typecheck and production build passed.
- Portal tests: `77 passed`; Portal production build failed on unresolved `@vercel/edge-config`.
- Public web production build passed.
- `npm ci --dry-run --ignore-scripts` in Portal failed because manifest and lockfile disagree.
- Current npm advisory queries: Console `2 critical, 4 high`; Portal `1 critical, 2 high`; public web `3 high`.
- Python `make pip-audit`: command passed only with six ignored findings in Core and three in Admin Gateway.
- Read-only GitHub API: `main` has no classic branch protection and repository rulesets are empty.

## 4. Repository Coverage Ledger

The repository contains approximately 3,500 tracked files: 2,116 Python, 362 TSX, 293 Markdown, 190 SQL, 130 JSON, 118 shell, 106 TypeScript, and 68 JavaScript files. The ledger accounts for production-relevant roots; generated caches, `.venv`, `node_modules`, `.next`, `.git`, and local provider metadata were excluded from source conclusions.

| Root | Tracked files | Classification | Coverage and conclusion |
| --- | ---: | --- | --- |
| `tests/` | 724 | TEST-ONLY | Collected globally; security, identity, frontend, and gate behavior exercised |
| `services/` | 643 | ACTIVE / PARTIAL | Authority engines, repositories, assessment/evidence/remediation/governance traced |
| `apps/` | 545 | ACTIVE / PARTIAL / ORPHANED | Console, Portal, public web, and nested duplicate Console examined |
| `api/` | 376 | ACTIVE / COMPATIBILITY | App assembly, middleware, 1,236 AST routes, auth, DB, major route groups traced |
| `docs/` | 231 | ACTIVE / STALE MIX | Runbooks, launch evidence, architecture, proof claims, contradictions sampled systematically |
| `migrations/` | 188 | ACTIVE | 0001-0187 ordering, RLS gates, identity and authority tables examined |
| `scripts/` | 180 | DEV/OPS / PARTIAL | Backup, proof, tenant, migration, and gate scripts inventoried |
| `tools/` | 168 | CI/DEV | Route, RLS, authority, release and plan gates inspected |
| `admin_gateway/` | 78 | ACTIVE / PARTIAL | OIDC, tenant/admin routes, projection worker, health and deployment traced |
| `agent/` | 71 | ACTIVE / PARTIAL | Enrollment, credentials, event transport, fallback limiter, service unit reviewed |
| repository root | 61 | MIXED | Docker, Make, requirements, authority manifest, product/status documents reviewed |
| `contracts/` | 57 | GENERATED / PROOF TEMPLATES | OpenAPI and current/pending proof artifacts examined |
| `artifacts/` | 35 | GENERATED / STALE MIX | Backup health, route summaries, T5/T6 historical evidence examined |
| `packages/` | 29 | ACTIVE | Shared UI/navigation packages and consumer relationships checked |
| `deploy/` | 22 | PARTIAL | Helm variants, dev K8s, Prometheus/Grafana, systemd reviewed |
| `backend/` | 20 | ORPHANED / DEMO | Separate static FastAPI demo; no production entry-point reference found |
| `.github/` | 12 | ACTIVE / PARTIAL | CI, backup and restore workflows, trigger/path behavior examined |
| `engine/` | 12 | ACTIVE / FEATURE-FLAGGED | Rules, doctrine, ROE, pipeline and public feature-flagged surfaces examined |
| `schemas/` | 10 | GENERATED / CONTRACT | OpenAPI and event/artifact schema ownership reviewed |
| `jobs/` | 8 | PARTIAL / STUB | Merkle/simulation jobs plus explicit placeholder chaos job found |
| `policy/` | 6 | ACTIVE / PARTIAL | OPA policy/bundle and deployment relationship reviewed |
| `marketing/` | 5 | ACTIVE CLAIM SURFACE | Public claims compared with runtime proof |
| `auth0/`, `keycloak/`, `security/`, `env/` | 4 | CONFIG / COMPATIBILITY | Auth action and environment/security definitions reviewed |

Classification confidence is lower for modules that are only dynamically loaded or feature-flagged. Static absence of a caller was not, by itself, classified as dead; entry-point, router, manifest, or deployment evidence was required.

## 5. Architecture Map

```text
Browser (operator/customer admin)
  -> Console (NextAuth/Auth0, role classification)
  -> Console BFF allowlist, tenant resolution, machine credential, delegation proof
  -> Core AuthGate -> credential resolution -> ActorContext/RBAC -> tenant binding
  -> SQLAlchemy service/repository -> PostgreSQL + RLS -> audit/evidence side effects

Browser (portal user)
  -> Portal OIDC PKCE -> server-side pnu1 session
  -> Portal BFF allowlist + static service tenant/key
  -> Core portal session validation -> membership/auth-version/engagement scope
  -> tenant-bound persistence

Core assessment route
  -> durable job row -> FastAPI BackgroundTasks (same process)
  -> connector -> normalized scan -> evidence -> finding -> report/QA/delivery

Core identity mutation
  -> canonical DB transaction -> identity_projection_outbox
  -> separate polling worker -> Auth0 Management API projection

GitHub schedule
  -> backup script -> encrypted dump + HMAC manifest -> S3/R2
  -> monthly scratch-Postgres restore drill
```

Actual production-like topology in `.railway/railway.ts` declares Core API, Admin Gateway, an identity projection worker, PostgreSQL, Redis, and volumes. Console, Portal, and public web are Vercel-oriented. Docker Compose additionally describes NATS, OPA, migration/bootstrap services, and local workers; these are not proof of Railway runtime composition.

## 6. Runtime Authority Map

| Concept | Canonical authority | Competing/compatibility authority | Verdict |
| --- | --- | --- | --- |
| Tenant | `tenants` plus tenant lifecycle | request/BFF tenant hints; legacy defaults | Canonical DB exists; transport remains complex |
| Principal | `fg_principals` | Auth0 subject/session claims | DB is authorization authority |
| External identity | `fg_external_identities` | legacy identity modules | Canonical, current production proof pending |
| Membership | `tenant_users.principal_id` | portal grants and older subject/email bindings | Canonical for workforce; Portal has parallel membership model |
| Role/permission | DB role assignment + RBAC permission mapping | JWT roles; compatibility platform-admin path | Multiple input paths; final DB checks strong on critical tenant-admin routes |
| Platform credential | canonical `fgk.*` credential authority | gateway secret Path E in COMPATIBILITY mode | Not singular until CANONICAL is enforced |
| Invitation | `tenant_invitations`, hashed `fgwi1.*` token | old workforce/portal invitations, bootstrap-admin | Current path strongest; parallel legacy surfaces remain |
| Assessment engagement | `fa_engagements` | legacy `assessments`/`reports` path | Field Assessment should be designated sellable canonical spine |
| Evidence | `fa_evidence` and related lineage | `/evidence` authority plus scan/evidence links | Fragmented authority |
| Finding | `fa_normalized_findings` | compliance/risk/governance findings | Fragmented by bounded context |
| Report | Field Assessment `fa_report*` | legacy `reports`; `/governance-reports` | Three active representations |
| Remediation | Field Assessment status + `fa_rem_*` authority | `remediation_tasks` and portal remediation | Three parallel models |
| Governance state | derived field-assessment state and multiple governance authorities | readiness/control-tower/intelligence aggregates | No single customer-facing canonical state |
| Billing | legacy billing ledger plus P1.5 billing/subscription authorities | Stripe webhooks and manual commercial process | Partial, not a revenue prerequisite |

**PROVEN FACT:** `authority_manifest.yaml` declares separate active `remediation`, `remediation_authority`, `report_authority`, and `governance_reporting` authorities, several with no declared consumers.
**RISK:** customers and engineers can receive inconsistent answers depending on route family.
**RECOMMENDATION:** designate, do not rewrite, the Field Assessment engagement/evidence/finding/report path as the Customer-One authority and freeze expansion of competing routes.

## 7. Component Inventory

| Component | Purpose | Entry point/caller | Persistence | Boundary | Coverage | Exposure/readiness |
| --- | --- | --- | --- | --- | --- | --- |
| Core API | Main product API | `api.main:app` | PostgreSQL/SQLite | AuthGate, scopes, ActorContext, tenant GUC | Broad tests | ACTIVE, conditional |
| Contract app | Deterministic OpenAPI generation | `build_contract_app()` | None/fake | Contract-only | Schema gates | GENERATED, not runtime proof |
| Admin Gateway | Admin OIDC and Core proxy | `admin_gateway.asgi:app` | shared DB/session | OIDC + scopes | Unit/integration | ACTIVE, basic health only |
| Identity worker | DB-to-Auth0 projection | `python -m admin_gateway.identity.worker_main` | outbox | management credentials | focused tests | PARTIAL, no health, branch drift |
| Console | Operator/customer-admin UI | Next.js root app | Redis/Upstash registry, Core | NextAuth + BFF | 2,957 source-heavy tests; build pass | ACTIVE, blocked by dependencies |
| Nested Console | duplicate UI tree | no production mount found | same concepts | duplicate BFF | recursively tested/typechecked | ORPHANED/HIGH CONFIDENCE |
| Portal | named customer UX | Next.js Portal | pnu sessions + Core | OIDC PKCE + BFF | 77 tests | PARTIAL, build/security blocked |
| Public web | marketing | Next.js static app | None | public | build pass | ACTIVE claim surface |
| Field Assessment | engagement delivery | `/field-assessment/*` | `fa_*` | governance scopes + tenant | extensive | ACTIVE, best revenue spine |
| Legacy assessment/report | lead assessment and AI report | `/ingest/assessment/*` | `assessments`, `reports` | mixed lead/tenant | tested | COMPATIBILITY/PARTIAL |
| Evidence authority | generalized evidence | `/evidence/*` | evidence authority tables | tenant | authority gate | ACTIVE but little UI consumption |
| Report/remediation authorities | governed lifecycle engines | `/reports`, `/remediation-authority` | separate `fa_*` sets | tenant/RBAC | many structural tests | ACTIVE but not sellable integration |
| Governance engines | chain, learning, optimization, orchestration, intelligence | multiple routers/services | many `fa_gov_*` tables | tenant | extensive unit tests | PARTIAL/UNPROVEN product path |
| Billing/subscriptions | commercial state | `/billing`, `/subscriptions`, admin routes | multiple ledgers | admin/tenant | warning/skipped integration checks | PARTIAL |
| Agent | endpoint collection/control | agent API + systemd | agent tables/queue | enrollment/device credentials | focused tests | PARTIAL; not Customer-One need |
| Backup/restore | data protection | GitHub schedules/scripts | R2/S3 + artifacts | ops secrets | old drill | PARTIAL |
| `backend/` demo | static missions/intel API | `backend.app.main:app` | static | none | small tests | ORPHANED/DEV |
| Chaos job | test placeholder | `jobs/chaos/job.py` | status only | job runner | none material | STUB |

## 8. Route Inventory and Dead-End Analysis

Machine inventory at audited HEAD contains **1,236 route declarations**, **1,178 marked scoped**, and **1,083 marked tenant-bound**. Committed OpenAPI contains 1,023 operations across 876 paths. The route gate passed because runtime-only routes under `/admin`, `/ui`, debug/control families, and health are explicitly allowlisted. This proves inventory consistency, not business completion.

### B. Route Health

| Route/Group | Consumer | Auth | Tenant Boundary | Backend Complete | Persistence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `/field-assessment/*` (151) | Console, Portal subset | scopes + permissions | Yes | Major path complete; async recovery missing | `fa_*` | WORKS PARTIALLY |
| `/admin/*` (150) | Console/operator | platform/tenant admin + gateway | target binding varies | Broad | DB | PARTIAL; compatibility authority |
| `/control-plane/*` (136) | Console/internal | scoped | Mostly | Broad, product use uneven | DB | ACTIVE/INTERNAL |
| `/intelligence/*` (74) | sparse UI/internal | scoped except health | Yes | Engines present | DB | UNPROVEN CUSTOMER PATH |
| `/governance/*` (54) | Console/Portal subset | scoped | Yes | broad | DB | PARTIAL |
| `/ui/*` (49) | Console | route-handler auth | Mostly | aggregation varies | mixed | ACTIVE; broad middleware exemption |
| `/portal/*` (48) | Portal | pnu/session or invite token | session-bound | major reads/writes present | DB | PARTIAL |
| `/governance-orchestration/*` (43) | no declared consumer | scopes | Yes | engine present | DB | UNPROVEN/ORPHAN-RISK |
| `/evidence/*` (37) | no major UI consumer found | scopes | Yes | authority complete in isolation | DB | DUPLICATE AUTHORITY |
| `/identity/*` (30) | Console/Admin Gateway | invite token, gateway, admin | invitation-derived | current flow coded | DB/outbox | LIVE PROOF PENDING |
| `/remediation-authority/*` (24) | no Console consumer found | scopes/RBAC | Yes | state machine present | `fa_rem_*` | UNPROVEN CUSTOMER PATH |
| `/billing/*` (23) | webhooks/admin; no product UI | signature/scopes | mixed | partial | multiple billing sets | PARTIAL |
| `/ingest/*` (21) | Console legacy assessment | scopes/webhook | lead or tenant | report workflow works locally | DB + process task | COMPATIBILITY/PARTIAL |
| `/controls/*`, `/control-effectiveness/*` | internal engines | scopes | Yes | present | DB | ACTIVE, fragmented |
| `/risk-acceptances/*`, `/risk-governance/*` | no major UI path | scopes | Yes | present | ORM-only table gap | CANNOT PROVE DB DEFENSE |
| `/workforce/*` (18) | Console | scopes + canonical tenant admin | Yes | lifecycle present | DB/outbox | ACTIVE; old accept route is 410 |
| `/freshness*` (21) | governance engines | scopes | Yes | scheduled execution unclear | DB | PARTIAL |
| `/remediation/*` (17) | older Portal/engines | scopes | Yes | separate implementation | DB | DUPLICATED |
| `/reports/*` (15) | sparse; field UI uses another family | scopes/capability | Yes | engine present | `fa_report*` | DUPLICATED |
| `/verification-requests/*` (13) | no major UI consumer | scopes | Yes | engine present | DB | UNPROVEN CUSTOMER PATH |
| `/governance-reports/*` (10) | no major UI consumer | scopes | Yes | engine present | risk report tables | DUPLICATED |
| `/agent/*`, `/agents/*` | installed agents | device/bootstrap credentials | credential-derived | broad | DB | PARTIAL/FEATURE |
| `/missions`, `/rings`, `/roe` | none found | public when flags mounted | None | read/compute only | files/defaults | DEV/FEATURE-FLAGGED; path disclosure risk |
| `/health/live` | orchestrator | public | N/A | liveness only | none | WORKS |
| `/health/ready` | orchestrator | public | N/A | DB/auth/Redis checks; NATS may be "not supported" | probes | PARTIAL READINESS |
| `/metrics` | Prometheus | `admin:read` | N/A | metrics | memory | INTERNAL/PROTECTED |
| `/_debug/routes` | admin | `admin:read` | N/A | introspection | none | INTERNAL/PROTECTED |
| invite preflight GET | public token URL | token fingerprint | invitation-derived | returns metadata | DB | WORKS; over-discloses email |
| Stripe webhooks | Stripe | signature | event-derived | idempotent paths present | DB | CONFIG-DEPENDENT |

Dead-end proofs:

- Scan initiation commits a `fa_scan_jobs` row, then calls `BackgroundTasks.add_task()` at ten connector route sites in `api/field_assessment.py`. `DurableJobService.recover_orphans()` exists at `services/field_assessment/durable_job_service.py:299`, but has no production caller. A crash leaves queued/running jobs stranded.
- Legacy report generation commits `ReportRecord(status='pending')` then schedules in-process work at `api/reports_engine.py:701-711`; no recovery worker was found.
- `regenerate_report()` commits at `api/reports_engine.py:1180`, then dereferences expired ORM instances for audit and task arguments at lines 1181-1195. Prior production evidence documents this transaction/RLS failure class.
- `/workforce/users/accept-invite` is deliberately a 410 tombstone (`api/workforce.py:863-874`), yet remains in runtime inventory for compatibility.
- Current production-proof routes exist, but their committed artifacts say `PENDING_LIVE_RUN` or `NOT_PROVEN`; route presence is not completion.

## 9. Authentication, Authorization, and Identity Findings

The intended law, "External IdP authenticates; FrostGate authorizes," is substantially implemented in the current invitation acceptance path. `api/identity_acceptance.py` verifies a gateway-originated named user, verified email, hashed invitation token, invitation row lock, email match, tenant lifecycle, principal/external identity, and membership in one transaction.

Material exceptions:

- `PLATFORM_AUTH_MODE` defaults to `COMPATIBILITY` in both Core and Console BFF. In that mode `FG_INTERNAL_GATEWAY_SECRET` is accepted as both gateway provenance and `platform.admin` authority on `/admin/**` (`api/platform_auth_mode.py`, `api/auth_scopes/resolution.py:363-443`, Console BFF lines 22-58 and 610-620). Railway IAC does not declare this mode for Core. One secret therefore retains two authorities until an environment is proven CANONICAL.
- Console production startup rejects bootstrap subject/email lists, which is good (`apps/console/lib/startup-validation.ts:43-59`). However, the underlying JWT callback still grants Administrator by email without first requiring `email_verified` (`apps/console/auth.config.ts:37-69`). A misconfigured or bypassed startup path restores that escalation risk.
- CANONICAL Console BFF validation only logs `[STARTUP_FATAL]`; it does not throw (`apps/console/app/api/core/[...path]/route.ts:45-58`). Core startup does fail through shared validation when CANONICAL issues are present.
- Commit `194e669f` adds full invitation email as public preflight `login_hint` even though the response already has a masked address. Anyone possessing or observing an invite URL can retrieve the full invited email before authentication (`api/identity_acceptance.py:165-174`). The token is high entropy, so this is not enumeration proof; it is unnecessary PII amplification.
- Migration 0187 exposes a security-definer lookup function with a fixed search path, which is good, but the function is not explicitly revoked from `PUBLIC`; runtime grants function execution broadly. Token entropy limits exploitation, but privilege should be explicit.
- Current live proofs are absent: `tests/test_p1139_production_proof.py:11-13` declares both phases not run; `contracts/artifacts/identity/auth-role-001c-evidence.json` is pending; `client-production-e2e-002-evidence.json` is a schema template.

## 10. Tenant Isolation and RLS Findings

**PROVEN FACT:** `tenant_db_required`/`auth_ctx_db_session` bind tenant context, and `api/db.py:set_tenant_context()` uses transaction-local PostgreSQL `set_config(..., true)`. Critical repositories generally also filter `tenant_id`. Security tests include extensive negative tenant cases.

**PROVEN FACT:** SQLAlchemy metadata contains 327 tables. Fifty-seven table names never occur anywhere in migration SQL; 52 of those models have a `tenant_id` column. Examples include billing integration, control registry, governance assets/graph, readiness, risk governance, subscription, and usage tables.

**PROVEN FACT:** `tools/ci/check_core_rls.py:164-170` discovers its audit universe only by regex-parsing `CREATE TABLE` in SQL migrations. Its green result covered 150 discovered tables, not the 52 tenant-scoped ORM-only models. `Base.metadata.create_all()` creates those tables before numbered migrations in PostgreSQL (`api/db.py:1946-1953`). Dynamic migrations cover many `fa_*` tables, but no repository-wide policy pass covers all ORM-only non-`fa_*` tables.

**RISK:** these tables rely on application filters, not proven database defense in depth. `services/billing/engine.py:183-210`, for example, fetches/updates billing accounts by object ID without a tenant predicate, expecting a surrounding tenant context/RLS boundary. The exposed route is admin-scoped, limiting current exploitability, but the database invariant is not established.

**RECOMMENDATION:** create a metadata-versus-live-schema RLS gate, classify global tables explicitly, migrate every customer table under SQL ownership, and prove cross-tenant denial using the production application role. Do not "fix" this by granting a BYPASSRLS application role.

RLS context poisoning remains a known transaction hazard: `SET LOCAL` is correctly fail-closed after commit, but handlers that use ORM instances after `commit()` can fail because refresh occurs with cleared context. Most prior sites capture identifiers before commit; legacy report regeneration remains a high-confidence exception.

## 11. Database and Migration Findings

- Migration head is `0187_invitation_token_lookup_fn.sql`; ordering is numeric and the migration gate passed.
- Migration 0186 adds `acceptance_token_hash` with an index but no uniqueness constraint. The lookup function uses `LIMIT 1`; duplicate hash rows are cryptographically unlikely but schema authority is weaker than the one-token/one-invitation invariant.
- Fresh PostgreSQL startup invokes `Base.metadata.create_all(checkfirst=True)` and then all numbered migrations. Docker Compose also defines a separate migration service. This creates two schema authorities and requires either an elevated migration URL inside the API service or DDL capability on the runtime role.
- `FG_DB_MIGRATIONS_REQUIRED` verifies recorded versions, not that ORM-only tables have migration/RLS ownership.
- `api/config/required_env.py` calls itself the single authoritative list but requires `DATABASE_URL`; production invariants independently require `FG_DB_URL`. No equality invariant was found.
- Several important bounded contexts have ORM tables but no SQL representation, so rollback, drift detection, RLS review, and reproducible environment creation depend on `create_all()` behavior.
- Security-definer functions were generally written with fixed `search_path`; execute grants and intended roles need a complete privilege inventory.

## 12. Workflow Completeness Matrix

### C. Workflow Health

| Workflow | Entry | Completion | Recovery | Production Proof | Status |
| --- | --- | --- | --- | --- | --- |
| 1. Prospect/client creation | operator/lead assessment | lead or tenant record | manual | historical only | PARTIAL |
| 2. Tenant provisioning | Console `/admin/tenants` | active tenant + key/config | retries partly idempotent | current flow pending | PARTIAL |
| 3. Initial admin onboarding | `invite-initial-admin` | bound principal/member, operational | resend/reinvite | P-113.9 phases pending | PARTIAL/BLOCKER |
| 4. Workforce onboarding | tenant admin invite | bound active member | resend, suspend/revoke | structural tests | PARTIAL |
| 5. Assessment engagement | create engagement | closed/cancelled | status controls | T6 historical | ACTIVE |
| 6. Field assessment | Console engagement workspace | evidence-ready engagement | operator retries | historical rehearsal | ACTIVE/PARTIAL |
| 7. Evidence collection | scans/docs/observations | linked, lifecycle-controlled evidence | manual retry | broad tests | ACTIVE |
| 8. Connector ingestion | initiate/import | normalized scan/evidence/findings | no worker recovery | MS live proof absent | PARTIAL/BLOCKER |
| 9. Finding creation | normalize/promote | governed finding | operator correction | tests/T6 | ACTIVE |
| 10. Report generation | report generate | generated version | no durable execution | historical | PARTIAL/BLOCKER |
| 11. Report QA | review/approve | approved version | reject/revise | historical T6 | ACTIVE |
| 12. Report delivery | deliver/auto-advance | delivered + Portal access | supersede | historical | ACTIVE/PARTIAL |
| 13. Remediation | finding status or authority plans | completed task | reopen paths differ | no unified E2E | DUPLICATED/PARTIAL |
| 14. Verification | bundle/request/task verification | approved/completed | reopen/reject | structural tests | PARTIAL |
| 15. Reassessment | new scan/engagement | changed posture | manual | no scheduled proof | PARTIAL |
| 16. Continuous governance | monitoring/re-scan | longitudinal delta | manual | T6 v0 only | NOT MRR READY |
| 17. Client Portal | named OIDC session | report/findings/actions | logout/revoke | current build fails | BLOCKED |
| 18. Billing handoff | webhook/admin APIs | billing state | reconciliation code | no customer E2E | PARTIAL/DEFER |
| 19. Backup/recovery | scheduled workflow | restored current schema | monthly drill | latest proof 0172; health critical | BLOCKED |
| 20. Incident response | runbooks/alerts | containment/recovery evidence | manual | no current rehearsal found | PARTIAL |

State details:

- Tenant: absent -> active/admin_unset -> admin_unbound -> operational; suspension supersedes admin state. Authority is `api/client_lifecycle.py`, persistence is `tenants`, `tenant_users`, principals and identities. Recovery actions exist, but current OIDC enrollment proof is pending.
- Engagement: `in_progress` -> gated auto-delivery -> `delivered` -> `remediation|monitoring|closed`; remediation and monitoring can alternate; closed/cancelled terminal (`services/field_assessment/models.py:9-20,122-129`).
- Remediation authority task: open -> assigned/in-progress/blocked -> ready-for-review -> verifying -> approved -> completed, with reopen/rework transitions (`services/remediation_authority/state_machine.py`). This is not the only remediation state machine.
- Report version: generated/draft -> review -> approved -> delivered -> superseded. Human QA is the credible control; generation execution is process-local.
- Evidence: collected -> linked -> approved/locked -> pending purge/legal hold. Audit locks are strong, but deletion remains an operator SQL procedure.

## 13. Console, BFF, and Core Findings

The Console production build succeeds and emits 42 static/dynamic pages. The BFF has a path/method allowlist, rejects arbitrary tenant steering for customer sessions, generates short-lived HMAC delegation proofs for admin routes, and makes Core perform final authorization.

Failures and contradictions:

- The Console dependency graph contains two critical and four high production advisories. The direct `next-auth@5.0.0-beta.31` range includes an Auth.js configuration-error fail-open advisory. Middleware uses `!!req.auth` as its first authentication decision (`apps/console/middleware.ts:9-42`), though downstream BFF handlers generally require `session.user` and role classification. This reduces but does not eliminate exposure; upgrade and regression proof are mandatory before external access.
- BFF platform authority defaults to COMPATIBILITY; the startup validator does not require CANONICAL mode.
- BFF rate limiting explicitly fails open when Redis/Upstash is unavailable or increments fail (`apps/console/app/api/core/[...path]/route.ts:257-278`). Tests are named as though production does not fail open, but assert the fallback behavior structurally.
- `ci-console` runs lint, tests, and a non-blocking npm audit; it does not run the production build. Coverage is `continue-on-error` in CI.
- `apps/console/console/` is a second complete Console tree. No deployment or caller was found, but root TypeScript/test globs include it. It is an orphaned duplicate that doubles change/test surface and carries older dependencies.
- Console UI primarily uses Field Assessment routes. It does not provide a complete consumer for remediation authority, governance reports, verification requests, or canonical evidence authority.

## 14. Portal Findings

The named-user Portal design is materially stronger than its old shared-password design: Authorization Code + PKCE, short-lived HttpOnly bootstrap token, server-side `pnu1.*` session fingerprint, membership/auth-version checks, engagement scope, and Core-side revocation.

It is not deployable from the audited tree:

- `npm run build` fails at `apps/portal/lib/tenant-registry.ts:34` because `@vercel/edge-config` is not installed.
- `package.json` declares that package, but `package-lock.json` does not. A clean `npm ci --dry-run` fails with two missing lock entries. The Make target masks `npm ci` failure by falling back to `npm install`, and Vercel explicitly uses `npm install`, so ephemeral builds may pass while reproducibility is lost.
- Portal pins `next@14.2.5`; current audit reports one critical and two high production dependency findings. The critical middleware authorization-bypass range includes this version. Data BFF routes revalidate sessions, limiting direct tenant-data impact, but external exposure is indefensible until patched.
- Production `resolveAuth()` disables dynamic tenant steering and always uses static `CORE_TENANT_ID`/`CORE_API_KEY` (`apps/portal/app/api/core/[...path]/route.ts:40-67`). Core still validates the user session, but each deployment is operationally pinned to one service tenant/key.
- Redis failure falls back to a per-process Map, so rate limits diverge across instances. `/api/health` always reports overall `ok` even when Redis is unavailable.
- Production password login correctly returns 403 (`PORTAL_DEMO_AUTH_DISABLED`), while multiple operator runbooks still tell staff to distribute and rotate `PORTAL_PASSWORD`. That normal workflow would fail.

## 15. Assessment Platform Findings

Field Assessment is FrostGate's most complete and commercially useful bounded context. It has explicit engagement states, tenant-scoped scans, questionnaire, observations, document registration/upload, normalization, evidence links, findings, report generation/versioning, QA, delivery, Portal views, remediation states, verification bundles, and promotion to governance history.

Customer-One scope should use:

- engagement creation and explicit assessor ownership;
- DNS/email, web-header, network and other no-auth scanners only after legal authorization;
- questionnaire, interviews, observations, and bounded document evidence;
- deterministic control/finding generation;
- human QA and signed report delivery;
- operator-managed remediation plan and scheduled reassessment.

Do not promise all assessment types merely because the enum includes CMMC, HIPAA, SOC 2, ISO 27001, PCI DSS, DORA, FedRAMP, NIST 800-171, and comprehensive. The strongest verified sellable framing is AI governance assessment with selected mappings, not certification or continuous compliance.

## 16. Autonomous AI Governance Findings

The repository contains substantial engines for governance execution, chain, learning, optimization, adaptive intelligence, simulation, control effectiveness, trust intelligence, and readiness. This is an emerging technical asset, not a proven autonomous product.

`api/readiness_monitoring_manager.py:547-554` explicitly sends empty policy, provenance, provider, retrieval, audit, and runtime inputs because they are "not wired in this release." Authority-manifest consumers are empty for multiple advanced services. The T6 "continuous governance v0" proof is a manual rescan/delta procedure, not a scheduled, recovering control loop.

**Classification:** deterministic governance primitives are REAL; autonomous closed-loop operation is UNPROVEN; "continuous drift detection" on the public site is currently a MARKETING CLAIM beyond demonstrated runtime.

## 17. Evidence, Finding, and Remediation Findings

Strengths:

- evidence hashes, provenance, chain-of-custody, lifecycle events, report links, legal holds, append-only records, signatures, verification bundles, and tenant tests are real implementations;
- human QA and report-version history provide a defensible service workflow;
- remediation authority has a rigorous state machine and immutable terminal states.

Gaps:

- evidence is represented in Field Assessment, canonical Evidence Authority, scan-result links, and governance graph structures;
- findings exist as normalized field findings, compliance findings, risk records, and governance outputs;
- remediation exists as finding status, `remediation_tasks`, Portal remediation, and `fa_rem_*` plans/tasks;
- no single UI-to-persistence path proves the generalized authorities as the customer system of record;
- retention deletion can conflict with evidence locks; the last drill left three `fa_scan_results` rows and accepted them as non-identifying residuals.

For first revenue, preserve lineage and signatures inside Field Assessment. Do not merge all models first. Establish an explicit adapter/ownership contract only where the sellable workflow crosses authority boundaries.

## 18. Connector and Integration Findings

No-auth scanners and import paths can provide immediate assessment value. Microsoft Graph, Entra governance, SharePoint/OneDrive, OAuth risk, endpoint inventory, AI tool discovery, and AI data access mapping have substantial implementations, device-code flows, normalization, and tests.

They are not production proven. `docs/governance/status/T6_OPERATIONAL_REHEARSAL_EVIDENCE.md:258-283` records failure/blockage because no Microsoft tenant was available. The later summary at lines 538-539 labels H10/H11 "PASS with operational note" even though no live Microsoft scan completed. Public marketing calls the integration native and automatic (`apps/web/app/page.tsx`), and the first-client playbook assumes Microsoft 365. This is a first-class contradiction.

Connector execution shares the same stranded-job failure path. Credentials are stored through a canonical encrypted credential authority, and its gate passed; the production provider permissions, consent, expiration, revocation, and error recovery still require a real-tenant proof.

## 19. Configuration and Deployment Findings

### D. Config Health

| Config Area | Expected | Actual | Fail-Closed | Risk | Action |
| --- | --- | --- | ---: | --- | --- |
| Environment mode | explicit production | `FG_ENV` checked | Yes | low | retain |
| Database URL | one authority | both `FG_DB_URL` and `DATABASE_URL` required | Partly | drift/mismatch | unify and assert equality during transition |
| DB schema | migrations-only runtime role | API runs `create_all` then migrations | No | elevated runtime/schema drift | separate migration release step |
| Auth | enabled; no fallback | Core rejects fail-open flags | Yes | low in Core | prove deployed values |
| Platform admin | CANONICAL, distinct secrets | COMPATIBILITY default | No | gateway secret has dual authority | cut over and remove Path E |
| Delegation proof | required in prod | request-time 503 if absent | Yes per request | startup blind spot | validate at startup |
| Console bootstrap lists | absent | startup rejects when present | Yes | underlying callback remains | remove callback after DR design |
| OIDC/Auth0 | issuer, clients, verified email | many aliases across services | Mixed | onboarding drift | one service matrix + live proof |
| Identity worker DB | PostgreSQL required in prod | SQLite default allowed | No | false-healthy worker | prod invariant + health |
| Core rate limiting | distributed Redis | prod invariant disallows fail-open | Yes | config proof needed | live outage proof |
| Console rate limiting | distributed/fail-closed for admin writes | explicitly fail-open | No | abuse/DoS | fail closed on sensitive routes |
| Portal rate limiting | distributed | in-memory fallback | No | multi-instance bypass | require Redis for external prod |
| NATS | checked if enabled | readiness may report `not_supported` and continue | No | false readiness | implement check or disable |
| Email | Resend/from/base URL | onboarding depends on it | Request errors | customer dead end | delivery/bounce proof |
| Report signing | key required | generation fails in prod if absent | Yes | operational failure | startup validation + proof |
| Stripe | globally required by Core prod list | product billing not proven | Yes startup | blocks service-led deployments unnecessarily | separate "payments enabled" invariant |
| Anthropic | globally required | report generation depends on it | Yes startup | provider outage | deterministic fallback/SLA policy |
| Telemetry | Sentry/Prometheus/OTel expected | partial; no worker health proof | No | silent degradation | minimum SLO alerts |
| Portal install | lockfile reproducible | manifest/lock disagree | No | clean deploy failure | regenerate/certify lock |
| Frontend dependencies | no critical/high exploitable advisories | critical/high findings | No | auth/availability exposure | upgrade before external use |
| Backup | encrypted, offsite, restorable | workflow expects this; fresh artifact says otherwise | Workflow yes | proof contradiction | current-schema drill |

Deployment contradictions:

- Docker image sets `FROSTGATE_ENFORCEMENT_MODE=block`; runtime requires separate `FG_ENFORCEMENT_MODE=enforce`.
- `.railway/railway.ts` deploys identity worker from `feat/auth-role-001c-worker-deployment`, not the audited branch/main, and sets `checkSuites: false`.
- Core API source also sets `checkSuites: false`; GitHub main has no branch protection or rulesets.
- Railway IAC includes preserved secrets but no explicit API build/start/health configuration, while Docker and platform defaults are expected to supply behavior.
- Two Helm chart trees plus dev K8s and Docker Compose describe more services than Railway IAC. They are alternatives, not one proven production topology.
- Vercel Console/Portal use `npm install`, hiding strict lockfile reproducibility problems.

## 20. Test and CI Findings

FrostGate's test breadth is a strength, but gate semantics overstate proof.

- 22,500 tests are collected. Many frontend tests inspect source text and regular expressions; 2,957 Console tests completed in about 0.3 seconds, demonstrating structural assertions rather than browser/runtime behavior.
- Security suite breadth is meaningful: 1,234 passed. Most runs still use SQLite, fake providers, TestClient, monkeypatching, and synthetic actors rather than production PostgreSQL/RLS/network boundaries.
- Live proof tests are correctly gated and label skips as not proven. Committed status documents and roadmap language do not consistently retain that distinction.
- `fg-required-summary` writes an OK summary after prerequisite targets; it is an aggregator, not independent proof.
- `ci-console` and `ci-portal` omit production builds. npm audit is non-blocking (`|| true`). Coverage is allowed to fail.
- Python audit ignores nine findings. The exception document's 14-day review cadence is overdue; fixed versions are documented for Starlette and `python-multipart`.
- Two production upload routes use `python-multipart==0.0.27` (`api/field_assessment.py:10130`, `api/rag_corpus_ingestion.py:330`) while three fixed multipart CVEs are explicitly ignored.
- Main has no enforced checks. A green workflow can be bypassed by direct push, and Railway source explicitly disables check-suite gating.

What current gates prove: deterministic source shape, route registration consistency, many permission/tenant negative cases, migration text properties, contract shape, and local behavior. They do not prove current production configuration, current live schema/RLS, Auth0 enrollment, real connector permissions, process restart recovery, email delivery, current restore, Vercel clean installation, or customer completion.

## 21. Security Findings

No P0 exploit was proven from repository-only analysis. External production use is nevertheless blocked by several P1 conditions whose exploit or failure paths are concrete.

1. **Console authentication dependency failure path (P1, PROVEN).** `apps/console/package.json` pins prerelease Auth.js/NextAuth and Next.js versions for which the clean dependency audit reports two critical and four high production advisories. The Auth.js configuration-error advisory can fail open: a deployment/configuration error can turn an intended authentication failure into an accepted session. That is directly on the Console's platform-admin boundary.
2. **Portal middleware authorization bypass exposure (P1, PROVEN).** `apps/portal/package.json` pins Next.js 14.2.5; the clean audit reports the critical middleware authorization-bypass advisory affecting that version. The Portal relies on middleware plus BFF session enforcement. A crafted request that bypasses middleware reaches a larger attack surface than the design assumes, even though route-level checks may still stop individual calls.
3. **RLS closed-world gap (P1, PROVEN design gap; exploitation NEEDS RUNTIME PROOF).** Runtime metadata contains 327 tables, while 57 table names cannot be found in numbered migration SQL and 52 of those models carry `tenant_id`. The RLS audit enumerates migration `CREATE TABLE` statements, so those tables are outside its proof set. Object-ID-only service lookups such as those in `services/billing/engine.py` are safe only if deployed RLS is correct. A missing policy plus a guessed/captured ID becomes cross-tenant read or mutation.
4. **Multipart parser exposure (P1, PROVEN dependency; exploitability version-specific).** `python-multipart==0.0.27` is used by upload routes in `api/field_assessment.py` and `api/rag_corpus_ingestion.py`; three fixed multipart advisories are ignored by the Python audit gate. An authenticated attacker can force the vulnerable parser path with a crafted upload before application validation completes.
5. **Dual platform credential authority (P1, PROVEN).** `PLATFORM_AUTH_MODE` defaults to `COMPATIBILITY`. In that mode, the gateway secret can prove request provenance and also enter legacy platform-admin Path E. Leakage or misuse therefore has a broader authority radius than the intended delegated capability design.
6. **Invitation PII amplification (P2, PROVEN).** `api/identity_acceptance.py` returns a complete email address as `login_hint` from a bearer invitation token even though a masked address is also supplied. A leaked URL can disclose the invitee's full address before authentication. The token remains hashed at rest and acceptance remains email-bound, so this is not an enrollment bypass.
7. **Public feature metadata exposure (P2, PROVEN when flags enabled).** Public `/rings`, `/missions`, and `/roe` paths intentionally bypass authentication behind feature flags. The rings output includes model/database path metadata. This is reconnaissance exposure, not a proven mutation path.

Positive controls are substantive: production Core rejects fail-open auth flags, invitation acceptance verifies issuer/subject/email and locks the invitation row, credential storage is encrypted through a canonical authority, tenant-scoped security tests are broad, report/evidence signing fails closed, and raw invite tokens are not persisted.

## 22. Resilience and Operations Findings

- **Durable jobs are not durably executed.** Scan routes persist a job and then dispatch work through FastAPI `BackgroundTasks`. `DurableJobService.recover_orphans()` exists, but static tracing found no production startup, scheduler, or worker caller. A process restart after commit can leave `queued` or `running` work indefinitely; retry timestamps do not execute themselves.
- **Legacy report generation has the same process-lifetime boundary.** The route commits a pending report before launching an in-process task guarded by a process-local semaphore. A crash strands the report, while multiple replicas do not share the semaphore.
- **Report regeneration has a likely post-commit RLS/session defect.** `regenerate_report` commits and subsequently dereferences ORM state. Under transaction-local tenant context, expiration/reload can occur after the RLS context is gone and yield a 500. This is HIGH CONFIDENCE and needs PostgreSQL reproduction.
- **Current backup proof is red.** `artifacts/operations/backup_health.json` dated 2026-09-06 records `backup_status: critical`, no encryption/offsite confirmation, a 17-byte artifact, and restore `UNKNOWN`. An August restore drill passed against migration 0172, not current head 0187. This proves contradictory evidence, not that no external backup exists.
- **Retention proof is conditional.** The scheduled workflow runs direct SQL monthly; its last drill left three `fa_scan_results` rows and treated them as permitted residuals. Evidence/legal-hold interactions and current-schema deletion require proof.
- **Health can overstate readiness.** Portal Redis loss falls back to process-local rate limits and the health surface remains successful. NATS readiness can report `not_supported` without failing. Identity worker deployment has no equivalent customer-facing end-to-end health proof.
- **Recovery depends on engineering knowledge.** Runbooks and workflows exist for backup, restore, incident response, and retention, but evidence is not connected into a single release/customer go-live gate. Several normal failure recoveries still require shell, workflow dispatch, or SQL-level inspection.

## 23. Customer-Experience Findings

| Persona | Real entry path | What works | Intervention or dead end | Readiness |
| --- | --- | --- | --- | --- |
| FrostGate operator | Console, CLI, scripts, runbooks | broad administrative APIs and diagnostics | must reconcile env aliases, worker topology, proof artifacts, and deployment branches | PARTIAL |
| New customer administrator | invitation link -> Auth0/OIDC -> acceptance | canonical enrollment path is implemented and transactionally coherent | live Auth0, email delivery, worker, and multi-tenant production proof absent | PARTIAL |
| Workforce user | invitation/OIDC and tenant membership | canonical membership/RBAC primitives exist | complete self-service workforce journey not proven in browser | PARTIAL |
| Assessor | Console Field Assessment | manual/no-auth collection, findings, QA, and reports are substantial | crash recovery and some operation steps need engineering/operator tooling | CONDITIONAL |
| Compliance officer | reports/evidence/exports | signed, evidence-backed artifacts and lineage are valuable | authority variants and retention semantics need an operating contract | CONDITIONAL |
| Security/risk officer | findings, remediation, governance views | rich control/risk/remediation primitives | generalized governance authorities are not one proven system of record | PARTIAL |
| Executive | delivered assessment report | human-QA report is sellable as a service deliverable | Portal delivery and continuous posture claims exceed proof | CONDITIONAL |

Normal customer operation must not require direct SQL, operator-created IdP users, secret editing, or undocumented API calls. Today, provisioning and assessment can be operated as a controlled service, but a self-serve platform promise would conceal material operator work. Shell/SQL access remains legitimate only for break-glass diagnosis, restore, and incident response.

## 24. Dead, Stale, and Duplicate Code Findings

| Component | Classification | Confidence | Evidence and consequence |
| --- | --- | ---: | --- |
| `apps/console/console/` | ORPHANED duplicate application | HIGH | complete nested Next.js tree; no deployment entry found, but root globs still typecheck/test it |
| `backend/` | DEV-ONLY/ORPHANED demo | HIGH | standalone demo server/assets with no production deployment reference |
| `jobs/chaos/job.py` | STUB | PROVEN | explicitly placeholder implementation |
| `jobs/__init__.py` | PARTIAL | PROVEN | TODO remains at package authority boundary |
| public rings/missions/ROE | FEATURE-FLAGGED/PARTIAL | HIGH | routes register only under flags; no customer-one need |
| generalized evidence/remediation/report authorities | ACTIVE but parallel | PROVEN | registered routes and persistence exist, but consumer ownership overlaps Field Assessment |
| legacy gateway platform-admin Path E | COMPATIBILITY | PROVEN | active whenever platform auth mode is compatibility; no enforced retirement date |
| password Portal documentation | STALE | PROVEN | production shared-password login is disabled while runbooks still distribute `PORTAL_PASSWORD` |
| Helm/K8s/Docker topologies | ALTERNATIVE/UNKNOWN | HIGH | materially differ from Railway service topology; no single declared production authority |

Repository-wide marker searches were reviewed in context. Many `mock`, `fake`, `in-memory`, and `fallback` hits are legitimate tests or explicit development adapters. The table lists only production-relevant cases with evidence of exposure, build impact, or architectural ambiguity.

## 25. Contradiction Register

| ID | Sources in conflict | Contradiction | Confidence | Required resolution |
| --- | --- | --- | ---: | --- |
| C-01 | runtime models vs migrations/RLS gate | 57 metadata tables are absent from migration SQL; 52 are tenant-scoped | PROVEN | closed-world schema/RLS reconciliation |
| C-02 | Core startup vs Docker Compose | API runs `create_all` plus migrations while Compose has a migration service | PROVEN | migrations-only production authority |
| C-03 | secure auth architecture vs defaults | canonical delegation is intended; COMPATIBILITY is default | PROVEN | explicit canonical cutover |
| C-04 | Console startup vs callback implementation | production rejects bootstrap lists, but callback still grants Administrator by email | PROVEN | remove or isolate break-glass path |
| C-05 | Portal auth runtime vs runbooks | named-user OIDC is production law; docs distribute a shared password | PROVEN | retire stale docs and secret assumptions |
| C-06 | Portal manifest vs lockfile | `@vercel/edge-config` is declared but absent from lock; build cannot resolve it | PROVEN | reproducible clean install/build |
| C-07 | CI status vs deploy enforcement | workflows exist; GitHub main has no protection/rules and Railway disables check suites | PROVEN | enforced release gate |
| C-08 | audited source vs worker deployment | identity worker Railway source points at a different feature branch | PROVEN | deploy one immutable SHA |
| C-09 | detailed T6 evidence vs summary | Microsoft scans were blocked/no tenant; summary says PASS with note | PROVEN | mark unproven until a real-tenant run |
| C-10 | marketing vs connector proof | site promises native/continuous Microsoft behavior not demonstrated in production | PROVEN | narrow claims or complete proof |
| C-11 | continuous-governance name vs runtime | current v0 path is operator-triggered/manual rescan | PROVEN | sell managed cadence, not autonomous monitoring |
| C-12 | backup policy vs latest artifact | required encrypted/offsite/restorable backup; latest artifact is critical/unknown | PROVEN | current-schema backup/restore proof |
| C-13 | old restore proof vs schema head | prior drill used migration 0172; current head is 0187 | PROVEN | repeat at audited SHA/head |
| C-14 | retention success label vs residue | drill reports conditional pass with three scan-result rows left | PROVEN | prove policy semantics and legal holds |
| C-15 | CI package gates vs production build | Console/Portal CI omits build and npm audit is advisory | PROVEN | clean-install/build/audit required |
| C-16 | env authority docs vs runtime | required sets disagree on `FG_DB_URL` and `DATABASE_URL` | PROVEN | one canonical setting with transition check |
| C-17 | enforcement config vs runtime | image sets `FROSTGATE_ENFORCEMENT_MODE=block`; runtime requires `FG_ENFORCEMENT_MODE=enforce` | PROVEN | remove alias ambiguity and test deployment env |
| C-18 | readiness labels vs external proof | broad test PASS language is used where live Auth0, email, PostgreSQL RLS, and connector proof is skipped | HIGH | evidence classes and expiration rules |

## 26. Production-Proof Gaps

The following must be executed against an ephemeral production-equivalent environment at the audited immutable SHA, never by mutating a live customer environment:

1. clean Console and Portal install, audit, typecheck, test, and production build;
2. deployment only after required checks, with image/source SHA attestation for every process;
3. PostgreSQL migration from empty and representative prior schema to head 0187 without runtime `create_all`;
4. closed-world table/RLS comparison against live catalog plus two-tenant negative access probes;
5. Auth0/OIDC invitation acceptance with verified email, mismatch, replay, expiry, disabled tenant, and role-escalation negatives;
6. email delivery, link origin, bounce/failure, resend, and recovery proof;
7. identity worker restart/retry/idempotency and health proof on PostgreSQL;
8. assessment job crash/restart recovery after commit and during connector execution;
9. no-auth/manual evidence -> finding -> QA -> signed report -> delivery -> remediation -> reassessment vertical proof;
10. current encrypted offsite backup and isolated restore through migration 0187 with tenant/evidence integrity checks;
11. retention/legal-hold drill with an explicit residual-row oracle;
12. real Microsoft test-tenant consent, least privilege, scan, normalization, revocation, expiry, throttling, and recovery proof before any connector promise.

## 27. First-Paid-Customer Readiness

FrostGate can sell expertise and a controlled evidence-backed deliverable sooner than it can safely sell unattended platform access. The smallest credible wedge is a **fixed-scope, service-led AI governance assessment** using manual/no-auth evidence collection, deterministic findings, human QA, a signed report, and a bounded remediation review. Do not include Microsoft automation in the committed scope until its live proof passes.

### E. Customer One Blockers

| Rank | Finding | Severity | Effort | Dependency | Revenue Impact |
| ---: | --- | --- | --- | --- | --- |
| 1 | Console/Portal critical and high dependency exposure | P1 | M | tested upgrade path | blocks external identities and admin use |
| 2 | release gates do not bind tested SHA to deployed SHA | P1 | M | GitHub/Railway controls | invalidates all other production claims |
| 3 | schema/RLS gate is not closed-world | P1 | M | migration reconciliation | unacceptable tenant-data uncertainty |
| 4 | canonical platform auth is not the default/only production path | P1 | M | deployment config, client migration | excessive credential authority |
| 5 | onboarding live proof is incomplete | P1 | M | Auth0, email, identity worker | administrator cannot be safely onboarded |
| 6 | durable assessment execution/recovery is absent | P1 | M | worker/queue ownership | paid engagement can strand |
| 7 | current backup/restore proof is red or stale | P1 | M | storage/KMS/restore env | customer data cannot be accepted defensibly |
| 8 | Portal clean build fails | P1 | S | lockfile repair | customer-facing deployment is not reproducible |
| 9 | Python upload dependencies have ignored fixed advisories | P1 | S-M | compatibility regression tests | exposed evidence ingestion risk |
| 10 | Customer-One vertical production proof does not exist | P1 | M | blockers 1-9 | cannot substantiate readiness |

"Conditional" means a contractually bounded, operator-led engagement only after these gates pass. It does not mean accepting risk through disclaimers.

## 28. MRR Readiness

The recurring offer should be **managed remediation plus scheduled monthly or quarterly reassessment**, not autonomous continuous governance. It reuses the real assessment, evidence, finding, remediation, report, and history primitives while keeping humans at decision boundaries.

### F. MRR Blockers

| Rank | Finding | Severity | Effort | Revenue Unlock | Action |
| ---: | --- | --- | --- | --- | --- |
| 1 | persisted jobs have no production recovery loop | P1 | M | reliable scheduled reassessment | deploy durable worker, lease/reclaim, idempotency |
| 2 | Portal is single-tenant-by-deployment and not clean-build proven | P1 | M | repeatable customer access | canonical tenant binding and release gate |
| 3 | backup, restore, retention, and alerts lack current proof | P1 | M | supportable data custody | automate evidence-expiring operations gate |
| 4 | remediation authorities and consumer ownership overlap | P2 | M | consistent recurring record | declare Field Assessment system of record and adapters |
| 5 | provider outages/retries are not customer-SLA proven | P2 | M | predictable report cadence | bounded retries, recovery UX, operator alerts |
| 6 | no longitudinal customer-success production proof | P1 | M | defensible renewal value | complete two reassessment cycles and compare state |
| 7 | support/incident ownership is not encoded in go-live | P2 | S-M | manageable operations | SLOs, paging, runbook rehearsal, case ownership |

MRR is not ready today because recurring obligations amplify every unresolved durability, recovery, retention, and deployment-control gap.

## 29. Enterprise Readiness

Enterprise scale is a later gate. It requires multi-tenant Portal operation, SSO lifecycle proof, service-credential rotation, external audit evidence, load/capacity testing, distributed rate limiting, queue backpressure, regional/data-residency decisions, formal support objectives, billing/entitlement authority, and current DR evidence. The repository contains primitives for many of these, but they are not one certified operating system.

Enterprise billing, generalized control-plane expansion, more frameworks, more connectors, autonomous remediation, and broad governance dashboards must not precede Customer-One and MRR proof. They increase support burden and attack surface without resolving the present revenue blocker.

## 30. Moat Analysis

### G. Moat

| Capability | Current Strength | Defensibility | Missing Piece | Priority |
| --- | --- | --- | --- | --- |
| evidence lineage, hashes, signatures, chain of custody | strong implementation | REAL MOAT | repeated external audit/customer cycles | DO NOW |
| deterministic governance state | substantial assessment implementation | REAL MOAT | one customer-proven authority path | DO NOW |
| remediation verification | rigorous state primitives | EMERGING MOAT | recurring reassessment loop | DO NOW |
| authority graph and canonical identity | strong design | EMERGING MOAT | production cutover and proof | BEFORE CUSTOMER ONE |
| cross-framework mappings | broad model/data surface | EMERGING MOAT | validated mappings and buyer outcomes | AFTER CUSTOMER ONE |
| historical governance intelligence | data model foundation | EMERGING MOAT | longitudinal customer data | MRR PRIORITY |
| governance digital twin | partial graph/runtime concepts | UNPROVEN | wired authoritative inputs | DEFER |
| benchmark data | little operating evidence | UNPROVEN | consented multi-customer corpus | DEFER |
| connectors | many integrations | COMMODITY until proven | live permissions/recovery evidence | SELECTIVE |
| dashboards and report generation | broad surface | COMMODITY | differentiated verified outcomes | DEFER SURFACE GROWTH |

The strongest current moat is the evidence-to-decision-to-remediation provenance chain and its signed, auditable history. It compounds only when repeated paid cycles produce verified longitudinal outcomes. Additional dashboards, framework labels, or unproven automation do not materially deepen it.

## 31. Ranked Blocker Register

This is the canonical finding register. Earlier observations roll up into these records; severity is not based on code volume.

| ID | Sev. | Confidence | Category / Component | Evidence | Customer / Security / Revenue Impact | Effort | Dependencies | Recommended Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FGA-001 | P1 | PROVEN | dependencies / Console | `apps/console/package.json`; production `npm audit`: 2 critical, 4 high | unsafe admin boundary / possible auth fail-open / blocks external use | M | framework compatibility | upgrade, test negative auth, clean build, block advisories |
| FGA-002 | P1 | PROVEN | dependencies / Portal | Next 14.2.5; production `npm audit`: 1 critical, 2 high | customer auth boundary exposed / bypass risk / blocks Portal | M | Next/Auth compatibility | upgrade and add route-level bypass regression proof |
| FGA-003 | P1 | PROVEN | build / Portal | manifest declares Edge Config; lock omits it; clean build unresolved | unreproducible deployment / supply-chain ambiguity / blocks onboarding | S | FGA-002 | regenerate lock with clean install and build |
| FGA-004 | P1 | PROVEN | release / GitHub, Railway | branch protection 404; rulesets empty; `checkSuites:false` | untested SHA can deploy / control bypass / invalidates proof | M | repository/platform access | require checks and attest deployed SHA |
| FGA-005 | P1 | PROVEN | auth / platform authority | `PLATFORM_AUTH_MODE` defaults COMPATIBILITY; gateway Path E | excess credential blast radius / privilege path / blocks defensible admin use | M | Console/Core migration | canonical-only mode, distinct secrets, remove fallback |
| FGA-006 | P1 | PROVEN gap | identity / onboarding | 96 focused tests pass; 3 live proofs skip | admin journey unproven / identity mismatch risk / delays customer start | M | Auth0, email, ephemeral prod | execute full positive and negative live proof |
| FGA-007 | P1 | PROVEN | deploy / identity worker | Railway source is another branch; SQLite fallback; no complete health proof | enrollment may stall / inconsistent authority / blocks onboarding | S-M | FGA-004 | same SHA, PostgreSQL-only prod, health/retry proof |
| FGA-008 | P1 | PROVEN | resilience / jobs and reports | committed jobs use `BackgroundTasks`; orphan recovery has no caller | work strands on restart / integrity and availability / blocks reliable delivery | M | worker topology | durable lease/claim/recover loop with idempotency |
| FGA-009 | P1 | PROVEN gap | database / RLS | 327 metadata tables; 57 absent from migration SQL, 52 tenant-scoped | tenant isolation cannot be proven / cross-tenant risk / blocks data acceptance | M | schema inventory | reconcile all tables and make gate closed-world |
| FGA-010 | P1 | PROVEN | database / migration authority | runtime `create_all` plus numbered migrations | schema drift / unintended DDL authority / invalidates release reproducibility | M | FGA-009 | migrations-only production startup |
| FGA-011 | P1 | PROVEN evidence | operations / backup | latest backup artifact critical, 17 bytes, restore unknown; old drill at 0172 | recovery not demonstrated / data-loss exposure / blocks custody | M | current deployment/storage | encrypted offsite backup and isolated 0187 restore |
| FGA-012 | P1 | PROVEN gap | connector / Microsoft | detailed T6 run blocked/no tenant; later summary says PASS | promised workflow may fail / consent/data risk / scope overpromise | M | real test tenant | exclude from offer until complete live proof |
| FGA-013 | P1 | PROVEN dependency | security / Python uploads | ignored Starlette and multipart advisories; two upload routes | crafted request parser exposure / DoS or parser risk / blocks upload use | S-M | compatibility tests | upgrade, remove exceptions, negative upload tests |
| FGA-014 | P1 | PROVEN gap | operations / retention | direct-SQL drill leaves three scan-result rows | erasure semantics unclear / privacy evidence risk / enterprise objection | M | schema/RLS reconciliation | explicit deletion oracle plus legal-hold proof |
| FGA-015 | P1 | PROVEN | product / Portal tenancy | production BFF uses static Core tenant/key | deployment-per-tenant burden / confused boundary risk / MRR scale blocker | M | canonical membership authority | bind tenant from validated session/membership |
| FGA-016 | P2 | PROVEN | privacy / invitation | public preflight returns full `login_hint` email | invite-link leak discloses PII / no auth bypass / trust cost | S | UX decision | omit full address or return only after IdP |
| FGA-017 | P2 | HIGH | runtime / report regeneration | commit followed by ORM dereference under transaction-local RLS | intermittent 500 / no direct escalation / assessor friction | S-M | PostgreSQL reproduction | preserve IDs/data or re-enter tenant transaction |
| FGA-018 | P2 | PROVEN | architecture / authorities | parallel report, evidence, finding, remediation models/routes | inconsistent system of record / policy drift / slows delivery | M | customer wedge contract | declare ownership and adapters; do not rewrite |
| FGA-019 | P2 | PROVEN | abuse controls / frontends | Console fail-open and Portal process-local Redis fallback | multi-replica bypass / DoS exposure / support risk | S-M | Redis/readiness | fail closed for sensitive writes and surface degraded health |
| FGA-020 | P2 | PROVEN | product claims / autonomy | readiness manager explicitly leaves core inputs unwired | misleading automation / unsafe reliance / sales credibility | M-L | durable jobs, evidence authority | label experimental; defer closed-loop claims |
| FGA-021 | P2 | HIGH | operations / observability | NATS may be not-supported; worker/customer SLO evidence absent | silent stuck work / delayed detection / recurring support burden | M | FGA-008 | minimum metrics, queue age, alerts, runbooks |
| FGA-022 | P2 | HIGH | maintenance / duplicate Console | `apps/console/console/` full nested app in root globs | stale code can affect builds / no direct security exploit / slows changes | S-M | ownership confirmation | remove from build or document active purpose |
| FGA-023 | P2 | PROVEN | documentation / runtime truth | password Portal, connector PASS, topology and env contradictions | operators follow unsafe/stale path / proof confusion / onboarding errors | S-M | canonical decisions | correct docs in same PRs as runtime changes |
| FGA-024 | P3 | HIGH | hardening / invitation and DB grants | invite token hash lacks proven uniqueness; broad security-definer grant patterns need live inspection | replay/race defense relies on row/state; excessive DB privilege possible | S-M | live catalog proof | add constraint where compatible; least-privilege function grants |

No finding is P0 because this audit did not prove an unauthenticated catastrophic tenant-data or authority exploit. FGA-001, FGA-002, FGA-005, FGA-009, and FGA-013 still require remediation before exposing their affected surfaces.

## 32. Technical-Debt Register

| Debt ID | Item | Priority | Why it matters | Retirement condition |
| --- | --- | --- | --- | --- |
| TD-01 | nested duplicate Console | P2 | expands test/build and ownership ambiguity | one Console tree in build graph |
| TD-02 | runtime schema creation | P1 | hides migration omissions | production role cannot create schema |
| TD-03 | compatibility platform auth | P1 | preserves duplicate authority | all clients use canonical delegation |
| TD-04 | parallel domain authorities | P2 | invites split-brain writes | written ownership/adapter contract and telemetry |
| TD-05 | environment aliases | P2 | deployment-specific behavior drifts | one canonical variable per concept |
| TD-06 | process-local jobs/semaphores/rate limits | P1/P2 | replicas and restarts change behavior | durable/distributed ownership where required |
| TD-07 | advisory exceptions | P1 | exceptions became permanent policy | fixed versions and zero overdue waivers |
| TD-08 | source/regex-heavy frontend tests | P2 | green suite can miss runtime failure | browser and production-build gates cover core journeys |
| TD-09 | stale proof documents | P2 | labels outlive underlying environment/schema | generated, SHA-bound, expiring evidence |
| TD-10 | multiple deployment topologies | P3 | operating assumptions diverge | one supported topology; alternatives explicitly non-production |
| TD-11 | public feature-flag experiments | P3 | unnecessary metadata/exposure surface | disabled by invariant or separately authenticated |
| TD-12 | placeholder job packages | P3 | implies capability not present | implement only when required or remove from production census |

## 33. Required Before Customer One

The following is the minimum bar for accepting customer data or providing customer/admin access:

1. **DO NOW:** lock the audited SHA to required CI and deployed artifact identity.
2. **DO NOW:** eliminate exploitable critical/high frontend and upload-parser advisories and make clean installs/builds reproducible.
3. **DO NOW:** reconcile metadata, migrations, live catalog, tenant ownership, and RLS; prevent runtime schema creation.
4. **DO NOW:** deploy canonical-only platform authority with distinct gateway/delegation credentials and no legacy fallback.
5. **BEFORE CUSTOMER ONE:** deploy the identity worker from the same SHA on PostgreSQL and prove invitation, verified identity, membership, role, replay, mismatch, expiry, and recovery end to end.
6. **BEFORE CUSTOMER ONE:** move paid assessment/report execution to a recoverable durable worker and prove restart/idempotency.
7. **BEFORE CUSTOMER ONE:** produce a current encrypted offsite backup and isolated restore at migration 0187; prove retention/legal holds.
8. **BEFORE CUSTOMER ONE:** run the fixed-scope vertical workflow twice from clean tenant creation through signed report and remediation handoff.
9. **BEFORE CUSTOMER ONE:** define operator ownership, escalation, status communication, RTO/RPO, and incident contacts.
10. **BEFORE CUSTOMER ONE:** contract and marketing must match the proven wedge; exclude continuous/autonomous and Microsoft automation claims.

## 34. Required Before MRR

In addition to the Customer-One bar:

1. deploy scheduled reassessment through the durable job authority with queue-age and failure alerts;
2. make Portal tenancy derive from the verified principal/membership rather than a static deployment tenant;
3. prove remediation state, evidence lineage, report versions, and reassessment deltas across two billing periods;
4. prove provider outage, email outage, Redis outage, retry, cancellation, and manual recovery behavior;
5. automate backup recency, restore age, retention, dependency, certificate, queue, and worker-health gates;
6. establish support SLOs, capacity bounds, release rollback, data export/offboarding, and subscription ownership;
7. obtain explicit customer consent for longitudinal use and keep tenant data logically and cryptographically bounded;
8. only add Microsoft connector scope after a real test-tenant proof and support runbook.

## 35. Deferred Work

**DO AFTER CUSTOMER ONE:** broader Portal UX, additional framework mappings, selective connector hardening, consolidated domain read models, and commercial workflow automation.

**DEFER:** new route families, new governance frameworks without a contracted buyer, additional connectors, autonomous remediation, governance digital twin expansion, benchmark products, enterprise billing breadth, generalized marketplace integrations, new dashboards, and architectural rewrites.

These are not rejected ideas. They are lower return than proving one secure revenue cycle and then repeating it.

## 36. Recommended PR Sequence

### H. PR Plan

| Order | PR | Purpose | Effort | Dependency | Customer Impact | Revenue Impact | Moat Impact |
| ---: | --- | --- | --- | --- | --- | --- | --- |
| 1 | PR-A Release perimeter | bind clean, secure build to deployed SHA | M | none | prevents unsafe exposure | prerequisite | preserves evidence credibility |
| 2 | PR-B Closed-world schema/RLS | prove every runtime table and remove runtime DDL | M | PR-A | protects tenant data | prerequisite | strengthens authority provenance |
| 3 | PR-C Canonical platform auth | retire compatibility privilege path | M | PR-A | safer administration | prerequisite | strengthens authority graph |
| 4 | PR-D Identity worker deployment | same-SHA PostgreSQL worker with health | S-M | PR-A, PR-C | enables onboarding | prerequisite | validates canonical identity |
| 5 | PR-E Onboarding proof | live invitation-to-membership harness | M | PR-B-D | reliable tenant admin start | unlocks Customer One | moderate |
| 6 | PR-F Durable assessment execution | recoverable jobs/reports | M | PR-B | prevents stranded work | unlocks delivery/MRR | preserves evidence chain |
| 7 | PR-G Recovery and retention | current backup/restore/erasure proof | M | PR-B, PR-A | defensible data custody | unlocks Customer One | protects historical evidence |
| 8 | PR-H Customer-One vertical gate | one immutable end-to-end release proof | M | PR-A-G | credible paid workflow | unlocks first invoice | proves current moat |
| 9 | PR-I Managed reassessment | scheduled remediation/reassessment loop | M-L | PR-F-H | recurring service | unlocks MRR | compounds longitudinal moat |
| 10 | PR-J Portal multi-tenancy | principal-derived tenant binding | M | PR-C, PR-E, PR-H | scalable customer access | reduces MRR burden | strengthens authority history |

### PR-A: Enforce the Release Perimeter

**Problem / why now:** tests do not control what deploys, dependency gates are advisory, and the Portal build is not reproducible. **Exact scope:** patch supported frontend/Python dependencies, regenerate Portal lock, require clean install/typecheck/test/build/audit, protect main, remove Railway `checkSuites:false`, and attest source/image SHA. **Likely files/subsystems:** package manifests/locks, Python requirement files, `.github/workflows/`, `.railway/railway.ts`, release scripts, audit exceptions. **Invariants:** no auth semantic weakening; no critical/high production advisory without an approved current waiver; one SHA across processes. **Tests:** existing suites plus negative authentication and crafted-upload regressions. **Production proof:** ephemeral deploy reports commit/image SHA and passes browser login-denial probes. **Dependencies:** none. **Effort:** M. **Revenue effect:** prerequisite. **Moat effect:** makes signed evidence operationally credible. **Definition of done:** an untested SHA cannot reach production and all three frontend production builds pass from clean locks.

### PR-B: Establish Closed-World Schema and RLS

**Problem / why now:** 57 runtime tables escape migration-text census and 52 are tenant-scoped. **Exact scope:** generate a metadata-to-migration/live-catalog manifest, create corrective migrations/policies/constraints, classify legitimate non-persistent models, test security-definer grants, and disable production `create_all`. **Likely files/subsystems:** models, `migrations/`, DB startup, RLS audit scripts/tests. **Invariants:** all tenant tables force RLS or have documented platform-only authority; no table silently appears. **Tests:** empty/prior migration, two-tenant positive/negative access, platform operation, rollback rehearsal. **Production proof:** ephemeral PostgreSQL catalog equals manifest at head 0187. **Dependencies:** PR-A. **Effort:** M. **Revenue effect:** prerequisite for customer data. **Moat effect:** strengthens deterministic authority/evidence. **Definition of done:** the gate fails on any unclassified metadata or live table.

### PR-C: Make Platform Authorization Canonical

**Problem / why now:** compatibility mode gives the gateway secret a second platform-admin meaning. **Exact scope:** inventory callers, migrate delegation proofs/capabilities, require `CANONICAL` in production, separate secrets, remove Path E and residual bootstrap-email grant after a documented break-glass design. **Likely files/subsystems:** Core auth middleware/actor construction, Console BFF/auth, startup validators, auth tests/docs. **Invariants:** external IdP authenticates; FrostGate authorizes; one principal, membership, role, tenant authority; no arbitrary tenant headers or wildcard fallback. **Tests:** confused-deputy, replay, scope, tenant, email-verification, and secret-substitution negatives. **Production proof:** legacy credential fails while delegated Console workflows pass. **Dependencies:** PR-A. **Effort:** M. **Revenue effect:** prerequisite. **Moat effect:** strengthens authority graph. **Definition of done:** compatibility cannot start in production and no production caller needs it.

### PR-D: Deploy One Identity Worker

**Problem / why now:** Railway points the worker to a different branch and permits a SQLite-shaped default. **Exact scope:** same immutable source as Core, PostgreSQL production invariant, explicit queue/provider configuration, readiness, retries, idempotency, and dead-letter visibility. **Likely files/subsystems:** identity worker entrypoint, Railway IAC, health/telemetry, worker tests/runbook. **Invariants:** one canonical identity transaction authority; no second database; no silent fallback. **Tests:** restart mid-job, duplicate delivery, provider timeout, invalid event, disabled tenant. **Production proof:** ephemeral worker SHA matches Core and recovers a deliberately interrupted event. **Dependencies:** PR-A and PR-C. **Effort:** S-M. **Revenue effect:** enables onboarding. **Moat effect:** validates identity provenance. **Definition of done:** worker health measures real dependencies and no enrollment requires SQL/operator-created IdP users.

### PR-E: Prove Initial Administrator Onboarding

**Problem / why now:** local tests do not prove Auth0, email, browser, worker, and PostgreSQL together. **Exact scope:** a production-equivalent harness for tenant creation, invite delivery, OIDC verified identity, canonical principal/external identity/membership, role, acceptance, resend, and failure recovery; remove full-email preflight leakage. **Likely files/subsystems:** identity acceptance, invitations, Console invitation UI/BFF, email provider, E2E proofs. **Invariants:** token hashed, single use, tenant-bound, email-bound, row-locked; unverified/mismatched identities fail closed. **Tests:** positive plus enumeration, replay, expiration, concurrency, disabled tenant, role escalation, cross-tenant cases. **Production proof:** two clean tenants onboard separate admins with negative cross-checks. **Dependencies:** PR-B-D. **Effort:** M. **Revenue effect:** unlocks Customer One access. **Moat effect:** supports auditable authority. **Definition of done:** an operator uses only documented UI and receives immutable proof tied to SHA.

### PR-F: Make Assessment Execution Recoverable

**Problem / why now:** database durability is undercut by process-local execution. **Exact scope:** designate a worker/queue authority, lease and heartbeat jobs, call orphan recovery, add idempotency, retry/cancel/dead-letter semantics, and route report generation through it; reproduce/fix report regeneration transaction context. **Likely files/subsystems:** durable job service, scan/report routes, worker package, models/migrations, telemetry, UI status/retry. **Invariants:** one active owner per job; side effects idempotent; tenant context re-established in every transaction; terminal results immutable. **Tests:** kill/restart at each state, duplicate claim, stale lease, provider timeout, cancellation, cross-tenant claim. **Production proof:** deliberately terminate workers during a full assessment and complete once without duplicated evidence. **Dependencies:** PR-B. **Effort:** M. **Revenue effect:** enables reliable paid delivery and reassessment. **Moat effect:** preserves lineage under failure. **Definition of done:** no committed job depends on an API process remaining alive.

### PR-G: Prove Recovery and Retention

**Problem / why now:** the freshest backup evidence is critical/unknown and retention proof is conditional. **Exact scope:** encrypted offsite backup, current-head isolated restore, tenant/evidence/hash validation, explicit RPO/RTO, retention/legal-hold oracle, alerting, and expiring proof artifacts. **Likely files/subsystems:** operations workflows/scripts, backup/retention tests, runbooks, artifact schema. **Invariants:** no production mutation during drills; legal holds win; proof includes SHA/schema/time but no secrets. **Tests:** corrupt/missing backup, wrong key, partial restore, residual row, held evidence. **Production proof:** restore head 0187 into isolation and verify representative tenant/report/evidence integrity. **Dependencies:** PR-A-B. **Effort:** M. **Revenue effect:** prerequisite for custody and contracts. **Moat effect:** protects longitudinal history. **Definition of done:** latest passing proof is current, encrypted, offsite, restorable, and automatically expires.

### PR-H: Add the Customer-One Vertical Gate

**Problem / why now:** component PASS results do not prove a customer outcome. **Exact scope:** provision tenant/admin, collect manual/no-auth evidence, normalize, create findings, human QA, sign/deliver report, create remediation, verify/reassess, export, and offboard in one harness; produce a machine-readable evidence manifest. **Likely files/subsystems:** existing production-proof scripts, Field Assessment, Console/Portal BFF, report/evidence/remediation, release workflow. **Invariants:** normal flow uses public product interfaces, not direct SQL; every artifact tenant-bound and SHA-bound; failures are explicit. **Tests:** positive journey and denial/recovery checkpoints. **Production proof:** two consecutive runs from clean tenants in an ephemeral production-equivalent stack. **Dependencies:** PR-A-G. **Effort:** M. **Revenue effect:** unlocks first paid assessment. **Moat effect:** proves the evidence-to-remediation chain. **Definition of done:** the release cannot claim Customer-One ready without a current successful manifest.

### PR-I: Productize Managed Reassessment

**Problem / why now:** recurring value exists in remediation verification, but scheduling and longitudinal proof are incomplete. **Exact scope:** bounded monthly/quarterly schedules, customer-visible status, reminder/escalation, reassessment deltas, signed history, operator SLOs, cancellation, and billing handoff only as needed for the offer. **Likely files/subsystems:** durable worker, assessment/remediation/report services, Portal views, notifications, observability. **Invariants:** humans approve consequential decisions; history is append-only; schedules cannot cross tenants or duplicate work. **Tests:** multi-period simulation, retry, missed window, cancellation, role changes, provider outage. **Production proof:** two complete cycles on a non-customer reference tenant before contracted MRR. **Dependencies:** PR-F-H. **Effort:** M-L. **Revenue effect:** unlocks MRR. **Moat effect:** creates longitudinal governance intelligence. **Definition of done:** recurring delivery has measurable SLOs and needs no engineering intervention.

### PR-J: Remove Portal Deployment-Scoped Tenancy

**Problem / why now:** static Core tenant/key configuration creates deployment-per-tenant burden and authority ambiguity. **Exact scope:** derive tenant from validated principal/membership, enforce allowed tenant switching if required, use delegated BFF credentials, require distributed rate limiting, and expose dependency health. **Likely files/subsystems:** Portal auth/session store, BFF Core client, middleware/routes, Core delegation checks, deployment config. **Invariants:** browser cannot assert tenant directly; Core reauthorizes every request; no shared service credential becomes tenant authority. **Tests:** cross-tenant, stale membership, role removal, concurrent sessions, Redis outage, middleware bypass. **Production proof:** two tenants share one deployment and fail every cross-access probe. **Dependencies:** PR-C, PR-E, PR-H. **Effort:** M. **Revenue effect:** lowers MRR operating cost. **Moat effect:** produces trustworthy per-principal history. **Definition of done:** static `CORE_TENANT_ID` is not required for normal Portal requests.

## 37. Seven-Day Execution Plan

Days 1-2: freeze scope to the service-led assessment; assign owners; capture immutable baseline; enforce main/release checks; upgrade dependency blockers; repair Portal lock/build.

Days 3-4: complete metadata/migration/live-catalog census, classify all 57 tables, draft corrective migrations/RLS tests, and make production runtime DDL fail.

Days 5-6: set canonical platform auth in an ephemeral stack, align identity worker SHA/PostgreSQL configuration, and run invitation/email/Auth0 negatives.

Day 7: conduct go/no-go review using fresh artifacts. Do not onboard a customer if release identity, dependency, schema/RLS, identity, or restore proof remains red.

Expected outcome: PR-A substantially complete; PR-B/C/D evidence available; a precise date for a bounded paid pilot, not a launch claim.

## 38. Thirty-Day Execution Plan

Week 1: complete PR-A through PR-D. Week 2: land PR-E and PR-F, including worker-kill recovery. Week 3: complete PR-G and run backup, restore, retention, and incident drills. Week 4: complete PR-H twice, train the operator/assessor on the exact runbook, finalize bounded assessment terms, and onboard one design-partner customer only if every Customer-One gate is green.

Commercially, sell one fixed-scope assessment with defined inputs, human QA, signed deliverable, remediation review, timeline, exclusions, data handling, and support contact. Measure operator hours and every manual intervention; those observations determine the MRR product, not the roadmap.

## 39. Sixty/Ninety-Day Plan

By day 60, complete the first paid assessment, close remediation actions, run the first reassessment, and land PR-I's scheduling/alerting subset. Resolve authority ownership only where the paid path crosses parallel models. Prove Microsoft separately on a controlled test tenant; add it to scope only on green evidence.

By day 90, complete a second reassessment cycle, validate recurring unit economics and SLOs, land PR-J if multi-tenant Portal access is required, and turn verified longitudinal deltas into the core customer review. Then choose one expansion based on paid demand: Microsoft automation, another framework mapping, or a deeper evidence/remediation integration. Do not pursue all three.

## 40. Final Recommendation

Do next: execute PR-A and PR-B in parallel with separate owners, then PR-C/D/E as one authority-and-onboarding chain. These steps remove the two assumptions that invalidate every other claim: that the tested artifact is the deployed artifact, and that every runtime tenant table is covered by migrations and RLS. In parallel, sell only a conditional, fixed-scope assessment start date contingent on the Customer-One gate; do not place customer data in FrostGate before that gate and current restore proof pass.

1. **CAN I SAFELY PUT CUSTOMER ONE ON FROSTGATE TODAY?**
   **CONDITIONAL.** Not on the currently evidenced Console/Portal deployment. Customer One becomes defensible only after the release, dependency, schema/RLS, canonical auth, onboarding, durable execution, and restore gates pass at one immutable SHA.

2. **CAN I CHARGE FOR A FROSTGATE ASSESSMENT TODAY?**
   **CONDITIONAL.** A fixed-scope, service-led engagement can be contracted now with platform processing/delivery contingent on preflight. It must use manual/no-auth evidence, human QA, and a signed report, with Microsoft and autonomous claims excluded.

3. **CAN I SUPPORT RECURRING MRR TODAY?**
   **NO.** Durable scheduling/recovery, Portal tenancy, current operational proof, support SLOs, and repeated longitudinal delivery are not demonstrated.

4. **WHAT IS THE SINGLE SHORTEST PATH TO FIRST PAID REVENUE?**
   Sell one service-led AI governance assessment: bounded evidence intake -> deterministic findings -> human QA -> signed report -> remediation review, after PR-A through PR-H's minimum gate passes.

5. **WHAT IS THE SINGLE SHORTEST PATH TO DEFENSIBLE MRR?**
   Convert the paid assessment into managed remediation and monthly or quarterly reassessment after durable jobs, tenant-derived Portal access, alerts, restore/retention proof, and two successful longitudinal cycles.

6. **WHAT MUST NOT BE BUILT YET?**
   New framework families, additional connectors, new dashboards, autonomous remediation, digital-twin expansion, benchmark products, enterprise billing breadth, and new route groups.

7. **WHAT IS THE HIGHEST-ROI ENGINEERING WORK REMAINING?**
   A current-SHA vertical production gate that includes secure dependencies, closed-world schema/RLS, canonical identity/authority, crash recovery, and current restore.

8. **WHAT IS THE MOST DANGEROUS FALSE ASSUMPTION IN THE CURRENT PLATFORM?**
   That green tests, OpenAPI presence, or a PASS summary prove production behavior. The Portal build, Microsoft proof, deployed SHA controls, schema/RLS census, and backup artifact demonstrate that they do not.

9. **WHAT IS FROSTGATE'S STRONGEST CURRENT MOAT?**
   Evidence-to-decision-to-remediation provenance: signed artifacts, deterministic state, human QA, chain of custody, and auditable history.

10. **WHAT WOULD MOST INCREASE THAT MOAT OVER THE NEXT 90 DAYS?**
    Complete repeated paid assessment/remediation/reassessment cycles and preserve verified longitudinal outcomes tied to identity, tenant, evidence, controls, findings, actions, reports, and immutable release provenance.

**Trust, but Verify.**
