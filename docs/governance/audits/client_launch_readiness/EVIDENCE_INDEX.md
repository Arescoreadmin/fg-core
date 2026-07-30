# Evidence Index — Client Launch Readiness Audit

Every material claim in this audit maps to repository evidence below. Classification:
**VF** = verified fact (read in code/config) · **SI** = strong inference · **UU** = unresolved uncertainty · **DC** = documentation-only claim · **UT** = untested behavior

## Security & tenant safety

| # | Claim | Evidence | Class |
|---|-------|----------|-------|
| E1 | Row-level security is enforced with FORCE on tenant tables | `migrations/postgres/0003_tenant_rls.sql` (ENABLE + FORCE RLS, `current_setting('app.tenant_id')` policies); 158 `FORCE ROW LEVEL SECURITY` occurrences across `migrations/postgres/` | VF |
| E2 | Tenant context is set with parameterized `set_config`, not f-string SQL | `api/db.py:1911` `set_tenant_context()` uses `SELECT set_config('app.tenant_id', :tenant_id, true)` with bound param | VF |
| E3 | Assessment endpoints are no longer auth-free (SYSTEM.md is stale) | `api/assessments.py:36-39` router requires `require_scopes("ingest:assessment")`; lead-namespace tenant binding at `api/assessments.py:284-339` (`lead:{assessment_id}`) | VF |
| E4 | Portal password/demo login is disabled in production, fail-closed | `apps/portal/app/api/auth/login/route.ts:64-73` (403 `PORTAL_DEMO_AUTH_DISABLED`); `apps/portal/lib/session.ts` `isProdLikeEnv()` treats unknown env as prod | VF |
| E5 | Portal middleware gates all non-public routes on a session cookie | `apps/portal/middleware.ts` (PUBLIC_PREFIXES: /login, /api/auth, /api/health, /accept-invite) | VF |
| E6 | Named-user (pnu1.) sessions are edge-validated for form only; authoritative validation is server-side in Core | `apps/portal/lib/session.ts` `verifySessionToken()` comment + `PNU_TOKEN_RE`; Core-side validation via portal_scope claimed in comments | VF (BFF) / SI (Core path exercised in prod) |
| E7 | Browser logout revokes the Core-side named session | `apps/portal/app/api/auth/logout/route.ts` DELETE `/portal/named-sessions/self` with pnu token | VF (code) / UT (prod) |
| E8 | SSRF protection is centralized, multi-layer, no bypasses | `services/connectors/safe_target_validator.py` (RFC1918/CGNAT/link-local/metadata blocking, DNS-rebinding all-IPs-must-pass, CIDR expansion) | VF |
| E9 | FA mutation and read routes enforce permissions via ActorContext | `api/field_assessment.py` — 98 `require_permission` call sites across 63 handlers; ROADMAP PRs #514/#517 | VF (count) / SI (completeness, backed by CI coverage gate) |
| E10 | Audit ledger is HMAC-chained | `services/audit_engine/engine.py:63-77` (HMAC-SHA256 over self_hash with keyed chain) | VF |
| E11 | Append-only enforcement exists at DB level | append-only triggers asserted by `api/db_migrations.py:98` `assert_append_only_triggers()`; numerous migrations (0002, 0082, 0083, 0085…) | VF |
| E12 | Evidence lifecycle locks + legal hold implemented | ROADMAP H15 (PR fix 49): `FaEvidenceLifecycleEvent`, `FaLegalHold`, migration 0083; `services/field_assessment/evidence_lifecycle.py` exists | VF (existence) / DC (behavior detail) |
| E13 | Cross-tenant denial is regression-tested | `tests/test_fa_forensic_*` — 15 modules incl. tenant write isolation; 634 test files total | VF (existence) / SI (coverage adequacy) |
| E14 | No live secrets committed to the repository | `env/prod.env` contains only `CHANGE_ME_*` placeholders; `tools/ci/check_no_plaintext_secrets.py` CI gate exists | VF |
| E15 | Ed25519 report/evidence signing implemented | `services/field_assessment/evidence_authority.py`, ROADMAP PR-SIGN series (#415 merged), `FG_REPORT_SIGNING_KEY` documented in CLIENT_READINESS #38 | VF (existence) |

## Production & operations

| # | Claim | Evidence | Class |
|---|-------|----------|-------|
| E16 | Migrations auto-apply at startup in Postgres mode with a version ledger | `api/db.py:1855-1866` (`create_all(checkfirst)` then `apply_migrations`); `api/db_migrations.py` schema_migrations table | VF |
| E17 | Schema is hybrid ORM-create_all + SQL migrations | `api/db.py:1857-1862` comment: migrations 0073+ ALTER tables materialized by ORM | VF |
| E18 | 168 migrations exist (docs claim 77) | `ls migrations/postgres | wc -l` = 168; SYSTEM.md §7 says 0001–0077 | VF |
| E19 | CI is comprehensive and green on main | `.github/workflows/ci.yml` — 15+ jobs (guard, unit, contract_authority, integration, migrations_replay, db_postgres_verify, admin, console, pt, hardening, compliance, evidence, agents); GitHub Actions runs #2455–#2477 on main all `success` (2026-07-29/30) | VF |
| E20 | Sentry + Prometheus endpoint exist; Prometheus unscraped in prod | `api/main.py:286` `_init_sentry()`, `api/main.py:870` `/metrics`; CLIENT_READINESS B1/B3 | VF |
| E21 | No backup/restore procedure exists | grep across `docs/`, `deploy/`, `Makefile`: no pg_dump/restore runbook; ops_governance tables are records only (`docs/SOC_ARCH_REVIEW_2026-02-15.md:1842`) | VF (absence) |
| E22 | Background work is in-process (BackgroundTasks); durable job records mitigate | `api/field_assessment.py:3421,3517,3697,3767`; `services/field_assessment/durable_job_service.py:80` (lease model) | VF |
| E23 | Production incidents occurred in July and were fixed reactively | ROADMAP Platform Recovery rows R0, R0.1, R0.2 ("found and fixed during live incident recovery"), R1, R3, R6, R7 | DC (roadmap-recorded) / SI |
| E24 | Startup validation is extensive and fail-closed in prod | `api/config/startup_validation.py` (1,283 lines); `api/main.py:317-420` lifespan raises on failure when `is_production` | VF |
| E25 | 222 routers mounted; FA API is a 12,747-line module | `grep -c include_router api/main.py` = 222; `wc -l api/field_assessment.py` = 12747 | VF |
| E26 | Retention purge is not implemented | CLIENT_READINESS F7 open; no purge code in `api/`, `services/`, `jobs/` | VF (absence) |
| E27 | Uptime monitoring + error alerting configured | CLIENT_READINESS A9/B2/B3 (UptimeRobot 3 services; Sentry capturing) | DC (checked items, dated) |
| E28 | admin_gateway is compose-only; prod topology bypasses it | `docker-compose.yml:319`; CLIENT_READINESS A1–A6 lists Railway API + 2 Vercel apps only | SI / UU (whether any prod flow needs it) |

## Console & portal product

| # | Claim | Evidence | Class |
|---|-------|----------|-------|
| E29 | Console registers ~22 nav items in 6 groups incl. 4 dashboards | `packages/navigation/src/registrations/console.ts`; `apps/console/components/layout/Sidebar.tsx` GROUP_ORDER | VF |
| E30 | Console has 37 pages; portal has 20 | `find apps/{console,portal}/app -name page.tsx` | VF |
| E31 | Role-based nav filtering exists | `apps/console/components/layout/Sidebar.tsx:77` `getNavigationItemsForPrincipal` | VF |
| E32 | Portal `/changes` is a permanent-empty stub | `apps/portal/app/changes/page.tsx:15` `const [groups] = useState<ChangeGroup[]>([])` — no setter ever called | VF |
| E33 | Portal `/export` defaults options to unavailable | `apps/portal/app/export/page.tsx` `available: false` defaults | VF |
| E34 | Portal home is a real risk dashboard (severity strip, NIST coverage, remediation center) | `apps/portal/app/page.tsx` (793 lines, live portalApi data, RemediationCenter 4-tab) | VF |
| E35 | Portal support page has real self-serve content | `apps/portal/app/support/page.tsx` DEFAULT_TOPICS | VF |
| E36 | In-app notifications derive from audit events; no client email nudges | `apps/portal/app/notifications/page.tsx` (listAuditEvents; localStorage read-state); Resend mailer used only by invite route `apps/console/app/api/email/route.ts` | VF |
| E37 | Invite email delivery requires RESEND_API_KEY (throws if unset) | `apps/console/lib/mailer.ts:7-10` | VF |
| E38 | Console tenant provisioning is zero-touch with fail-closed persistence | `apps/console/app/api/admin/provision-tenant/route.ts`; ROADMAP P-3/P-3a/R0 (Edge Config + Redis fallback, 503 PERSISTENCE_UNAVAILABLE + key revoke on dual failure) | VF (existence) / DC (behavior) |
| E39 | Executive PDF export implemented with reportlab incl. data-collected appendix | `services/governance/report/serialization.py` `export_pdf_bytes`; `requirements.txt:14` reportlab; ROADMAP PR 38 + item 22 | VF (existence) / UT (current rendering quality) |
| E40 | Client-facing operator letters + DPA template exist | `docs/operators/letters/1–6*.md`; `contracts/dpa_template.md` | VF |

## Commercial & delivery

| # | Claim | Evidence | Class |
|---|-------|----------|-------|
| E41 | Operator runbooks exist for setup/onboarding/prep/credentials | `docs/operators/{azure_ad_app_setup,onboarding_runbook,first_client_prep,console_user_guide,credential_delivery}.md` | VF (existence) |
| E42 | A full dry run completed 2026-06-01 — before the identity overhaul | ROADMAP Phase 2 row 32 vs CLIENT_READINESS §H unchecked; identity cutover PRs (#577+, 0164) dated late July | VF (dated records) → the *current-stack* flow is UT |
| E43 | Anthropic balance was $3.50 on 2026-05-31 | CLIENT_READINESS B4 | DC (dated) |
| E44 | 13 scan types exist incl. AI tool discovery / risk register / vendor governance | `services/connectors/` subpackages (dns_email, web_headers, network_scan, msgraph, oauth_inventory, oauth_risk, endpoint_inventory, entra_governance, sharepoint, ai_tool_discovery, ai_data_access_mapping, external_ai_risk_register, ai_vendor_governance) | VF |
| E45 | Remediation closed loop + roadmap + quick-wins implemented | ROADMAP PRs 31/32; portal RemediationCenter wired (R-2 #545) | VF (existence) |
| E46 | Verification bundle (deterministic snapshot + tamper detection) implemented | `services/verification_bundle/bundle_service.py`, migration 0086, console/portal panels (ROADMAP #52) | VF (existence) |
| E47 | Billing v2/capability PRs are open with placeholder PR numbers | ROADMAP rows "PR PR_NUMBER (P1.2–P1.5)" | VF (roadmap state) |
| E48 | Stripe webhook configured in prod | CLIENT_READINESS A4 (whsec_ set 2026-05-31) | DC |

## Cross-cutting uncertainties carried into the plan

| # | Uncertainty | Why it matters | Resolution path |
|---|-------------|----------------|-----------------|
| U1 | Does invite→OIDC→portal session work in production for an external identity? | Only login path (E4) | FG-LR-002 (Stage 0) |
| U2 | Does the current production DB have all 168 migrations applied cleanly? | Hybrid create_all+migrations (E17); `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` set (CLIENT_READINESS A7) | Run `migration_status` against prod during dry run |
| U3 | Railway plan/backup posture today | E21, E28 | FG-LR-003/004 |
| U4 | PDF renders correctly on current stack | E39 | FG-LR-011 during dry run |
| U5 | Which identity-governance features assume admin_gateway in prod | E28 | FG-LR-019 topology decision |
