# Production Operations Connectors — FrostGate Core

Evidence base: production topology inferred from `ROADMAP.md` (Railway prod mode, Railway GitHub auto-deploy, Stripe webhook, Azure AD app registration), `.vercel/repo.json` + `apps/console/vercel.json` (console on Vercel), `deploy/grafana/dashboards/*.json` (3 dashboards, unclear if provisioned), `deploy/prometheus/alerts.yml`, `api/main.py` (Sentry SDK init), `api/observability/`, `api/identity_providers/auth0.py`.

**Default posture for every recommendation in this file: strict read-only.** Any connector capable of mutating production state is marked **HIGH RISK** and called out separately with the required controls, per the audit's strict decision rules. None of the HIGH RISK items are recommended for installation now — they are documented so the risk is visible, not because this audit is proposing them.

---

## 1. Observability Recommendations

| Area | Current state (evidence) | Recommendation | Access mode | Risk |
|---|---|---|---|---|
| Distributed tracing | `opentelemetry-api`/`sdk`/`exporter-otlp-proto-http` installed, wired in `api/observability/tracing.py` and `api/middleware/otel_tracing.py` — but no confirmed OTLP collector endpoint or trace backend (Grafana Tempo/Honeycomb/etc.) in `deploy/` | **Verify first, connect second.** Before recommending any trace-viewing connector, confirm whether spans are actually landing anywhere in Railway prod. If yes: a read-only trace-query connector (whatever backend is confirmed) scoped to the prod trace index only, no span injection/mutation capability. If no: this is a configuration gap, not a tooling gap — no connector fixes an exporter pointed at nothing. | Read-only, prod, once backend is confirmed live | Low (read-only) once verified |
| Metrics | `prometheus-client` wired (`api/metrics.py`), `deploy/prometheus/alerts.yml` exists, 3 Grafana dashboard JSON files in `deploy/grafana/dashboards/` | Same verify-first posture as tracing — confirm a Prometheus/Grafana instance is actually scraping Railway-hosted services before recommending a query connector. If a managed Grafana (Grafana Cloud) or self-hosted instance exists, a **read-only** dashboard/query connector scoped to the FrostGate org/instance is reasonable. | Read-only | Low once verified |
| Error reporting | `sentry-sdk[fastapi]` installed and initialized in `api/main.py`; `SENTRY_DSN` visibility gap is **already closed** — `api/config/startup_validation.py` `_check_observability_config()` (PR #590) emits a `severity="warning"` at startup when `SENTRY_DSN` is absent in prod/staging. The check is intentionally **non-blocking**: `docs/observability/deployment_topology.md` documents a no-telemetry topology as a valid deliberate choice, and blocking startup on a missing DSN would take down traffic for an observability configuration decision. | **Configuration gap is already addressed** — the startup validator will warn loudly in logs when `SENTRY_DSN` is absent; operators can act on that warning without it being a hard failure. The remaining recommendation is connector-only: once `SENTRY_DSN` is confirmed set and errors are landing in a Sentry project, a read-only Sentry issues/events connector scoped to the FrostGate prod project is reasonable for fast triage. No action needed on the configuration side. | Read-only, prod project scoped | Medium — prod error events can carry tenant-identifying context in stack traces/breadcrumbs; confirm PII scrubbing rules in the Sentry project config before any connector is wired, since regulated-industry clients (healthcare per SYSTEM.md) may have error payloads containing sensitive identifiers |
| Logs | `admin_gateway/logging_config.py`, `api/logging_config.py`, `jobs/logging_config.py`, `python-json-logger` dependency — structured JSON logging present | No log-aggregation backend (Loki/Datadog/CloudWatch) evidenced in `deploy/` or Railway config reviewed. Railway has its own built-in log viewer; if that's the operative tool today, no new connector is needed unless log retention/searchability becomes a documented pain point. | N/A until a backend is confirmed | N/A |
| Correlation IDs / audit-event inspection | `api/observability/log_context.py`, plus the hash-chain audit ledger (`0010_security_audit_hash_chain.sql`) and `services/audit_engine/` | This is **already a first-party FrostGate capability** (the platform's own audit/evidence chain), not a gap needing an external observability connector. Any "audit inspection" tooling need is better served by extending the existing audit-chain verification scripts (`scripts/verify_audit_chain.py`) than by adopting a generic observability product. | N/A — already solved internally | N/A |

---

## 2. Deployment Integrations

| Platform | Evidence | Recommendation | Access mode | Risk |
|---|---|---|---|---|
| Vercel (console) | `.vercel/repo.json` → project `console.frostgate.ai`, org `team_ynR0L5dXqTQmAJcX0MmjzOBm`; `apps/console/vercel.json`; Vercel MCP plugin available in this environment but requires the user to complete OAuth | **PILOT** — read-only deployment status, build logs, and preview-URL inspection scoped to the single `console.frostgate.ai` project. Do **not** grant org-wide Vercel access; scope the connection to this one project if the platform allows project-level tokens. | Read-only | Low, provided scope is project-limited |
| Railway (backend, admin gateway) | Inferred from `ROADMAP.md` PR notes ("Railway prod mode", "Railway GitHub auto-deploy") — no `railway.json`/`railway.toml` found in the file listing captured during this audit, so exact service topology on Railway wasn't independently confirmed beyond the roadmap narrative | **DEFER** pending confirmation of what Railway-side tooling (CLI token scope, project structure) actually exists — this audit did not locate Railway config files to evidence a specific integration point. Recommend a follow-up, narrower audit specifically of the Railway project once its config is locatable, rather than speculating here. | Read-only if pursued | Unknown until scoped |
| Database provider | Postgres via `pgvector/pgvector:pg16` image locally; prod DB host not confirmed in this audit's evidence (likely Railway-managed Postgres or an external managed Postgres, per the "Railway prod mode" note, but not independently verified) | See §3 below (Database and Redis Tooling) | — | — |
| DNS | No DNS provider config found in-repo (expected — DNS is typically managed outside the app repo) | Not applicable to this audit's evidence base | — | — |
| Email provider | No transactional-email provider config found (no SendGrid/Postmark/SES references located in the files reviewed) — `api/` handles report/notification logic but the audit did not locate an email-provider SDK dependency | **Flag for follow-up**, not a connector recommendation — if client-facing report delivery or notifications rely on email, confirm which provider is used before this can be scoped | — | — |
| Object storage | No S3/GCS/Azure Blob SDK dependency found in `requirements*.txt`; evidence artifacts appear to be filesystem-based (`artifacts/` directory structure) | If evidence bundles are stored only on Railway's ephemeral/attached filesystem rather than durable object storage, that is a **product durability gap worth flagging to the user**, separate from this audit's connector scope — evidence bundles are this platform's core commercial asset per `FOUNDER_DIRECTIVE.md`'s moat framing, and losing them to a redeploy would be a real incident. Recommend the user confirm evidence persistence separately from this audit. | — | — |

---

## 3. Database and Redis Tooling

| Target | Recommendation | Access mode | Risk |
|---|---|---|---|
| Local/dev Postgres | Read-only schema/RLS/explain-plan MCP — see `CLAUDE_CODE_MCP_RECOMMENDATIONS.md` #2 | Local only | Low |
| Staging Postgres | **DEFER** — no staging environment was independently confirmed to exist separately from "dev" in the evidence reviewed (`FG_ENV=dev`/`FG_ENV=test`/`FG_ENV=prod` are the values seen in CI, no distinct `staging` env var value observed). If a staging tier exists, a read-only connector following the same local-only pattern (scoped credentials, `SELECT`/`EXPLAIN` only, no `INSERT`/`UPDATE`/`DELETE`/DDL) would be reasonable **for schema inspection and query-plan review only** — never for browsing real customer-adjacent staging data if staging is seeded from anonymized prod snapshots. | Read-only, staging only, if staging exists | Medium — depends entirely on what staging actually contains |
| **Production Postgres** | **HIGH RISK — REJECT for any AI-agent connector, including read-only.** This is a multi-tenant governance/evidence platform serving regulated industries (healthcare, legal, govcon per `SYSTEM.md`). Even read-only access to production tenant data through an AI tool creates a data-handling question (does tenant data touch a model provider's context window, under what data-processing terms) that is a **founder/legal decision, not a tooling decision**, and is explicitly out of this audit's authority to approve. | **Never** | High |
| Redis (rate-limit state) | Local-only read-only inspection, see `CLAUDE_CODE_MCP_RECOMMENDATIONS.md` #6 (DEFERred there due to narrow current usage) | Local only | Low |
| Production Redis | **HIGH RISK if ever proposed** — same reasoning as production Postgres; Redis in this repo currently only holds rate-limit counters (low sensitivity), but the principle (no AI-agent access to production infrastructure) should apply uniformly regardless of the specific data class, to avoid a precedent that erodes as Redis's role expands. | **Never** | High if attempted |

---

## 4. Authentication Visibility

| Target | Recommendation | Access mode | Risk |
|---|---|---|---|
| Auth0 (prod identity provider) | **DEFER** — no repository evidence of a recurring Auth0-debugging workflow that would justify a connector. `api/identity_providers/auth0.py` documents the expected configuration (`FG_AUTH0_DOMAIN`, `FG_AUTH0_AUDIENCE`, roles-in-token Action) clearly enough that config questions are usually answerable by reading that file, not by querying Auth0 live. If a specific recurring need emerges (e.g., debugging a role-mapping issue), scope a **read-only** connector to Auth0's Management API `read:users`/`read:logs` at that time — do not pre-provision broad Auth0 tenant access speculatively. | Read-only, if ever pursued | Medium — Auth0 logs can contain login-attempt metadata (IPs, user agents) for real users across all tenants, not just FrostGate's own data |
| Keycloak (dev-only IdP) | No connector needed — this is a disposable local dev container (`fg-idp` in `docker-compose.yml`), not a production system. | N/A | N/A |

---

## 5. Tenant-Provisioning Monitoring

- **Evidence:** `api/provisioning_manager.py`, `api/tenant_lifecycle.py`, `services/provisioning/`, migrations `0050_tenant_provisioning.sql`, `0156_canonical_tenants.sql`, `0157/0158_tenant_lifecycle_transitions*.sql`. Tenant provisioning is a first-party, heavily-migrated subsystem.
- **Recommendation:** No external connector is justified. The highest-value addition here is a **synthetic smoke test** (see §7 below) that exercises the provisioning API end-to-end against a disposable test tenant in CI or on a schedule — this is a test-authoring task, not a connector-installation task, and should be scoped as a follow-up engineering task rather than a tooling recommendation.

---

## 6. Report-Generation Monitoring

- **Evidence:** `api/reports_engine.py`, `api/report_jobs.py`, `api/report_authority.py`, `services/report_authority/`, report signing (`api/signed_artifacts.py`, `api/signing.py`), executive PDF export (ROADMAP PR 38).
- **Recommendation:** Same reasoning as tenant provisioning — a scheduled synthetic "generate a report for the seeded demo tenant, verify the manifest hash and signature" smoke test (extending `scripts/verify_bp_c_004.py`-style verification scripts, or `make evidence`) is more valuable than any generic monitoring connector, because report *correctness* (not just report *availability*) is what actually matters for this product's legally-defensible-report requirement (`FOUNDER_DIRECTIVE.md` §4). No third-party tool can verify FrostGate-specific manifest/signature correctness — this must stay a first-party test.

---

## 7. Synthetic Monitoring / Uptime Checks

- **Evidence:** ROADMAP.md PR note "Health endpoint HEAD fix ... UptimeRobot HEAD checks now return 200" confirms an external uptime checker (apparently UptimeRobot) is already in use against `/health`, but no in-repo configuration, webhook receiver, or alerting-rule file was found to confirm current scope.
- **Recommendation:** **PLAN** — formalize what's already informally in place. At minimum, confirm (outside this audit's read-only scope) that UptimeRobot or an equivalent checks: the `/health` endpoint, console login page reachability, and portal reachability. If synthetic *authenticated* transactions (login → view a report) are wanted beyond simple uptime pings, that's the Playwright MCP use case from `CLAUDE_CODE_MCP_RECOMMENDATIONS.md`, run on a schedule against a seeded test tenant rather than a real client tenant — never point synthetic transaction monitoring at real client data.

---

## 8. Webhook Delivery Monitoring

- **Evidence:** `api/stripe_webhooks.py`, `api/webhook_security.py`; ROADMAP confirms a Stripe webhook endpoint is configured in prod with `STRIPE_WEBHOOK_SECRET` set.
- **Recommendation:** Stripe's own dashboard already provides webhook delivery/retry visibility — no additional connector needed. If failures are hard to notice today, the lower-cost fix is alerting on `webhook_security.py`'s failure path (existing code), not a new monitoring product.

---

## 9. Queue Depth / Background-Job Health

- **Evidence:** NATS (`docker-compose.yml`), `jobs/` directory (chaos, Merkle anchor, sim validator), no dedicated queue-depth dashboard found.
- **Recommendation:** **DEFER** — NATS usage in this repo appears bounded (event bus for a specific set of jobs, not a large distributed queue system under visible load pressure). Revisit if job backlog becomes a documented operational pain point; until then, a monitoring connector here would be solving a problem not yet evidenced.

---

## 10. Incident Response Integration

- **Evidence:** No PagerDuty/Opsgenie/Incident.io configuration or reference found anywhere in the repository.
- **Recommendation:** **Out of scope for a connector recommendation at this stage.** Incident-response tooling is an organizational-process decision (on-call rotation, escalation policy) that should precede any tool selection — recommending a specific IR platform without evidence of how the team currently handles incidents would be exactly the kind of generic, non-repository-evidenced recommendation this audit is required to avoid.

---

## 11. Least-Privilege Guidance (Summary)

The safest minimum-privilege configuration achievable from this audit's evidence, ranked by what to grant first:

1. **GitHub, read-only**, scoped to `Arescoreadmin/fg-core` only — highest evidenced value, lowest risk.
2. **Local Postgres (compose), read-only** — high value for migration/RLS work, zero prod exposure by construction.
3. **Vercel, read-only**, scoped to the `console.frostgate.ai` project only — moderate value, low risk if scope is held tight.
4. **Local Redis (compose), read-only** — low priority, low risk, defer until Redis usage grows.
5. **Sentry, read-only, prod-scoped** — contingent on first confirming Sentry is actually live and PII-scrubbed in prod; do not connect blind.
6. **Auth0 Management API, read-only** — defer until a specific recurring need is identified; do not pre-provision.
7. **Production Postgres/Redis, any access level, for any AI agent** — **never**, without an explicit, separate, founder/legal-level decision that is outside this audit's authority to make.

Every item above assumes the existing `.claude/hooks/` deny-list (`sudo`, `rm -rf`, `terraform apply`, `kubectl apply/delete`, `helm upgrade`, `aws secretsmanager`) and `.env*`/`secrets/**` read-denial remain in force unchanged.
