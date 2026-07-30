# Production & Operations Audit

**Question:** can a one-person team operate this reliably for paying clients?
**Answer:** yes for 1–3 concurrent white-glove clients **after** the P0 gaps close; no for 10 without the P2 automation. **Operational readiness: 4/10 today; ~6.5/10 after the 18.5-day plan.**

Classification per item: **IV** implemented+verified · **IU** implemented, unverified · **DO** documented only · **M** missing.

---

## Deployment & release

| Area | State | Class | Evidence |
|------|-------|-------|----------|
| Deploy pipeline | Railway GitHub auto-deploy (API); Vercel (console, portal); Docker/Helm/systemd configs exist but are dev/local or unused in prod | IV | ROADMAP PR 39; deploy/ tree |
| Repeatability | Container build from Dockerfile; env contract templated (`env/prod.env` placeholders); startup validation fail-closed in prod (~20 validators satisfied per ROADMAP item 25) | IV | E24 |
| Release validation | CI: 15+ jobs incl. contract authority, migrations replay, postgres verify, hardening, evidence, compliance lanes; main is green (runs #2455–#2477 all success) | IV | E19 |
| Rollback | **No documented procedure; never drilled** | M | FG-LR-005 |
| Environment validation | Startup validation report stored on app.state; `/health` HEAD-capable | IV | api/main.py |

## Data

| Area | State | Class |
|------|-------|-------|
| Migrations | 168 SQL files, auto-applied at startup with version ledger + RLS/append-only assertions; hybrid ORM `create_all` for FA substrate (documented, idempotent) | IV |
| Migration replay in CI | dedicated `migrations_replay` + `db_postgres_verify` jobs | IV |
| Backups | **Nothing.** No runbook, no verified provider backups; ops_governance tables are ledgers about backups, not backups | **M — P0 (FG-LR-003)** |
| Restore testing | Never performed | **M — P0** |
| Retention/deletion | Policy schema defines `retention.days=90`; no purge job or endpoint; DPA already promises it | **M — P1 (FG-LR-006)** |
| Disaster recovery | Undefined RPO/RTO | M — set trivially with the backup work: RPO = backup cadence, RTO = restore drill time |

## Observability & alerting

| Area | State | Class |
|------|-------|-------|
| Uptime | UptimeRobot on API `/health`, console, portal | IU (confirmed 2026-05-30, re-verify in dry run) |
| Errors | Sentry wired in API (`_init_sentry`), capturing confirmed during crash cycles | IV/IU |
| Metrics | `/metrics` Prometheus endpoint with rich counters (trust, capability, subscription) — **unscraped in prod**; Grafana/Prometheus configs local-only | IU → P2 (FG-LR-017) |
| Logs | Railway dashboard logs; structured logging configured (`jobs/logging_config.py`) | IU |
| Alert routing/ownership | **Undefined** — no triage doc, no response-time contract | **M — P1 (FG-LR-010)** |

## Operational workflows

| Workflow | State | Class |
|----------|-------|-------|
| Tenant provisioning | Zero-touch console flow, fail-closed persistence, error taxonomy — hardened by July incidents | IV (code) / IU (clean prod run pending) |
| Client onboarding | Runbooks: azure_ad_app_setup, onboarding_runbook (all connectors, pre-/in-meeting split), first_client_prep (75–90 min), console_user_guide, credential_delivery | DO→IV (validated at June dry run; re-validate) |
| Incident response | Ad hoc; July incidents prove both capability and absence of process | **M — P0 (FG-LR-005)** |
| Secret rotation | No procedure; 12+ secrets across two platforms | **M — P1 (FG-LR-012)** |
| Client offboarding / deletion | No path | M — P1 minimum: manual purge runbook |
| Dependency updates / vuln mgmt | constraints.txt + shared requirements authority (PR 14); no automated CVE scanning found in workflows | M — P2 (add pip-audit/npm audit lane, 0.5d, post-launch) |
| Container security | Standard Dockerfile; no image scanning gate found | M — P2 |
| Background work | In-process BackgroundTasks + durable job records w/ lease + orphan recovery + dead-letter; DB-fallback status route | IV (design) / IU (orphan recovery unobserved in prod) — P0-4 verifies |
| Scheduler | None (ENTERPRISE_PLAN Phase 2) — re-scans and retention are manual | M — accepted until stage 3 |

## Support readiness

- Support channel = the operator relationship; portal `/support` FAQ is real. **Adequate for ≤3 clients; scores 4/10 because it doesn't scale and has no SLA instrumentation.**
- Letters #4–#6 (delivery, 30-day follow-up, close-out) give the comms backbone. Missing: alert-driven proactive comms (covered by FG-LR-005 template).

## The July signal (why ops, not product, is the gating dimension)

The Platform Recovery series (R0→R7) is the most informative evidence in the repository: production credential/provisioning failures discovered live, root-caused, fixed, and hardened — *fast and well*. It demonstrates (a) real production traffic exists, (b) the founder can operate under incident pressure, and (c) none of it was procedure — every recovery was improvised. With zero clients, improvisation is free. With a paying client mid-engagement it is not. That is why FG-LR-003/004/005 are P0 while nothing in the security column is.

## Minimum ops bar for client one (all inside the 18.5-day plan)

1. Verified backup + one restore drill + runbook (1.5d)
2. Incident/rollback runbook + one timed drill (1d)
3. Alert triage ownership doc + Sentry notification rule (0.5d)
4. Plan headroom + concurrent load check + orphan-recovery observation (1d)
5. Manual retention purge runbook (0.5d)
6. Pre-engagement `pg_dump` step added to first_client_prep.md (0d — inside item 1)
