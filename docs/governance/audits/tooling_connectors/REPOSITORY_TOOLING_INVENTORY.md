# Repository Tooling Inventory — FrostGate Core

**Audit type:** Repository-driven tooling, connector, integration, and developer-productivity audit
**Repository:** `~/Projects/fg-core` (branch `feature/pr-588-actor-service-target-attribution`, HEAD `61aa749ef8feaa8fe74d9c0d6ee8e059d6d9b465` — merged to main as PR #588)
**Method:** Static inspection only. Nothing was installed, configured, connected, modified, or committed.
**Principle:** Trust, but Verify.

---

## 1. Architecture Summary

FrostGate Core is a single-repo, multi-service monolith-plus-satellites system:

| Subsystem | Path | Technology | Responsibility |
|---|---|---|---|
| Core API | `api/` (~230 modules) | FastAPI 0.136 / Python 3.12, SQLAlchemy 2.0, Alembic | Governance, policy, evidence, decisions, identity, connectors, billing, RAG, reporting — the control plane |
| Engine | `engine/` | Python | Decision/policy evaluation pipeline (ROE, rules, doctrine) |
| Admin Gateway | `admin_gateway/` | FastAPI, own Alembic chain | Separate privileged administrative service with its own auth/identity/middleware stack |
| Agent | `agent/` | Python (Linux + Windows service), Go sidecar (`supervisor-sidecar/`) | Endpoint agent shipped to clients; Windows build produced in CI |
| Console | `apps/console/` | Next.js (App Router), NextAuth v5, deployed to **Vercel** (`console.frostgate.ai`, org `team_ynR0L5dXqTQmAJcX0MmjzOBm`) | Operator-facing UI, Auth0 OIDC login |
| Portal | `apps/portal/` | Next.js | Client-facing engagement/report/remediation portal |
| Web | `apps/web/` | Next.js | Marketing/landing |
| Connector framework | `services/connectors/` + `api/connectors_*.py` | Python | Pluggable scan drivers: MS Graph (core, OAuth inventory/risk, endpoint, Entra governance, SharePoint), DNS/email, web headers, network scan, AI tool discovery, AI vendor governance |
| Jobs | `jobs/` | Python | Chaos testing, Merkle anchoring, simulation validator |
| Policy | `policy/opa`, `policy/bundles` | Open Policy Agent (OPA) | Policy evaluation engine, run as its own container in `docker-compose.yml` |
| Data stores | Postgres (`pgvector/pgvector:pg16`), Redis, NATS | — | Primary DB (with pgvector for embeddings/RAG), cache/rate-limit/queue signal, event bus |
| Identity | `api/identity_providers/` (Auth0, Entra, API key), `keycloak/` (dev-only IdP, `fg-idp` compose service) | Auth0 RS256 JWT (prod), Keycloak (local dev OIDC), API keys | Multi-provider identity abstraction (`base.py` interface) |
| Deployment | `deploy/` (Helm × 2 chart trees, k8s dev manifests), `Dockerfile`, `docker-compose*.yml`, Railway (per ROADMAP.md), Vercel (console) | Helm, Kubernetes (dev only), Railway (prod backend), Vercel (prod console) | Two parallel Helm chart trees (`deploy/helm/frostgatecore` and `deploy/frostgate-core`) — **duplication, see §4** |
| Migrations | `migrations/postgres/` | Raw SQL, hand-rolled runner (`api/db_migrations.py`) | 168 sequential migrations, no Alembic autogenerate; RLS, append-only triggers, hash-chain audit tables |
| Contracts | `contracts/` (`core/openapi.json`, `admin/`, `agent/`, `ai/`, `connectors/`, `dashboard/`) | OpenAPI, custom diff/gen scripts | Contract-authority pattern: prod OpenAPI spec is the single source of truth, hash-pinned in `BLUEPRINT_STAGED.md` |
| Testing | `tests/` (600+ files), `admin_gateway/tests/`, `agent/tests/`, `backend/tests/` | pytest 9.x, pytest-asyncio, pytest-cov | Extremely dense in-house gate suite (BP-* blueprint gates, RLS gates, invariant gates, forensic FA gates) |
| Observability | `api/observability/`, `api/middleware/otel_tracing.py`, `api/metrics.py`, `deploy/grafana/`, `deploy/prometheus/alerts.yml` | OpenTelemetry (API + SDK + OTLP HTTP exporter), `prometheus-client`, Sentry (`sentry-sdk[fastapi]`, wired in `api/main.py`) | Tracing/metrics libraries present and wired; no evidence of a receiving backend (Tempo/Jaeger/Grafana Cloud) configured for prod |
| CI/CD | `.github/workflows/` (6 workflows, 2,469 lines), `.github/actions/` (2 composite actions) | GitHub Actions | Extremely mature — path-filtered fan-out, contract-authority gate, migration replay, compliance-artifact gate, evidence-bundle signing (minisign) |
| Governance/compliance docs | `SYSTEM.md`, `ROADMAP.md`, `BLUEPRINT_STAGED.md`, `FOUNDER_DIRECTIVE.md`, `CONTRACT.md`, `docs/ci/*`, `docs/governance/*` | Markdown | Unusually rigorous internal documentation discipline; self-authored CI performance audits exist (`docs/ci/CI_OPTIMIZATION_PLAN.md`) |

**Production topology (evidence-based, not assumed):**
- Backend (`frostgate-core`, `admin_gateway`) → Railway (ROADMAP.md PR 39/25: "Railway prod mode", "Railway GitHub auto-deploy")
- Console → Vercel (`.vercel/repo.json`, `apps/console/vercel.json`)
- Auth → Auth0 (prod), Keycloak (dev only)
- DB → Postgres + pgvector (RLS-enforced, 168 migrations)
- Billing → Stripe (`api/stripe_webhooks.py`, `api/billing*.py`)
- No evidence of AWS/Azure/GCP account integration for the platform's own infra — Railway + Vercel is the full deployment surface today.

---

## 2. Current Tooling Inventory & Classification

| Tool / capability | Evidence | Classification |
|---|---|---|
| GitHub Actions (6 workflows) | `.github/workflows/*.yml` | **Active and well integrated** — path filters, artifact retention, concurrency groups, matrix jobs (Linux + Windows agent build) |
| Composite actions (`fg-python-setup`, `fg-secrets`) | `.github/actions/*/action.yml` | **Active and well integrated** — DRY setup, ephemeral CI secret generation (no static CI secrets for API keys) |
| In-house CI performance audit | `docs/ci/CI_OPTIMIZATION_PLAN.md` | **Active, self-diagnosed** — identifies 3 concrete duplications (DUP-01/02/03) costing ~30 min/PR; this is a stronger diagnostic than most third-party build-speed tools would produce out of the box |
| Changed-path detection | `tools/ci/detect_changed_paths.py` | **Active and well integrated** — repo-native equivalent of `dorny/paths-filter`, gates console/compliance/python/core lanes |
| pytest + 600+ test files, markers (`e2e_http`, `integration`) | `pytest.ini`, `pyproject.toml` | **Active and well integrated** — very high test density per subsystem |
| `pip-audit` | `Makefile:965`, invoked in `ci` target and `codex_gates.sh` | **Active but narrow** — vulnerability scan only, no automated dependency-update PRs (no Dependabot/Renovate found anywhere in `.github/`) |
| Custom secret scanner (`tools/ci/check_no_plaintext_secrets.py`, `check_secret_history.py`) | CI `fg_guard` job, pre-commit hook `no-plaintext-secrets` | **Active and well integrated** — purpose-built for this repo's env-file conventions (URL-embedded creds, `_SECRET_SUFFIXES` regex, blocklist of known-leaked values); more precise for this codebase than a generic scanner |
| `codex_gates.sh` cheap secret tripwire (ripgrep for API-key/PEM patterns) | root `codex_gates.sh` | **Active, local-only** — coarse regex safety net layered under the precise scanner above |
| Custom SBOM generator | `scripts/generate_sbom.py`, `make compliance-sbom` | **Active, hand-rolled** — CycloneDX 1.5 output from `requirements.txt`/`package.json` parsing; not using Syft/CycloneDX-Python tooling, so it will miss transitive dependency depth a real SBOM tool captures |
| CIS/SCAP compliance checks | `scripts/cis_check.py`, `scripts/scap_scan.py`, `make compliance-cis`, `make compliance-scap` | **Active, hand-rolled, CI-only** — custom implementations, not OpenSCAP or a CIS-benchmark tool |
| Contract-authority gate | `scripts/contract_authority_check.py`, `scripts/contracts_gen_core.py`, `scripts/contracts_diff_core.py` | **Active and well integrated** — prod OpenAPI spec hash-pinned in `BLUEPRINT_STAGED.md`, CI fails on drift |
| Evidence-bundle signing | `ci-evidence` job in `ci.yml`, `minisign` | **Active, CI-only** — signs evidence manifests; conditional skip if `MINISIGN_SECRET_KEY` absent (soft gate) |
| Pre-commit framework | `.pre-commit-config.yaml` | **Partially configured** — ruff + ruff-format + 3 local hooks (admin-gateway pytest subset, secret check, SOC sync/verify); not all CI gates mirrored locally, so pre-commit can pass while CI later fails on gates not mirrored (e.g., RLS checks, contract-authority) |
| `mypy` | `mypy.ini`, `requirements-dev.txt`, `mypy_hotspots.txt` | **Active but underused in CI** — `codex_gates.sh` runs it locally/strictly; not observed as a blocking step inside `.github/workflows/ci.yml` (no `mypy` step found in the workflow) — **verification gap** |
| `ruff` (lint + format) | `pyproject.toml`, pre-commit, Makefile | **Active and well integrated** |
| OpenTelemetry SDK + OTLP HTTP exporter | `requirements.txt`, `api/observability/tracing.py`, `api/middleware/otel_tracing.py` | **Active but underused / missing verification** — library is wired, but no OTLP collector endpoint, Tempo/Jaeger config, or Grafana Tempo datasource found in `deploy/`; traces likely have nowhere to land in production today |
| `prometheus-client` + Grafana dashboards | `deploy/prometheus/alerts.yml`, `deploy/grafana/dashboards/*.json` (3 dashboards), `api/metrics.py` | **Partially configured** — dashboards and alert rules exist as JSON/YAML artifacts, but no evidence of a running Prometheus/Grafana instance wired to Railway prod (no Grafana Cloud, no managed Prometheus config found) |
| Sentry SDK | `requirements.txt` (`sentry-sdk[fastapi]`), `api/main.py` | **Active but missing verification** — SDK is imported and initialized in code; no `SENTRY_DSN` documented as required/validated at startup the way other prod-critical vars are (see `console/lib/startup-validation` pattern used for console, not mirrored for Sentry in API) |
| Repo-local MCP server (`repo-tools`) | `.mcp.json`, `tools/mcp/repo_tools_server.py` | **Active, well-scoped, local-only** — exposes `run_target` (allowlisted Make targets only: lint/typecheck/test-fast/compose-*), `compose_logs`, `read_file` (repo-root-jailed), `grep_code`, `git_diff_summary`. This is a genuinely good pattern: least-privilege by construction |
| Claude Code hooks (`pre_bash_guard.sh`, `post_edit_guard.sh`) | `.claude/hooks/`, `.claude/settings.json` | **Active and well integrated** — deny-regex blocks `sudo`, `rm -rf`, `terraform apply`, `kubectl apply/delete`, `helm upgrade`, `aws secretsmanager`; diff-scope nudge over 5 changed files; `.env*` and `secrets/**` reads denied by permission config |
| Helm charts | `deploy/helm/frostgatecore/` **and** `deploy/frostgate-core/` | **Duplicated** — two parallel chart trees for the same service; unclear which is authoritative (see §4) |
| k8s dev manifests | `deploy/k8s/dev/` | **Local/dev only** — no k8s in the actual prod path (Railway), so this is either a stale artifact of a prior deployment plan or a DR/portability option not currently exercised |
| Keycloak (`fg-idp`) | `docker-compose.yml`, `keycloak/realms/` | **Local dev only** — prod uses Auth0; Keycloak exists purely so local dev doesn't need live Auth0 credentials |
| Dependabot / Renovate | — | **Missing entirely** — no `.github/dependabot.yml`, no Renovate config anywhere in the repo |
| CodeQL / Semgrep / SAST | — | **Missing entirely** — no workflow, no config, no reference anywhere in `.github/` or `tools/` |
| Container image scanning (Trivy/Grype) | `docker-ci.yml`, `release-images.yml` reviewed | **Missing** — images are built and pushed with signing scaffolding (`FG_SIGNING_SECRET`, minisign) but no vulnerability scan step found |
| Gitleaks / TruffleHog | — | **Missing, and likely unnecessary** — the repo's custom secret scanner is more precise for this codebase's env-file conventions; see GITHUB_CI_ADDON_RECOMMENDATIONS.md |
| Browser/E2E testing (Playwright/Cypress) | Searched `apps/console`, `apps/portal`, `tests/` | **Missing** — no browser automation found for console/portal login flows, despite both being auth-gated, multi-tenant, client-facing UIs |
| API contract testing beyond internal diff (Schemathesis, Dredd) | — | **Missing** — contract-authority gate checks the OpenAPI *spec* for drift, not that live responses conform to it |
| Node dependency scanning (`npm audit`, root/console/portal) | `package-lock.json` present at root, in `apps/console/`, `apps/portal/` | **Not observed in CI** — no `npm audit` step in `console` or `docker-ci` jobs |

---

## 3. Existing Strengths (do not replace without a clear advantage)

1. **Contract-authority pattern** — the prod OpenAPI spec is hash-pinned as the literal single source of truth (`BLUEPRINT_STAGED.md` header), enforced by `make contract-authority-check` in CI. This is stronger than most third-party API-contract tools because it's wired directly into the platform's own governance doctrine.
2. **Blueprint gate system** (`BP-S0-*`, `BP-M1-*` … `BP-C-*`, `scripts/verify_bp_*.py`, `tests/test_bp_*_gate.py`) — a self-built maturity/compliance gate framework mapped to explicit requirement IDs, enforced in CI (`bp-*-gate` Make targets). This is bespoke governance tooling a generic GRC SaaS cannot replicate for this repo's own build.
3. **RLS + append-only + hash-chain audit trail as code** — `migrations/postgres/0003_tenant_rls.sql`, `0002_append_only_triggers.sql`, `0010_security_audit_hash_chain.sql`, enforced by `check_core_rls.py`, `check_connectors_rls.py`, `check_agent_phase2_rls.py`. Tenant isolation is tested at the SQL layer, not just the app layer.
4. **Self-diagnosed CI redundancy** (`docs/ci/CI_OPTIMIZATION_PLAN.md`) — the team already found ~30 min/PR of duplicate work (`DUP-01/02/03`) through first-party analysis. Any external "CI speed" tool would be re-deriving what's already documented here.
5. **Ephemeral CI secrets** (`fg-secrets` composite action generates fresh random secrets per run, not static GitHub Secrets for most values) — reduces blast radius of a leaked Actions log.
6. **Scoped MCP server** — `tools/mcp/repo_tools_server.py` allowlists exactly 6 Make targets and jails filesystem reads to the repo root. This is the correct minimum-privilege pattern and should be the template for any new MCP server added to this repo, not replaced by a broad general-purpose filesystem MCP.

---

## 4. Duplication

| Item | Detail |
|---|---|
| Helm charts | `deploy/helm/frostgatecore/` and `deploy/frostgate-core/` both define a chart for the same service with different structure (one has `templates/` with configmap/deployment/secret/serviceaccount/service, the other only `chart.yaml` + `values.yaml`). No Makefile target references both consistently in the excerpt reviewed — needs a human decision on which is canonical, not a tooling fix. |
| `.env` files | `.env`, `.env.ci`, `.env.dev`, `.env.example`, `.env.local`, `env/prod.env` — five+ env file variants at root plus per-app `.env.example` files (console, agent). Managed by the custom secret scanner, so not a security gap, but a discoverability one for new contributors. |
| `readme.md` (empty, 0 bytes) vs `README.md` (815 bytes) | Dead/stale file — case-duplicate empty file at root. |
| Contract generation scripts | `scripts/contracts_gen.py`, `scripts/contracts_gen_core.py`, `scripts/contract_toolchain_check.py`, `scripts/contract_lint.py`, `scripts/contracts_diff_core.py` — five related-but-distinct contract scripts; likely each has a distinct purpose but the naming makes ownership hard to infer without reading each one. |

---

## 5. Dead Code / Stale Artifacts (flagged, not removed)

- `console.log` (655 KB), `unit.log` (124 KB), `frostgate_tree.txt` / `frostgate_tree_everything.txt` (417 KB) at repo root — look like committed debug/snapshot output, not source.
- `fg-test.db`, `frostgate_decisions.db-shm`, `state/*.db*` — SQLite artifacts at root and in `state/`; some are gitignored patterns but several appear tracked given they showed up in a plain `ls`.
- `main` (0-byte file at root) — no evident purpose.
- `assert` (37-byte file at root, non-standard name) — worth a human look, out of scope for this audit to interpret.
- Roughly 40 one-off `scripts/fg_fix_*.sh` / `scripts/fg_patch_*.sh` / `scripts/nuclear_makefile_patch.sh` scripts — named like single-use historical patches (e.g., `fg_fix_decisions_diff_escape.sh`, `fg_fix_explanation_brief_defend_v3.sh`). These are evidence of past firefighting, not currently-invoked tooling; none appeared referenced from the Makefile target list captured in this audit.

---

## 6. Underused Capabilities

| Capability | Why it's underused |
|---|---|
| OpenTelemetry SDK | Present, wired to middleware, but no configured trace backend found — spans are likely generated and dropped (exporter with no reachable OTLP collector fails silently or errors, depending on config) |
| Sentry SDK | Initialized in `api/main.py` but not part of the startup-validation gate pattern the console uses (`instrumentation.ts` → `validateProductionConfig()`); no evidence prod actually has a valid `SENTRY_DSN` set, vs. failing fast if missing |
| Grafana dashboards (3 JSON files) | Exist as artifacts in `deploy/grafana/dashboards/`, but nothing in the CI or deploy scripts reviewed provisions them into a running Grafana instance — they may be aspirational/documentation-only today |
| `mypy` | Strict-by-default in `codex_gates.sh`, but not a blocking CI step in `ci.yml` — so the type-checking bar is only enforced when a human/agent runs the full local gate script, not on every PR |
| Node `package-lock.json` at 3 levels (root, console, portal) | No `npm audit` / `npm ci --audit` step anywhere in CI — JS dependency risk is currently unmonitored despite lockfiles being committed |

---

## 7. Major Developer Friction

1. **CI critical path ~110 minutes per PR** (per the team's own `docs/ci/CI_OPTIMIZATION_PLAN.md`), with ~30 min identified as pure duplication (DUP-01/02/03) not yet fully eliminated as of this audit.
2. **Five+ root-level `.env*` files** plus per-app `.env.example` files — new contributors have no single authoritative bootstrap path documented at a glance (though `scripts/bootstrap.sh`, `scripts/dev_env.sh` exist and likely encapsulate this — not fully read in this audit).
3. **No mypy in CI** means type errors surface only when someone remembers to run `codex_gates.sh` locally, or not at all until runtime.
4. **No browser E2E** for two auth-gated, multi-tenant Next.js apps (console, portal) — regressions in login/session/tenant-switch flows are only caught by API-level tests, not by exercising the actual browser session cookie / NextAuth JWT path.
5. **168 sequential hand-written SQL migrations** with a custom runner (`api/db_migrations.py`) — powerful and precise, but any new contributor must learn this bespoke system instead of standard Alembic autogenerate (Alembic is a dependency, per `requirements-shared.txt`, but migrations are raw SQL, not Alembic revisions — worth confirming intent, not assuming it's accidental).

---

## 8. Production-Operation Gaps

- No confirmed live trace/metrics backend for OpenTelemetry/Prometheus in the Railway-hosted prod backend.
- No container image vulnerability scanning before `release-images.yml` pushes images.
- No synthetic/uptime monitoring evidence beyond the `/health` endpoint fix noted in ROADMAP.md (PR "Health endpoint HEAD fix" for UptimeRobot) — suggests UptimeRobot or similar is used externally, but no config/webhook is present in-repo to confirm scope or alerting rules.
- No Dependabot/Renovate means dependency version drift (Python, Node, Docker base images) is only caught by manual `pip-audit` vulnerability scanning, not proactive version-bump PRs.

This inventory is the evidence base for the recommendations in the companion files in this directory.
