# Claude Code & MCP Recommendations — FrostGate Core

Evidence base: `REPOSITORY_TOOLING_INVENTORY.md`. Existing MCP surface: `.mcp.json` → one stdio server, `repo-tools` (`tools/mcp/repo_tools_server.py`), allowlisted to 6 Make targets, ripgrep search, repo-root-jailed file reads, and `git status`/`git diff --stat`. Claude Code hooks (`.claude/hooks/pre_bash_guard.sh`, `post_edit_guard.sh`) already deny `sudo`, `rm -rf`, `terraform apply`, `kubectl apply/delete`, `helm upgrade`, `aws secretsmanager`, and deny reads of `.env*`/`secrets/**`.

**Path-jail correction (addressed in this PR):** the original `_safe_path()` in `repo_tools_server.py` used `str(p).startswith(str(REPO_ROOT))`, which is vulnerable to a sibling-path attack — a path like `../fg-core-secrets/token` resolves to a sibling directory whose string representation shares the repo-root prefix. Fixed to `p.is_relative_to(REPO_ROOT.resolve())` (Python 3.9+ `Path` method), which checks actual filesystem ancestry rather than string prefix. New servers following this pattern must use `is_relative_to`, not `startswith`.

**Design constraint carried through every recommendation below:** the existing `repo-tools` server proves the team's preferred pattern is a *narrow, purpose-built, allowlisted* MCP server, not a broad general-purpose connector. New recommendations follow that pattern — extend `repo-tools`-style servers rather than install broad third-party MCP servers with wide default scopes.

---

## Ranked Recommendations

| Rank | Connector / MCP | Category | Repo evidence | Workflow improved | Permissions | Access mode | Risk | Effort | Benefit | Recommendation |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | GitHub MCP server (read-only) | GitHub | 6 workflows, 870-line `ci.yml`, `gh pr` already used per this session's git context, PR-heavy workflow (branch name references PR #588) | PR/issue/checks/workflow-run triage without leaving Claude Code; reading CI failure logs across 6 workflows without manual `gh run view` | `repo:read`, `checks:read`, `actions:read`, `pull_requests:read` | Read-only (issues, PRs, checks, Actions runs). No write, no merge, no branch protection changes | Low | Low | High — this repo's CI is 2,469 lines across 6 workflows; fast failure triage is the single biggest recurring loop | **INSTALL NOW** |
| 2 | Postgres MCP (local/dev only) | PostgreSQL | 168 migrations, RLS on tenant tables (`0003_tenant_rls.sql`, `0005_tenant_rls_policy_enforcement.sql`, `0075_fa_rls.sql`), pgvector for RAG, custom migration runner `api/db_migrations.py` | Inspecting schema/RLS policies/index usage while writing migrations 169+; validating a new migration against the local `pgvector/pgvector:pg16` compose service before opening a PR | Read-only SQL role against the **local docker-compose Postgres only** | Local-only, read-only (`SELECT`, `EXPLAIN`, `\d`-equivalent). Never staging, never production | Low (local only) | Low | Medium-High — RLS correctness is safety-critical here and currently verified only by running the full pytest RLS gate suite; a schema-inspection MCP shortens the write-migration-verify loop | **PILOT** |
| 3 | Playwright MCP (local/dev, non-prod credentials) | Browser automation | No browser/E2E tooling found anywhere for `apps/console` or `apps/portal`; both are Auth0/NextAuth-gated, multi-tenant, client-facing | Authenticated console/portal login + tenant-switch + session-expiry smoke checks that currently have zero coverage (see inventory §7 friction item 4) | None beyond a local dev/test tenant login | Local-only against `docker-compose` / local dev servers, using seeded test tenant credentials — never staging or prod sessions | Low (local only, test creds) | Medium (no existing scaffolding to extend) | High — this is the single largest *coverage* gap identified, not just a productivity gap; auth/session bugs in console/portal are currently invisible to any automated check | **PILOT** |
| 4 | Extend `repo-tools` MCP: add `read_migration_history`, `openapi_diff` tools | Filesystem/repo intelligence | `scripts/contracts_diff_core.py`, `api/db_migrations.py`, `contracts/core/openapi.json` already exist as CLI scripts | Faster contract-authority and migration-ordering checks surfaced directly as MCP tools instead of shelling out each time | Same allowlist model as existing server — add 2 narrowly-scoped read tools | Local-only, read-only, jailed to repo root (same pattern as existing server) | Low | Low | Medium — incremental, reuses a pattern already proven safe in this repo | **PLAN** |
| 5 | Vercel MCP / `vercel:*` skills (already available as a plugin in this session) | Deployment platform | Console deployed to Vercel (`.vercel/repo.json`, project `console.frostgate.ai`); Vercel CLI already present in this environment (though outdated) | Reading console deployment status/build logs/preview URLs without leaving the session; diagnosing console-only prod incidents faster | Vercel read scopes (deployments, logs) for the `console.frostgate.ai` project only | Read-only deployment/log inspection; **no** env var writes, no production promotion, no domain changes | Low-Medium (Vercel access is org-scoped, not just this project — scope it to the one project if the Vercel plugin allows) | Low (plugin already installed, needs user OAuth) | Medium — console is one of three deployable surfaces (console/portal/backend); today only console has a plausible connector, since portal/backend are Railway-hosted | **PILOT** (blocked on user completing Vercel OAuth — plugin reports auth required) |
| 6 | Redis MCP (local/dev only, read-only) | Redis | `redis:7-alpine` in `docker-compose.yml`, used for portal rate-limiting (`apps/portal/lib/redis.ts`) and referenced in 9 Python files | Debugging rate-limit bucket state, TTLs, and key-namespace tenant isolation locally during development | Read-only Redis client, local compose instance only | Local-only, read-only (`GET`/`TTL`/`SCAN`, no `FLUSHALL`/`DEL`/`CONFIG SET`) | Low (local only) | Low | Low-Medium — Redis usage in this repo is narrow (rate limiting + light caching), not a primary data store, so the ceiling on value is lower than the Postgres MCP | **DEFER** (revisit if Redis usage expands beyond rate-limiting) |
| 7 | OpenAPI-aware API testing / contract-replay tool (e.g. Schemathesis-style) | API testing | Contract-authority gate (`make contracts-core-diff`, `contract-authority-check`) verifies the *spec* doesn't drift, but nothing verifies live responses conform to the spec | Catching spec/implementation drift the current gate structurally cannot catch (spec-vs-spec diff, not spec-vs-runtime conformance) | None beyond hitting local/CI API instance | CI-only or local-only against a running local/CI server, never staging/prod | Low | Medium | Medium — real gap, but the contract-authority system already catches the most common failure mode (accidental breaking change); this closes a narrower residual gap | **PLAN** |
| 8 | Sentry MCP / error-reporting connector | Observability | `sentry-sdk[fastapi]` installed and initialized in `api/main.py`, but no confirmed live `SENTRY_DSN` enforcement (inventory §6) | Once Sentry is confirmed live in prod: surfacing recent prod exceptions/error groups directly in Claude Code sessions for faster triage | Sentry read-only project access (issues, events) | Read-only, prod project scoped | Medium (prod error data may contain tenant-identifying context — must confirm PII scrubbing in Sentry config before connecting) | Low | Medium (contingent) | **DEFER** — blocked on first confirming Sentry is actually receiving events in prod (see PRODUCTION_OPERATIONS_CONNECTORS.md) |
| 9 | Generic/broad filesystem or semantic-code-search MCP (e.g. a vector-indexed codebase search server) | Filesystem/repo intelligence | Repo already has `repo-tools`' `grep_code` (ripgrep-based) plus Claude Code's built-in Explore agent and Read/Grep tools | Marginal — would duplicate `grep_code` and the built-in Explore agent for a repo of this size (~230 API modules, indexable by ripgrep in seconds) | Would require indexing the full repo, including any files under `.env.*`-adjacent or `secrets/**` paths unless carefully excluded | N/A | Medium (broad indexers are easy to misconfigure to include denied paths) | Medium | Low — duplicates existing, already-scoped capability | **REJECT** — no measurable advantage over `grep_code` + Explore agent at this repo's current size |
| 10 | Broad/write-capable GitHub MCP (issue creation, PR merge, branch protection edits) | GitHub | Same evidence as #1 | Would allow Claude Code to open/merge PRs, edit issues, change branch protection autonomously | `repo:write`, `admin:repo_hook`, branch protection admin | Write | High | Low (same install, different scope) | N/A — value is in read access; write access has no repo-evidenced need | **REJECT** — no task in this repo requires Claude Code to write to GitHub directly; PR creation/push already goes through the user-approved `gh pr create` / `git push` flow in the current session, which is the correct human-in-the-loop boundary |
| 11 | Production database MCP (staging or prod Postgres) | PostgreSQL | Same schema as #2, but pointed at Railway prod/staging | Would allow live tenant-data inspection | Any DB credential with prod/staging reach | Would require prod credentials in the Claude Code environment | High (customer evidence data, PHI/PII depending on tenant vertical — healthcare is an explicit target market per SYSTEM.md §1) | N/A | N/A | **REJECT** — never staging, never production. Every DB interaction from Claude Code must stay local-only against the docker-compose Postgres seeded with synthetic data |

---

## Full Structure — Top Recommendations

### 1. GitHub MCP server (read-only)

- **Category:** GitHub
- **Problem solved:** Manual `gh` CLI round-trips to check CI status across 6 workflows (2,469 lines) and triage PR review comments slow down iteration on this actively-developed branch (`feature/pr-588-actor-service-target-attribution`).
- **Repository evidence:** `.github/workflows/{ci,docker-ci,fg-required,testing-module,ai-ledger-guard,release-images}.yml`; git context shows active PR-based workflow with `gh pr` usage already permitted in `.claude/settings.local.json`.
- **Proposed workflow:** Claude Code reads PR status, check-run results, and review comments directly; surfaces failing-job logs inline instead of the user pasting them in.
- **Claude Code usage:** Direct tool calls during PR review / CI-failure debugging sessions.
- **Installation location:** User-level or project-level `.mcp.json` addition (new server entry alongside `repo-tools`).
- **Required permissions:** `repo:read`, `pull_requests:read`, `checks:read`, `actions:read` on `Arescoreadmin/fg-core` only (not org-wide).
- **Recommended access mode:** Read-only.
- **Data accessed:** PR metadata, diffs, check-run logs, issue text.
- **Data leaving repository:** PR/issue text and CI log excerpts pass through the MCP server to the model context — same class of data already visible via `gh pr` commands run manually in this session.
- **Security impact:** Low — no write capability, no secrets in scope (GitHub Actions secrets are not readable via the GitHub API regardless).
- **Operational impact:** None (no production system touched).
- **Developer experience impact:** High — removes the manual copy-paste loop for CI triage.
- **Commercial impact:** None directly (internal tooling).
- **Moat impact:** None directly.
- **Cost category:** Free (GitHub API, PAT/OAuth-scoped).
- **Setup effort:** Low — token/OAuth scoped to repo, added to `.mcp.json`.
- **Maintenance effort:** Low.
- **Alternatives:** Continue using `gh` CLI manually (current state) — works, but is the friction this recommendation removes.
- **Why this is better than current state:** Same data, fewer manual steps, less context-window spent on raw `gh` command output.
- **Acceptance criteria:** Server can list PR #588's check runs and surface a failing job's log tail without the user running `gh run view` manually.
- **Rollback strategy:** Remove the `.mcp.json` entry; no repo state changes to undo.
- **Final verdict: INSTALL NOW.**

### 2. Postgres MCP (local-only, read-only)

- **Category:** PostgreSQL
- **Problem solved:** Writing/reviewing migration 169+ or debugging an RLS policy currently requires shelling out to `psql` (`scripts/psql.sh`) or writing a one-off pytest. No structured schema/RLS/explain-plan introspection is available to Claude Code directly.
- **Repository evidence:** `migrations/postgres/` (168 files), `0003_tenant_rls.sql`, `0005_tenant_rls_policy_enforcement.sql`, `0075_fa_rls.sql`, `0110_core_tenant_rls_hardening.sql`; `tools/ci/check_core_rls.py`, `check_connectors_rls.py`, `check_agent_phase2_rls.py`; `docker-compose.yml` `postgres` service (`pgvector/pgvector:pg16`).
- **Proposed workflow:** During migration authoring, Claude Code inspects current schema/RLS policies/indexes on the **local compose Postgres** to validate a draft migration before running the full pytest RLS gate suite.
- **Claude Code usage:** Direct read-only SQL tool calls (`\d`, `SELECT * FROM pg_policies`, `EXPLAIN`) scoped to the local instance.
- **Installation location:** New MCP server entry, connection string pointed at `localhost` compose Postgres (`make deps-up` / `db-postgres-up` target), never an env var that could resolve to Railway.
- **Required permissions:** A dedicated read-only Postgres role, local instance only.
- **Recommended access mode:** Local-only, read-only.
- **Data accessed:** Local schema, seeded/synthetic test data only (never production tenant data — local compose Postgres has no path to real customer data).
- **Data leaving repository:** Schema and synthetic row samples enter model context; no real tenant/PHI data involved because the connection is local-only by construction.
- **Security impact:** Low, provided the connection string is hard-pinned to `localhost`/compose network and reviewed at install time — this is the one item in this list where a misconfiguration (accidentally pointing at Railway) would be a real incident, so the setup step must include an explicit assertion the connection host is not the prod hostname.
- **Operational impact:** None.
- **Developer experience impact:** Medium-high for migration/RLS work specifically.
- **Commercial impact:** None directly.
- **Moat impact:** None directly, but indirectly protects the RLS-correctness moat asset by making it easier to get RLS right before merge.
- **Cost category:** Free.
- **Setup effort:** Low (compose already runs Postgres; add read-only role + MCP server).
- **Maintenance effort:** Low.
- **Alternatives:** `scripts/psql.sh` manual sessions (current state, works fine, just manual).
- **Why this is better than current state:** Same access, integrated into the Claude Code loop instead of a separate terminal.
- **Acceptance criteria:** Server can list RLS policies on a tenant table and confirm `USING`/`WITH CHECK` clauses reference the session tenant GUC, without a human running `psql` manually.
- **Rollback strategy:** Remove server entry and the read-only role; no schema changes involved.
- **Final verdict: PILOT** — trial for one migration cycle, confirm the local-only connection guarantee holds, then promote to INSTALL NOW.

### 3. Playwright MCP (local dev, seeded test tenant only)

- **Category:** Browser automation
- **Problem solved:** Console and portal are both Auth0/NextAuth-session-gated, multi-tenant Next.js apps with zero browser-level test coverage today (confirmed absence, inventory §2/§7).
- **Repository evidence:** `apps/console/auth.config.ts` (NextAuth v5, JWT session strategy, role/tenant claims in session), `apps/console/middleware.ts`, `apps/portal` (client-facing, portal session cookie per ROADMAP PR 24 "HMAC-SHA256 session cookies"). No `playwright.config.ts`, no `tests/e2e` directory, no Cypress config found in either app.
- **Proposed workflow:** Authenticated smoke walkthroughs (login → tenant-scoped dashboard → logout; portal engagement view → report view) run locally against `make console-dev` / `make portal-dev`, using a seeded non-production test tenant.
- **Claude Code usage:** Drive browser sessions to verify a UI change actually renders/behaves correctly before declaring a frontend task done — directly satisfies this system's own "test the golden path in a browser" operating rule.
- **Installation location:** Dev dependency in `apps/console` and/or `apps/portal`, MCP server local-only.
- **Required permissions:** None beyond local filesystem/network; login uses seeded test credentials, never real customer or Auth0-production credentials.
- **Recommended access mode:** Local-only.
- **Data accessed:** Locally rendered UI state, seeded test data.
- **Data leaving repository:** Screenshots/DOM snapshots of locally-rendered pages enter model context — no real tenant data if seeded correctly.
- **Security impact:** Low, contingent on test credentials being clearly synthetic and never reused from a real client engagement.
- **Operational impact:** None.
- **Developer experience impact:** High — closes a real, currently-total coverage gap on the two most client-visible surfaces in the product.
- **Commercial impact:** Indirect — fewer regressions in the client-facing portal directly protects paying-client trust.
- **Moat impact:** None directly.
- **Cost category:** Free (Playwright is open source).
- **Setup effort:** Medium — no existing scaffolding, needs a seeded test tenant fixture and login flow script.
- **Maintenance effort:** Medium (browser tests need upkeep as UI changes).
- **Alternatives:** Continued manual click-through testing before merge (current state, not scalable, easy to skip under time pressure).
- **Why this is better than current state:** Converts "did you check it in a browser" from a manual step that's easy to skip into a repeatable, scriptable one.
- **Acceptance criteria:** A scripted login+navigate+assert flow passes locally for both console and portal against seeded test data.
- **Rollback strategy:** Remove dev dependency and MCP entry; no production surface touched.
- **Final verdict: PILOT** — start with one flow (console login → dashboard) to validate the pattern before expanding to portal and remediation workflows.

*(Ranks 4–11 above carry sufficient rationale in the ranked table; they are DEFER/PLAN/REJECT and do not warrant the full structure per the strict decision rules — PILOT/INSTALL NOW items only.)*

---

## Answers to Required Topics (Claude Code / MCP scope)

1. **Most useful MCP servers for this repo:** GitHub (read-only) and a local-only Postgres inspector, in that order — both target the two highest-friction loops evidenced above (CI triage, migration/RLS authoring).
2. **GitHub access level:** Read-only across repo contents, issues, PRs, checks, and Actions. **No write access.** PR creation and pushes should continue to go through the existing user-approved `gh pr create`/`git push` flow, which is already the correct human-in-the-loop boundary per this session's permission model.
3. **Database access:** Yes, but narrowly.
4. **Scope:** **Local only.** Never staging, never production. This repo's tenant data can include regulated-industry evidence (healthcare/legal/govcon per `SYSTEM.md` §1) — there is no configuration of a staging/prod DB connector that is worth the residual risk given the local compose Postgres already covers the schema/RLS-authoring use case.
5. **Vercel logs/deployments access:** Pilot, read-only, scoped to the `console.frostgate.ai` project only — useful for the one Vercel-hosted surface, but should not extend to org-wide Vercel access.
6. **Auth0 configuration/logs access:** Not recommended at this time. No repository evidence of a recurring Auth0-debugging workflow, and Auth0 tenant configuration is a shared production security boundary — changes or even read access there sit outside "repo-driven" tooling scope. Revisit only if a specific recurring Auth0 debugging need is identified.
7. **Redis/Upstash access:** Local-only, read-only, low priority (DEFER) — Redis's role in this repo (rate-limit bucket state) is narrow enough that `docker compose exec redis redis-cli` remains adequate for now.
8. **Best browser automation fit:** Playwright — MIT-licensed, no vendor lock-in, matches the Next.js/App Router stack used by console and portal.

All recommendations above assume the existing `.claude/hooks/pre_bash_guard.sh` deny-list and `.env*`/`secrets/**` read-denial remain in place unchanged — none of the PILOT/INSTALL NOW items require loosening those guards.
