# Tooling & Connector Audit — Executive Summary

**FrostGate Core repository audit.** Analysis only — nothing was installed, configured, connected, modified, or committed. Full detail in the companion files in this directory. Trust, but Verify.

---

## What should be connected immediately?

- **Dependabot** (security-updates only) — closes the "detect but don't fix" gap left by the existing `pip-audit` gate, at near-zero cost.
- **`npm audit`** in CI — Python dependency scanning exists (`pip-audit`); Node (console, portal, root) currently has none.
- **Coverage reporting** — `pytest-cov` is already an installed dependency and simply unused; turning it on costs one CI flag.
- **GitHub MCP server, read-only, repo-scoped** — the fastest win for Claude Code sessions working this repo's 2,469-line, 6-workflow CI surface.

## What should be piloted?

- **Postgres MCP, local-only, read-only** — for the migration/RLS-authoring loop (168 migrations and counting), with a hard-pinned local-only connection guarantee.
- **Playwright, starting with one flow (console login)** — this repo's single largest evidenced coverage gap: two auth-gated, multi-tenant, client-facing Next.js apps (console, portal) with zero browser-level testing today.
- **Trivy container scanning**, non-blocking first — no image vulnerability scanning exists anywhere in the Docker build/release path today.
- **Vercel MCP, project-scoped** — pending the user completing OAuth; console is the one Vercel-hosted surface in an otherwise Railway-hosted backend.
- **CodeQL** — pending confirmation of GitHub Advanced Security licensing for this private repo.

## What should NOT be added?

- **Gitleaks / TruffleHog** — would duplicate a custom secret scanner (`tools/ci/check_no_plaintext_secrets.py` + `check_secret_history.py`) already tuned precisely to this repo's env-file conventions, and would likely be noisier, not more thorough.
- **SonarCloud / Snyk** — redundant with `ruff`/`mypy`/`pip-audit`/CodeQL, and introduces a third-party data-egress decision for an enterprise governance/evidence platform serving regulated-industry clients (healthcare, govcon) that should be made explicitly by the founder, not defaulted into via a CI add-on.
- **Renovate** — overlaps Dependabot and conflicts with this repo's strict `==` version-pinning discipline.
- **Any AI-agent access to production Postgres or Redis** — this platform holds regulated-industry, multi-tenant customer evidence data; no read or write access from an AI tool is recommended at any scope short of local/synthetic data. This is outside this audit's authority to approve regardless of access mode.
- **Third-party CI-speed / build-cache products** — the team already self-diagnosed and *fixed* its largest CI duplication (`docs/ci/CI_OPTIMIZATION_PLAN.md` DUP-01/02/03, confirmed merged in `tools/testing/harness/lane_runner.py`) before this audit began. No external product would have found or fixed that faster.

## What will save the most development time?

The **GitHub MCP server** and **Postgres MCP** together target this repo's two highest-friction recurring loops: triaging a 6-workflow, ~110-minute CI critical path, and authoring/validating migrations against a 168-migration, RLS-enforced schema. Both are read-only, low-effort, and reuse patterns (scoped tokens, local-only DB access) already proven safe by the existing `repo-tools` MCP server design.

## What will improve production confidence?

Closing the **observability verification gap**: OpenTelemetry and Sentry are both installed and wired in code, but this audit could not confirm either actually reaches a live backend in production. The single highest-leverage action here is not a new connector — it's verifying `SENTRY_DSN` and an OTLP collector endpoint are actually set and receiving data in Railway prod, mirroring the fail-fast pattern the console already uses (`instrumentation.ts` → `validateProductionConfig()`). A Sentry connector only becomes safe to wire *after* that verification, given the PII-exposure risk flagged for a healthcare-vertical client base.

## What will strengthen enterprise readiness?

**Container image scanning (Trivy)** and **CodeQL SAST**, once GHAS licensing is confirmed — this platform's own governance doctrine (`BLUEPRINT_STAGED.md`) requires enterprise-grade evidence and control coverage of *itself*, and today the built container images (backend, admin gateway, console, plus 4 base images) ship with no vulnerability scan, and 230+ API modules handling multi-tenant auth and RLS have no dedicated SAST pass beyond linting/typing.

## What will create the strongest commercial moat?

**Microsoft Defender/Sentinel ingestion via the Graph Security API** (native connector roadmap, rank 2). It is the lowest-incremental-cost extension of the connector framework already built (reuses the existing MS Graph device-code client entirely) and it converts FrostGate from a periodic-assessment tool into a continuous-signal aggregator — precisely the "continuous governance" differentiation `FOUNDER_DIRECTIVE.md` stakes out against Vanta/Drata/OneTrust, none of which ingest live security-detection signal. The **Okta connector** (rank 1) is a close second: it removes the single biggest structural limitation in the current connector suite (100% of authenticated connectors are Microsoft-Graph-only today).

## Top five actions

1. Enable Dependabot (security updates only) — `.github/dependabot.yml`.
2. Add `npm audit` to CI for console/portal/root.
3. Turn on coverage reporting (`pytest --cov`, self-hosted artifact).
4. Install GitHub MCP server, read-only, scoped to this repo.
5. Verify OpenTelemetry/Sentry actually reach a live backend in Railway prod, before wiring any observability connector.

---

*Full evidence, per-recommendation structure, risk register, and sequencing are in `REPOSITORY_TOOLING_INVENTORY.md`, `CLAUDE_CODE_MCP_RECOMMENDATIONS.md`, `GITHUB_CI_ADDON_RECOMMENDATIONS.md`, `PRODUCTION_OPERATIONS_CONNECTORS.md`, `FROSTGATE_NATIVE_CONNECTOR_ROADMAP.md`, `TOOLING_RISK_REGISTER.md`, `TOOLING_IMPLEMENTATION_ROADMAP.md`, and `tooling_recommendations.json` in this directory.*
