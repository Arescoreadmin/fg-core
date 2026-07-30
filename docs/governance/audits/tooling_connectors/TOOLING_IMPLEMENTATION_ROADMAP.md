# Tooling Implementation Roadmap — FrostGate Core

Only INSTALL NOW and PILOT items get a concrete implementation entry. PLAN/DEFER items are noted at the end of their horizon with the trigger condition that should promote them. REJECT items are not included (see the companion recommendation files for rejection rationale).

---

## Immediate: 0–7 days

### 1. Enable Dependabot (security updates only)
- **Outcome:** Python and Node dependencies with known CVEs automatically get a PR, closing the "detect but don't fix" gap left by `pip-audit`.
- **Files affected:** New file `.github/dependabot.yml`.
- **Prerequisites:** None.
- **Implementation steps:** Add `.github/dependabot.yml` with `package-ecosystem: pip` (root) and `package-ecosystem: npm` (root, `apps/console`, `apps/portal`) entries, `open-pull-requests-limit` set conservatively, `versioning-strategy: security-updates-only` (or equivalent — do not enable routine version-bump PRs, which would conflict with this repo's strict `==` pinning discipline).
- **Validation steps:** Confirm the config validates (GitHub will flag syntax errors on push); wait for the first scheduled Dependabot run and confirm any resulting PR is scoped to a single dependency with a linked advisory.
- **Rollback plan:** Delete `.github/dependabot.yml`; no other state changes.
- **Estimated effort:** 30 minutes.
- **Expected ROI:** High — near-zero cost, closes a real evidenced gap (no dependency-update automation existed at all).

### 2. Add `npm audit` to CI
- **Outcome:** Node dependency vulnerabilities (console, portal, root) are caught in CI the way `pip-audit` already catches Python ones.
- **Files affected:** `.github/workflows/docker-ci.yml` or `ci.yml`'s `console` job (add a step); possibly `Makefile` (`console-lint`/`console-test` target) to keep the check runnable locally, consistent with this repo's pattern of exposing every CI check as a Make target.
- **Prerequisites:** None.
- **Implementation steps:** Add `npm audit --omit=dev --audit-level=high` (or equivalent) as a non-blocking step first; review output for a cycle; promote to blocking once false-positive rate is confirmed low.
- **Validation steps:** Run locally against `apps/console` and `apps/portal` package-lock.json files before adding to CI; confirm the step doesn't fail on the current lockfiles in a way that would immediately red the build.
- **Rollback plan:** Remove the CI step / Make target.
- **Estimated effort:** 1–2 hours.
- **Expected ROI:** Medium-High — closes a real, evidenced, zero-cost gap.

### 3. Turn on coverage reporting (self-hosted artifact)
- **Outcome:** Test coverage becomes visible and trendable; `pytest-cov` is already a dependency but unused.
- **Files affected:** `Makefile` (`test-unit` or `unit` lane target), `.github/workflows/ci.yml` (`unit` job — add `--cov --cov-report=xml` flags and an `actions/upload-artifact` step for the coverage report).
- **Prerequisites:** None.
- **Implementation steps:** Add `--cov=api --cov=engine --cov-report=xml --cov-report=term` to the relevant pytest invocation; upload `coverage.xml` as a build artifact (mirroring the existing artifact-upload pattern already used throughout `ci.yml`).
- **Validation steps:** Confirm the coverage report generates without materially slowing the `unit` job; spot-check the XML is well-formed.
- **Rollback plan:** Remove the flags/upload step.
- **Estimated effort:** 1 hour.
- **Expected ROI:** Medium — cheap, and directly informs where the browser-E2E and mutation-testing gaps (noted elsewhere) are most worth closing first.

### 4. Install GitHub MCP server (read-only, repo-scoped)
- **Outcome:** Faster PR/CI/issue triage inside Claude Code sessions without manual `gh` command round-trips.
- **Files affected:** `.mcp.json` (new server entry alongside `repo-tools`).
- **Prerequisites:** Repo-owner-issued fine-grained PAT or GitHub App installation scoped to `Arescoreadmin/fg-core` only (see `TOOLING_RISK_REGISTER.md` #1).
- **Implementation steps:** Generate a scoped token/App installation; add the MCP server entry; verify scope is limited to this one repository before first use.
- **Validation steps:** Confirm the server can read PR #588's status/checks but cannot write (attempt a benign read-only query, do not test write capability since none should be granted).
- **Rollback plan:** Remove the `.mcp.json` entry and revoke the token.
- **Estimated effort:** 1 hour (mostly token/scope setup).
- **Expected ROI:** High for CI-heavy PR workflows like the one currently in progress on this branch.

**Note (context, not an action item):** `docs/ci/CI_OPTIMIZATION_PLAN.md`'s Priority 1 fix (removing duplicated `fg-contract`/`fg-security`/`gap-audit` invocations from `lane_runner.py`'s `fg-fast` lane) is **already merged** in the current codebase — confirmed by reading `tools/testing/harness/lane_runner.py` directly. No action needed here; it is called out only so this roadmap doesn't imply outstanding work that has already shipped.

---

## Near term: 8–30 days

### 5. Trivy container image scan (non-blocking pilot)
- **Outcome:** Base-image and OS-package CVEs in the 5 built/pulled images (`frostgate-core`, `frostgate-admin-gateway`, `frostgate-console`, plus base images `redis:7-alpine`, `pgvector/pgvector:pg16`, `nginx:alpine`, `quay.io/keycloak/keycloak:24.0`) become visible before release.
- **Files affected:** `.github/workflows/release-images.yml` (add a scan step after image build, before push); possibly `.github/workflows/docker-ci.yml`.
- **Prerequisites:** None (OSS scanner, no external account required).
- **Implementation steps:** Add a Trivy scan step in non-blocking mode; capture output as a build artifact; build an ignore-list (`.trivyignore`) for accepted/unfixable base-image findings over the pilot period.
- **Validation steps:** Run once, review the finding set, confirm it's actionable (not overwhelming noise) before considering a blocking gate.
- **Rollback plan:** Remove the workflow step.
- **Estimated effort:** 1 day (including reviewing first-run output and building the initial ignore-list).
- **Expected ROI:** High — closes a real, currently-unfilled gap in the image-release path.

### 6. Postgres MCP (local-only, read-only) — pilot
- **Outcome:** Faster migration/RLS-policy authoring loop for migration 169+.
- **Files affected:** `.mcp.json` (new server entry); a new read-only Postgres role created against the local compose instance (not a repo file change — a local setup step).
- **Prerequisites:** Repo-owner review of the exact connection-string configuration (must hard-pin to `localhost`/compose network per `TOOLING_RISK_REGISTER.md` #2).
- **Implementation steps:** Create a read-only role on the local compose Postgres; configure the MCP server with that role's credentials and a connection string that cannot resolve to the Railway prod host; add a startup assertion the host is local before the server will start.
- **Validation steps:** Confirm the server can list RLS policies on `fa_field_observations` (or another RLS-protected table) via `pg_policies`; confirm it cannot connect if pointed at a non-local host (deliberately test the assertion).
- **Rollback plan:** Remove the `.mcp.json` entry and drop the read-only role.
- **Estimated effort:** 2–4 hours.
- **Expected ROI:** Medium-High for migration-heavy work specifically (168 migrations already, clearly an ongoing pattern).

### 7. Playwright — first flow (console login → dashboard) — pilot
- **Outcome:** First browser-level coverage for the console's Auth0/NextAuth login flow, closing the largest coverage gap identified in this audit.
- **Files affected:** New `apps/console/tests/e2e/` (or similar) directory, `apps/console/package.json` (add Playwright dev dependency), possibly a new `Makefile` target (`console-e2e`) and a new CI job.
- **Prerequisites:** A seeded, clearly-synthetic test tenant and test user credentials (do not reuse real client data).
- **Implementation steps:** Add Playwright as a dev dependency; write one flow (login → land on tenant-scoped dashboard → confirm session claims render correctly → logout); wire a `make console-e2e` target for local runs before deciding whether to add a CI job.
- **Validation steps:** Run locally against `make console-dev`; confirm the flow fails if login is broken (mutate the test briefly to confirm it's not a false-positive-only check).
- **Rollback plan:** Remove the test directory and dev dependency.
- **Estimated effort:** 1–2 days for the first flow (includes fixture/seed-tenant setup, which is the bulk of the work).
- **Expected ROI:** High — directly targets the single largest evidenced coverage gap (zero browser-level testing on two client-facing, auth-gated apps).

### 8. Vercel MCP (read-only, project-scoped) — pilot, contingent on OAuth
- **Outcome:** Faster console-deployment triage.
- **Files affected:** MCP/plugin configuration (session/environment level, not a repo file).
- **Prerequisites:** User completes Vercel OAuth (currently blocked per this session's connector status); confirm project-level (not org-level) scoping is available.
- **Implementation steps:** Complete OAuth; verify scope is limited to `console.frostgate.ai`; if only org-wide scoping is offered, escalate to owner before proceeding (per `TOOLING_RISK_REGISTER.md` #4).
- **Validation steps:** Confirm the connector can read deployment status for the console project but cannot see unrelated Vercel projects under the same team.
- **Rollback plan:** Revoke the OAuth grant.
- **Estimated effort:** 30 minutes once the user is available to complete OAuth.
- **Expected ROI:** Medium.

### Near-term watch items (PLAN, not yet actioned)
- **CodeQL:** confirm GitHub Advanced Security licensing status for this private repo before scheduling implementation. Promote to an implementation entry once licensing is confirmed.
- **OpenAPI-aware contract-replay testing:** scope after the above items land; not urgent given the existing contract-authority spec-drift gate already catches the most common failure mode.
- **Flaky-test detection (rerun-rate tracking, not auto-retry):** instrument once coverage reporting (#3) has been live long enough to also have a baseline test-run-time dataset to correlate against.

---

## Medium term: 31–90 days

### 9. Okta native connector (product feature, rank 1 in FROSTGATE_NATIVE_CONNECTOR_ROADMAP.md)
- **Outcome:** Identity-governance parity for non-Entra-ID clients, widening addressable market beyond Microsoft-365-only shops.
- **Files affected:** New `services/connectors/okta/{__init__.py,runner.py}`, new `api/connectors_okta.py` (or extension of an existing connectors router), new migration under `migrations/postgres/`, new entry in `contracts/connectors/policies/`, `docs/CONNECTOR_CROSSREF.md` update, new tests under `tests/`.
- **Prerequisites:** Okta API credential model decided (client-credentials OAuth2 vs. SSWS token); reuse of `services/connectors/registry.py`, `policy.py`, `idempotency.py` confirmed compatible.
- **Implementation steps:** Follow the existing `entra_governance` connector as the structural template; implement MFA/role/OAuth-grant/guest-exposure parity findings; register in the connector registry; add console scan panel.
- **Validation steps:** Full test suite for the new connector mirroring the pattern in `tests/test_field_assessment_msgraph_bridge.py`-style bridge tests; RLS/tenant-scoping check consistent with `check_connectors_rls.py`.
- **Rollback plan:** Feature-flag the connector off in the registry; the connector is additive and doesn't touch existing MS Graph connectors.
- **Estimated effort:** 2–3 weeks (one engineer), based on the complexity of comparable existing connectors.
- **Expected ROI:** High — see FROSTGATE_NATIVE_CONNECTOR_ROADMAP.md rank 1 rationale.

### 10. Microsoft Defender/Sentinel via Graph Security API (product feature, rank 2)
- **Outcome:** Continuous-monitoring-tier signal ingestion, not just point-in-time posture.
- **Files affected:** Extends `services/connectors/msgraph/`; new bridge/finding logic; migration; contract policy entry.
- **Prerequisites:** New Graph scopes (`SecurityEvents.Read.All`/`SecurityAlert.Read.All`) added to the existing app-registration documentation (`docs/operators/azure_ad_app_setup.md`).
- **Implementation steps:** Extend the existing MS Graph client rather than building a new one; add finding types for security alerts/incidents.
- **Validation steps:** Same pattern as #9.
- **Rollback plan:** Additive; disable via registry if issues found.
- **Estimated effort:** 1–2 weeks (lower than Okta given the client is already built).
- **Expected ROI:** High — see roadmap rank 2 rationale (highest revenue-tier leverage for lowest incremental cost).

### Medium-term watch items (PLAN)
- **AWS connector credential infrastructure (rank 3):** begin design/security-review work in this window even if implementation lands in the strategic horizon, given the dedicated-security-review requirement flagged in `TOOLING_RISK_REGISTER.md` #13.
- **Slack/Teams alerting (rank 6):** small enough to slot in opportunistically within this window if engineering capacity allows, ahead of its formal rank position, per the sequencing note in FROSTGATE_NATIVE_CONNECTOR_ROADMAP.md §3.

---

## Strategic: 90+ days

### 11. AWS Organizations/Config/Security Hub/CloudTrail bundle (product feature, rank 3)
- **Outcome:** First-party cloud-posture evidence for govcon/fintech clients.
- **Files affected:** New credential-storage subsystem (extends or parallels `services/connectors/oauth_store.py`), new `services/connectors/aws_*` modules, new migrations, new contract policies.
- **Prerequisites:** Completed design/security review from the medium-term watch item above; explicit sign-off on the cross-account role-assumption credential model.
- **Implementation steps:** Split into (a) credential infrastructure PR, reviewed in isolation, then (b) data-collection logic PR(s) per AWS service (Config, Security Hub, CloudTrail, Organizations).
- **Validation steps:** Dedicated security review (not just standard PR review) per `TOOLING_RISK_REGISTER.md` #13; tenant-isolation tests for the new credential store mirroring existing connector-credential tests (`tests/test_r4_9b_connector_credentials.py`).
- **Rollback plan:** Additive; feature-flag off via registry.
- **Estimated effort:** 4–6 weeks across the split PRs.
- **Expected ROI:** High, contingent on govcon/fintech pipeline demand materializing as expected.

### 12. Jira/ServiceNow bidirectional remediation sync (product feature, rank 5)
- **Outcome:** Retention/stickiness improvement by embedding FrostGate remediation workflow into clients' existing ticketing systems.
- **Files affected:** New sync-state model/migration, new webhook receiver endpoints, extends `services/remediation/`, `api/remediation_authority.py`.
- **Prerequisites:** This is FrostGate's first write-capable, bidirectional connector — recommend an explicit design review before implementation begins (per `TOOLING_RISK_REGISTER.md` #14), not just standard PR review at the end.
- **Implementation steps:** Design conflict-resolution rules defensively (prefer human-review flags over auto-resolution); build one direction (FrostGate → ticketing system) before the harder reverse direction (ticketing system → FrostGate finding status).
- **Validation steps:** Sync-state consistency tests; explicit test for the "conflicting update on both sides" case; verify a finding can never be auto-marked-resolved without a corresponding verified evidence link.
- **Rollback plan:** Feature-flag per tenant; sync can be disabled without affecting the underlying remediation data model.
- **Estimated effort:** 4–5 weeks.
- **Expected ROI:** Medium-High, primarily as a renewal/retention lever rather than a new-evidence lever.

### Strategic watch items (founder decision required, not scheduled)
- **OneTrust/Archer/Drata/Vanta evidence-import connector:** do not schedule until the founder makes an explicit strategic call (see `TOOLING_RISK_REGISTER.md` #15) — this is a positioning decision, not an engineering-readiness one.
- **Google Workspace, CrowdStrike, Snowflake, GitHub/GitLab connectors (ranks 4, 8, 9, 11):** re-evaluate against actual client-pipeline demand at the 90-day mark rather than committing engineering time speculatively.
