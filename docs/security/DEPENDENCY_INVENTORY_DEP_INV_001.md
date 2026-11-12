# DEP-INV-001 — Dependency Inventory Authority and Vulnerability Triage

- **Audit date:** 2026-11-11
- **Repository baseline:** `a2c183af` (main after #820)
- **Machine-readable inventory:** [`dependency_alert_inventory_2026-11-11.json`](dependency_alert_inventory_2026-11-11.json), produced by `tools/ci/dependency_alert_inventory.py`
- **Method:** read-only. The Dependabot alert and PR exports came from `gh api`. Vercel project settings, build logs and production aliases came from `vercel project inspect`, `vercel inspect` and `vercel ls`. Lockfile and manifest tracing was done in the repository.
- **Changes made by this audit:** none to deployments, repository settings or alert state. No alerts were dismissed.

## 1. Headline

**GitHub's 154 open alerts and real production exposure do not overlap.**

- All 10 critical alerts and all 60 runtime high alerts are on manifests that no pipeline installs:
  - `apps/console/pnpm-lock.yaml` is a stale lockfile;
  - `apps/console/console/package-lock.json` belongs to an obsolete duplicate tree.
- The deployed console lockfile has no critical or high alerts.

**Real production exposure is invisible to GitHub.** Two production frontends run old builds that no current lockfile describes:

| Production host | Vercel project | Live deployment | Next.js | Why it is stale |
|---|---|---|---|---|
| `app.frostgate.ai` | app.frostgate.ai (root `apps/portal`) | 2026-10-06, commit `ec56641` | **14.2.5** | `ignoreCommand` added in #745 uses repo-root paths, but Vercel runs it from the project root. The pathspec matches nothing, so **every portal build since 2026-10-06 has been skipped** (§4.1). |
| `frostgate.ai`, `www.frostgate.ai` | fg-web (root `apps/web`) | 2026-05-29, CLI upload (no git source) | **14.2.35** | The project does not build commits: it posts no commit statuses, and its only production builds are manual `vercel deploy` uploads. |
| `console.frostgate.ai` | console.frostgate.ai (root `apps/console`) | 2026-11-10, commit `751666a` | 15.5.29 | Current. Build log: `npm install`, then `Next.js 15.5.29`. |

**The stale and obsolete lockfiles accidentally describe real exposure.** The obsolete tree pins `next@14.2.5`, the exact version live on `app.frostgate.ai`. The stale pnpm lockfile pins `next@14.2.35`, the exact version live on `frostgate.ai`. So the critical Next.js advisories on those "unused" manifests describe the two live sites; GitHub just attributes them to the wrong file.

## 2. Authoritative lockfile per application

| Application | Authoritative lockfile | How it is installed | Evidence |
|---|---|---|---|
| Console | `apps/console/package-lock.json` | Vercel `installCommand: npm install` (`apps/console/vercel.json`); `apps/console/Dockerfile` (`npm ci`, compose service `console`); Makefile `console-deps` (`npm ci`); CI `frontend-dependency-security.yml` (`npm ci`) | Vercel production log 2026-11-10: `Running "install" command: npm install` → `Detected Next.js version: 15.5.29` (matches the npm lock, not pnpm's 14.2.35). |
| Portal | `apps/portal/package-lock.json` | Vercel `npm install`; Makefile `portal-deps`; CI `npm ci` | Production is not built from it (§4.1). |
| Web | `apps/web/package-lock.json` | Vercel (default detection), CI `npm ci` | Production is a 2026-05-29 CLI upload, not this lockfile. |
| Root tooling | `package-lock.json` | Only `markdownlint-cli` (devDependency) | Never shipped. |
| Agent | `agent/requirements.txt` | `agent/Dockerfile` only | Not in `release-images.yml` or `docker-compose.yml`, so no repo-managed deployment. |
| Python platform | `requirements.txt`, `requirements-shared.txt`, `constraints.txt` | API images (Railway `frostgate-core`) | No open Dependabot alerts. The `pip-audit` gate from #786 applies. |

### 2.1 `apps/console/pnpm-lock.yaml`: STALE, UNUSED and actively harmful

- **Not installed by anything.** No Dockerfile, compose file, workflow, Makefile, script or Vercel config invokes pnpm; a repository-wide search finds no references. Its 2026-06-01 timestamp and `next@14.2.35` / `next-auth@5.0.0-beta.31` pins predate the #819 upgrade.
- **Vercel detects it but does not use it.** The build log says `Detected pnpm-lock.yaml 9 … Using pnpm@10.x`, and the explicit `installCommand` then runs `npm install`.
- **Harmful.** Dependabot security updates triggered by its alerts rewrite the authoritative console manifest. PR #842 ("console-security group", presented as security fixes) changes `apps/console/package.json` from `"next": "^15.5.29"` to `"^16.4.1"`, and the lockfile from Next 15.5.29 to 16.4.1. That is an unrequested major migration of the live console. PRs #832, #833 and #834 also rewrite it.
- **Alerts:** 69 (6 critical, 30 high).

### 2.2 `apps/console/console/`: OBSOLETE DUPLICATE TREE, but still coupled

- **Not built or deployed.**
  - Next.js builds `apps/console/app` only; a nested `console/app` is not a route root.
  - The Vercel root is `apps/console`.
  - Nothing imports from the nested tree, and no pipeline installs its `package.json`, which pins `next 14.2.5` and React 18.
  - Its `Dockerfile` is referenced nowhere.
  - The architecture audits of 2026-07-02 already classified it as "duplicate legacy shell tree".
- **Still coupled to the live console's CI, so it can't simply be ignored:**
  - `apps/console/tsconfig.json` includes `**/*.ts`, so the nested `.ts` sources are type-checked in the real console build. #819 had to edit `console/console/lib/coreApi.ts` for that reason.
  - `node --test` (the console `npm test` and `make ci-console`) discovers `console/console/tests/*.test.js`. These 15 legacy test files run as part of the console suite; verified by the duplicated test name `health route includes ok status response` appearing twice in TAP output.
  - The Docker builder stage copies the tree. The standalone runner image does not include it.
- **Alerts:** 65 (4 critical, 30 high).

## 3. Critical and high alerts grouped by real runtime exposure

Exposure classes come from `tools/ci/dependency_alert_inventory.py`.

| Exposure | Critical | High | Medium | Low | Manifests |
|---|---|---|---|---|---|
| PRODUCTION_RUNTIME (deployed lockfile, runtime scope) | **0** | **0** | 0 | 0 | — |
| NOT_INSTALLED (no pipeline installs it) | 10 | 60 | 53 | 11 | `apps/console/pnpm-lock.yaml`, `apps/console/console/package-lock.json` |
| DEVELOPMENT_ONLY | 0 | 8 | 8 | 2 | root `package-lock.json` (markdownlint-cli chain); `minimatch` in console/portal lockfiles (eslint) |
| RUNTIME_NOT_REPO_DEPLOYED | 0 | 0 | 2 | 0 | `agent/requirements.txt` (`requests 2.32.3`) |

### 3.1 The 10 critical alerts

| Alert | Manifest | Package | Advisory | Fixed in | Applies to a live host? |
|---|---|---|---|---|---|
| 160, 83 | pnpm-lock / console/console | next | GHSA-2464-fhr4-w9xw (sharp memory bug → RCE on glibc Linux, image optimization) | 15.5.28 | Same Next lines run on portal (14.2.5) and web (14.2.35). Both use `next/image`. On Vercel, image optimization is generally served by Vercel's own infrastructure, not the app's `sharp`; **probable mitigation, NOT_VERIFIED.** Docker images use `node:20-alpine` (musl), so the glibc-specific path does not apply there. |
| 147, 73 | pnpm-lock / console/console | next | GHSA-2xp9-vwfh-vxw4 (libheif AVIF → RCE, image optimization) | 15.5.24 | Same as above. **NOT_VERIFIED.** |
| 146, 72 | pnpm-lock / console/console | next | GHSA-p293-qw3h-jr36 / CVE-2026-75604 (RCE on Windows-hosted servers) | 15.5.24 | **Not applicable:** Vercel and Docker are Linux. |
| 7 | console/console | next | GHSA-f82v-jwr5-mffw / CVE-2025-29927 (middleware authorization bypass) | 14.2.25 | Portal production (14.2.5) is in range. The advisory states Vercel-hosted deployments are automatically protected. |
| 128 | pnpm-lock | next-auth | GHSA-8fpg-xm3f-6cx3 / CVE-2026-73421 (config error → existence-based auth check passes) | 5.0.0-beta.32 | Not live: console production runs beta.32 (fixed in #819). The portal does not use next-auth. |
| 125, 124 | pnpm-lock | next-auth, @auth/core | GHSA-7rqj-j65f-68wh / CVE-2026-73420 (email normalization) | beta.32 / 0.41.3 | Not live (as above). |

### 3.2 Production exposure that GitHub does not report

**`app.frostgate.ai` (portal, `ec56641`):** `npm audit --omit=dev` on the exact deployed lockfile reports 1 critical package and 4 high.

| Package | Exposure |
|---|---|
| `next@14.2.5` | 37 advisories: 4 critical, 13 high, 16 moderate, 4 low |
| `postcss` | high (XSS, file read) |
| `nanoid` | high (DoS) |
| `zod` | high (memory exhaustion) |
| `source-map-js` | high (DoS) |

Besides the dependency exposure, five merged portal PRs are not in production:

| PR | Change |
|---|---|
| #804 | L14-PORTAL-HANDOFF-001: post-payment activation |
| #805 | L14 unified brand, navigation and customer journey |
| #815 | L14-CUSTOMER-ZERO-E2E-001 synthetic customer acceptance (portal tests) |
| #817 | L14-PORTAL-TRUTH-001: canonical reports and **engagement isolation** |
| #819 | Next 15.5.29 / React 19 |

The backend (Railway) parts of those PRs are deployed independently. The portal-side tenant/engagement isolation from #817 is not.

**`frostgate.ai` (fg-web, CLI upload):** `next@14.2.35` has 25 advisories (3 critical, 9 high). The full dependency graph of a CLI upload is **NOT_VERIFIED**, because there is no lockfile of record.

## 4. Root causes

### 4.1 The portal `ignoreCommand` always skips builds

`apps/portal/vercel.json` (added in #745, 2026-10-06 01:45Z, 11 minutes after the last real portal production build):

```json
"ignoreCommand": "git diff HEAD^ HEAD --quiet -- apps/portal packages/navigation packages/ui"
```

- **Where Vercel runs it:** in the project's Root Directory (`apps/portal`), so the pathspec resolves to `apps/portal/apps/portal/...`. That always matches nothing, `git diff --quiet` exits 0, and Vercel cancels the build.
- **Reproduced locally:** run from `apps/portal` against the tree of `751666a1`, the pathspec as written exits 0 (skip); the relative pathspec `. ../../packages/navigation ../../packages/ui` exits 1 (build).
- **The console's equivalent is correct.** It uses `. ../../packages/...`.
- **Skipped builds report success.** The `Vercel – app.frostgate.ai` commit status still shows `success`, so nothing alerted.

### 4.2 Dependabot PRs cannot pass required checks unaided

All 22 open Dependabot PRs fail `fg-required`, `Guard` and `CI Required`. This is by design and must not be weakened:

- `verify-offline-simulation-evidence`: the evidence is bound to the git tree hash, and Dependabot cannot regenerate it.
- `soc-review-sync`: changes to `.github/workflows/` and `tools/ci` require a SOC record.
- `pr-fix-log-guard`: requires a `docs/ai/PR_FIX_LOG.md` entry.

Consequence: every dependency fix needs a human-carried PR that applies the change and regenerates evidence. The plan in §6 carries the security fixes and closes the rest.

### 4.3 The #819 gate protects repository state, not deployed state

`make frontend-audit` on `a2c183af` reports PASS for portal, console and web: production critical/high 0/0 for all three. The gate is correct for the repository, but it cannot see that two of three production frontends do not run the repository's lockfile. See residual risk R2.

## 5. Dependabot PR overlap: security updates versus routine upgrades

"Fixes alerts" means the PR changes an alerted manifest to the patched version. Several PRs mention advisories only through upstream release notes.

| PR | Manifest(s) | Kind | Overlap / verdict |
|---|---|---|---|
| #842 console-security | apps/console lock + **package.json** + pnpm-lock | Security group, **but bumps next 15.5.29 → 16.4.1 in the deployed console** | Do not merge. Superseded by deleting pnpm-lock (§6 PR-B). Next 16 is outside this mission (item 11). |
| #834 next 16.4.5 (console), #828 (portal), #826 (web), #827 eslint-config-next 16 (portal) | app locks | Routine major | Hold or close. 15.5.29 has 0 critical/high (gate PASS); there is no security justification for 16. |
| #832 console-routine (16 updates), #833 recharts 3 | console lock + pnpm-lock | Routine | Overlaps #842 and #834 on the same three files. Rebase after PR-B. recharts 3 is a major and needs its own review. |
| #839 brace-expansion, #840 js-yaml, #841 minimatch + eslint-config-next | apps/console/console lock | Security (obsolete tree) | Moot: superseded by retiring the tree (PR-C). Close after it merges. |
| #835 smol-toml, #836 brace-expansion, #837 markdown-it, #838 js-yaml | root package-lock (+package.json) | Security (dev tooling) | Mutually conflicting: #835, #837 and #838 each bump `markdownlint-cli`. Replace with one carried PR (PR-D). |
| #824 portal-routine, #821 TypeScript 7, #822 @types/node 26 | portal / web | Routine | Hold. TypeScript 7 and @types/node 26 are majors, and @types/node 26 does not match the Node 24 runtime. |
| #830 python-routine (27), #831 reportlab ≥ 5.1 | Python manifests | Routine (#830 body cites 2 advisories) | Too broad to carry as a security fix. The agent `requests` fix is carried narrowly in PR-E. |
| #823 upload-artifact 7, #825 setup-go 7, #829 download-artifact 8 | workflows | Routine majors | Hold. These change workflows that `check_github_repo_security.py` guards, so each needs its own review. |

## 6. Recommended remediation sequence (smallest safe PRs)

Each step is a separate PR, none merged automatically. A PR that triggers a deployment says so, and its timing is the founder's decision.

| # | PR | Change | Alerts closed | Deploy impact / verification |
|---|---|---|---|---|
| A (P0) | Fix the portal `ignoreCommand` | `apps/portal/vercel.json`: pathspec → `. ../../packages/navigation ../../packages/ui` (mirrors the console) | 0 GitHub alerts; closes live exposure (37 Next advisories + 4 high) and ships #804/#805/#815/#817/#819 to the portal | **Triggers a portal production deployment on merge.** Moves production from Next 14 / React 18 to 15 / 19. The PR's own preview build will be the first Vercel build of the Next 15 portal: verify the preview (login, handoff, reports) before merging. |
| A2 (P0, operator) | Restore the fg-web deployment path | Reconnect fg-web to Git, or deploy `apps/web` from `main` | Closes 25 live Next advisories on `frostgate.ai` | Production deploy of the marketing site. Founder authorization required. |
| B | Remove `apps/console/pnpm-lock.yaml` | Delete the stale lockfile; close #842 as superseded | 69 (6 crit / 30 high) | Triggers console and api.frostgate.ai rebuilds with the **unchanged** npm lockfile. Verify the preview log still shows `npm install` and Next 15.5.29. |
| C | Retire `apps/console/console/` | Delete the tree. The console tsconfig and `node --test` then stop covering legacy files (15 test files duplicate `apps/console/tests`). Close #839, #840 and #841 | 65 (4 crit / 30 high) | Console rebuild. Console test count drops by the legacy duplicates. Confirm `ci-console`, typecheck and `next build` pass. |
| D | Root markdownlint toolchain | One carried PR bumping `markdownlint-cli` and the transitive chain; close #835 to #838 | 16 (8 high, dev only) | No deploy. |
| E | Agent `requests` | `agent/requirements.txt` `requests==2.32.3` → `2.33.x` | 2 (moderate) | No repo-managed deploy. Run the agent tests. |
| F | eslint `minimatch` | Patch via `overrides` within eslint-config-next 15 | 2 (moderate, dev only) | No deploy. |
| — | Next 16 (#826/#827/#828/#834) | Not proposed | — | Requires a separate compatibility and security justification (mission item 11). |

**Exposure after A + A2:** no known critical or high runtime advisory on any live frontend. The #819 gate shows 0/0 for all three app lockfiles.

**Exposure after B to F:** GitHub's open-alert count falls from 154 to 0 through remediation, not dismissal.

## 7. Residual risks

- **R1. Deployed-state drift is undetected.** A required check cannot see that production does not run `main`.
  - *Recommendation:* add a read-only deployed-version check that compares each production alias's `Detected Next.js version` or build commit with `main`. It belongs with the `repo-security-drift` schedule.
  - *Status:* not implemented here.
- **R2. Skipped Vercel builds report `success`.** `Vercel – app.frostgate.ai: success` hid five weeks of skipped deploys.
- **R3. Vercel-side mitigation of the image-optimization RCEs is not verified.** It is treated as unverified until a vendor statement or a live check confirms it.
- **R4. The api.frostgate.ai Vercel project duplicates the console.** It builds preview deployments of `apps/console` and has no production alias (`api.frostgate.ai` is served by Railway). Decide whether to retire it or confirm that deployment protection covers its previews.
- **R5. The fg-web dependency graph is NOT_VERIFIED.** A CLI upload has no lockfile of record.

## 8. Controls preserved

- **Required checks and rulesets:** the five required checks, the rulesets and `.github/security/*` are unchanged. No gate is weakened, and there are no bot exemptions.
- **Tenant isolation:** no tenant isolation code is touched. The portal-side isolation in #817 is not yet in production; PR-A ships it.
- **Alerts:** none dismissed. `.github/dependabot.yml` is unchanged.

## 9. Remediation log (append-only; the findings above are historical and unchanged)

### DEP-REMEDIATE-002: `apps/console/pnpm-lock.yaml` retired (step B)

- **Verification before deletion** (2026-11-11). The lockfile is installed by nothing:
  - the two Vercel projects rooted at `apps/console` have no dashboard install override, and `vercel.json` sets `installCommand: npm install`;
  - the console production build log shows `Detected pnpm-lock.yaml … Using pnpm@10.x`, then `npm install`, then `Next.js 15.5.29`. The pnpm lockfile pins 14.2.35, so it was never the install source;
  - Docker, the Makefile and CI all use `npm ci`;
  - there is no `packageManager` field, workspace file or `.npmrc`, and the repo contains no pnpm references outside audit records.
- **Change:** the file is deleted. In `MANIFEST_AUTHORITY` its status is now `RETIRED`.
- **Recurrence guard:** `tools/ci/check_lockfile_authority.py`, run from `check_security_regression_gates.py`, enforces exactly one lockfile and package manager per app, an explicit Vercel installer, classification of every lockfile, and that no RETIRED file reappears.
- **Alerts targeted:** 69 (6 critical, 30 high, 27 medium, 6 low). The IDs are in `dep_remediate_002_alert_reconciliation.json`.
  - 68 of them have no corresponding vulnerable version in the deployed npm lockfile.
  - #169 (minimatch GHSA-g3hv-75wg-m249, moderate) overlaps a real **development-only** exposure (`minimatch` 10.2.6 via `@typescript-eslint`). That exposure is tracked separately as alert #88 and remains open; it belongs to DEP-REMEDIATE-006.
- **Alert accounting:** the 154-alert baseline above is historical. The post-merge count is to be recorded from GitHub's rescan, by alert ID. No alert was dismissed.

**Outcome (recorded at DEP-REMEDIATE-003 start, 2026-11-11):** #847 merged as `e5bcd96ed`. GitHub then reported 85 open alerts; the 69 targeted IDs show as fixed, none dismissed.

### DEP-REMEDIATE-003: `apps/console/console/` retired (step C)

- **Verification before deletion** (2026-11-11). The tree had no consumer:
  - no Vercel project, Dockerfile, compose service, Makefile target, CI workflow or import references it;
  - it is not a Next.js app root;
  - its only effects were on the active Console's type-check (91 files) and test discovery (712 tests that read the nested copies, not deployed code).

  Full proof: `DEP_REMEDIATE_003_NESTED_CONSOLE_RETIREMENT.md` §2.
- **Coverage:** all 712 legacy tests were executed against the active source and mapped: 706 ALREADY_COVERED, 6 OBSOLETE_WITH_EVIDENCE, 0 BLOCKED.
  - The 6 obsolete tests include three fail-closed rate-limit outage tests that `225d21c25` deliberately reversed. They are recorded as a residual risk, not reinstated.
  - 11 new behavioural tests execute the real `lib/rateLimitStore.ts`.
  - The ledger is `dep_remediate_003_retirement_ledger.json`.
- **Change:**
  - all 118 files are deleted, including the last copy of the `TenantSwitcher` removed in #706;
  - `MANIFEST_AUTHORITY` now marks the nested lockfile `RETIRED`;
  - the lockfile-authority guard now rejects nested application roots inside policy apps and anything under `retired_roots`.
- **Alerts targeted:** 65 (4 critical, 30 high, 26 medium, 5 low). IDs are in `dep_remediate_003_alert_reconciliation.json`.
  - 64 have no vulnerable counterpart in the deployed npm lockfile.
  - #87 (minimatch, development-only) overlaps #88, which remains open under DEP-REMEDIATE-006.
- **Alert accounting:** nothing was dismissed. The projected open count after the rescan is 20, to be confirmed by ID.

**Outcome (recorded at DEP-REMEDIATE-004 start, 2026-11-11):** #848 merged as `e1dba3a5b`. All 65 targeted IDs are `fixed` with `dismissed_at` null. GitHub now reports 20 open alerts: root 16, agent 2, Console 1 (#88), Portal 1 (#170).

### DEP-REMEDIATE-004: root npm tooling remediated (step D)

- **Change:**
  - `markdownlint-cli` ^0.48.0 → ^0.50.0 (parent update);
  - scoped overrides `markdownlint-cli` → `minimatch ^11.0.8` and `micromark-extension-math` → `katex ^0.18.11`, because the latest releases of both parents still pin vulnerable ranges.
- **Scope:** the Console, Portal and Web lockfiles are byte-identical. Nothing installs the root manifest in CI or deployment.
- **Alerts targeted:** 16 open root alerts. GitHub had auto-dismissed 5 further high root alerts (#172, #177, #178, #183, #184) at 2026-11-11T01:15Z without any FrostGate action. Their advisories are real and their base versions were vulnerable, so they are tracked and resolved too.
- **Evidence:**
  - `dep_remediation_final_inventory.json` (all open alerts, each with an owner PR);
  - `dep_remediate_004_reconciliation.json`;
  - `DEP_REMEDIATE_004_ROOT_TOOLING.md`, which also holds the DEP-REMEDIATE-005 (agent `requests`) and DEP-REMEDIATE-006 (Console/Portal minimatch) plans.
- **Alert accounting:** nothing was dismissed. The projected open count after the rescan is 4 (#1, #2, #88, #170), to be confirmed by ID.

**Outcome (recorded at DEP-REMEDIATE-005 start, 2026-11-11):** #850 merged as `10924ed44`. All 16 targeted IDs and the 5 previously auto-dismissed IDs (#172, #177, #178, #183, #184) are `fixed` with `dismissed_at` null. GitHub now reports 4 open alerts: agent 2 (#1, #2), Console 1 (#88), Portal 1 (#170).

### DEP-REMEDIATE-005: agent `requests` remediated (step E)

- **Change:** `agent/requirements.txt` `requests==2.32.3` → `requests==2.34.2` (latest; >= 2.33.0 fixes both advisories). Supersedes Dependabot #851 (2.33.0).
- **Alerts targeted:** #1 (GHSA-9hjg-9r4m-mvj7) and #2 (GHSA-gc5v-m9x4-r6x2).
- **Evidence:** `DEP_REMEDIATE_005_AGENT_REQUESTS.md`; `dep_remediation_final_inventory.json` (#1 and #2 IMPLEMENTED); `tests/agent/test_requests_advisory_regression.py`.
- **Alert accounting:** nothing was dismissed. The projected open count after the rescan is 2 (#88, #170), to be confirmed by ID.

**Outcome (recorded at DEP-REMEDIATE-006 start, 2026-11-12):** #852 merged as `c236a7a33`; #851 closed unmerged. The default-branch manifest and dependency graph show `requests` 2.34.2, but GitHub still reports #1 and #2 `open` (last updated 2026-11-11T01:15Z). This is tracked as an external reconciliation item; nothing was dismissed.

### DEP-REMEDIATE-006: Console and Portal minimatch remediated (step F)

- **Change:** scoped override `"@typescript-eslint/typescript-estree": {"minimatch": "^11.0.8"}` in both apps (no patched 10.x and no newer parent exist).
- **Alerts targeted:** #88 (Console) and #170 (Portal), GHSA-g3hv-75wg-m249.
- **Evidence:** `dep_remediation_final_inventory.json` (#88 and #170 IMPLEMENTED); `npm audit` 0 in both apps.
- **Alert accounting:** nothing was dismissed. After the rescan, every alert this inventory tracks is remediated in source; #1 and #2 await GitHub reconciliation.
