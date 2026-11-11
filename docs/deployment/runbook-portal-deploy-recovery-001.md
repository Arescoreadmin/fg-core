# P0-PORTAL-DEPLOY-RECOVERY-001 — Portal Deployment Recovery Runbook and Release Decision

- **Status:**
  - ENGINEERING PASS · PREVIEW PASS (scoped, see §5) · **PRODUCTION NOT_VERIFIED**
  - Production is still serving `ec566412` (Next 14.2.5).
- **Date:** 2026-11-11
- **Branch:** `deploy/p0-portal-deploy-recovery-001`
- **Evidence:**
  - [`evidence/portal_provenance_2026-11-11_pre_recovery.json`](evidence/portal_provenance_2026-11-11_pre_recovery.json): live production provenance, DRIFT.
  - [`evidence/portal_preview_acceptance_2026-11-11.json`](evidence/portal_preview_acceptance_2026-11-11.json): preview build and security probes.

## 1. Root cause (verified live, not only from the DEP-INV-001 audit)

`apps/portal/vercel.json` (from #745, 2026-10-06 01:45Z) had this ignore command:

```text
git diff HEAD^ HEAD --quiet -- apps/portal packages/navigation packages/ui
```

Vercel runs the Ignored Build Step **from the project Root Directory** (`apps/portal`). From there the pathspec resolves to `apps/portal/apps/portal`, which matches nothing, so `git diff --quiet` exits 0 and Vercel sets the deployment to `CANCELED`.

Live evidence, read-only via the Vercel API:

- **Recent history:** the last 100 portal deployments are all `CANCELED`, 19 of them production.
- **The #817 production build:** `dpl_EvtGEb8SQR7y…`, commit `c69f9d7`. Its log reads: `Running "git diff HEAD^ HEAD --quiet -- apps/portal …"` → `The deployment was canceled because the Ignored Build Step command returned exit code 0.`
- **The live deployment:** `app.frostgate.ai` → `dpl_4LeXwoa4LjvnohVZ4y4PpzqD8QiW`, created 2026-10-06 01:30Z, git `ec566412` on `main`. Its build log shows `Detected Next.js version: 14.2.5`.
- **Six relevant `main` commits are not deployed:** #745, #804, #805, #815, #817 and #819.
- **Why nothing alerted:** a CANCELED build still posts a `success` commit status to GitHub.

**Second defect.** Even with correct paths, `HEAD^` compares only against the parent commit. A portal change whose build is cancelled or fails is never retried by later, unrelated commits, so production silently falls further behind.

## 2. Fix

`tools/vercel/ignore_build.sh`, called from `apps/portal/vercel.json`:

```text
bash ../../tools/vercel/ignore_build.sh apps/portal packages/navigation packages/ui tools/vercel/ignore_build.sh || exit 1
```

| Rule | Closes |
|---|---|
| Paths are resolved from `git rev-parse --show-toplevel`, never the current directory | The #745 root cause |
| The diff base is `VERCEL_GIT_PREVIOUS_SHA` (Vercel: "the last successful deployment for the project and branch") | Skipped or failed builds hiding changes |
| Production with no previous SHA → build. Preview first deploy → `HEAD^` fallback; no parent → build | Missing history |
| Base SHA absent from the clone → build | Shallow clone or force-push |
| A watch path missing at HEAD, or absolute/`..`/`-` paths → build | Dead pathspecs (the #745 class) |
| `git diff` exit > 1 → build | Malformed diff or git errors |
| Same SHA as the last successful deployment → build | Explicit redeploys |
| The script exits only 0 or 1; `\|\| exit 1` maps any other code (127 for a missing script) to build | Vercel's 0/1 contract |

**Watch paths.** These are everything the portal build consumes from outside `apps/portal`:

- `packages/navigation` and `packages/ui`, consumed via `file:` dependencies, `tsconfig` paths and the Tailwind content glob;
- the skip script itself.

Portal authentication and authorization code lives under `apps/portal` (`middleware.ts`, `lib/session.ts`, `app/api/auth/*`, the BFF). Backend authorization (`api/`) deploys separately on Railway, so it is deliberately not a portal trigger. A test derives the consumed paths from `package.json` and `tsconfig.json` and fails if any is unwatched.

**Scope.** Only the portal project changes. The console and api.frostgate.ai projects keep their own ignore commands, and fg-web is out of scope. Verified on the preview commit: the console and api.frostgate.ai builds were `CANCELED` (correct skip), and fg-web had no deployment.

## 3. Before and after skip-rule behaviour

| Scenario | Old command (from `apps/portal`) | New script |
|---|---|---|
| Portal source change | SKIP ✗ | BUILD |
| `packages/ui` or `packages/navigation` change | SKIP ✗ | BUILD |
| Portal middleware or auth change | SKIP ✗ | BUILD |
| Portal lockfile change | SKIP ✗ | BUILD |
| Docs-only, console-only or backend-only change | SKIP | SKIP |
| Portal change whose build was cancelled, followed by a docs commit | SKIP ✗ | BUILD (diff against last success) |
| Base SHA missing, shallow clone or root commit | error → undefined | BUILD |
| `git diff` fails | undefined | BUILD |
| Script missing or broken | n/a | BUILD (`\|\| exit 1`) |

Covered by `tests/tools/test_vercel_ignore_build.py` (27 tests, temporary git repositories, run from `apps/portal` exactly as Vercel does).

## 4. Deployment provenance (`make portal-deploy-provenance`)

`tools/ci/check_deployment_provenance.py` resolves **the deployment the production alias actually serves**. It never uses CI status, commit status or "latest deployment". Its controls:

| Control | DRIFT when | NOT_VERIFIED when |
|---|---|---|
| `deployment_resolved` | — | The alias does not resolve, or a read fails |
| `project_identity` | The serving project ≠ `prj_f98i83…` | — |
| `production_alias` | `app.frostgate.ai` is not assigned to it | — |
| `target_production` | The alias serves a preview | — |
| `build_outcome` | Not `READY`, or the build was skipped | — |
| `git_source` | The repository or branch ≠ `Arescoreadmin/fg-core@main` | CLI upload or no SHA |
| `commit_known` | — | The SHA is not in local history |
| `security_baseline` | Deployed SHA does not contain `751666a1` (#819, which includes #804–#817) | Shallow or missing history (never a false DRIFT) |
| `freshness` | The latest `main` commit touching the watch paths is not deployed | Ancestry is unknowable |
| `build_log_commit` | The build log's cloned commit ≠ the metadata SHA | — |
| `framework_version` | Build-log Next.js ≠ lockfile at that SHA | The log or lockfile is unavailable |

- **Exit codes:** 0 PASS · 1 DRIFT · 2 NOT_VERIFIED.
- **Safety:** read-only. It uses `vercel api` GET only, and only allow-listed fields enter the evidence; environment values never do.
- **Limit of what it proves:** a git SHA identifies the source tree Vercel cloned. It does **not** attest the installed dependency graph. The framework version is cross-checked between the build log and the lockfile, and is recorded as exactly that.
- **Current result: DRIFT.**
  - `security_baseline` DRIFT (`ec566412` predates `751666a1`);
  - `freshness` DRIFT (6 relevant commits not deployed);
  - every identity and outcome control PASS;
  - `framework_version` PASS (14.2.5 in both the build log and the lockfile).
- **Tests:** `tests/tools/test_deployment_provenance.py`, 27 tests.

## 5. Preview security acceptance

- **Preview:** `dpl_Hkq2g4XsKoJtToUanasDPG7r9rFQ`, target `preview`, READY, commit `12cddef6`.
- **Build:** `npm install` → `Detected Next.js version: 15.5.29` → compiled successfully.
- **Environment:** every portal environment variable is **production-scoped**, so the preview runs with no Core API, Auth0, session or Redis configuration.

| Check | Result |
|---|---|
| Next 15.5.29 / React 19 production build (Vercel and local) and `tsc --noEmit` | PASS |
| Portal test suite (`npm test`) | PASS: 85/85 |
| Lint | PASS |
| Unauthenticated `/`, `/dashboard`, `/reports`, `/engagement/<other tenant>` → 307 `/login?next=…` | PASS |
| Forged signed-session cookie → 307 login | PASS |
| BFF `/api/core/*` without a session → 307 login | PASS |
| BFF non-allowlisted route with a forged session and a spoofed `X-Tenant-Id` → 403 portal policy | PASS |
| BFF allowlisted route with a forged, well-formed `pnu1.` token → 500 "CORE_TENANT_ID is not configured" (fail-closed, no upstream call) | PASS |
| `POST /api/auth/login` (password/demo) → 403 `PORTAL_DEMO_AUTH_DISABLED` | PASS |
| OIDC start without configuration → 503; forged OIDC callback → `/login?error=oidc_not_configured` | PASS |
| Client bundle: no secret names or key patterns in `.next/static`. `NEXT_PUBLIC_PORTAL_DEMO_TENANTS` holds tenant IDs only, by design | PASS |
| Named-user OIDC login and session lifecycle | **NOT_VERIFIED**: no preview Auth0 configuration |
| Tenant A vs tenant B, engagement ownership, cross-tenant report denial, restricted roles, report delivery | **NOT_VERIFIED live**: no tenant sessions. Engineering coverage: backend suites in `make fg-security` (incl. `test_tenant_access_001`, #817 engagement isolation tests) |
| BFF credential forwarding to Core | **NOT_VERIFIED**: no `CORE_API_KEY` in preview |

Note on `/reports` with a forged well-formed `pnu1.` token: the page shell returns 200. This is by design (`lib/session.ts`: the edge accepts well-formed opaque tokens, and every data request is re-validated by Core). No data is served without Core validation.

**Disclosure.** `vercel curl`, the access path the Vercel skill recommends, **automatically created a "Protection Bypass for Automation" secret** on the app.frostgate.ai project at 2026-11-11 14:01Z. The project had none before. This is an unplanned project-settings change. Recommendation: revoke it under *Settings → Deployment Protection → Protection Bypass for Automation* unless you intend to keep it for automation. Nothing else changed: protection mode, aliases, environment variables and deployments are unchanged.

## 6. Release decision report

| Item | Value |
|---|---|
| Current production | `dpl_4LeXwoa4LjvnohVZ4y4PpzqD8QiW` · `ec566412` · 2026-10-06 · Next 14.2.5 / React 18.3.1 |
| Proposed | Production build of the merge commit on `main` (the identity is created at merge) · Next 15.5.29 / React 19.3.1 |
| Source delta (`apps/portal`, ec566412..751666a1) | 26 files, +2093/−876 |
| Security changes included | #817 engagement isolation and canonical reports; #804 post-payment activation; #819 Next 15.5.29 (closes 37 Next advisories incl. 4 critical) plus postcss, nanoid, zod and source-map-js highs; #815 acceptance tests; #805 navigation; this PR's fail-safe ignore step |
| Framework delta | Next 14.2.5 → 15.5.29 (async request APIs; caching defaults; `instrumentation.ts` runs by default), React 18 → 19, eslint-config-next 15 |
| Tests completed | §5 PASS rows, §7 suites |
| Not verified | Authenticated named-user flows, live tenant isolation, report delivery and BFF→Core credentials (all need production configuration) |
| Compatibility risks | (1) The first build ever with **production** env on Next 15: config validation or the Auth0 callback may behave differently from the env-less preview. (2) Next 15 async `cookies()`/`headers()`, migrated in #819 and type-checked, not exercised against real Auth0. (3) The React 19 hydration path with real data. |
| **Does merge deploy?** | **YES.** The project is Git-linked with `productionBranch: main` and `autoAssignCustomDomains: true`. On merge, the ignore step sees `VERCEL_GIT_PREVIOUS_SHA = ec566412`, which is either absent from the clone (BUILD) or differs (BUILD). Vercel then builds production and **moves `app.frostgate.ai` automatically**. |
| Rollback candidate | `dpl_4LeXwoa4…` (Next 14.2.5) via Instant Rollback. **Emergency-only and time-boxed:** it reinstates 37 known Next advisories (4 critical) and removes #817's portal-side engagement isolation. Not acceptable long-term. The preferred recovery is roll-forward. |

## 7. Founder-approved production promotion (exact steps)

Founder approval is required. Nothing below has been executed.

**Constraint (Codex P2, verified in code): an authenticated login cannot be completed on the unaliased deployment.**

- `apps/portal/app/api/auth/oidc/route.ts` takes `redirect_uri` from `PORTAL_AUTH0_CALLBACK_URL`, which in production is `https://app.frostgate.ai/api/auth/oidc/callback`.
- It sets the CSRF cookie `fg_oidc_state` host-only: no `domain`, `path=/`, `sameSite=lax`.
- So a login started on `<deployment>.vercel.app` returns from Auth0 to `app.frostgate.ai`, which is the **old** deployment until promotion. That host has no `fg_oidc_state` cookie, so the callback (`callback/route.ts:94–97`) answers `session_expired`.
- Pointing `PORTAL_AUTH0_CALLBACK_URL` and the Auth0 allowlist at the deployment host would not help either. Env changes need a rebuild, so the verified build would be a different artifact, with a non-production callback, from the one later promoted.

Authenticated verification is therefore necessarily **post-promotion**. Pre-promotion checks prove the new build loaded production configuration.

**Recommended path (staged):**

1. **Baseline.** Run `make portal-deploy-provenance`; expect DRIFT. Save the output.
2. **Settings change (founder).** Temporarily turn off *Settings → Domains → auto-assign custom domains* for production, so the production build does not move the alias.
3. **Merge.** Merge the PR. A production build of the merge commit starts.
4. **Check the build.** Wait for READY. Confirm the build log shows `ignore-build: BUILD …` and `Detected Next.js version: 15.5.29`.
5. **Pre-promotion checks on the unaliased deployment URL.** No auth configuration change and no login.
   1. Run the §5 unauthenticated probes: protected pages → 307 `/login`; `POST /api/auth/login` → 403.
   2. **The OIDC configuration is loaded.** `GET /api/auth/oidc` must return 302 to `https://<PORTAL_AUTH0_DOMAIN>/authorize` with `redirect_uri=https://app.frostgate.ai/api/auth/oidc/callback`. Read only the `Location` header and **do not follow it**. A 503 means config is missing, so abort.
   3. **Core credentials are loaded, and Core rejects forgeries.** Call an allowlisted BFF route, e.g. `GET /api/core/portal/me`, with a random well-formed `pnu1.` cookie. It must be rejected by Core (401/403), never 200 and never `CORE_TENANT_ID is not configured`. This is one read-only, rejected request against production Core.
   4. `GET /api/health` must report `"status":"ok"` with Redis configured.

   Note: if the access method needs a protection bypass, use the existing one, or `vercel api` GET calls. `vercel curl` creates a bypass secret (see §5).
6. **Promote, inside a scheduled verification window** (low traffic, founder on call): `vercel promote <deployment-id> --scope frost-gate-s-projects`.
7. **Post-promotion authenticated verification on `app.frostgate.ai`, within 30 minutes.** Perform one named-user OIDC login per **test** tenant (A and B), then confirm:
   - A cannot list or open B's engagements or reports, by URL or through the BFF;
   - restricted roles are denied;
   - an authorized report download succeeds;
   - logout clears the session.

   Use test tenants only, and make no writes to customer tenants.
8. **Provenance.** `make portal-deploy-provenance` **must be PASS**, with the new deployment ID, the merge SHA and Next 15.5.29. Save it as `docs/deployment/evidence/portal_provenance_<date>_post_recovery.json`.
9. **Restore the setting.** Turn auto-assign back on.
10. **Record PRODUCTION VERIFIED** only when steps 7 and 8 both pass.

**Simple path:** merge with auto-assign left on, then steps 4, 5 (against `app.frostgate.ai`), 7 and 8. This loses only the pre-alias configuration checks in step 5.

**Abort criteria and recovery:**
- **Before promotion:** a failed build, or any failure in step 5 → do not promote. Production stays on the old build, which is safe from regression but still vulnerable. Roll forward with a fix PR.
- **After promotion:** an OIDC login failure, any cross-tenant read, a restricted-role allow, or provenance not PASS → `vercel rollback dpl_4LeXwoa4LjvnohVZ4y4PpzqD8QiW --scope frost-gate-s-projects`. This is **emergency-only and time-boxed** (hours): it reinstates Next 14.2.5's advisories and drops #817's portal-side isolation. Then roll forward.

**Follow-up for true pre-promotion authenticated testing (out of scope; it changes auth code and Auth0 configuration):**
- derive `redirect_uri` from the request host, validated against an explicit allowlist (`PORTAL_AUTH0_CALLBACK_URLS`);
- register a fixed verification hostname, e.g. `portal-verify.frostgate.ai`, in Auth0;
- alias the candidate deployment to that hostname before promoting it.

This must keep the state cookie host-bound, and must reject unlisted hosts.

## 8. Residual risks

- **R1. The drift check is operator-run.** `make portal-deploy-provenance` needs a Vercel login. A scheduled CI run needs a read-only Vercel token stored as a repository secret, which requires founder provisioning; it is not added here.
- **R2. No authenticated preview path.** Previews have no environment, so authenticated preview testing is impossible. Option (founder): preview-scoped variables pointing at a non-production Core and Auth0 tenant.
- **R3. The console uses the same `HEAD^` pattern.** Its pathspec is correct (`.`), but it does not diff against the last successful deploy. Follow-up: adopt `ignore_build.sh` for console and api.frostgate.ai.
- **R4. fg-web / frostgate.ai deployment authority** is a separate workstream (DEP-INV-001 A2), not addressed here.
- **R5.** The Protection Bypass secret created during verification (§5) remains until revoked.
- **R6. No pre-promotion authenticated test path.** `redirect_uri` is env-bound to `app.frostgate.ai`, and the OIDC state cookie is host-only (§7 constraint). The follow-up design is in §7.
