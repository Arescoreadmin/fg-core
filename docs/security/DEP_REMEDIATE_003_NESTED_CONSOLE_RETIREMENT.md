# DEP-REMEDIATE-003: retire the obsolete nested Console tree

Work item DEP-REMEDIATE-003, implementing step C of the DEP-INV-001 remediation sequence. Recorded 2026-11-11 at baseline `e5bcd96ed` (#847 merged).

Machine-readable evidence:

- `dep_remediate_003_retirement_ledger.json` records every deleted file and every legacy test. `tools/ci/dep_remediate_003_ledger.py` regenerates it, and `tests/tools/test_dep_remediate_003_retirement.py` validates it.
- `dep_remediate_003_alert_reconciliation.json` holds the live Dependabot snapshot and the per-alert overlap check.

## 1. Root cause

`apps/console/console/` was a full second copy of the Console: 118 files, its own `package.json`, a `package-lock.json` pinning `next 14.2.35`, a Dockerfile and a tsconfig. Nothing built or deployed it, but it still had three effects:

- **GitHub alerts.** GitHub scanned its lockfile, which produced 65 Dependabot alerts (4 critical, 30 high).
- **Type-check.** The active Console's `tsconfig.json` (`**/*.ts`) type-checked 91 of its files.
- **Tests.** The active `npm test` (`node --test`) ran its 15 test files (712 tests). Those tests read the **nested** sources, so they never tested deployed code.

The tree had been flagged twice before: FGA-022 in `docs/audits/FROSTGATE_FORENSIC_PLATFORM_AUDIT_2026.md`, and the 2026-07-02 architecture audit.

## 2. Authority proof (nothing depends on the tree)

| Consumer | Result |
|---|---|
| Vercel | The two projects rooted at `apps/console` are `console.frostgate.ai` (`prj_bAtFbfu4…`) and `api.frostgate.ai` (`prj_W8Y2uUuO…`). Both use `vercel.json` with `npm install`. Production serves `e5bcd96ed`, built with Next 15.5.29 (read-only API). No project is rooted at `apps/console/console`. |
| Next.js | `apps/console/app/` is the only app router. `console/` is not a route segment, and the 48 routes are unchanged. |
| Docker / compose | The `apps/console/Dockerfile` builder copies the directory, but the runner keeps only `.next/standalone` and `.next/static`. No Dockerfile or compose service uses `console/console`. |
| Makefile / GitHub Actions | No references. `ci-console` runs `console-lint console-test console-audit` in `apps/console`. |
| Imports | No `@/console/`, `./console/` or `../console/` import exists in either direction. Nested `@/` imports resolved to the active root. |
| Tailwind / ESLint | Tailwind content globs cover only `app/`, `components/`, `lib/` and `packages/ui`. `next lint` default directories exclude `console/`. |
| Dependency graph | The nested lockfile was never installed. The canonical `apps/console/package-lock.json` is unchanged (sha256 `ab46e65b…` before and after `npm ci`). |
| Documentation | Only historical audits, a marketing source list and inventory evidence mention it. None claims the tree is active, and they are left unchanged. |

## 3. File retirement inventory

All 118 tracked files were deleted. Per-file sha256 values and decisions are in the ledger.

| Comparison with `apps/console/<same path>` | Files |
|---|---|
| Byte-identical copy | 86 |
| Differs (an older copy of an active file) | 31 |
| Exists only in the nested tree | 1: `components/common/TenantSwitcher.tsx` |

`TenantSwitcher.tsx` was the last surviving copy of the client-side `tenant_id` switcher that #706 (`4560cf763`) deliberately removed from the active Console. Deleting it removes a reintroduction path, and the ledger test asserts that no `TenantSwitcher.tsx` is tracked anywhere.

Files deleted, by kind:

| Kind | Files |
|---|---|
| Routes (`app/`) | 29 |
| Source (`components/`, `lib/`, `styles/`, `public/`) | 65 |
| Tests | 15 |
| Build config: `Dockerfile`, `next.config.js`, `tsconfig.json`, `tailwind.config.ts`, `postcss.config.js`, `.env.example` | 6 |
| Dependency manifests: `package.json`, `package-lock.json` | 2 |
| Documentation: `README.md` | 1 |

`.env.example` held placeholder names only, no values.

## 4. Test migration ledger

Method:

1. Each nested test file was extracted from `e5bcd96ed`.
2. Its `'..'` root was rewritten to the **active** `apps/console/`.
3. Each file was executed with `node --test`. Every legacy assertion was therefore evaluated against the deployed source.
4. Every runtime test title was mapped to a canonical active test.

| State | Legacy tests | Security-relevant |
|---|---|---|
| ALREADY_COVERED | 706 | 128 |
| OBSOLETE_WITH_EVIDENCE | 6 | 3 |
| MIGRATED | 0 | 0 |
| BLOCKED | 0 | 0 |

- **673 of the 712** legacy tests pass unchanged against the active source, and each also exists by title in the same active test file.
- **33 are ALREADY_COVERED, but their nested assertions fail against the active source.** Each targeted pre-redesign source text. The same-titled active test was rewritten for the current implementation:
  - Executive Command Center: `cbafe262f` (#499);
  - registry-driven navigation: `5f8f34745` (#498);
  - server-side BFF URL resolution: `d2c252af3` (#512);
  - readiness and provenance page graduations: PR 91 and PR 92.

  Two of the 33 map to renamed active tests:
  - the dev-only tenant query override test maps to `tenant query parameter cannot override server tenant authority`, which is **stronger**: the flag was removed in #706 and is asserted absent;
  - the alignment-URL test maps to `alignment fetch builds absolute server URL through the shared console origin helper`.
- **6 are OBSOLETE_WITH_EVIDENCE:**
  - The three provenance placeholder-page tests. The page became the evidence explorer in PR 92, which the active `provenance-validation-panel.test.js` and `evidence-explorer.test.js` cover.
  - `redis_outage_does_not_fail_open_in_prod`, `route_passes_errorCode_through_to_503_response` and `redis_unavailable_in_prod_returns_stable_error`. These encoded a **fail-closed (503)** rate-limit outage policy. `225d21c25` (2026-07-17) deliberately reversed it, and the active suite asserts the reverse (`route_fails_open_when_store_unavailable`). They are **not** reinstated, because that would change canonical Console behaviour. They are recorded as residual risk R1.

No legacy assertion was found that holds on deployed code but is not already asserted by an active test. So nothing needed moving, and no test was weakened, skipped or replaced by a snapshot.

### Coverage strengthened

`apps/console/tests/rate-limit-store-behavior.test.js` adds 11 tests. Both the retired tests and their active twins exercise an **inline copy** of the rate-limit builder. The new tests instead execute the **real** `lib/rateLimitStore.ts`, transpiled with the Console's TypeScript so they run on CI's Node 20. They cover:

- the production and staging config-required paths;
- CHANGE_ME and blank rejection;
- the test-environment memory fallback;
- lazy Redis construction;
- allow-up-to-limit and block-above-limit behaviour;
- tenant-key independence;
- EXPIRE set once per window;
- client-error propagation;
- a health probe that does not leak the URL.

As a mutation check, forcing `isDevOrTestEnv()` to return true, which silently falls back to memory in production, fails 6 of the 11.

### Console test counts

| | Tests | Pass | Fail | Skipped |
|---|---|---|---|---|
| Before (`e5bcd96ed`) | 3147 | 3147 | 0 | 0 |
| After | 2446 | 2446 | 0 | 0 |

3147 − 712 (legacy, mapped above) + 11 (new behavioural tests) = 2446. The reduction is fully explained.

## 5. Security invariants retained (active suite, unchanged)

- **Tenant isolation and authority.** Tenant A cannot reach tenant B. Unknown or invalid tenants fail closed. Query, body and demo tenant overrides are rejected. Client authority never inherits platform-admin privileges. These are covered by behavioural tests over `lib/consoleAccess.js`: `tenant-isolation-e2e`, `tenant-context-resolution`, `console-access-policy`, `authority-aware-client-administration` and `portal-console-boundary`.
- **The BFF never forwards browser credentials.** It never forwards cookie or Authorization headers, sets its own server-side `X-API-Key`, keeps a strict route allowlist with no wildcards, and returns `no-store` error contracts. Covered by `dashboard-mvp2`, `auth-secret-isolation` and `core-credential-resolution`.
- **No secret leakage.** No `NEXT_PUBLIC_CORE_API_KEY` or `NEXT_PUBLIC_CORE_API_URL` is used, and the client bundle never references Redis config. Covered by `dashboard-mvp2` and `bff-rate-limit-prod`.
- **Rate-limit configuration enforcement** in production and staging. Covered by `bff-rate-limit-prod`, and now also by the real-module tests.

## 6. Dependency manifests retired

- `apps/console/console/package.json` and `apps/console/console/package-lock.json` are deleted.
- `MANIFEST_AUTHORITY` changes their status from `OBSOLETE_DUPLICATE_TREE` to `RETIRED`.
- The canonical `apps/console/package.json` and `package-lock.json` are untouched. There is no Next, React, TypeScript or NextAuth change.

## 7. Recurrence guard (extends DEP-REMEDIATE-002)

`tools/ci/check_lockfile_authority.py` and `.github/security/lockfile-authority.json` add two rules, enforced through the required Guard and fg-security lanes via `check_security_regression_gates.py`:

- **No second application root inside a policy app.** A tracked `package.json`, `tsconfig.json`, `next.config.*` or lockfile below `apps/console`, `apps/portal` or `apps/web` fails. `node_modules` is ignored. Package roots outside policy apps (for example `packages/*`) stay allowed.
- **`retired_roots`.** Any tracked file under `apps/console/console/` fails, even a lone source file.

A reintroduced nested lockfile fails three independent ways:

1. nested application root;
2. retired tree;
3. RETIRED lockfile.

An invalid `retired_roots` value, or a repository state that can't be read, exits 2. The guard never reports success in either case.

## 8. Alerts targeted (pre-merge snapshot, 2026-11-11)

**Open alerts: 85.**

| Manifest | Open alerts |
|---|---|
| Nested Console | 65 |
| Root tooling | 16 |
| Agent | 2 |
| Console | 1 (#88) |
| Portal | 1 |

**The 65 targeted alerts** are 4 critical, 30 high, 26 medium and 5 low (46 runtime-scope, 19 development-scope). IDs: 3–17, 23, 24, 26–28, 31, 32, 35–58, 63–68, 70–74, 79–85, 87.

- **Overlap with deployed code:** 64 of the 65 have no vulnerable version in the deployed npm lockfile.
- **#87** (minimatch, GHSA-g3hv-75wg-m249, moderate) is the same development-only exposure as #88 on the active lockfile. #88 stays open, and DEP-REMEDIATE-006 owns it.

No alert was dismissed and no Dependabot setting changed. Closure happens only through GitHub's rescan of `main`.

## 9. Production impact

- Merging changes `apps/console/`. The Console `ignoreCommand` (`git diff HEAD^ HEAD -- .`) therefore builds, and with `autoAssignCustomDomains: true` on the `main` production branch, both **console.frostgate.ai and api.frostgate.ai rebuild and promote automatically**.
- The rebuild uses the same npm lockfile and the same application source. The deleted tree was never part of the runtime image.
- Merge timing is a founder decision. CI success is not proof of production correctness, so the post-merge checks below are required.

## 10. Post-merge verification

```bash
git switch main && git pull --ff-only origin main && git log -1 --format='%H %s'
python -m pytest -q tests/tools/test_dep_remediate_003_retirement.py tests/tools/test_lockfile_authority.py tests/tools/test_dependency_alert_inventory.py
python tools/ci/check_lockfile_authority.py
(cd apps/console && npm ci && sha256sum package-lock.json && npm run typecheck && npm run lint && npm test && npm run build)
make fg-contract && make fg-fast && make fg-security
make repo-security-drift   # read-only; ruleset must still read COMPLIANT
for n in 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 23 24 26 27 28 31 32 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 63 64 65 66 67 68 70 71 72 73 74 79 80 81 82 83 84 85 87; do
  gh api repos/Arescoreadmin/fg-core/dependabot/alerts/$n --jq '"\(.number) \(.state) \(.dismissed_reason // "-")"'
done   # every line must read "<n> fixed -"; any "dismissed" is a failure
gh api --paginate 'repos/Arescoreadmin/fg-core/dependabot/alerts?state=open&per_page=100' --jq '.[].dependency.manifest_path' | sort | uniq -c   # target: 20 open
for p in prj_bAtFbfu4R8PWqGJEwOaSU8FEmiq5 prj_W8Y2uUuOBEIcJKfL2y133o3nO9Lk; do
  vercel api "/v6/deployments?projectId=$p&target=production&limit=1" | python3 -c "import json,sys;d=json.load(sys.stdin)['deployments'][0];print(d['uid'],d['state'],d['meta'].get('githubCommitSha'))"
done   # must be READY at the merge SHA; build log must show `npm install` and Next.js 15.5.29
git branch -d chore/dep-remediate-003
```

## 11. Residual risks

- **R1: Console rate limiting fails open in production.** This is a deliberate product decision (`225d21c25`): a Redis or Upstash outage disables BFF rate limiting rather than returning 503. Retiring the tree removes the last code that encoded fail-closed. This PR keeps the decision unchanged, so it needs explicit founder confirmation or a separate work item.
- **R2: BFF proxy route invariants are static source assertions only.** These cover cookie and Authorization non-forwarding and the tenant-parameter path in `app/api/core/[...path]/route.ts`. Executing the route needs `next/server` and `next-auth` harnessing, so it was not added here. Tenant authority itself is covered behaviourally through `lib/consoleAccess.js`.
- **R3: Historical documents keep their nested-tree references.** These are the audits, the marketing source list and DEP-INV-001 §2 and §4. They are records of history and are intentionally unchanged.
- **R4: Alert closure depends on GitHub's rescan.** The 20-alert target is a projection.
