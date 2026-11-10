# L14-FRONTEND-DEPENDENCY-SEC-001 — Frontend Dependency Security

**Branch:** `security/l14-frontend-dependency-sec-001` · **Base:** `7ae17b4ddc5e17e36817e2e3332e02fc52531500` (main after PR #818) · **Date:** 2026-11-10 · **Class:** SECURITY (remediation of known advisories; REPAIR-authorized)

## 1. Executive summary

All three customer-facing Next.js applications shipped critical advisories in their production dependency trees. The worst were three unauthenticated remote-code-execution advisories in the Next.js Image Optimization API and runtime, an Auth.js configuration fail-open, and a Next.js middleware authorization bypass (portal, on Next 14.2.5).

After this change:

- `npm audit` reports **0 critical / 0 high** in the production tree **and** the full lockfile tree of `apps/portal`, `apps/console` and `apps/web`;
- a fail-closed CI gate audits all three apps on every pull request, on every push to main, daily, and on demand, and treats an audit that cannot run as a failure;
- lockfile-bound CycloneDX SBOMs are generated and validated for each app.

Remaining items are moderate dev-tooling advisories (§10) and two repository-settings gaps that need a repo admin (§11).

## 2. Before / after (fresh `npm audit`, 2026-11-10, registry reachable)

| App | Prod before (C/H) | Prod after | Full tree before (C/H/M) | Full tree after (C/H/M) |
|---|---|---|---|---|
| portal | 1 / 4 | **0 / 0** | 1 / 13 / 8 | **0 / 0 / 6** |
| console | 3 / 5 | **0 / 0** | 3 / 16 / 9 | **0 / 0 / 6** |
| web | 1 / 4 | **0 / 0** | 1 / 5 / 8 | **0 / 0 / 0** |

The before counts match the 2026-11-09 historical baseline exactly.

## 3. Advisory remediation matrix (production critical/high)

| Advisory | Package (before) | Apps | Remediation |
|---|---|---|---|
| GHSA-2464-fhr4-w9xw (critical, RCE via SVG in image optimizer) | next ≤15.5.27 | all | next 15.5.29 |
| GHSA-2xp9-vwfh-vxw4 (critical, RCE via AVIF in image optimizer) | next <15.5.24 | all | next 15.5.29 |
| GHSA-p293-qw3h-jr36 (critical, RCE on Windows-hosted servers) | next <15.5.24 | all | next 15.5.29 |
| GHSA-f82v-jwr5-mffw (critical, middleware authorization bypass) | next 14.2.5 | portal | next 15.5.29 |
| GHSA-7gfc-8cq8-jh5f, GHSA-gp8f-8m3g-qvj9, GHSA-mwv6-3258-q52c, GHSA-5j59-xgg2-r9c4, GHSA-h25m-26qc-wcjf, GHSA-q4gf-8mx6-v5v3, GHSA-8h8q-6873-q5fj, GHSA-c4j6-fc7j-m34r, GHSA-36qx-fr4f-26g5, GHSA-m99w-x7hq-7vfj, GHSA-89xv-2m56-2m9x, GHSA-p9j2-gv94-2wf4, GHSA-p3m5-59mp-jv5r (high: auth bypass, cache poisoning, SSRF, RSC/Server Action DoS) | next 14.2.x | all | next 15.5.29 |
| GHSA-8fpg-xm3f-6cx3 (critical, auth checks fail open on configuration errors) | next-auth 5.0.0-beta.31 | console | next-auth 5.0.0-beta.32 |
| GHSA-7rqj-j65f-68wh (critical, email-normalizer homoglyph bypass); GHSA-xmf8-cvqr-rfgj (high) | @auth/core 0.41.2 | console | @auth/core 0.41.3 (via next-auth beta.32) |
| GHSA-6g55-p6wh-862q, GHSA-r28c-9q8g-f849 (high, source-map file disclosure) | postcss 8.4.31 (pinned by next) | all | npm `overrides`: `next → postcss ^8.5.32` (resolved 8.5.32) |
| GHSA-28wg-ghj8-5hjv, GHSA-2v37-7h3g-55p8, GHSA-xwg4-73v4-xw9w (high) | nanoid 3.3.11/3.3.12 | all | nanoid 3.3.20 (in range) |
| GHSA-68fv-2mgg-jv7q (high) | source-map-js 1.2.1 | all | source-map-js 1.2.2 (in range) |
| GHSA-mrhx-c7xc-m3w5 (high, memory exhaustion) | zod 3.25.76 | portal, console | portal: **removed** (declared, never imported); console: zod 4.6.7 + @hookform/resolvers 5.9.2 |
| GHSA-2m5v-pch6-74hx (high, TLS validation bypass) + 5 more high | undici 6.26.0 (via @vercel/blob) | console | undici 6.29.1 (within @vercel/blob's `^6.23.0`) |
| GHSA-rgj7-g3m4-5g8c, GHSA-wq5f-xc86-pv6w (high, libheif/librsvg) | sharp 0.35.2 | web (and next's optional sharp) | sharp 0.35.5 |

High dev and build-time findings were also cleared with in-range updates: postcss (direct dev), browserslist, brace-expansion, js-yaml, flatted, minimatch 3.x and picomatch.

## 4. Exact dependency changes

| Package | portal | console | web |
|---|---|---|---|
| next | 14.2.5 → 15.5.29 | 14.2.35 → 15.5.29 | 14.2.35 → 15.5.29 |
| react / react-dom | 18.3.1 → 19.3.1 | 18.3.1 → 19.3.1 | 18.3.1 → 19.3.1 |
| next-auth (@auth/core) | — | beta.31 (0.41.2) → beta.32 (0.41.3) | — |
| zod | 3.25.76 → removed | 3.25.76 → 4.6.7 | — |
| @hookform/resolvers | 3.10.0 (unchanged) | 3.10.0 → 5.9.2 | — |
| sharp | — → 0.35.5 (next optional) | — → 0.35.5 (next optional) | 0.35.2 → 0.35.5 |
| eslint-config-next | 14.2.5 → 15.5.29 | 14.2.5 → 15.5.29 | — (no lint) |
| @typescript-eslint/parser | 7.2.0 → 8.72.2 | 7.2.0 → 8.72.2 | — |
| @types/react(-dom) | 18 → 19 | 18 → 19 | 18 → 19 |
| postcss (direct dev) / autoprefixer | → 8.5.32 / 10.5.5 | → 8.5.32 / 10.5.5 | → 8.5.32 / 10.5.5 |
| npm `overrides` | `next.postcss ^8.5.32` | `next.postcss ^8.5.32` | `next.postcss ^8.5.32` |

Unchanged: TypeScript 5.9.3, Node engine (CI uses Node 20, local 22), eslint 8.57.1, and every other direct dependency.

Shared packages `@fg/ui` and `@fg/navigation` widen their peer range to `react ^18 || ^19`. Their source has no React-19-removed APIs (`defaultProps` on function components, `propTypes`, `findDOMNode`, string refs).

## 5. Compatibility decisions

- **Next 15.5.29, not 16.x.** 15.5.29 is the maintained `backport` line and clears every advisory. Next 16 would also remove `next lint` (used by portal and console), rename middleware to proxy and make Turbopack the default build. Those are separate migrations with no additional security benefit today. Moving to 16 is recommended as a follow-up before the 15.x backport window closes.
- **React 19.** Next 15's App Router requires React 19. The peer range admits 18 only for the Pages Router, and all three apps use the App Router. Every existing UI dependency already declares React 19 support: radix, react-hook-form, recharts 2.15.4, lucide-react, react-query and zustand.
- **Next 15 async request APIs** (minimal edits, behaviour unchanged):
  - portal `app/layout.tsx`: `await cookies()`;
  - console `lib/consoleUrl.ts` (two sites) and legacy `console/lib/coreApi.ts`: `await headers()`;
  - Promise-typed route `params` in portal `api/core/[...path]` and `api/assessment/payment-status/[id]`, and console `api/core/[...path]`;
  - the console client page `identity/invitations/[token]` unwraps `params` with React 19 `use()`.
- **`outputFileTracingRoot: __dirname`** in all three `next.config.js`. Next 15 infers the tracing root from lockfiles and would otherwise pick the repo root. Pinning it keeps `.next/standalone/server.js` where the console Dockerfile copies it (verified after the build).
- **postcss override rather than Next 16:** 8.4.31 → 8.5.32 is a same-major, API-compatible update of next's build-time CSS processor. All three production builds pass with it.
- **TypeScript ESLint parser warning resolved.** `@typescript-eslint` 7.2.0 supported TypeScript <5.5. 8.72.2 (via eslint-config-next 15) supports TypeScript <6.1, so TypeScript 5.9.3 is now in range without downgrading anything.
- **One rule-scoped lint suppression.** eslint-config-next 15 flags the console sidebar's `<a href="/api/auth/logout">`. The target is a route handler that must be a full document navigation, because it clears session cookies and redirects to the IdP; a `next/link` would prefetch the logout route. The anchor is kept, with an `eslint-disable-next-line @next/next/no-html-link-for-pages` and a written rationale. The existing console test that forbids `<Link>` for logout still passes. No other rule is relaxed.
- **jose Edge-runtime build warning (new, benign, fail-closed).** @auth/core 0.41.3 brings jose 6.2.17. Its JWE decompression path references `CompressionStream`, which the Edge build flags. That path runs only after authenticated decryption with the server `AUTH_SECRET`, only for `zip: "DEF"` (which Auth.js never emits), and is capped at 250 KB. Where the API is absent, jose throws, and the result is no session.

- **Console startup validation is now live.** Next 15 runs `instrumentation.ts` by default. Next 14 needed `experimental.instrumentationHook`, which was never set, so the console's `validateProductionConfig()` was dormant until now. In any prod-like environment the console refuses to start unless all of these hold:
  - `CORE_API_URL` and `CORE_TENANT_ID` are set;
  - `AUTH_SECRET` is set;
  - an internal gateway secret is set;
  - `FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK=false`;
  - no bootstrap-admin variables are present.

  This is the intended fail-closed control. It surfaced in Docker Compose CI, where the console service received none of these values and returned 500. The fix is `docker-compose.yml`: the console now receives the stack's existing `CORE_TENANT_ID` and `FG_INTERNAL_AUTH_SECRET`, plus `CORE_API_URL` (the code's own default), `FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK=false`, and an `AUTH_SECRET` taken from a per-run random `CONSOLE_AUTH_SECRET` in docker-ci. Unset values stay empty, so the check keeps failing closed.

  Combined with next-auth beta.32, a console with a missing session secret no longer treats every request as authenticated, as beta.31 did. **Pre-deploy check:** confirm that every console deployment environment satisfies this list before rolling out.

## 6. CI enforcement

- **Workflow** `.github/workflows/frontend-dependency-security.yml`. It runs on every pull request (no path filter), pushes to main, a daily schedule (`17 6 * * *`) and `workflow_dispatch`.
  - **Install:** `npm ci --ignore-scripts` per app, so lockfile drift fails and no lifecycle scripts run.
  - **Gate:** the audit is fail-closed; SBOMs are generated and validated.
  - **Evidence:** the artifact `frontend-dependency-security-<attempt>`, retained for 14 days.
  - **Durable finding:** a failing scheduled or main run opens, or comments on, the issue "[security] Frontend dependency gate failing on main".
- **Tool** `tools/ci/frontend_dependency_audit.py`, also available as `make frontend-audit` and `make frontend-sbom`.
  - **Exit codes:** 0 = PASS, 1 = FAIL (blocking advisory), 2 = **AUDIT_UNVERIFIED**.
  - **AUDIT_UNVERIFIED** covers no JSON, an npm error object, missing metadata, a non-zero exit with zero findings, and a timeout. It is never treated as clean.
  - **Blocking:** critical or high in either the production audit **or** the full-tree audit. The full-tree audit is not advisory: `--omit=dev` can drop a production package that is deduped with a devDependency, such as next's overridden postcss.
  - **Evidence binding:** each run records the source SHA (`GITHUB_SHA` or `HEAD`), the lockfile and `package.json` SHA-256, node/npm versions, advisory IDs, URLs, vulnerable ranges and dependency paths. Captured output is redacted for npm and GitHub tokens, bearer tokens and URL credentials.
- **Exceptions** `tools/ci/frontend_dependency_exceptions.json` (currently empty). An entry applies only if it is APPROVED by a named approver, has an owner and is unexpired, with a horizon of at most 90 days. Policy: `docs/security/DEPENDENCY_AUDIT_EXCEPTIONS.md`.
- **Make lanes:** `console-audit` and `portal-audit` were the non-blocking `|| true` pilot. They now run the blocking gate, the planned "Phase 3". The existing `ci-console` and `ci-portal` CI jobs therefore enforce it as well.
- **Anti-bypass:** `check_security_regression_gates.py::check_frontend_dependency_gate`, which runs in the Guard job, fails if any of the following holds:
  - the workflow, tool or registry is missing;
  - a trigger is removed;
  - a `paths:` filter, `continue-on-error` or `|| true` is added;
  - a Makefile `npm audit … || true` reappears.
- **Tests:** `tests/tools/test_frontend_dependency_audit.py`, 28 offline tests. They prove that a synthetic critical advisory fails the gate and that six kinds of synthetic audit-execution failure are AUDIT_UNVERIFIED. They also cover approved, unapproved, expired and over-horizon exceptions, redaction, SBOM validation and binding, and each bypass the guard rejects.

## 7. SBOM evidence

- **Format:** CycloneDX 1.5 JSON per app (`sbom-<app>.cdx.json`) plus `sbom-manifest.json`, which records each file's SHA-256.
- **Source:** generated from `package-lock.json`, which is exactly what `npm ci` installs. It covers the production tree, with devDependencies omitted.
- **Contents:**
  - application identity in `metadata.component`;
  - every component's name, version, purl, registry integrity hash (SHA-512) and lockfile path;
  - direct and transitive relationships in `dependencies`;
  - the generator in `metadata.tools`, and a timestamp;
  - `fg:source_sha`, `fg:lockfile_sha256` and `fg:npm_version`.
- **Why not `npm sbom`:** npm 10.9.7's `npm sbom` refuses (ESBOMPROBLEMS) to emit SBOMs for portal and console, because of the file-linked `@fg/ui` and `@fg/navigation` packages. On web it omits five production packages that next requires (including the overridden postcss). The lockfile generator matches all 48 of npm's web components and also includes those five. The existing `scripts/generate_sbom.py` reads only `package.json` ranges and is not suitable for frontend inventory.
- **Validation:** CycloneDX structure, serial number, application identity, generator, non-empty components with purls, resolvable dependency references, and the SHA and lockfile bindings. Each app's own manifest declares its React dependencies. Declared dependencies of the linked packages that the lockfile cannot resolve are recorded as `fg:unresolved_dependency` (none at present).
- **Signing:** SBOMs are **not signed** (`fg:signed=false`). No signing or independent verification is claimed.

SBOM hashes are per-run, because they include a timestamp and serial number. The current values are in the PR description and the CI artifact.

## 8. Regression results

Results are recorded in `docs/ai/PR_FIX_LOG.md` and the PR description:

- frontend tests, lint, typecheck and builds per app;
- the PR #816, #817 and #818 suites;
- `make fg-security` and `make fg-contract`;
- browser acceptance.

**PR #818 release-boundary proof:** `tests/test_assessment_assurance/test_release_boundary_repair.py` (6 tests) passes on this branch. A QA-rejected report is refused at governed-delivery execute even when an earlier authorization exists. An evidence change after authorization blocks delivery. A legitimate delivery still succeeds.

No frontend route was added. The portal and console BFF proxies forward to the same Core endpoints, and only their `params` typing changed. So no new path reaches the delivery transport without passing the backend gate.

## 9. Coverage gaps (not fabricated)

- `apps/web` has no `test` or `lint` script and no CI build lane. It is covered by `tsc`, `next build`, the dependency gate and a check of the prerendered output.
- `apps/console/console/` is an orphaned legacy copy with its own `package.json`. It is not built, deployed or referenced by the Makefile, CI or compose. It is compiled only by the console tsconfig glob, so one `await headers()` edit keeps that typecheck green. Its own lockfile is out of scope and should be deleted in a follow-up.
- `apps/console/pnpm-lock.yaml` is stale; CI and Docker use npm.

## 10. Remaining risks

- **Moderate, dev-only:** `minimatch` GHSA-g3hv-75wg-m249 under `@typescript-eslint/typescript-estree` 8.72.2, the latest release (portal and console, 6 entries each). It is not shipped and not blocking. It clears when typescript-eslint releases a fix.
- **Next 15.x backport window:** plan the Next 16 migration (§5).
- **Web security headers:** apps/web sets no CSP, HSTS or frame headers. This predates this PR, is unchanged, and is recommended as a follow-up.

## 11. Release blockers requiring a repository admin (not changed here)

1. **`main` has no branch protection and no rulesets** (GitHub API: "Branch not protected", rulesets `[]`). No required check, including `fg-required`, Guard and this gate, is enforced by GitHub, so a direct push or an admin merge bypasses all CI. Required action: protect `main`, require PRs, and require at least `fg-required`, `Guard (paths + syntax + fg-fast)` and `Frontend Dependency Security`.
2. **Dependabot alerts and security updates are disabled** (`vulnerability-alerts` 404, `automated-security-fixes.enabled=false`). Together with `open-pull-requests-limit: 0`, no automated dependency PRs exist. The daily workflow is currently the only detector. Required action: enable alerts and security updates. `.github/dependabot.yml` now also covers `apps/web`.

## 12. Release impact

- **Runtime upgrade:** this upgrades the framework runtime of all three customer-facing apps.
- **Console configuration:** the console now enforces its production configuration at startup (§5). A deployment missing a required variable will refuse to serve instead of running misconfigured.
- **Deployment:** it requires the normal preview → staging deploy.
- **Environment:** there is no environment-variable, secret, schema, migration or API-contract change.

## 13. Rollback

Revert the merge commit. It touches only `apps/*/package.json`, the lockfiles, `next.config.js`, the small async-API edits, shared-package peer ranges, CI and tooling files, and docs.

Reverting **reintroduces the critical advisories**. Prefer rolling forward. If you must roll back, do it with `git revert`, not by editing lockfiles, then run `npm ci` and redeploy. A partial rollback is possible per app by reverting only that app's `package.json` and `package-lock.json`.
