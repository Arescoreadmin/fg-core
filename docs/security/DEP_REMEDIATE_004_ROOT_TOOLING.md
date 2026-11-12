# DEP-REMEDIATE-004: root npm tooling remediation, and plans for 005 and 006

Status: DEP-004 implemented on branch `chore/dep-remediate-004`. DEP-005 and DEP-006 are planned and not started.
Base: `main` at `e1dba3a5b` (after #848). Observed: 2026-11-11.
Machine-readable evidence:
- `dep_remediation_final_inventory.json` covers every open alert.
- `dep_remediate_004_reconciliation.json` covers the root alerts.
- `dep_remediation_alerts_snapshot_2026-11-11.json` is the trimmed GitHub export.

Both JSON files are generated and guarded by `tools/ci/dep_remediation_final_inventory.py`.

## 1. Baseline (verified, read-only)

- Working tree clean. `main` was fast-forwarded to `origin/main`, and `e5bcd96ed` (#847) and `e1dba3a5b` (#848) are ancestors.
- #848 outcome: all 65 targeted alerts are `state=fixed` with `dismissed_at` null (fixed 2026-11-11T23:35Z).
- GitHub shows 20 open alerts, 0 dismissed by users, and 5 auto-dismissed by GitHub (see §3).

| Manifest | Open | Severity | Owner |
|---|---|---|---|
| `package-lock.json` (root) | 16 | 8 high, 6 medium, 2 low | DEP-REMEDIATE-004 |
| `agent/requirements.txt` | 2 | 2 medium | DEP-REMEDIATE-005 |
| `apps/console/package-lock.json` | 1 (#88) | medium | DEP-REMEDIATE-006 |
| `apps/portal/package-lock.json` | 1 (#170) | medium | DEP-REMEDIATE-006 |

## 2. DEP-REMEDIATE-004: what changed

The root manifest exists only for `markdownlint-cli`. Nothing in CI or deployment installs it: no workflow, Make target or Dockerfile runs `npm` at the repo root, and no Vercel project is rooted there. It runs only when a developer invokes `node_modules/.bin/markdownlint`.

| Package | Before | After | How |
|---|---|---|---|
| markdownlint-cli | 0.48.0 | 0.50.0 (latest) | Parent update |
| markdownlint | 0.40.0 | 0.42.1 | Via the parent |
| markdown-it | 14.1.1 | 15.0.3 | Via the parent |
| linkify-it | 5.0.0 | 6.1.0 | Via markdown-it 15 |
| js-yaml | 4.1.1 | 5.5.0 | Via the parent |
| smol-toml | 1.6.1 | 1.9.1 | Via the parent |
| minimatch | 10.2.5 | 11.0.8 | Scoped override (`markdownlint-cli` → `minimatch ^11.0.8`). Even the latest markdownlint-cli pins `~10.2.6`, which is inside GHSA-g3hv-75wg-m249. |
| brace-expansion | 5.0.6 | 5.0.13 | Via minimatch 11 |
| katex | 0.16.46 | 0.18.11 | Scoped override (`micromark-extension-math` → `katex ^0.18.11`). Even the latest micromark-extension-math (3.1.0) declares `^0.16.0`. |

The parent update came first. The overrides are used only where no upstream release fixes the problem, and each is scoped to the single parent that needs it. I did not use `npm audit fix --force`.

The lockfile has 76 entries. Every one has a sha512 integrity hash and resolves from registry.npmjs.org, and none has install scripts. `npm ls` is consistent, and three packages are new: `@isaacs/nonrecursive-glob-match`, `micromark-util-edit-map` and `re2js`.

Lockfile sha256: `4500a0ef…` before, `612b7c07…` after. The Console, Portal and Web lockfiles are byte-identical before and after.

**Compatibility.**
- `.markdownlint.json` is unchanged.
- Linting all 381 tracked Markdown files gave 9,456 findings before and 9,461 after. The difference is strictly additive and comes from improved rules (MD034 now flags bare e-mail addresses, +2; MD036, +3); no finding was lost.
- I probed every code path the overrides touch:
  - `--ignore` globs (minimatch 11);
  - YAML config, including merge keys (js-yaml 5);
  - TOML config (smol-toml);
  - JSONC config;
  - stdin input;
  - loading micromark-extension-math's HTML module and katex 0.18 `renderToString`.
- markdownlint-cli 0.49 and later require Node 22 or newer. This affects local tooling only, since no CI job runs root markdownlint.

**Audit.** `npm audit` reported 10 vulnerable packages before (6 high, 1 moderate, 3 low) and 0 after.

## 3. Alerts GitHub auto-dismissed

GitHub auto-dismissed root alerts #172 (linkify-it) and #177, #178, #183 and #184 (brace-expansion) at 2026-11-11T01:15Z, by its own triage. No FrostGate action dismissed them.

All five are real, high-severity, non-withdrawn advisories, and the base versions (linkify-it 5.0.0, brace-expansion 5.0.6) were inside their ranges. They are now tracked in both JSON files and guarded exactly like open alerts, and DEP-004 resolves all five.

They may stay `auto_dismissed` after the rescan. I did not change their state.

## 4. Recurrence guard

`tools/ci/dep_remediation_final_inventory.py` reuses `dependency_alert_inventory.build_inventory` and `MANIFEST_AUTHORITY` rather than creating a parallel system.

It exits 1 when:
- an implemented alert resolves inside its vulnerable range;
- an implemented package disappears (the alert must be reclassified);
- an alert has no decision, or a decision has no alert;
- a manifest is unclassified.

It exits 2 when a range, lockfile, pin or snapshot cannot be parsed or read.

Tests: `tests/tools/test_dep_remediation_final_inventory.py`, 30 tests. Forcing `in_range` to always return False makes 16 of them fail.

No workflow, ruleset or required check was changed. The tests run in the existing `tests/tools` lanes.

## 5. Deployment impact of DEP-004

| Path | Effect on merge |
|---|---|
| `apps/console/vercel.json` `ignoreCommand` includes `../../package-lock.json` | **The Console Vercel production projects rebuild.** console.frostgate.ai and api.frostgate.ai rebuild from unchanged `apps/console` inputs (same lockfile `ab46e65b…`). |
| Portal (`tools/vercel/ignore_build.sh apps/portal …`) | No rebuild; the root files are outside its watched paths. |
| `release-images.yml` (every push to main) | Republishes the root image. `COPY . /app` carries `package.json` and `package-lock.json` as inert files; the image has no npm. |
| Agent and Web | None. |

**Smoke test after merge:**
1. The Console deployment for the merge SHA is READY.
2. `/api/health` returns 200.
3. A sign-in page loads.

**Rollback:** revert the PR. The Console redeploys from identical inputs.

There are no secret, environment, authentication or tenant implications.

## 6. Plan: DEP-REMEDIATE-005 (agent `requests`)

**Advisories:**
- #1, GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081, `.netrc` credential leak via a malicious URL; fixed in 2.32.4.
- #2, GHSA-gc5v-m9x4-r6x2 / CVE-2026-25645, insecure temp-file reuse in `extract_zipped_paths`; fixed in 2.33.0.

The installed version is `requests==2.32.3`, a direct runtime dependency.

**Change:**
- One file, `agent/requirements.txt`: `requests==2.32.3` becomes `requests==2.34.2`. The minimum fix is 2.33.0; 2.34.2 is what the shared CI `.venv` already runs, so the repo's agent tests already exercise it.
- No change to `windows-requirements.txt`. `tools/build/build_agent_windows.ps1` installs only pyinstaller.
- The inventory decision for #1 and #2 moves from PLANNED to IMPLEMENTED, so the guard then enforces it.

**Transport review, required by the prompt, not a code change in 005:**
- `agent/core_client.py` sets an explicit timeout and `allow_redirects=False`.
- `agent/app/core_client.py` uses `session.get/post` with a timeout but follows redirects, and `trust_env` is left at its default, so the agent reads `.netrc`.
- Verify TLS verification is never disabled (no `verify=False` was found).
- Record whether disabling `trust_env` or redirects for the legacy client is wanted. That would be a behaviour change and needs its own decision.

**Tests:**
- `agent/tests` and `tests/agent` (including `test_core_client_security.py` and `test_core_transport_policy.py`);
- `make fg-security`;
- `docker build -f agent/Dockerfile .` locally (privileged; ask first);
- the Windows build is unaffected and has no CI lane.

**Deployment:** none repo-managed. The agent image is built only by `agent/docker-compose.yml`. It is not in `release-images` and not in the root compose file.

**Post-merge check:** `gh api repos/Arescoreadmin/fg-core/dependabot/alerts/{1,2} --jq '[.number,.state,.dismissed_at]'`.

## 7. Plan: DEP-REMEDIATE-006 (Console #88, Portal #170)

**Advisory:** both alerts are GHSA-g3hv-75wg-m249 / CVE-2026-118764 (minimatch globparts DoS, `>= 7.0.0, < 11.0.1`).

**Chain, identical in both apps:**
- The vulnerable copy is `node_modules/@typescript-eslint/typescript-estree/node_modules/minimatch@10.2.6`, a dev dependency reached through `eslint-config-next` 15.5.29 → `@typescript-eslint/*` 8.72.2.
- The top-level `minimatch@3.1.5` used by ESLint 8 is outside the range.

**No parent fix exists.** typescript-estree 8.72.2, the latest release, still declares `minimatch ^10.2.2`.

**Change:**
- In `apps/console/package.json` and `apps/portal/package.json`, add `"@typescript-eslint/typescript-estree": {"minimatch": "^11.0.8"}` alongside the existing `next.postcss` override.
- Regenerate both lockfiles with `npm install --package-lock-only`.

**Scratch probe (2026-11-11), each app:**
- the lockfile delta is exactly 2 entries (minimatch 11.0.8 and the new `@isaacs/nonrecursive-glob-match`);
- next 15.5.29, react 19.3.1 and next-auth are unchanged;
- `npm audit` reports 0 (all scopes) and 0 (production).

There is no Next 16, React, TypeScript or NextAuth change.

**Tests, per app:**
- `npm ci`, `tsc`, `next lint` (the code path that uses typescript-estree), the full test suite and `next build`;
- `make frontend-audit`;
- the lockfile-authority guard;
- the route inventory;
- portal deploy provenance (`make portal-deploy-provenance`).

**Deployment:** the merge **will** trigger production builds of the Console (both Vercel projects) and the Portal. It needs a founder-approved window, a preview check of each project, and read-only post-merge provenance checks.

**Rollback:** revert the PR.

**Post-merge check:** alerts #88 and #170 are `state=fixed` and `dismissed_at` null.

## 8. PR order and open Dependabot PRs

The order is 004, then 005, then 006, each after the previous one is merged and verified on GitHub.

Superseded once DEP-004 merges and is verified:
- #836 (brace-expansion);
- #837 (markdown-it / markdownlint-cli);
- #838 (js-yaml / markdownlint-cli).

PR #835 (smol-toml), which DEP-INV-001 lists in the same set, is already closed.

Do not close them before then. All other Dependabot PRs (Next major, TypeScript major, Node types, Actions majors, ReportLab major, routine Python and frontend updates) are unrelated to these alerts and stay open for their own decisions.

## 9. Residual risk

- Closing the alerts depends on GitHub's rescan of `main`. Nothing is claimed as fixed until each ID reads `state=fixed` with `dismissed_at` null.
- The five auto-dismissed alerts may never show as `fixed`. The guard is their evidence.
- After DEP-004, 4 alerts remain open (#1, #2, #88, #170) until DEP-005 and DEP-006 land.
- A zero open-alert count is not sufficient on its own. After DEP-006, confirm that the dependency graph still lists all 5 manifests as scanned (`gh api repos/Arescoreadmin/fg-core/dependency-graph/sbom` is read-only).
