# Dependency consolidation audit — Dependabot #879–#890

This audit covers all 12 open Dependabot pull requests, based on `main` at `0cf8955e`. It is delivered as one consolidated PR (branch `fix/deps/consolidated-remediation`).

The rule applied throughout: security and compatibility outrank version novelty. An upgrade is taken only when it is compatible and verified, or when it is required for security. The original Dependabot PRs stay open until this PR is merged and its replacement coverage is verified.

## Why every Dependabot PR failed CI

All 12 PRs failed `Guard (paths + syntax + fg-fast)`, `fg-required` and `CI Required` for one shared reason that has nothing to do with the dependencies.

`verify-offline-simulation-evidence` binds `customer_one/offline_simulation_evidence.json` to the tree hash, and Dependabot cannot regenerate it. For example, the log for #888 says: `source_tree_hash='e388e50673b48cca' does not match current tree '968c29a957eb33d1' — stale evidence`. This is the structural blocker already recorded in #859.

The failures that are actually caused by a dependency are:

| PR | Failing check | Root cause |
|---|---|---|
| #883 | Frontend Dependency Security, Vercel | `npm error ERESOLVE`: `eslint-config-next@16.4.6` needs ESLint 9+ (flat config), but Portal has `eslint@8.57.1` and uses `next lint` |
| #884 | Frontend Dependency Security | **High** `zod` GHSA-mrhx-c7xc-m3w5 (patched in 4.6.6), production path `@vercel/cli-config/node_modules/zod`. The chain is `@vercel/blob@2.9.0` → `@vercel/oidc@^3.6.1` → `@vercel/cli-config@0.3.1` → `zod@4.1.11`. Every `@vercel/oidc` 3.x release, including the latest 3.8.10, pins `cli-config` ≤ 0.3.1 |
| #887 | Docker Compose Validation and Gate | `admin-gateway` container unhealthy. SQLAlchemy 2.1 no longer installs `greenlet`, and `admin_gateway/auth/dependencies.py` imports `sqlalchemy.ext.asyncio`. This is the failure already diagnosed in #858 |

## Disposition matrix

| PR | Dependency | Current → proposed | Category | Decision | Evidence and validation |
|---|---|---|---|---|---|
| #879 | `actions/checkout` (11 workflows, 37 uses) | v4 → v7 | B | **Taken** | Moves to the Node 24 runtime (v5+), as GitHub requires. v6 stores persisted credentials in a separate file; no workflow pushes with them. v7 blocks fork checkouts under `pull_request_target` and `workflow_run`: the only `workflow_run` workflow (`prod-auth-smoke.yml`) already requires `head_repository == repository`. GitHub-hosted runners meet the v2.327.1 minimum. Verified by this PR's CI |
| #880 | `actions/setup-python` (8 workflows, 15 uses) | v5 → v7 | B | **Taken** | v6 moves to Node 24. v7 removes the `pip-install` input, which no workflow uses. Every job uses Python 3.12. Verified by this PR's CI |
| #881 | Portal `@tanstack/react-query`, `react-hook-form` | ^5.62 → ^5.107, ^7.54 → ^7.92 | D | **Superseded: removed** | Neither package is imported anywhere in `apps/portal` or `packages/` (#862). They are removed instead of bumped, and the lockfile drops exactly 4 entries |
| #882 | Portal `@hookform/resolvers` | ^3.9.1 → ^7.0.6 | D | **Superseded: removed** | Unused, as for #881 (#862) |
| #883 | Portal `eslint-config-next` | ^15.5.29 → ^16.4.6 | E | **Deferred** (#857) | ERESOLVE: needs ESLint 9 flat config and moves with Next 16, which removes `next lint` (used by Portal and Console lint and CI) |
| #884 | Console group (16 packages) | see below | B, with one pin | **Taken, except `@vercel/blob`** | 15 updates taken. `@vercel/blob` is pinned to exactly `2.4.0`, the last 2.x release that does not depend on `@vercel/oidc`. That keeps the vulnerable `zod` out with no override. `@vercel/blob@2.4.0` has no advisory, and `main` audits clean on it |
| #885 | Console `@hookform/resolvers` | ^5.9.2 → ^7.0.6 | B | **Taken** | Peer requirements met (`react-hook-form` ^7.55, now 7.92.0; `zod` ^3.25 or ^4, locked 4.6.7). The only use is `zodResolver` from `@hookform/resolvers/zod` in `app/onboarding/page.tsx`, and that export still exists |
| #886 | Console `openai` | ^6.40.0 → ^7.56.0 | E | **Deferred** (#857, runtime decision) | `openai@7` declares `engines.node >=22.0.0`. CI and the Console Docker image (`node:20-alpine`) run Node 20 |
| #887 | Python group (19 updates) | see below | A, B and E split | **Partly taken** | See the Python table |
| #888 | `aiosqlite` floor | `>=0.19.0` → `>=0.22.1,<1.0.0` | B | **Taken** | The resolved version is already 0.22.1, so this only raises the floor |
| #889 | Web `tailwindcss` | ^3.4.17 → ^4.3.5 | E | **Deferred** (#857) | Tailwind 4 is a major CSS-first migration (new configuration and PostCSS plugin). It has no security driver, and Web `npm audit` is clean on 3.4 |
| #890 | Web `next` | ^15.5.29 → ^16.4.6 | E | **Deferred** (#857) | Next 16 removes `next lint` and must move with `eslint-config-next` 16 and the ESLint 9 change, one app at a time. Next 15.5.29 has no open advisory |

### #884: Console versions

| Package | Main | Selected |
|---|---|---|
| `@radix-ui/react-checkbox`, `-dialog`, `-dropdown-menu`, `-label`, `-progress`, `-select`, `-separator`, `-tabs`, `-tooltip` | 1.3.3 / 1.1.15 / 2.1.16 / 2.1.8 / 1.1.8 / 2.2.6 / 1.1.8 / 1.1.13 / 1.2.8 | 1.4.1 / 1.3.1 / 2.2.1 / 2.1.17 / 1.2.1 / 2.4.1 / 1.2.0 / 1.2.1 / 1.4.1 |
| `@tanstack/react-query` | 5.100.9 | 5.107.1 |
| `@vercel/edge-config` | 1.4.3 | 1.5.1 |
| `cytoscape` / `@types/cytoscape` | 3.33.4 / 3.21.9 | 3.35.0 / 3.31.0 |
| `react-hook-form` | 7.75.0 | 7.92.0 |
| `resend` | 6.12.4 | 6.38.1 (latest patch in range) |
| `@vercel/blob` | 2.4.0 | **2.4.0, pinned exactly** (security, see above) |

Lockfile effect: 45 version changes. Ten nested `@radix-ui` copies are de-duplicated. Two packages are added (`@radix-ui/react-use-is-hydrated`, `@vercel/global-config-fs`). `@vercel/oidc` and `@vercel/cli-config` are absent. No new package with install scripts.

### #887: Python group

| Package | Main → proposed | Decision | Reason |
|---|---|---|---|
| `mako` (`constraints.txt`) | 1.3.12 → 1.4.3 | **Taken, A (security)** | GHSA-5639-2j2p-m4mx / CVE-2026-102991: Mako ≤ 1.4.1, path traversal through a Windows drive-letter URI in `TemplateLookup`, medium, fixed in 1.4.2. Production runs Linux, so impact is low, but the advisory is real. `pip-audit` (PyPI DB) does not report it; the GitHub Advisory DB does. Alembic 1.18.4 requires only `Mako` (unbounded) |
| `ecdsa` (`constraints.txt`) | `==0` → `==0.19.2` | **Rejected** | `ecdsa==0` is a deliberate install block for CVE-2024-23342 / GHSA-wj6h-64fc-37mp (Minerva timing attack). That advisory affects `>= 0` and has **no patched version**. 0.19.2 fixes only CVE-2026-33936, so the bump would reinstate a package with an unpatched advisory. The clean install confirms `ecdsa` is not installed |
| `psycopg[binary]` | 3.3.8 → 3.3.9 | **Taken, B** | Patch release |
| `jsonschema` (dev) | 4.23.0 → 4.26.0 | **Taken, B** | Minor; used by contract tooling |
| `pre-commit` (dev) | 4.0.1 → 4.7.0 | **Taken, B** | Developer tooling only |
| `loguru` | 0.7.3 → 0.8.0 | **Taken, B** | Used by `jobs/` logging and `tools/tenants/registry.py`; covered by the job-logging tests |
| `pytest`, `pytest-env` (dev, agent, admin-gateway) | 9.0.3 → 9.2.0; 1.2.0 → 1.8.5 | **Deferred, E** | Measured: with `pytest` 9.2.0, every run aborts with `INTERNALERROR PytestDeprecationWarning: "asyncio_default_fixture_loop_scope" is unset`, because `pytest.ini` sets `filterwarnings = error`. With 9.0.3 the same tests pass. Adopting it needs a suite-wide asyncio fixture loop-scope decision; there is no security driver |
| `pytest-asyncio` | 1.3.0 → 1.5.0 | **Deferred, E** | Same warning-as-error failure. Moves with the pytest decision |
| `ruff` | 0.15.11 → 0.17.5 | **Deferred, E** | Formatter and lint-rule changes would reformat unrelated files and change the `ruff format --check` CI gate. Belongs in its own formatting PR |
| `fastapi`, `starlette`, `uvicorn[standard]`, `pydantic`, `pydantic-core` (admin-gateway), `pydantic-settings`, `httpx` (and the admin-gateway `httpx` floor) | 0.136.3 / 1.3.1 / 0.30.0 / 2.9.0 / 2.23.2 / 2.5.2 / 0.27.2 → 0.162.5 / 1.10.0 / 0.54.0 / 2.14.3 / 2.50.4 / 2.16.3 / 0.28.1 | **Deferred, C** (#858) | API framework stack migration; it must preserve OpenAPI contracts, auth, tenant middleware and the starlette TestClient's `httpx2` transport. No advisory on the current versions |
| `sqlalchemy`, `alembic` | 2.0.20 → 2.1.8; 1.18.4 → 1.20.1 | **Deferred, C** (#858) | Root cause of #887's Docker failure: SQLAlchemy 2.1 drops `greenlet` and breaks admin-gateway's async import. Needs `sqlalchemy[asyncio]`, plus RLS, migrations replay and Postgres verification, in its own PR |

## Security verification

- **Python, fresh install** (`make venv`, which runs `pip install -c constraints.txt -r requirements.txt -r requirements-dev.txt`):
  - `pip check`: no broken requirements;
  - `ecdsa` is not installed;
  - Mako is 1.4.3;
  - `make pip-audit`: run in the full gate sequence, exit codes are in the PR.
- **Frontend:**
  - each app runs `npm ci`, `npm ls --all` and `npm audit --omit=dev --audit-level=high`;
  - the repository's fail-closed `make frontend-audit` gate also runs;
  - results and exit codes are in the PR.
- **Install scripts:** only `fsevents` (all apps) and `unrs-resolver` (Console, Portal) declare install scripts. Both are already on `main`, and nothing new was introduced.
- **Lockfiles:** every manifest change is paired with an npm 10 lockfile (lockfileVersion 3). No retired pnpm lockfile was touched, and `check_lockfile_authority.py` runs in the gates.
- **No `overrides` or `resolutions`** were added anywhere.
- **No credentials or secrets** were introduced; the secret-scan tripwire runs in `codex_gates.sh`.
- **No change to authentication, RBAC, RLS, evidence-integrity code or production infrastructure.** The only CI change is the action major versions.

## Findings outside the 12 PRs (not changed here)

- **`stripe>=10.0.0` is unbounded** in `requirements.txt`. A fresh install resolves `stripe` 17.0.0, while the long-lived local venv has 15.3.1, which is the version the MSP-006 billing audit (F10) recorded. CI installs fresh, so CI may already run a different Stripe SDK than the audit assumed.
  - **Recommendation:** pin `stripe` in its own PR, after re-checking MSP-006 finding F10 against the pinned version.
- **Strict mypy repaired:** 18 pre-existing errors in 8 test and tool files were also present on `main` with the same mypy 1.5.1. They are repaired here with precise types; no ignore was added. See the PR fix log.

## CI performance (investigated, not changed)

- **`Hardening Gates (ci-hardening)`** runs the whole of `pytest tests/security` in one process. It took 38.4 minutes on #878, 31 minutes on #891 and 53.9 minutes on #892, against a 55-minute limit.
- **Per-test cost:** the MSP suites each spend about 2–3 seconds per test building an isolated application (`build_app`) and its SQLite schema. That fixture cost, not test logic, dominates.
- **Options, each to be a separate CI performance change:**
  - shard `tests/security` across parallel jobs (no coverage removed);
  - cache the application schema per worker.
- **Not done here,** because neither is needed to make this dependency PR reliable.

## Rollback

Revert the PR. All changes are pin and lockfile edits, the action version bumps, and typing-only test and tool fixes. There is no schema, data or runtime-authority change.

Portal: the only change is removing three unused packages. A merge to `main` triggers the Portal production build (app.frostgate.ai), so it needs explicit approval.

## Follow-up tracking

| Issue | Items |
|---|---|
| #857 | Next 16 + `eslint-config-next` 16 (#883, #890), Tailwind 4 (#889), `openai` 7 together with the Node 22/24 runtime decision (#886) |
| #858 | SQLAlchemy 2.1 + alembic 1.20, then the FastAPI / Starlette / Pydantic / httpx / uvicorn stack |
| New (recommended) | pytest 9.2 + pytest-asyncio 1.5 with an explicit `asyncio_default_fixture_loop_scope`; ruff 0.17 as a formatting-only PR; `stripe` pin |
| #859 | The remaining Actions Node 24 majors (`cache`, `upload-artifact`, `download-artifact`, `setup-go`, `setup-node`) |

## Dependabot PR closure

None of #879–#890 is closed by this work. After this PR merges and its CI on `main` is verified:

- **Close as superseded:** #879, #880, #881, #882, #884 (except the `@vercel/blob` part), #885, #888, and the taken parts of #887.
- **Close with a link to the tracking issue:** #883, #886, #889, #890, and the deferred parts of #887.
