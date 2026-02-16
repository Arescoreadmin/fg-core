# Enforceable Findings Matrix

| Finding ID | Invariant | Test Strategy | CI Gate | Release Blocker |
|---|---|---|---|---|
| SOC-P0-001 | `FG_AUTH_ALLOW_FALLBACK` must remain false in prod/staging runtime invariants. | runtime invariant + prod profile validation. | `make soc-invariants`, `make prod-profile-check` | Y |
| SOC-P0-002 | Fail-open controls (`FG_RL_FAIL_OPEN`, `FG_AUTH_DB_FAIL_OPEN`) must be false in prod/staging. | runtime invariant + hardening tests. | `make soc-invariants`, `make test-auth-hardening` | Y |
| SOC-P0-003 | `/decisions`, `/feed/live`, `/feed/stream` must deny unscoped or cross-tenant reads. | integration tests in protected suites. | `make test-tenant-isolation` | Y |
| SOC-P0-004 | Governance endpoints must require auth and fail closed on DB errors. | integration tests + startup validation. | `make test-auth-hardening` | Y |
| SOC-P0-005 | `FG_ENFORCEMENT_MODE` must be `enforce` in prod/staging. | runtime invariant + CI matrix (`FG_ENV=prod/staging`). | `make enforcement-mode-matrix` | Y |
| SOC-P0-006 | Tripwire egress policy must block disallowed webhook destinations. | security regression checks + targeted tests. | `make security-regression-gates` | Y |
| SOC-P0-007 | Admin redirect/CORS must reject unsafe production values. | admin startup + integration tests. | `make ci-admin` | Y |
| SOC-P1-001 | Route inventory drift is blocked unless snapshot is updated intentionally. | AST route extraction + snapshot diff. | `make route-inventory-audit` | Y |
| SOC-P1-002 | New fallback module import paths in runtime API are blocked. | static pattern checks in `tools/ci/check_soc_invariants.py`. | `make soc-invariants` | Y |
| SOC-P1-003 | Redirect-following HTTP clients are restricted to approved wrappers/files. | static pattern checks in `tools/ci/check_soc_invariants.py`. | `make soc-invariants` | Y |
| SOC-HIGH-001 | Protected security/invariant suites cannot contain vacuous assertions without explicit suppression. | test-quality static scan with suppression markers. | `make test-quality-gate` | Y |
| SOC-HIGH-002 | Security-critical PRs must update SOC review/execution docs. | diff-aware sync check. | `make soc-review-sync` | Y |

# MVP2 Stage Gate Definition

**MVP2 is achieved when ALL of the following are true:**

- [ ] `make soc-invariants` passes.
- [ ] `make prod-profile-check` passes.
- [ ] `make enforcement-mode-matrix` passes for `FG_ENV=prod` and `FG_ENV=staging`.
- [ ] `make security-regression-gates` passes.
- [ ] `make test-tenant-isolation` passes.
- [ ] `make ci-admin` passes.
- [ ] `make route-inventory-audit` passes.
- [ ] `make test-quality-gate` passes.
- [ ] `make soc-review-sync` passes.

Gate semantics:
- Binary pass/fail only.
- Zero exceptions in release branch.
- Every P0/P1/HIGH finding above maps to at least one hard-fail gate.

# CI Wiring Plan

## New/updated guard scripts
- `tools/ci/check_soc_invariants.py`
- `tools/ci/check_enforcement_mode_matrix.py`
- `tools/ci/check_route_inventory.py`
- `tools/ci/check_test_quality.py`
- `tools/ci/check_soc_review_sync.py`
- `tools/ci/check_soc_review_sync.py` deepens shallow history in CI to recover merge-base before `origin/${GITHUB_BASE_REF}...HEAD` diff; still fails closed if diff is not computable.

## Makefile targets
- `soc-invariants`
- `enforcement-mode-matrix`
- `route-inventory-generate`
- `route-inventory-audit`
- `test-quality-gate`
- `soc-review-sync`

## Workflow wiring
- `fg_guard` runs `make fg-fast` once (no duplicate execution of sub-gates).
- New `enforcement_mode_matrix` job runs `make enforcement-mode-matrix` to exercise prod/staging runtime invariant pass/fail cases (`enforce`, `observe`, and unset).

## Warning-to-fail promotions
- Observe mode in prod/staging is hard fail via runtime invariants + matrix test.
- Route inventory drift is hard fail.
- Vacuous assertions in protected suites are hard fail.
- Missing SOC doc updates for critical changes are hard fail.

## Risk if skipped
- Silent fallback/observe-mode drift reaches release.
- Route/auth shadow paths can be introduced undetected.
- Regressions are masked by non-assertive tests.
- SOC stage classification drifts from reality.

# Regression Immunity Architecture

1. **Route inventory audit**
   - Generate snapshot: `make route-inventory-generate`.
   - Stage snapshot update: `git add tools/ci/route_inventory.json`.
   - Enforce snapshot: `make route-inventory-audit`.
   - Snapshot file: `tools/ci/route_inventory.json`.
   - Inventory fields include `method`, `path`, `file`, `scoped`, `scopes`, and `tenant_bound`.
   - `scoped` / `tenant_bound` may be `true`, `false`, or `"unknown"` in generated inventory state.
   - Gate behavior:
     - FAIL on known regressions (`true -> false`).
     - FAIL when any unknown classification remains (`unknown` count must be zero).
     - Failure output includes exact `METHOD PATH (file)` rows and remediation hints:
       - `make route-inventory-generate`
       - `git add tools/ci/route_inventory.json`

2. **Fallback import detection**
   - `tools/ci/check_soc_invariants.py` blocks `import ...fallback...` patterns in repo-owned modules under `api/**` and `admin_gateway/**`.
   - The scanner excludes vendored/dependency and cache/build paths (e.g. `.venv`, `site-packages`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `node_modules`, `dist`, `build`) so SOC invariants apply only to first-party code.

3. **HTTP redirect wrapper enforcement**
   - `tools/ci/check_soc_invariants.py` blocks redirect-following clients outside approved files.

4. **Observe-mode runtime lock**
   - `api/config/prod_invariants.py` enforces `FG_ENFORCEMENT_MODE=enforce` in prod/staging.
   - `tools/ci/check_enforcement_mode_matrix.py` validates both pass/fail paths.

5. **Protected test-quality checks**
   - `tools/ci/check_test_quality.py` scans only protected suites: `tests/security/**` and invariant suites (`tests/**/test_*invariant*.py`).
   - Vacuous assertions require a strict, auditable marker on a nearby line:
     - `# SOC:ALLOW_VACUOUS_ASSERT reason="temp during refactor" remove_by="YYYY-MM-DD"`
   - Marker rules are enforced:
     - `reason` must be present and non-empty.
     - `remove_by` must be valid `YYYY-MM-DD` and not in the past.
     - total suppressions in protected suites must be `<= 10` in CI.
     - local-only cleanup override: `FG_TEST_QUALITY_SUPPRESSION_CAP` (ignored when `CI=true`).
     - example local usage: `FG_TEST_QUALITY_SUPPRESSION_CAP=15 make test-quality-gate`.
   - TODO-based skip markers are forbidden in protected suites.

# SOC Review Integration Plan

- Required docs:
  - `docs/SOC_ARCH_REVIEW_2026-02-15.md`
  - `docs/SOC_EXECUTION_GATES_2026-02-15.md`

- Required PR checklist:
  - `.github/PULL_REQUEST_TEMPLATE.md` references SOC findings and validating CI gates.

- Remediation pipeline:
  - `tools/ci/soc_findings_manifest.json` status values are constrained to `open`, `partial`, `mitigated`.
  - `mitigated` findings must include `evidence` (string path or list of paths).
  - Each evidence path must exist and include at least one CI/test linkage (`tests/**`, `tools/ci/**`, or gate-linked path).
  - `tools/ci/check_soc_invariants.py` enforces ID format, required P0 coverage, status validity, gate presence, and evidence-file existence/linkage.


## Mainline Rebase Hygiene

If PR diffing indicates `docs/SOC_ARCH_REVIEW_2026-02-15.md` is shown as newly added unexpectedly, rebase must be executed in the developer’s local clone against `origin/main` if required.
Use `make rebase-main-instructions` for the exact command sequence and verification check.


Note: SOC ID enforcement in CI is manifest-backed (`tools/ci/soc_findings_manifest.json`) and does not require ID tokens in prose-only review sections.

## 2026-02-16 — SOC manifest verify/sync tool hardening

- Added/updated `tools/ci/sync_soc_manifest_status.py` to provide production-grade SOC manifest verification and sync:
  - Explicit `--mode verify|sync` behavior (no misleading output).
  - Deterministic gate execution with timeout + parallelism.
  - Strict manifest schema validation + evidence existence checks.
  - Atomic write with no-churn behavior (writes only when changes occur).
  - Improved diagnostics on gate failures (tail output).

Validation:
- `make soc-manifest-verify`
- `make soc-manifest-sync`
- `make fg-fast`

## Usage

- Verify mode checks schema, evidence, gate results, and unresolved P0 findings without modifying the manifest.
- Sync mode applies only safe upgrades (`non-final -> mitigated`) when the gate passes and evidence exists, and writes only when content changes.
- CI wiring:
  - `make soc-manifest-verify` runs `PYTHONPATH=. .venv/bin/python tools/ci/sync_soc_manifest_status.py --mode verify --fail-on-unresolved-p0`.
  - `make soc-manifest-verify` is part of `make fg-fast` (developer lane).
  - CI uses `make fg-fast-full`/`make fg-fast-ci` to include `opa-check` in addition to `fg-fast`.
  - `make soc-manifest-sync` is opt-in/manual and is not part of `fg-fast`.
- Local commands:
  - `PYTHONPATH=. .venv/bin/python tools/ci/sync_soc_manifest_status.py --mode verify --fail-on-unresolved-p0`
  - `PYTHONPATH=. .venv/bin/python tools/ci/sync_soc_manifest_status.py --mode sync --write`
  - `make fg-fast`


## 2026-02-16 — Audit spine hardening gates

Audit determinism + evidence chain controls are now required in strict lanes:

- `make audit-chain-verify`
- `make audit-export-verify-determinism`
- `make audit-checkpoint-verify`
- `make audit-evidence-verify`

These are wired into `fg-fast-ci` / `fg-fast-full` and are fail-closed on:

- manifest signature mismatch
- export non-determinism
- checkpoint/chain tamper detection failures
- missing evidence metadata invariants

- offline evidence verification: `.venv/bin/python scripts/fg_audit_verify.py --bundle <export.zip> --pubkeys <keys.json>`
- prod invariant requires `FG_AUDIT_VERIFY_REQUIRED=1`; disabling verification is a startup hard-fail.

- offline verifier supports `--json` machine-readable reason codes with deterministic exit codes (0 pass / 1 fail).
