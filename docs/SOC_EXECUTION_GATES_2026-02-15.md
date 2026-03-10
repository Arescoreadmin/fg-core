## 2026-03-09 — SOC-HIGH-002 — route inventory CI write suppression and compatibility shim

**Change class:** CI/CD governance verification hardening

### Files reviewed
- `tools/ci/check_route_inventory.py`

### Summary
Hardened route inventory governance behavior so CI verification does not mutate tracked artifacts, and restored a backwards-compatibility shim required by existing route inventory summary tests.

### Rationale
`fg-fast` / `fg-required` could leave the working tree dirty because route inventory governance tooling could write tracked artifacts during CI execution. Verification paths in CI must be read-only.

Separately, route inventory summary tests still reference `_inventory_from_data`, which had been removed during refactor. A compatibility shim was restored to preserve the existing test contract without weakening the refactored implementation.

### Changes reviewed
- Added CI environment detection in `tools/ci/check_route_inventory.py`
- Suppressed `--write` behavior when `CI` is set
- Added explicit operator-facing messages:
  - `route inventory: write suppressed in CI`
  - `refusing to mutate tracked inventory artifacts when CI is set`
- Restored `_inventory_from_data()` as a compatibility shim delegating to `_inventory_from_doc()`
- Preserved explicit local regeneration path via:
  - `make route-inventory-generate`

### Verification
- Confirmed `tools/ci/check_route_inventory.py` compiles successfully
- Confirmed route inventory summary tests pass with compatibility shim restored
- Confirmed CI write path is blocked in CI mode
- Confirmed local explicit write mode remains available outside CI
- Intended outcome is elimination of dirty-tree mutation during CI verification while preserving test/tool compatibility

SOC review outcome:
- `soc-review-sync` coverage satisfied for `tools/ci/check_route_inventory.py`

## 2026-03-09 — SOC-HIGH-002 — route inventory writes suppressed during CI verification

**Change class:** CI/CD governance and verification behavior

### Files reviewed
- `tools/ci/check_route_inventory.py`

### Summary
Hardened route inventory verification so CI cannot mutate tracked route inventory artifacts during verification or test execution.

### Rationale
`fg-required` detected a dirty working tree after `fg-fast` because `tools/ci/route_inventory_summary.json` was being rewritten during CI execution. Governance verification lanes must be read-only in CI. Tracked inventory artifacts may be regenerated locally via explicit write mode, but CI verification must never mutate the repository state.

### Changes reviewed
- Added CI environment detection in `tools/ci/check_route_inventory.py`
- Suppressed `--write` behavior when `CI` is set
- Added explicit operator-facing message:
  - `route inventory: write suppressed in CI`
  - `refusing to mutate tracked inventory artifacts when CI is set`
- Preserved local regeneration path via:
  - `make route-inventory-generate`

### Verification
- Confirmed modified file compiles successfully
- Confirmed route inventory write path is now blocked in CI mode
- Confirmed local explicit write mode remains available outside CI
- Intended outcome is elimination of dirty-tree mutation from `tools/ci/route_inventory_summary.json` during `fg-fast` / `fg-required`

SOC review outcome:
- `soc-review-sync` coverage satisfied for `tools/ci/check_route_inventory.py`

## 2026-03-09 — SOC-HIGH-002 — docker-ci debug preflight uses baseline runner tooling

**Change class:** CI/CD workflow execution surface

### Files reviewed
- `.github/workflows/docker-ci.yml`

### Summary
Adjusted the docker-ci console source-tree debug preflight to use baseline runner tooling only.

### Rationale
The prior debug preflight used `rg`, which is not guaranteed on the GitHub runner image for this workflow and caused the diagnostic step itself to fail before the intended docker validation path executed. Replacing `rg` with `grep` preserves diagnostic coverage without introducing an undeclared runner dependency.

### Changes reviewed
- Replaced `rg` usage with `grep -RInE` in docker-ci debug preflight
- Replaced `rg` usage with `grep -RInE` in docker-ci failure dump path
- Preserved source-tree verification coverage for:
  - `@/lib/coreApi`
  - `@/lib/api`
  - `@/styles/tokens`
  - `@/components/tables/DecisionsTable`

### Verification
- Reviewed `.github/workflows/docker-ci.yml`
- Confirmed debug preflight now relies only on standard runner shell tooling
- Confirmed failure diagnostics still capture console import/path state before and after build failure

SOC review outcome:
- `soc-review-sync` coverage satisfied for `.github/workflows/docker-ci.yml`

## 2026-03-09 — SOC-HIGH-002 — docker-ci source-tree debug preflight for console build validation

**Change class:** CI/CD workflow execution surface

### Files reviewed
- `.github/workflows/docker-ci.yml`

### Summary
Extended `docker-ci` with explicit runner-side source-tree verification before compose image build and strengthened deterministic CI env bootstrap for compose-backed stack validation.

### Rationale
`docker-validate` showed repeated console build failures in GitHub Actions despite successful local compose builds on the same branch tip. To eliminate ambiguity between stale runner state, checkout drift, and Docker build context issues, the workflow now prints the checked-out commit, confirms required console source files exist on the runner, prints `console/tsconfig.json`, enumerates relevant imports, and records build-context file inventory before compose build.

### Changes reviewed
- Added runner-side debug preflight before docker compose build
- Verified presence of:
  - `console/lib/api.ts`
  - `console/lib/coreApi.ts`
  - `console/styles/tokens.ts`
  - `console/components/tables/DecisionsTable.tsx`
- Printed `console/tsconfig.json` and relevant alias imports
- Extended CI env bootstrap to include:
  - `FG_ENCRYPTION_KEY`
  - `FG_JWT_SECRET`
  - `FG_NATS_URL`
- Switched compose image build to deterministic `--no-cache`

### Verification
- Workflow remains fail-closed
- Compose render still occurs before stack startup
- Failure path now captures runner source-tree state needed to distinguish checkout drift from build/runtime failure

SOC review outcome:
- `soc-review-sync` coverage satisfied for `.github/workflows/docker-ci.yml`

## 2026-03-09 — SOC-HIGH-002 — fg-required compose env bootstrap for prod-profile-check

**Change class:** CI/CD workflow execution surface

### Files reviewed
- `.github/workflows/fg-required.yml`

### Summary
Extended the `fg-required` workflow to create a deterministic CI `.env` before running compose-backed gates.

### Rationale
`fg-fast` executes `prod-profile-check`, which runs `docker compose config`. Compose requires all interpolated variables to be present in `.env`. The workflow previously lacked required values such as `NATS_AUTH_TOKEN` and `FG_WEBHOOK_SECRET`, causing false-negative CI failures unrelated to application correctness.

### Changes reviewed
- Added CI `.env` bootstrap step in `fg-required.yml`
- Included deterministic placeholder values for:
  - `FG_API_KEY`
  - `FG_WEBHOOK_SECRET`
  - `FG_AGENT_API_KEY`
  - `REDIS_PASSWORD`
  - `POSTGRES_PASSWORD`
  - `NATS_AUTH_TOKEN`
  - `FG_NATS_URL`
  - `FG_ENCRYPTION_KEY`
  - `FG_JWT_SECRET`

### Verification
- Reviewed `.github/workflows/fg-required.yml`
- Confirmed workflow now provides required env interpolation inputs for compose-backed validation
- Confirmed this change preserves fail-closed behavior while removing CI-only env drift

SOC review outcome:
- `soc-review-sync` coverage satisfied for `.github/workflows/fg-required.yml`

## 2026-03-09 — SOC-HIGH-002 — fg-required timeout budget increase

**Change class:** CI/CD workflow execution surface

### Files reviewed
- `.github/workflows/fg-required.yml`

### Summary
Increased the fg-required job and lane timeout budgets so the `fg-fast` lane is not terminated early by harness or workflow limits.

### Rationale
Recent `fg-fast` runtime exceeds the prior fg-required lane timeout in CI, causing false-negative failures due to timeout rather than gate failure.

### Verification
- Reviewed `.github/workflows/fg-required.yml`
- Confirmed timeout budget changes align with observed `fg-fast` runtime
- Confirmed SOC review coverage for workflow execution change

SOC review outcome:
- `soc-review-sync` coverage satisfied for `.github/workflows/fg-required.yml`

## 2026-03-09T00:00:00Z — SOC-HIGH-002 — CI workflow hardening for compliance and fg-required stability

**Change class:** CI/CD execution surface (SOC-HIGH-002)

### Files reviewed
- `.github/workflows/ci.yml`
- `.github/workflows/fg-required.yml`

### Summary
- Hardened compliance workflow behavior around artifact generation and verification.
- Increased fg-required runtime budget to better match real fg-fast lane execution time.
- Improved CI resilience and artifact/debug handling for workflow-based gates.

### Rationale
- Prior workflow behavior could fail due to brittle assumptions around compliance artifact production and tight fg-required lane timing.
- The updated workflow reduces false-negative CI failures while preserving fail-closed verification.

### Verification
- Reviewed workflow changes in `.github/workflows/ci.yml`.
- Reviewed fg-required timeout/budget changes in `.github/workflows/fg-required.yml`.
- Confirmed SOC review sync coverage for both workflow files.

SOC review outcome:
- `soc-review-sync` coverage satisfied for CI workflow changes.

## 2026-03-09T00:00:00Z — SOC-HIGH-002 — compliance artifact discovery hardening

**Change class:** CI/CD execution surface (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/ci.yml`

### Summary
- Hardened compliance artifact verification to discover SBOM/provenance/CIS/SCAP outputs under `artifacts/` instead of assuming one rigid SBOM path.
- Broadened compliance artifact upload coverage so CI retains generated JSON evidence even when the SBOM location differs from the old fixed path.
- Added artifact inspection output to improve CI triage when compliance generation paths drift.

### Rationale
- The prior workflow assumed `artifacts/sbom.json`, but CI showed SBOM output was not always present at that exact location.
- This caused false-negative workflow failures during artifact verification and upload even when compliance generation partially succeeded.
- The update keeps the gate fail-closed while making artifact discovery path-robust.

### Verification
- Reviewed `.github/workflows/ci.yml` compliance job changes.
- Confirmed SOC review sync requirement is satisfied for this workflow-path update.

SOC review outcome:
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

## 2026-03-08T00:00:00Z — SOC-HIGH-002 — fg-required timeout budget alignment

**Change class:** CI/CD execution surface (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/fg-required.yml`

### Summary
- Increased `fg-required` job timeout budget to align with current `fg-fast` runtime.
- Increased the `run fg-required` step timeout so GitHub Actions does not kill the lane before the harness budget expires.
- Kept artifact capture in place so failed-lane logs remain available for triage.

### Rationale
- `fg-fast` now completes successfully locally but exceeds the prior 480-second / 8-minute CI lane budget.
- The prior failure mode was a timeout, not a test/assertion failure.
- This change aligns GitHub job/step timeout budgets with the harness runtime budget.

### Verification
- Reproduced the lane locally via `tools/testing/harness/fg_required.py`.
- Confirmed failure mode was `lane_timeout`.
- Confirmed lane log contained:
  - `make fg-fast`
  - `[timeout]`

SOC review outcome:
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

## 2026-03-07T02:15:00Z — SOC-HIGH-002 — CI workflow and route inventory governance sync

**Change class:** CI/CD execution surface and governance artifact sync (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/ci.yml`
- `.github/workflows/docker-ci.yml`
- `tools/ci/route_inventory_summary.json`

SOC review outcome:
- Reviewed CI workflow changes that hard-fail on stale OPA runtime config and improve fg-fast failure capture/logging.
- Reviewed docker validation workflow alignment for compose stack hardening, bootstrap/migration execution, and admin-gateway database wiring.
- Reviewed regenerated route inventory summary artifact to confirm governance metadata remains synchronized with current route inventory state.
- `make soc-review-sync` must pass with these files included in the SOC review record.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

## 2026-03-07T02:15:00Z — SOC-HIGH-002 — Plane registry inventory alignment for /v1/defend

**Change class:** CI/governance route inventory alignment (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/plane_registry_checks.py`
- `tools/ci/route_inventory.json`
- `tools/ci/route_inventory_summary.json`

### Why this changed
- Aligned AST-derived runtime inventory with the canonical `/v1/defend` alias that is mounted at runtime and present in the core contract.
- This removes false contract/runtime drift for `/v1/defend` during route inventory and plane registry checks.

### Risk review
- Change is limited to governance/inventory generation, not request handling behavior.
- Runtime route ownership and contract route coverage were revalidated after regeneration.
- `control-plane-check` now passes with `/v1/defend` represented consistently.

### Verification
- `python -m py_compile tools/ci/plane_registry_checks.py`
- `make route-inventory-generate`
- `make route-inventory-audit`
- `make control-plane-check`
- `make soc-review-sync`

SOC review outcome:
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.


## 2026-03-06T23:00:00Z — SOC-HIGH-002 — OPA config merge-error guard and stale config removal

**Change class:** CI/CD execution surface (SOC-HIGH-002)

**Issue:** CI OPA validation was vulnerable to stale duplicate config files under `policy/opa/`, causing merge errors during `opa-check`. The workflow was also missing an explicit fail-fast guard for this condition.

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/ci.yml`
- `policy/opa/opa-config.yml`

### Review summary
- Added CI fail-fast validation in `.github/workflows/ci.yml` to require `policy/opa/config.yaml` and fail if stale `policy/opa/opa-config.yml` exists.
- Removed stale `policy/opa/opa-config.yml` to eliminate duplicate top-level OPA YAML documents that caused merge errors during policy loading.
- Confirmed the canonical runtime OPA config remains `policy/opa/config.yaml`.

### Risk assessment
- Low implementation risk.
- Positive security and reliability impact because CI now fails deterministically on duplicate OPA config state instead of failing later inside policy validation.

### Validation
- `make soc-review-sync`
- `make opa-check`

SOC review outcome:
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.
## 2026-03-06T22:55:00Z — SOC-HIGH-002 — docker-ci and compose governance alignment

**Change class:** CI/CD execution surface (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/docker-ci.yml`
- `docker-compose.yml`

SOC review outcome:
- Verified docker validation workflow aligns with the profiled compose stack used by the repo.
- Verified compose core service naming now matches production-profile governance expectations.
- Verified admin gateway DB configuration no longer falls back to SQLite on read-only filesystem.
- `make prod-profile-check`: passed
- `make soc-invariants`: passed
- `make soc-review-sync`: expected to pass after this documentation update

<!-- SOC-HIGH-002::docker-ci-compose-alignment::2026-03-06 -->
## 2026-03-03T20:22:44Z — SOC-HIGH-002 — CI workflow governance update

**Change class:** CI/CD execution surface (SOC-HIGH-002)

### Files reviewed (required by SOC-HIGH-002)
- `.github/workflows/fg-required.yml`

### Verification performed
- `make soc-review-sync` (must pass after this entry)
- `make soc-manifest-verify`

<!-- SOC-HIGH-002::a56ee100af646285c520f5401b6821a53f7fffcb::2026-03-03 -->

## 2026-03-03T19:26:45Z — SOC-HIGH-002 — docker-ci workflow update

**Issue:** SOC-HIGH-002 triggered: security-critical CI workflow changed without SOC review acknowledgement.

<!-- SOC-HIGH-002::4773164b51fce50dcbcf139e1672c382ef90b353::2026-03-03 -->

### Critical-path files reviewed (SOC-HIGH-002)
- `.github/workflows/docker-ci.yml`

SOC review outcome:
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## 2026-03-01T21:24:06Z — SOC-HIGH-002 — Route inventory artifact updated

**Issue:** `tools/ci/route_inventory.json` changed and is classified as a critical SOC-tracked artifact.

**Resolution:** Recorded this change as an approved artifact refresh. No policy semantics changed; inventory updated via `make route-inventory-generate`.

**Files:**
- tools/ci/route_inventory.json

---

## 2026-03-01T19:00:46Z — SOC-HIGH-002 — Route inventory governance update

**Issue:** SOC-HIGH-002 triggered: critical CI governance artifacts changed without SOC review acknowledgement.

**Resolution:** Updated route inventory pipeline + plane registry checks; regenerated route inventory; recorded this change for SOC traceability.

**Files changed:**
- `tools/ci/check_route_inventory.py`
- `tools/ci/plane_registry_checks.py`
- `tools/ci/route_inventory.json`

**Entry policy:** Exactly one issue + one resolution per entry. If additional issues exist, add separate entries.

<!-- SOC-HIGH-002::854d66dd93ea1b3007b82c2b85851ce605d50480::2026-03-01 -->

# SOC Enforceable Findings Matrix (Release Authority)

This matrix defines **hard release invariants**.  
All gates are binary pass/fail. No warnings. No release exceptions.

---

## Findings Matrix

| Finding ID | Invariant | Enforcement Mechanism | CI Gate | Release Blocker |
|------------|-----------|-----------------------|---------|------------------|
| SOC-P0-001 | `FG_AUTH_ALLOW_FALLBACK` must be `false` in prod/staging runtime invariants. | Runtime invariant + prod profile validation. | `make soc-invariants`, `make prod-profile-check` | Y |
| SOC-P0-002 | Fail-open controls (`FG_RL_FAIL_OPEN`, `FG_AUTH_DB_FAIL_OPEN`) must be `false` in prod/staging. | Runtime invariant + hardening tests. | `make soc-invariants`, `make test-auth-hardening` | Y |
| SOC-P0-003 | `/decisions`, `/feed/live`, `/feed/stream` must deny unscoped or cross-tenant reads. | Integration tests (tenant isolation suites). | `make test-tenant-isolation` | Y |
| SOC-P0-004 | Governance endpoints must require authentication and fail closed on DB errors. | Integration tests + startup validation. | `make test-auth-hardening` | Y |
| SOC-P0-005 | `FG_ENFORCEMENT_MODE` must be `enforce` in prod/staging. | Runtime invariant + enforcement matrix test. | `make enforcement-mode-matrix` | Y |
| SOC-P0-006 | Tripwire egress policy must block disallowed webhook destinations. | Security regression tests. | `make security-regression-gates` | Y |
| SOC-P0-007 | Admin redirect and CORS must reject unsafe production values. | Admin startup validation + integration tests. | `make ci-admin` | Y |
| SOC-P1-001 | Route inventory drift is blocked unless snapshot is intentionally regenerated. | AST route extraction + snapshot diff. | `make route-inventory-audit` | Y |
| SOC-P1-002 | Fallback module imports in runtime API are prohibited. | Static invariant scan. | `make soc-invariants` | Y |
| SOC-P1-003 | Redirect-following HTTP clients are restricted to approved wrappers/files. | Static invariant scan. | `make soc-invariants` | Y |
| SOC-HIGH-001 | Protected security/invariant test suites cannot contain vacuous assertions without explicit suppression. | Static test-quality scan with enforced suppression rules. | `make test-quality-gate` | Y |
| SOC-HIGH-002 | Security-critical file changes require SOC review documentation updates. | Diff-aware SOC sync verification. | `make soc-review-sync` | Y |

---

# MVP2 Stage Gate Definition

MVP2 is achieved only when ALL gates pass:

- [ ] `make soc-invariants`
- [ ] `make prod-profile-check`
- [ ] `make enforcement-mode-matrix`
- [ ] `make security-regression-gates`
- [ ] `make test-tenant-isolation`
- [ ] `make ci-admin`
- [ ] `make route-inventory-audit`
- [ ] `make test-quality-gate`
- [ ] `make soc-review-sync`
- [ ] `make soc-manifest-verify`

## Gate Semantics

- Binary pass/fail only.
- Zero suppressed P0 violations.
- Zero unresolved HIGH findings.
- No exceptions in release branches.
- Every matrix entry maps to at least one enforced CI gate.

---

# CI Wiring Architecture

## Guard Scripts

- `tools/ci/check_soc_invariants.py`
- `tools/ci/check_enforcement_mode_matrix.py`
- `tools/ci/check_route_inventory.py`
- `tools/ci/check_test_quality.py`
- `tools/ci/check_soc_review_sync.py`
- `tools/ci/sync_soc_manifest_status.py`

### SOC Review Sync Behavior

`check_soc_review_sync.py`:

- Computes diff against merge-base (`origin/${GITHUB_BASE_REF}...HEAD`)
- Deepens shallow clones in CI when necessary
- Fails closed if diff cannot be computed
- Blocks changes to security-critical paths unless SOC docs are updated

---

# Makefile Targets

- `soc-invariants`
- `enforcement-mode-matrix`
- `route-inventory-generate`
- `route-inventory-audit`
- `test-quality-gate`
- `soc-review-sync`
- `soc-manifest-verify`
- `soc-manifest-sync`

---

# Workflow Wiring

- `fg-fast` → developer enforcement lane
- `fg-fast-full` / `fg-fast-ci` → extended CI lane
- `soc-manifest-verify` is part of `fg-fast`
- `soc-manifest-sync` is manual only

---

# Warning → Hard-Fail Promotions

The following are hard failures:

- Observe mode in prod/staging
- Route inventory drift
- Vacuous assertions in protected suites
- Missing SOC doc updates for critical file changes
- Unresolved P0 findings in manifest
- Missing evidence linkage for mitigated findings

---

# Regression Immunity Architecture

## 1. Route Inventory Audit

Snapshot file: `tools/ci/route_inventory.json`

Inventory fields:

- `method`
- `path`
- `file`
- `scoped`
- `scopes`
- `tenant_bound`

Allowed values for `scoped` and `tenant_bound`:

- `true`
- `false`
- `"unknown"`

### Gate Behavior

FAIL if:

- Any regression (`true → false`)
- Any `"unknown"` remains
- Snapshot drift without intentional regeneration

Remediation:

```
make route-inventory-generate
git add tools/ci/route_inventory.json
```

---

## 2. Fallback Import Detection

`check_soc_invariants.py` blocks `import ...fallback...` patterns under:

- `api/**`
- `admin_gateway/**`

Excluded paths:

- `.venv`
- `site-packages`
- `__pycache__`
- `.pytest_cache`
- `.mypy_cache`
- `node_modules`
- `dist`
- `build`

SOC invariants apply only to first-party code.

---

## 3. Redirect-Following Client Restrictions

Redirect-following HTTP clients are allowed only in explicitly approved wrappers/files.  
All other occurrences are hard-fail.

---

## 4. Observe-Mode Runtime Lock

`api/config/prod_invariants.py` enforces:

- `FG_ENFORCEMENT_MODE=enforce` in prod/staging.

Matrix tests validate both pass and fail branches.

---

## 5. Protected Test Quality Enforcement

Protected suites:

- `tests/security/**`
- `tests/**/test_*invariant*.py`

Vacuous assertions require explicit suppression marker:

```
# SOC:ALLOW_VACUOUS_ASSERT reason="..." remove_by="YYYY-MM-DD"
```

Rules:

- `reason` must be non-empty.
- `remove_by` must be valid date and not expired.
- Total suppressions ≤ 10 in CI.
- `FG_TEST_QUALITY_SUPPRESSION_CAP` allowed locally only (ignored when `CI=true`).
- TODO-based skip markers are forbidden.

---

# SOC Manifest Governance

Manifest file:

`tools/ci/soc_findings_manifest.json`

Allowed status values:

- `open`
- `partial`
- `mitigated`

Mitigated findings must:

- Include `evidence`
- Reference existing file paths
- Link to at least one:
  - `tests/**`
  - `tools/ci/**`
  - Gate-enforced file

`sync_soc_manifest_status.py` enforces:

- Schema validity
- Required P0 coverage
- Gate presence
- Evidence existence
- Deterministic atomic writes

---

# Mainline Rebase Hygiene

If SOC docs appear as newly added unexpectedly in a PR:

```
make rebase-main-instructions
```

Rebase locally against `origin/main` before re-running SOC gates.

---

# Local Usage

```
make soc-manifest-verify
make soc-manifest-sync
make fg-fast
make fg-fast-full
```

---

## SOC Review Sync Update Log

### 2026-02-21 — Egress policy + CI guard refresh

Critical-path files updated in this change set:

- `api/security/outbound_policy.py`
- `api/security_alerts.py`
- `tools/ci/check_plane_boundaries.py`
- `tools/ci/check_security_exception_swallowing.py`
- `tools/ci/route_inventory.json`

SOC review outcome:

- Egress policy logic was centralized and consumed by security alert + tripwire paths.
- New CI guards were added for plane-boundary imports and forbidden exception swallowing in security code.
- Route inventory updates were reviewed for connector ownership drift only; no intentional scope/tenant weakening accepted.

Gate impact:

- `soc-review-sync` satisfied by this documentation update.
- No SOC invariant gate exceptions were added.

Direct invocation:

```
PYTHONPATH=. .venv/bin/python tools/ci/sync_soc_manifest_status.py --mode verify --fail-on-unresolved-p0
PYTHONPATH=. .venv/bin/python tools/ci/sync_soc_manifest_status.py --mode sync --write
```


## 2026-02-18 Additive Security/Platform Gate Update

Reviewed critical-path additive changes for SOC-HIGH-002 coverage:
- `api/auth_federation.py`
- `api/middleware/resilience_guard.py`
- `tools/ci/check_openapi_security_diff.py`
- `tools/ci/check_artifact_policy.py`
- `tools/ci/check_governance_invariants.py`
- `tools/ci/check_plane_registry.py`
- `tools/ci/check_route_inventory.py`
- `tools/ci/check_security_regression_gates.py`
- `tools/ci/openapi_baseline.json`
- `tools/ci/protected_routes_allowlist.json`
- `tools/ci/artifact_policy_allowlist.json`
- `tools/ci/route_inventory.json`

Disposition: additive-only governance hardening; no route removals; deterministic gate/test coverage added.


## 2026-02-18 Formatting-only follow-up

Reviewed formatting-only edits to critical paths:
- `api/auth_federation.py`
- `api/middleware/resilience_guard.py`

Disposition: no semantic change; formatting normalization only.


## 2026-02-18 Security Review Sync Update

- Updated SOC review for Enterprise AI Console route additions and corresponding route inventory regeneration (`tools/ci/route_inventory.json`).
- Confirmed `tools/ci/validate_ai_contracts.py` is part of security-critical CI surface and remains enforced through `fg-contract`/CI lanes.
- Re-validated that `route-inventory-audit` and `soc-review-sync` must pass before merge.


## 2026-02-22 Control Plane Route Inventory and Static Analyzer Update

Critical-path files updated in this change set:

- `tools/ci/route_checks.py`
- `tools/ci/route_inventory.json`

SOC review outcome:

- `route_checks.py`: extended `_function_has_tenant_binding` to recognize two
  additional tenant-binding call patterns introduced by the new
  `/control-plane/*` API surface:
  - `_tenant_from_auth()` — used by all read endpoints; extracts tenant_id
    exclusively from the verified auth context (`request.state.auth`), never
    from caller-supplied headers or query params.
  - `_locker_command()` — the shared dispatch helper for all POST locker
    command endpoints (restart/pause/resume/quarantine); internally calls
    `_tenant_from_auth` and enforces fail-closed tenant binding before
    dispatching any command.
  These additions are purely additive to the recognizer; no existing
  detection patterns were removed or weakened.

- `route_inventory.json`: regenerated to include 10 new `/control-plane/*`
  routes. All 10 are classified `scoped=true` and `tenant_bound=true`.
  No existing route had its `scoped` or `tenant_bound` field regressed.

Security invariants confirmed:

- No route removed from inventory.
- No scope regression (true → false) on any existing route.
- No tenant_bound regression (true → false) on any existing route.
- All new routes require explicit scope (`control-plane:read`,
  `control-plane:admin`, or `control-plane:audit:read`).
- Tenant isolation enforced at auth context layer; global admin (no tenant
  binding) access is intentional and audited on every operation.

Gate impact:

- `route-inventory-audit` (SOC-P1-001): satisfied by regenerated inventory.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## Control Plane v2 — Route Inventory and CI Guard Update (2026-02-22)

### Changes

- `tools/ci/route_inventory.json`: regenerated to include 14 new
  `/control-plane/v2/*` and `/control-plane/evidence/bundle` routes
  introduced by `api/control_plane_v2.py`. All 14 routes are classified
  `scoped=true` and `tenant_bound=true`. No existing route had its `scoped`
  or `tenant_bound` field regressed.

- `tools/ci/check_control_plane_v2_invariants.py`: new CI guard with 16
  non-vacuous invariant checks for the Control Plane v2 implementation.
  Checks include: required tables in migration 0027, hash chain logic,
  no subprocess usage, receipt executor auth, MSP cross-tenant scope,
  no header-based tenant derivation, DB flush before return, command and
  playbook allowlists, append-only triggers, ledger verify endpoint,
  evidence bundle endpoint, compilation, negative test coverage, model
  structure, and router registration.

### Security Invariants Confirmed

- No route removed from inventory.
- No scope regression (true → false) on any existing route.
- No tenant_bound regression (true → false) on any existing route.
- All 14 new routes require explicit scope (`control-plane:read`,
  `control-plane:admin`, or `control-plane:audit:read`).
- Tenant isolation enforced via `_tenant_from_auth()` at auth context layer;
  MSP cross-tenant access requires explicit `control-plane:msp:read` or
  `control-plane:msp:admin` scope and emits cross-tenant audit events.
- Anti-enumeration 404 applied for unauthorized cross-tenant access.
- Append-only tables enforced by DB triggers (migration 0027).
- Hash-chain integrity verified by `verify_chain` endpoint.

### Gate Impact

- `route-inventory-audit` (SOC-P1-001): satisfied by regenerated inventory.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## Control Plane Phase 3 — Scope Refactor and Route Checker Hardening (2026-02-23)

### Changes

- `tools/ci/route_checks.py`: extended `_function_has_tenant_binding()` to
  recognise `_tenant_id_from_request` and `_tenant_id_from_request_optional`
  as tenant-binding signals. These internal helpers (equivalent to the
  previously recognised `_tenant_from_auth`) are used by the rewritten Phase 3
  control-plane routes; without this change the AST checker incorrectly
  classified seven routes as `tenant_bound: "unknown"`.

- `tools/ci/route_inventory.json`: regenerated after the route_checks fix.
  All control-plane routes that were previously classified `tenant_bound: true`
  retain that classification. No existing route had its `scoped` or
  `tenant_bound` field regressed.

- `api/control_plane.py`: scope identifiers updated from generic `admin:read` /
  `admin:write` to purpose-specific `control-plane:read`, `control-plane:admin`,
  and `control-plane:audit:read`. Tenant-guard added to `get_boot_trace` to
  restore the cross-tenant 404 anti-enumeration protection present in the
  previous implementation.

### Security Invariants Confirmed

- No route removed from inventory.
- No scope regression (true → false) on any existing route.
- No tenant_bound regression (true → false) on any existing route.
- All control-plane routes continue to require explicit scopes.
- Tenant isolation enforced via `_tenant_id_from_request_optional()` /
  `_tenant_id_from_request()` at auth context layer; cross-tenant access
  returns 404 (anti-enumeration).
- Route checker change is additive (new recognised names only); no previously
  passing routes can be made to appear tenant-bound by this change.

### Gate Impact

- `route-inventory-audit` (SOC-P1-001): satisfied by regenerated inventory.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## 8-Plane Governance / Attestation Controls Hardening (2026-02-24)

### Changes

- `tools/ci/check_plane_registry.py`: tightened governance checks with explicit
  `/admin` ownership policy (`control_only`), non-permanent exception lifecycle
  enforcement (`expires_at` required, expiry format checks, warn <=30 days,
  fail expired and >90-day horizon), and CI runtime-app mode hard-fail when
  dependencies are missing unless explicit local override is set.

- `tools/ci/check_route_inventory.py`: preserved per-build attestation bundle
  output and added deterministic topology hashing (`topology.sha256`) over
  stable governance topology artifacts.

- `tools/ci/plane_registry_checks.py`: continued central route extraction and
  ownership matching path used by both inventory and plane registry gates.

- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`,
  `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`,
  `tools/ci/plane_registry_snapshot.sha256`, `tools/ci/attestation_bundle.sha256`,
  `tools/ci/build_meta.json`, `tools/ci/topology.sha256`: regenerated via the
  hardened inventory pipeline as governance evidence artifacts.

### Security Invariants Confirmed

- `/admin*` route ownership is deterministic and explicitly modeled as
  control-plane owned.
- Temporary exceptions cannot become indefinite backlog entries without explicit
  permanence flag and justification metadata.
- Runtime-app verification is enforced in CI mode (fail-closed without
  dependency override).
- Deterministic topology hash and per-build attestation hash are separated,
  avoiding policy ambiguity between reproducible governance topology and
  chain-of-custody build evidence.

### Gate Impact

- `check_plane_registry`: strengthened (ownership, exception lifecycle,
  runtime-app CI behavior).
- `route-inventory-audit`: strengthened (deterministic topology hash +
  attestation bundle output).
- `soc-review-sync`: satisfied by this SOC execution gates update.

---

## 2026-02-25 Legacy Disabled UI Route Removal + Inventory Sync

### Critical-path files reviewed (SOC-HIGH-002)

- `tools/ci/route_inventory.json`
- `tools/ci/route_inventory_summary.json`

### Change summary

- Confirmed removal of legacy disabled route exposure from runtime surface
  (`GET /_legacy/ui_feed/_disabled` no longer appears in inventory).
- Confirmed inventory snapshot and summary were intentionally regenerated and
  route counts adjusted by exactly one route.
- Added regression test coverage to guard both inventory and source-level
  reintroduction of forbidden legacy disabled route paths.

### Security impact assessment

- No auth/scope/tenant weakening introduced.
- Change reduces exposed route surface and exception burden in plane governance.

### Gate impact

- `route-inventory-audit` (SOC-P1-001): satisfied by intentional snapshot update.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## 2026-02-25 Route Inventory Schema Normalization (Object Payload)

### Critical-path files reviewed (SOC-HIGH-002)

- `tools/ci/check_route_inventory.py`
- `tools/ci/check_openapi_security_diff.py`
- `tools/ci/check_governance_invariants.py`
- `tools/ci/route_inventory.json`

### Change summary

- Normalized `tools/ci/route_inventory.json` to an object payload with metadata
  and a `routes` array so strict schema readers no longer fail with
  `route_inventory must be an object`.
- Updated route-inventory consumers in CI/security tooling to read from
  `route_inventory.routes`.
- Kept route-diff semantics unchanged (method/path/file keying + scoped /
  tenant-bound regression checks).

### Security impact assessment

- No route authz or tenant-binding controls were relaxed.
- This is a format hardening / compatibility fix to restore deterministic
  route-inventory gate behavior.

### Gate impact

- `route-inventory-audit` (SOC-P1-001): restored by object-schema payload.
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.

---

## 2026-02-25 Route Inventory Audit Hotfix (_dump_json helper)

### Critical-path files reviewed (SOC-HIGH-002)

- `tools/ci/check_route_inventory.py`

### Change summary

- Added explicit JSON serialization helper (`_dump_json`) and wrapper helper
  (`_wrap`) in the route inventory checker, and routed write paths through the
  helper to prevent `NameError: _dump_json is not defined` in audit execution.
- Preserved route-inventory diff semantics and schema checks.

### Gate impact

- `route-inventory-audit` (SOC-P1-001): restored runtime stability (no NameError).
- `soc-review-sync` (SOC-HIGH-002): satisfied by this documentation update.


## SOC Review Update Log

- 2026-02-25: Added `testing-module.yml` CI workflow for fail-closed testing lanes (`fg-fast`, `fg-contract`, `fg-security`, `fg-full`) and validated this workflow remains under SOC-HIGH-002 review-sync governance.
- 2026-02-25: Regenerated `tools/ci/route_inventory.json` and related attestation/topology snapshots after adding Testing Control Tower preview routes so route-inventory and SOC gates remain synchronized.
- 2026-02-26: Moved Testing Control Tower API routes to `/control-plane/v2/testing/*`, tightened scopes/tenant binding, and regenerated route inventory/snapshot artifacts to keep SOC critical-file gates synchronized.
- 2026-02-26: Normalized route-inventory generated governance artifacts to schema `v1` object envelopes (`schema_version/generated_at/data`) and refreshed topology/attestation snapshots plus platform inventory generator compatibility.
- 2026-02-26: Updated CI workflow controls for the required testing gate in `.github/workflows/fg-required.yml` and adjusted `.github/workflows/testing-module.yml` trigger scope to `workflow_dispatch`-only; reviewed under SOC-HIGH-002 to keep critical workflow-path changes synchronized with SOC review evidence.

- 2026-02-26: Hardened `.github/workflows/testing-module.yml` for artifact handoff (`download-artifact` in `fg-flake-detect`), deterministic junit fallback, and non-failing artifact uploads (`if-no-files-found: warn`), and reviewed under SOC-HIGH-002.
- 2026-02-26: Updated Testing Control Tower routes and regenerated `tools/ci/route_inventory.json` to satisfy SOC-P1-001 route inventory drift controls.
- 2026-02-26: Regenerated critical CI governance artifacts (`tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/plane_registry_snapshot.sha256`, `tools/ci/attestation_bundle.sha256`, `tools/ci/build_meta.json`, `tools/ci/topology.sha256`) after testing route/schema/prefix updates; SOC-HIGH-002 sync maintained.

2026-03-02 — SOC-HIGH-002 — Workflow artifact upload path was too narrow
Issue: .github/workflows/fg-required.yml uploaded only artifacts/testing, causing missing diagnostic artifacts and reducing incident forensics.
Resolution: Expanded upload-artifact paths to include fg-required + gates + docker + testing roots and ensured _upload_notice.txt exists so uploads occur even on failure. No privilege escalation; retention set to 7 days.

## 2026-03-02 — CI Execution Surface Updates (Workflows + CI Helper)

**Change class:** CI/CD execution surface (SOC-HIGH-002)
**Files:**
- .github/workflows/ai-ledger-guard.yml
- .github/workflows/docker-ci.yml
- .github/workflows/fg-required.yml
- .github/workflows/release-images.yml
- .github/workflows/testing-module.yml
- tools/ci/wait_healthy.sh

**Intent:** Stabilize CI by enforcing required audit/update gates, hardening docker/compose validation inputs, and ensuring artifact collection always uploads correct roots.

**Risk notes:** No production runtime behavior change. CI behavior becomes stricter/more deterministic. Artifacts retained for post-failure forensics.

