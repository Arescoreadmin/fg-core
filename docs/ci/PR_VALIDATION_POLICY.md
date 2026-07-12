# PR Validation Policy

Generated: 2026-07-10

## Required Gates (Block Merge)

Every PR to `main` must pass ALL of the following:

### Gate 1: fg-required.yml
- **Who:** All PRs to main
- **What:** Deterministic hard gate — policy, required tests, fg-fast, fg-contract, fg-security (sequential)
- **SLA:** 45 min
- **Never skip:** Includes SOC invariants, audit-chain verification, RLS checks, security regression gates

### Gate 2: frostgate-core-ci (ci.yml)
- **Who:** All pushes/PRs to main
- **What:** Fan-out of lint, unit, integration, contract authority, migrations, hardening, evidence, agents
- **Critical path:** ~110 min (fg_guard → unit → integration → evidence)
- **Path-conditional jobs:** console (console paths), compliance (compliance paths)
- **Never skip:** security regression tests, RLS checks, tenant isolation tests, auth contract verification

## Non-Required Gates (Informational or Path-Conditional)

### testing-module.yml
- **Who:** PRs touching `tools/testing/policy/**`; schedule (03:15 UTC); workflow_dispatch
- **What:** fg-fast, fg-contract, fg-security, fg-full (sequential dependencies)
- **Blocking:** Only when triggered by path match
- **fg-full:** High cost (35-40 min) — optimization target

### ai-ledger-guard.yml
- **Who:** All PRs
- **What:** AI ledger consistency guard
- **SLA:** 5 min
- **Blocking:** No (informational)

## High-Risk Path Classification

PRs touching these paths trigger Layer 2 (high-risk) validation:

| Path Pattern | Risk Reason |
|-------------|-------------|
| `.github/workflows/**` | CI infrastructure change |
| `api/security/**` | Security enforcement |
| `api/middleware/**` | Auth middleware change |
| `api/auth**` | Authentication logic |
| `admin_gateway/**` | Admin plane security |
| `migrations/**` | Schema change |
| `contracts/**` | API contract change |
| `services/plane_registry/**` | Route ownership change |
| `tools/ci/check_security*.py` | Security gate change |
| `tests/security/**` | Security test change |

## Test Count Guards

- **fg-fast baseline:** 398 tests (`_FG_FAST_BASELINE_COUNT` in `tests/tools/test_fg_fast_budget_and_triage.py`)
- This guard MUST NOT be decreased without explicit SOC sign-off
- Adding new tests never requires updating the guard
- If the count drops below 398, the test fails and the PR cannot merge

## Security Domain Non-Negotiables

These items MUST always be covered regardless of lane optimization:

1. **RLS checks** — `check_core_rls.py`, `check_connectors_rls.py` (in `make fg-fast`)
2. **Tenant isolation** — `tests/security/test_tenant_binding_global.py` (in fg-security-pytest)
3. **Auth scope enforcement** — `check_route_scopes.py` (in fg_guard + make fg-fast)
4. **SOC invariants** — `make soc-invariants` (in make fg-fast)
5. **Audit chain** — `make audit-chain-verify` (in make fg-fast)
6. **Security regression gates** — `check_security_regression_gates.py` (in fg_guard + make fg-fast)
7. **Contract drift** — `make fg-contract` (in make fg-fast + standalone fg-contract job)
8. **No plaintext secrets** — `check_no_plaintext_secrets.py` (in fg_guard)
9. **Secret history** — `check_secret_history.py` (in fg_guard)
10. **Migration percent guard** — `guard_no_raw_percent_in_sql.py` (in fg_guard)

## Merge Queue Policy (Future)

When GitHub merge queue is enabled:
- Layer 3 validation runs for every queued PR
- Includes all plane smoke suites + integration suites
- Target: 45-90 min
- fg-full moves to nightly-only (not in merge queue)

## Flake Policy

- No automatic retries in any required gate
- Quarantine requires: owner, reason, expiration, GitHub issue link
- Maximum quarantine duration: 14 days
- Expired quarantine = build failure (must renew or fix)
- Flake detection runs nightly via fg-flake-detect after fg-full passes
