# CI Gate Execution Graph

Generated: 2026-07-10
Branch: audit/ci-gates-performance-and-assurance

## Summary

FrostGate has three blocking CI workflows per PR:

1. **fg-required.yml** — always blocks, runs the fg-required harness sequentially
2. **ci.yml** — always blocks (push/PR to main), fan-out of 14 parallel jobs
3. **testing-module.yml** — only triggered on `tools/testing/policy/**` path changes (or schedule/dispatch); runs fg-fast/contract/security/full sequentially then fg-full

## Workflow 1: fg-required.yml

**Trigger:** All PRs to main, workflow_dispatch  
**Job timeout:** 45 min outer / 60 min inner step  
**Blocks merge:** YES

```
fg-required job
  ├── hermetic minimal tests (unittest, no deps)
  ├── required-tests-gate resolution tests (unittest)
  ├── fg-required harness (global_budget=2800s, lane_timeout=1500s)
  │   ├── LANE: policy-validate (~5s)
  │   ├── LANE: required-tests-gate (~10s)
  │   ├── LANE: fg-fast (~1200s) ← make fg-fast
  │   │   includes: fg-contract, security-regression-gates, soc-invariants,
  │   │   audit-chain-verify, gap-audit, check-connectors-rls, fg-fast-pytest
  │   ├── LANE: fg-contract (~120s) ← DUPLICATE of fg-contract inside fg-fast lane
  │   └── LANE: fg-security (~1260s) ← DUPLICATE of soc-invariants+security-pytest inside fg-fast lane
  └── verify summary artifacts
```

**Estimated serial time:** 2715s (~45 min)  
**Key issue:** fg-contract and fg-security lanes duplicate work already done in the fg-fast lane.

## Workflow 2: ci.yml (frostgate-core-ci)

**Trigger:** Push to main, all PRs to main  
**Blocks merge:** YES

```
fg_guard (30 min)
  ├── detect_changed_paths.py → outputs: console/compliance/python/core
  ├── check_no_plaintext_secrets.py
  ├── check_secret_history.py
  ├── guard_no_raw_percent_in_sql.py
  ├── check_db_dependency.py
  ├── check_route_scopes.py
  ├── check_security_regression_gates.py
  └── make fg-fast-full (fg-fast + billing + opa + control-plane + compliance)

After fg_guard (parallel):
  ├── enforcement_mode_matrix (10 min)
  ├── contract_authority (20 min)
  ├── migrations_replay (25 min, real Postgres)
  ├── db_postgres_verify (25 min, real Postgres)
  ├── admin (20 min)
  ├── console (20 min, conditional on console paths)
  ├── pt (25 min)
  ├── hardening (25 min) ← pytest tests/security -q [DUPLICATE of fg-security]
  └── compliance (35 min, conditional on compliance paths)

After unit:
  ├── integration (25 min)
  ├── agent_linux (20 min)
  └── agent_windows (20 min)

After integration:
  └── evidence (30 min)
```

**Critical path:** fg_guard(30) → unit(25) → integration(25) → evidence(30) = **110 min**

## Workflow 3: testing-module.yml

**Trigger:** PRs touching `tools/testing/policy/**`, schedule (03:15 UTC), workflow_dispatch  
**Blocks merge:** Only if triggered (path-gated)

```
Parallel:
  fg-fast job (55 min timeout)
    ├── make fg-fast (~20 min)
    ├── required-tests-gate (~1 min)
    ├── policy-drift-check (~1 min)
    ├── runtime-budget-enforcement (~1 min)
    ├── security-invariant-coverage (~1 min)
    └── lane_runner --lane fg-fast (~24 min) ← DUPLICATION SITE
        ├── required_tests_gate.py [already ran above]
        ├── make fg-contract [DUPLICATE — in make fg-fast]
        ├── make fg-security [DUPLICATE — 21 min, fg-security job runs in parallel]
        └── pytest tests/test_gap_audit.py [DUPLICATE — in make fg-fast]

  fg-contract job (5 min)
    ├── make fg-contract
    └── check_contract_drift.py

  fg-security job (25 min)
    └── make fg-security (~21 min)

fg-full job (60 min) [needs: fg-fast + fg-contract + fg-security]
  ├── make fg-full (~35 min, all 20219 tests)
  └── flake-detect (~2 min)

fg-flake-detect job (15 min) [needs: fg-full]
```

**Key issue:** The `lane_runner --lane fg-fast` step runs `make fg-security` (21 min) and `make fg-contract` (2 min) AFTER the standalone `fg-security` (25 min) and `fg-contract` (5 min) jobs already ran them in parallel. This wastes ~23 min per PR on this workflow.

## Duplication Map

| Check | fg-fast (make) | lane_runner fg-fast | fg-security job | fg-required fg-contract lane | fg-required fg-security lane | ci.yml hardening |
|-------|----------|-------|-------|-------|-------|-------|
| fg-contract | YES | YES (DUP) | NO | YES (DUP) | NO | NO |
| soc-invariants | YES | via fg-security (DUP) | YES | NO | via fg-security (DUP) | NO |
| fg-security-pytest | NO | via fg-security (DUP) | YES | NO | YES (DUP) | YES (DUP) |
| security-regression-gates | YES | NO | NO | NO | NO | YES |
| gap-audit | YES | YES (DUP) | NO | NO | NO | NO |

## Test Count Snapshot

| Selection | Count | Lane |
|-----------|-------|------|
| All tests | 20,219 | fg-full-pytest |
| smoke or contract or security | 398 | fg-fast-pytest |
| smoke | 236 | subset |
| contract | 145 | subset |
| security (marker) | 17 | subset |
| tests/security/ (path) | ~701 | fg-security-pytest |
| integration or slow | 12 | excluded from fast lanes |
| unmarked | 19,809 | fg-full only |

## Machine-readable data

See `artifacts/ci/gate_execution_graph.json`
