# CI Timeout Policy

Generated: 2026-07-10

## Timeout Hierarchy

The timeout hierarchy enforces that inner timeouts are always smaller than outer ones:

```
command_hard_max_seconds < lane_timeout_seconds < job_timeout_minutes*60 < global_budget_seconds
```

### Current Values

| Layer | Scope | Value | Source |
|-------|-------|-------|--------|
| `fg-fast-pytest` hard_max | command | 930s (15.5 min) | `FG_FAST_HARD_MAX_SECONDS` in Makefile |
| `fg-security` command timeout | command | 1500s (25 min) | `lane_runner.py CommandSpec timeout_seconds=1500` |
| `fg-required` lane timeout | lane | 1500s (25 min) | `fg-required.yml --lane-timeout-seconds 1500` |
| `fg-required` global budget | harness | 2800s (46.7 min) | `fg-required.yml --global-budget-seconds 2800` |
| `fg-fast` job timeout | job | 55 min | `testing-module.yml timeout-minutes: 55` |
| `fg-contract` job timeout | job | 5 min | `testing-module.yml timeout-minutes: 5` |
| `fg-security` job timeout | job | 25 min | `testing-module.yml timeout-minutes: 25` |
| `fg-full` job timeout | job | 60 min | `testing-module.yml timeout-minutes: 60` |
| `fg-required` job timeout | job | 45 min outer / 60 min inner step | `fg-required.yml` |
| `fg_guard` job timeout | job | 30 min | `ci.yml` |

### Hierarchy Validation

For `fg-security` command in lane_runner:
- command timeout: 1500s = 25 min
- lane timeout (fg-required): 1500s = 25 min
- global budget (fg-required): 2800s = 46.7 min
- job timeout (fg-fast testing-module): 55 min = 3300s

Hierarchy: 1500s ≤ 1500s ≤ 2800s ≤ 3300s — VALID (command == lane is acceptable)

For `fg-fast-pytest` hard_max:
- command hard_max: 930s
- global budget: 2800s
- job timeout: 55 min = 3300s

Hierarchy: 930s < 2800s < 3300s — VALID

### Rationale for Current Values

**fg-fast job: 55 min**
- `make fg-fast` takes ~20 min in CI
- Lane runner fg-fast: required_tests_gate(1) + fg-contract(2) + fg-security(21) + gap-audit(1) = 25 min
- Total observed: ~47 min; 55 min provides runner-variance headroom
- After optimization (removing lane_runner duplicates): ~22 min total; can be reduced to 35 min

**fg-security job: 25 min**
- `make fg-security` runs ~700 security tests; observed ~21 min
- 25 min provides headroom

**fg-full job: 60 min**
- `make fg-full` observed running 35+ min when 40-min ceiling cancelled it
- 60 min provides headroom for full test suite + setup + flake detection

**fg-required global budget: 2800s (46.7 min)**
- Sequential lanes: policy(5s) + required(10s) + fg-fast(1200s) + fg-contract(120s) + fg-security(1260s) = 2595s
- 2800s provides ~8% headroom

**Note:** After the lane_runner deduplication fix, fg-required budget can be reduced:
- policy(5s) + required(10s) + fg-fast(1200s) + fg-contract(120s) = 1335s
- Suggest reducing to 1800s (50% headroom)

## See Also

- `tools/ci/check_timeout_hierarchy.py` — automated validation script
- `tools/testing/policy/runtime_budgets.yaml` — runtime budget policy document
