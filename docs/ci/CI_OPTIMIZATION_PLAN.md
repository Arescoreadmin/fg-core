# CI Optimization Plan

Generated: 2026-07-10  
Branch: audit/ci-gates-performance-and-assurance

## Current State

### PR Critical Path (Evidence-Based)

| Workflow | Blocking | Critical Path | Evidence |
|----------|----------|------------|---------|
| fg-required.yml | YES (all PRs) | ~45 min | fg_required harness: policy(5s)+required(10s)+fg-fast(1200s)+fg-contract(120s DUP)+fg-security(1260s DUP) |
| ci.yml | YES (all PRs) | ~110 min | fg_guard(30)+unit(25)+integration(25)+evidence(30) |
| testing-module.yml | Conditional | ~47 min fg-fast job | Only PRs touching tools/testing/policy/** |

**Total observed PR wait (parallel workflows):** fg-required (~45 min) runs concurrently with ci.yml (~110 min critical path). The PR cannot merge until BOTH complete. Effective blocker: **~110 min** from ci.yml critical path.

### Identified Duplications

#### DUP-01: fg-contract (6+ min wasted per PR)
`make fg-contract` runs inside:
1. `make fg-fast` (fg-required fg-fast lane, testing-module fg-fast job) — FIRST execution
2. `lane_runner.py ALLOWED_LANES['fg-fast']` step 2 — DUPLICATE (after make fg-fast already ran it)
3. `fg-required fg-contract lane` — DUPLICATE
4. `testing-module fg-contract standalone job` — parallel to fg-fast, acceptable for PR speed

#### DUP-02: make fg-security (~21 min wasted per PR) — HIGHEST PRIORITY

The `fg-fast` lane in `lane_runner.py` contains:
```python
"fg-fast": (
    CommandSpec((sys.executable, "tools/testing/harness/required_tests_gate.py")),
    CommandSpec(("make", "fg-contract")),
    CommandSpec(("make", "fg-security"), timeout_seconds=1500),  # ← 21 min DUPLICATE
    CommandSpec((".venv/bin/pytest", "-q", "tests/test_gap_audit.py")),
),
```

`make fg-security` (21 min) runs AFTER the standalone `fg-security` job (25 min timeout) in testing-module.yml already ran `make fg-security` in parallel. The lane runner executes sequentially after all steps, so by the time lane_runner runs, the standalone fg-security job has already completed or is running. Zero unique assurance is added.

The workflow comment confirms this:
> `# raised from 15→25→35→55: make fg-fast (~20 min) + lane runner (fg-contract ~2 min + fg-security ~21 min + gap-audit ~1 min) = ~47 min observed`

This is the single biggest optimization opportunity.

#### DUP-03: gap-audit (~1 min)
`pytest tests/test_gap_audit.py` in lane_runner fg-fast duplicates `make gap-audit` already called by `make fg-fast`.

## Proposed Changes

### Priority 1: Fix lane_runner.py ALLOWED_LANES['fg-fast'] (IMPLEMENTED)

Remove the duplicate `make fg-contract`, `make fg-security`, and `pytest test_gap_audit.py` from the `fg-fast` lane definition. These checks are covered by:
- Standalone `fg-contract` job in testing-module.yml
- Standalone `fg-security` job in testing-module.yml
- `make fg-fast` (which already calls fg-contract targets, gap-audit, soc-invariants, security-regression-gates)

The lane runner for `fg-fast` should only run `required_tests_gate.py` — this is the unique value-add: testing the gate resolution logic with artifact output that the lane runner collects.

**Savings:** ~23 min per PR in testing-module; ~21 min in fg-required harness

### Priority 2: Condition fg-full on high-risk paths (IMPLEMENTED)

`fg-full` in testing-module.yml currently runs on all PRs touching `tools/testing/policy/**`. After the lane-runner fix, the fg-full job adds another 40 min to the testing-module critical path.

For `tools/testing/policy/**` changes that are not high-risk:
- These are typically runtime budget adjustments, policy YAML changes, quarantine updates
- fg-fast already provides smoke+contract+security coverage
- fg-full's unique value is the 19,809 unmarked tests — important for nightly/merge but not critical for policy-only changes

**Proposed condition on fg-full:**
```yaml
if: |
  github.event_name == 'schedule' ||
  github.event_name == 'workflow_dispatch' ||
  contains(github.event.pull_request.head.ref, 'security') ||
  (github.event_name == 'pull_request' && (
    contains(toJson(github.event.pull_request.head.commit.modified), '.github/workflows/') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'api/security/') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'api/middleware/') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'api/auth') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'admin_gateway/') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'migrations/') ||
    contains(toJson(github.event.pull_request.head.commit.modified), 'contracts/')
  ))
```

**Note:** GitHub Actions path expressions in `if:` are limited — the `detect_changed_paths.py` approach from ci.yml is more robust. The implementation uses the `needs` dependency on a gate that already knows about paths.

**Savings:** ~40 min per non-high-risk testing-module PR run

### Priority 3: Artifact-Based Result Reuse for fg-contract

**Design (not implemented — non-trivial):**

If the set of files affecting contracts has not changed since the last successful `fg-contract` run, skip the job and use the cached result.

Files that affect contracts:
- `contracts/core/openapi.json`
- `api/main.py`, any `api/**/routes.py`
- `tools/testing/contracts/check_contract_drift.py`

Implementation approach:
1. In `fg-contract` job, compute a hash of contract-relevant files using `git hash-object`
2. Store hash as a GitHub Actions cache key: `fg-contract-{hash}`
3. If cache hit, skip the job (use `if: steps.cache.outputs.cache-hit != 'true'`)
4. If cache miss, run normally and write result to cache

**Estimated savings:** ~3 min per PR for non-contract-touching changes

### Priority 4: Affected-Plane-Aware Test Selection

See `tools/testing/affected_plane_selector.py` for the implementation.

The plane registry (`services/plane_registry/registry.py`) maps route prefixes to planes. For file changes in a single plane's directory, only that plane's tests need to run.

**Example:** A change to `api/identity_administration/routes/admin.py` affects only the `identity` plane. Instead of running all 398 fg-fast tests, run only the identity plane's tests plus global security invariants.

**Failsafe:** If plane classification is ambiguous (multiple planes, CI infrastructure, shared modules), fall back to the full fg-fast-pytest selection.

## Parallelization Audit

### Can fg-security tests run with pytest-xdist?

**Assessment: MOSTLY SAFE, one concern**

Safe patterns:
- `monkeypatch.setenv` — reverted per test by `_restore_env` autouse fixture in root conftest
- `FG_SQLITE_PATH` via `monkeypatch.setenv(tmp_path)` — unique per test, parallel-safe
- FastAPI TestClient — in-process, no shared server state

Concern:
- Default `FG_SQLITE_PATH=/tmp/frostgate/fg-conftest.db` in root conftest (setdefault)
- Tests that rely on the session-scoped `_test_env_defaults` fixture without overriding `FG_SQLITE_PATH` share this path
- With `pytest-xdist`, multiple workers would write to the same SQLite file → potential corruption

**Mitigation:** Pass `--dist worksteal` with `--sqlite-path=/tmp/frostgate/worker-{workerid}.db` OR audit all tests that call `init_db()` without a `tmp_path` argument.

**Recommendation:** Enable `pytest-xdist -n auto` for the ~17 marker-based security tests in fg-fast-pytest. Hold off on enabling it for the full `tests/security/` suite until the shared SQLite path is audited.

## Flake Strategy

- **No automatic retries** in any required gate (fg-required, ci.yml, testing-module fg-fast/contract/security)
- **Quarantine protocol:**
  - Requires: owner, reason, expiration date, linked issue
  - File: `tools/testing/policy/flaky_tests.yaml` (referenced by quarantine_policy.py)
  - Quarantined tests are deselected via `PYTEST_ADDOPTS` from `pytest_addopts_for_lane()`
  - Expiration: max 14 days without renewal
- **Flake detection:** `fg-flake-detect` job runs nightly after `fg-full` passes
- **Escalation:** Tests quarantined > 7 days with no resolution get flagged in triage report

## Machine-readable data

See `artifacts/ci/optimization_plan.json`
