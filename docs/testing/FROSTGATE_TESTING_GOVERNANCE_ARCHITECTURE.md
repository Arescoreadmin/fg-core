# FrostGate Testing & Governance System Architecture

## 1) Stage One Architecture Overview (PR hard gate foundation)

Stage One introduces a **single required check** named `fg-required` that is deterministic, fail-closed, and budgeted to complete in <=10 minutes on standard PRs.

### Stage One invariants (non-optional)
- **Single required check**: GitHub PR required status = `fg-required`.
- **Fail closed**: any missing artifact, timeout, unresolved base ref, parser error, or lane failure returns non-zero.
- **Deterministic outputs**: sorted JSON keys, normalized markdown, stable lane order, no wall-clock timestamps in content artifacts.
- **No shell evaluation**: all command execution uses subprocess argument arrays (`shell=False`) and fixed command allowlist.
- **No dynamic lane injection**: lane names are hardcoded and validated against a static enum.
- **Security by default**: sanitized logs, value-based secret redaction, environment allowlist.

### Stage One lane set
The `fg-required` runner executes exactly these lanes in fixed order:
1. `policy-validate`
2. `required-tests-gate`
3. `fg-fast`
4. `fg-contract`
5. `fg-security`

Each lane emits:
- `artifacts/testing/lanes/<lane>/lane.log`
- `artifacts/testing/lanes/<lane>/lane.triage.json`

Global artifacts emitted by the run:
- `artifacts/testing/fg-required-summary.json`
- `artifacts/testing/fg-required-summary.md`
- `artifacts/testing/contract-drift.json`
- `artifacts/testing/security-invariants.json`
- `artifacts/testing/required-tests-gate.json`

---

## 2) Stage Two Architecture Overview (Control Tower + extensibility)

Stage Two adds a Control Tower to the Control Plane UI while preserving Stage One guarantees.

### Core components
- **Control Plane Testing API**: trigger, list, inspect runs and lane states.
- **Runner Service**: isolated container lane execution with the same command allowlist and timeout policy as CI.
- **Testing persistence**: `testing_runs`, `testing_lane_results`, `testing_artifacts` with strict RLS.
- **Live telemetry**: WebSocket streaming for lane logs and transitions.
- **UI Dashboard**: run table, lane badges, trends, flaky counts, failure buckets, scoped rerun.

### Non-regression rule
Stage Two cannot alter the Stage One execution contract. UI-triggered run must call the same orchestrator entrypoint and policy files used in CI.

---

## 3) File tree with responsibilities

```text
.github/workflows/
  fg-required.yml                               # Single required PR check (10m hard timeout)

tools/testing/
  orchestrator/
    fg_required_runner.py                       # Main runner: lane schedule, budgets, artifacts, fail-closed
    lane_executor.py                            # allowlisted subprocess wrapper (shell=False)
    budget.py                                   # global+lane timeout enforcement
    sanitize.py                                 # secret redaction + log sanitization
    deterministic.py                            # stable JSON/markdown writers
  policy/
    lane_policy.yaml                            # lane command allowlist + lane timeouts + budgets
    ownership_map.yaml                          # path -> test categories mapping
    required_tests.yaml                         # category -> required test globs
    plane_registry.yaml                         # canonical plane registration map
  contracts/
    check_contract_drift.py                     # route/OpenAPI/registry drift checks
  security/
    check_security_invariants.py                # RLS/tenant/security checks
  reports/
    triage_schema.json                          # triage shape contract

tools/dev/
  new_spine_module.py                           # scaffolds module + baseline tests + ownership entry + docs

docs/testing/
  FROSTGATE_TESTING_GOVERNANCE_ARCHITECTURE.md # this architecture contract
```

---

## 4) Lane execution flow diagram (textual)

```text
[fg-required start]
  -> Load lane_policy.yaml (strict schema validate)
  -> Resolve base ref (verified fallback chain)
  -> Initialize global budget clock (600s)
  -> For lane in [policy-validate, required-tests-gate, fg-fast, fg-contract, fg-security]:
       -> Ensure lane is allowlisted enum member
       -> Check remaining global budget > 0
       -> Start lane timer (max 480s per lane)
       -> Execute fixed argv command with shell=False
       -> Stream stdout/stderr through sanitizer/redactor
       -> Write lane.log atomically
       -> Build lane.triage.json deterministically
       -> If exit!=0 OR timeout OR artifact write failure: abort all, mark run failed
  -> Validate presence of mandatory global artifacts
  -> Write fg-required-summary.json/.md (deterministic)
  -> Upload artifacts (strict required list)
[fg-required end: pass/fail]
```

---

## 5) Timeout and budget enforcement strategy

### Hard limits
- **Job limit (GitHub Actions)**: 10 minutes (`timeout-minutes: 10`).
- **Per-lane hard timeout**: 8 minutes max (`timeout 480s`) enforced in orchestrator, independent of CI.
- **Global budget**: 600 seconds tracked by monotonic clock.

### Enforcement rules
- Lane cannot start if `remaining_budget < lane_min_start_threshold` (e.g., 15s).
- Each lane has `effective_timeout = min(lane_timeout, remaining_budget)`.
- Timeout at process level returns dedicated error category (`lane_timeout`).
- If budget exhausted before finishing all lanes => fail with `global_budget_exhausted`.

### Why this is deterministic
- Budget decisions are based on monotonic elapsed seconds only.
- Fixed lane order; no data-dependent scheduling.

---

## 6) Required-tests gate algorithm (pseudocode)

```python
def run_required_tests_gate(repo_root: Path) -> int:
    base = resolve_base_ref_with_fallback_and_verification()
    if not base.ok:
        emit_actionable_base_ref_error(base.attempts)
        write_json("required-tests-gate.json", {
            "status": "fail",
            "category": "base_ref_resolution_failed",
            "attempts": base.attempts,
        })
        return 1

    changed = git_diff_name_status_rename_aware(base.sha, "HEAD")
    # changed item: {status, old_path?, new_path}

    ownership = load_yaml("tools/testing/policy/ownership_map.yaml", strict=True)
    required = load_yaml("tools/testing/policy/required_tests.yaml", strict=True)

    required_categories = OrderedSet()
    for item in stable_sort_changed(changed):
        effective_paths = [item.new_path] + ([item.old_path] if item.old_path else [])
        for path in effective_paths:
            cats = categories_for_path(path, ownership)
            for c in sorted(cats):
                required_categories.add(c)

    changed_paths = {c.new_path for c in changed}
    missing_categories = []
    for category in sorted(required_categories):
        test_globs = required["categories"][category]["required_test_globs"]
        if not any(path_matches_glob(p, test_globs) for p in changed_paths):
            missing_categories.append(category)

    if missing_categories:
        guidance = build_guidance(missing_categories, required)
        write_json("required-tests-gate.json", {
            "status": "fail",
            "missing_categories": missing_categories,
            "guidance": guidance,
            "base_sha": base.sha,
        })
        return 1

    write_json("required-tests-gate.json", {
        "status": "pass",
        "required_categories": sorted(required_categories),
        "base_sha": base.sha,
    })
    return 0
```

### Base ref fallback chain
1. `GITHUB_BASE_REF` merge-base.
2. `origin/main` merge-base.
3. default branch from remote HEAD.
4. previous commit (`HEAD~1`) as last fallback for local verification.

Each candidate must pass `git cat-file -e <sha>^{commit}` before use.

---

## 7) Secret redaction strategy

### Design
- Use **value-based redaction** sourced from allowlisted env keys and runtime secret providers.
- Replace exact and tokenized variants before writing logs/artifacts.

### Pipeline
1. Build redaction dictionary from:
   - approved env vars (if value length >= 8)
   - known tokens discovered from mounted secret files
   - CI-provided credentials (GitHub token, cloud creds)
2. Normalize values (trim, url-encoded variants, base64 variants where feasible).
3. For each output line:
   - remove control chars
   - cap line length
   - replace any secret value with `***REDACTED***`
4. Persist sanitized log only.

### Enforcement
- If sanitizer fails, lane fails (`sanitization_error`).
- Raw process streams are never written to disk.

---

## 8) Determinism strategy

- **Stable lane order** hardcoded.
- **JSON output** written with `sort_keys=True`, fixed indentation, UTF-8, LF endings.
- **Markdown summary** generated from deterministic template with sorted sections.
- **No variable timestamps** in artifacts; if required, store normalized UTC minute precision and exclude from hash-critical files.
- **No working tree mutation**; runner validates `git status --porcelain` unchanged before/after.
- **Stable diff parsing** using `git diff --name-status -M --find-renames` and lexical sort.
- **Atomic writes** (`.tmp` then rename) to prevent partial artifacts.

---

## 9) CI YAML (production-ready)

```yaml
name: fg-required

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: fg-required-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  fg-required:
    name: fg-required
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      FG_GLOBAL_BUDGET_SECONDS: "600"
      FG_LANE_TIMEOUT_SECONDS: "480"
      PYTHONUNBUFFERED: "1"
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: |
            requirements.txt
            requirements-dev.txt
            constraints.txt
            pyproject.toml

      - name: Install dependencies
        run: |
          python -m venv .venv
          .venv/bin/pip install -r requirements.txt -r requirements-dev.txt -c constraints.txt

      - name: Run fg-required orchestrator
        run: |
          .venv/bin/python tools/testing/orchestrator/fg_required_runner.py \
            --global-budget-seconds 600 \
            --lane-timeout-seconds 480 \
            --artifacts-dir artifacts/testing

      - name: Verify required artifacts
        run: |
          test -f artifacts/testing/fg-required-summary.json
          test -f artifacts/testing/fg-required-summary.md
          test -f artifacts/testing/contract-drift.json
          test -f artifacts/testing/security-invariants.json
          test -f artifacts/testing/required-tests-gate.json

      - name: Upload artifacts (strict)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: fg-required-artifacts
          path: artifacts/testing
          if-no-files-found: error
```

---

## 10) Control Tower API contracts (request/response schemas)

### `GET /control-plane/v2/testing/lanes`
Response:

```json
{
  "lanes": [
    {
      "name": "fg-fast",
      "required": true,
      "timeout_seconds": 480,
      "last_result": "pass",
      "p95_duration_seconds": 142
    }
  ]
}
```

### `GET /control-plane/v2/testing/runs?limit=50&cursor=...`
Response:

```json
{
  "items": [
    {
      "run_id": "uuid",
      "tenant_id": "tenant_123",
      "ref": "refs/pull/42/head",
      "commit_sha": "abc123",
      "triggered_by": "user:alice",
      "result": "fail",
      "failure_category": "required_tests_missing",
      "started_at": "2026-02-26T10:00:00Z",
      "ended_at": "2026-02-26T10:03:42Z",
      "duration_ms": 222000
    }
  ],
  "next_cursor": null
}
```

### `GET /control-plane/v2/testing/runs/{id}`
Response:

```json
{
  "run_id": "uuid",
  "lane_results": [
    {
      "lane": "fg-contract",
      "result": "pass",
      "duration_ms": 59000,
      "artifact_hash": "sha256:...",
      "triage": {"bucket": "ok"}
    }
  ],
  "summary_artifact": "s3://.../fg-required-summary.json",
  "audit_event_id": "uuid"
}
```

### `POST /control-plane/v2/testing/runs`
Request:

```json
{
  "ref": "main",
  "mode": "fg-required",
  "reason": "manual rerun after policy change"
}
```

Response `202`:

```json
{
  "run_id": "uuid",
  "accepted": true
}
```

Auth requirements:
- `testing.runs.trigger` scope mandatory.
- Tenant context mandatory unless global admin scope.

### WebSocket `/control-plane/v2/testing/runs/{id}/stream`
Event schema:

```json
{
  "type": "lane_log|lane_status|run_status",
  "run_id": "uuid",
  "lane": "fg-fast",
  "seq": 17,
  "message": "sanitized line",
  "ts": "2026-02-26T10:01:02Z"
}
```

---

## 11) DB schema (tables + RLS rules)

```sql
create table testing_runs (
  id uuid primary key,
  tenant_id text not null,
  commit_sha text not null,
  branch text,
  pr_number bigint,
  trigger_actor text not null,
  trigger_reason text not null,
  source text not null check (source in ('ci', 'ui', 'api')),
  result text not null check (result in ('pass', 'fail', 'running', 'canceled')),
  failure_category text,
  started_at timestamptz not null,
  ended_at timestamptz,
  duration_ms bigint,
  summary_sha256 text not null,
  created_at timestamptz not null default now()
);

create table testing_lane_results (
  id uuid primary key,
  run_id uuid not null references testing_runs(id) on delete cascade,
  tenant_id text not null,
  lane text not null,
  result text not null check (result in ('pass', 'fail', 'timeout', 'skipped')),
  started_at timestamptz not null,
  ended_at timestamptz,
  duration_ms bigint,
  artifact_sha256 text not null,
  failure_category text,
  triage jsonb not null,
  unique(run_id, lane)
);

create table testing_artifacts (
  id uuid primary key,
  run_id uuid not null references testing_runs(id) on delete cascade,
  tenant_id text not null,
  lane text,
  artifact_name text not null,
  storage_uri text not null,
  sha256 text not null,
  size_bytes bigint not null,
  created_at timestamptz not null default now(),
  unique(run_id, artifact_name)
);
```

### RLS policy baseline
- Enable RLS on all three tables.
- Tenant read policy: `tenant_id = current_setting('app.tenant_id', true)`.
- Service write policy: only service role can insert/update.
- Global admin read policy gated by `current_setting('app.is_global_admin', true) = 'true'` + mandatory audit log row on query path.

---

## 12) Threat model (runner + UI)

### Runner threats
1. **Command injection** via lane config or API payload.
   - Mitigation: lane enum + static allowlist map + `shell=False`.
2. **Secret leakage in logs/artifacts**.
   - Mitigation: value-based redaction pipeline + artifact write refusal on sanitizer failure.
3. **Artifact forgery/tamper**.
   - Mitigation: SHA-256 per artifact, hash stored in DB, verification on read.
4. **Budget bypass / denial**.
   - Mitigation: global monotonic budget gate and hard stop.

### UI/API threats
1. **Unauthorized trigger**.
   - Mitigation: scoped auth (`testing.runs.trigger`) + tenant binding + policy checks.
2. **Cross-tenant data exposure**.
   - Mitigation: strict RLS, tenant context required, deny by default.
3. **WebSocket stream hijack**.
   - Mitigation: token-authenticated channel, run ownership checks.
4. **Replay of trigger requests**.
   - Mitigation: idempotency keys + signed audit envelope.

---

## 13) Step-by-step phased implementation plan

### Phase A — Stage One hard gate (mandatory)
1. Add orchestrator package (`fg_required_runner.py`, `lane_executor.py`, `sanitize.py`, `budget.py`).
2. Define lane policy allowlist and strict schema validation.
3. Implement rename-aware required-tests gate with verified base-ref fallback chain.
4. Implement deterministic artifact generation + strict required artifact checker.
5. Add `.github/workflows/fg-required.yml` and mark check `fg-required` required in branch protection.

### Phase B — Stage One hardening
1. Add secret redaction unit tests with known token fixtures.
2. Add deterministic snapshot tests for summary JSON/MD.
3. Add tamper-detection verification command (`sha256sum` reconciliation).
4. Add negative tests (missing artifact, unresolved base, lane timeout) to ensure fail-closed behavior.

### Phase C — Stage Two Control Tower backend
1. Add testing run tables + RLS migrations.
2. Implement API endpoints + auth scopes + audit events.
3. Implement runner service with same orchestrator image/entrypoint as CI.
4. Persist lane metadata/artifact hashes.

### Phase D — Stage Two UI
1. Build runs table + lane status badges + drill-down details.
2. Add trends and failure buckets.
3. Add live log streaming and scoped rerun action.
4. Add flaky test counters computed from lane history.

### Phase E — Module integration guardrails
1. Extend `tools/dev/new_spine_module.py` to always emit baseline unit/security tests.
2. Auto-add ownership map category entries.
3. Enforce plane registry and route prefix declaration for new modules.

---

## 14) Acceptance criteria checklist

### Stage One (must pass before merge)
- [ ] Required PR check is named exactly `fg-required`.
- [ ] Check fails on any lane failure, timeout, sanitizer error, or missing artifact.
- [ ] Global runtime <=10 minutes; per-lane timeout <=8 minutes.
- [ ] Required artifacts always generated and uploaded with `if-no-files-found: error`.
- [ ] Required-tests gate is rename-aware and base-ref fallback is commit-verified.
- [ ] Contract drift, duplicate routes, plane registry drift, missing RLS, and tenant invariant violations fail PR.
- [ ] Module changes without required test updates fail PR.
- [ ] Logs are sanitized and value-based secrets are redacted.
- [ ] No shell evaluation or dynamic command injection path exists.
- [ ] Artifact outputs are deterministic across repeated runs on same commit.

### Stage Two (must not weaken Stage One)
- [ ] UI-triggered runs invoke equivalent lane engine and policy as CI.
- [ ] Trigger requires explicit auth scope and is audited.
- [ ] RLS enforces tenant isolation with global-admin read-only override.
- [ ] Live log stream never emits unsanitized secret values.
- [ ] Every artifact is hashed and hash is queryable.
- [ ] New module generator emits baseline tests + ownership + docs + registry hooks.
