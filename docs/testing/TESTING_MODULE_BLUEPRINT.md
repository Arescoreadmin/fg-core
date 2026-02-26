# FrostGate Testing Module (Production Blueprint)

## 1) Architecture overview

The testing module is a fail-closed control system that binds spine/module metadata to deterministic CI lanes and Control Plane execution APIs. It enforces: (a) contract/route/plane invariants, (b) tenant and RLS security invariants, (c) required-tests-on-change policy, and (d) auditable lane execution with immutable artifacts. The system uses four lanes (`fg-fast`, `fg-contract`, `fg-security`, `fg-full`) with PR-required lanes budgeted to <=10 minutes via parallel jobs and smoke-only integration in PRs.

Core control points:
- `tools/testing/harness/required_tests_gate.py`: changed-path => required category => hard-fail if tests/policy not updated.
- `tools/testing/harness/lane_runner.py`: allowlisted lane command execution + artifact hash metadata.
- `tools/testing/harness/triage_report.py`: deterministic failure bucketing + reproducible next command.
- Policy source of truth under `tools/testing/policy/*.yaml`.


## Delivery status in this PR

- **Delivered now**: Phase 0-1 foundations (policy, harness, lanes, CI enforcement, deterministic triage, onboarding generator).
- **Tracked but intentionally partial**: Control Tower API/UI and DB persistence are shipped as explicit stubs gated by feature flag and 501 responses to avoid false expectations.
- **Remaining**: full Control Tower execution backend, WebSocket streaming, and persistent analytics in Phase 3+.

## 2) File tree + responsibilities

```text
tools/testing/
  policy/
    ownership_map.yaml            # changed paths -> owner/module -> required categories
    required_tests.yaml           # category -> required test globs; module onboarding requirements
    module_manifest.yaml          # spine-aligned module descriptors (plane/routes/scopes/category)
  harness/
    required_tests_gate.py        # deterministic diff gate + module onboarding enforcement
    lane_runner.py                # allowlisted lane execution, metadata hashing, audit-ready output
    triage_report.py              # bucketized triage JSON for failures
  contracts/
    check_contract_drift.py       # route/openapi/plane drift checks
  security/
    check_security_invariants.py  # RLS/auth/security invariant checks
  integration/
    smoke_suite.py                # API/control-plane smoke checks
  templates/
    test_module_unit.py.tmpl
    test_module_security.py.tmpl
    module_doc.md.tmpl
tools/dev/
  new_spine_module.py             # module onboarding generator (tests/docs/module skeleton)
.github/workflows/
  testing-module.yml              # CI lanes + artifacts + fail-closed
docs/testing/
  TESTING_MODULE_BLUEPRINT.md     # architecture and operational contract
```

## 3) Lane definitions + budget strategy

### `fg-fast` (PR required, target <= 4 min)
- Scope: fast signal + deterministic correctness checks.
- Commands: `make fg-fast` + `make required-tests-gate`.
- Budget controls: no deep e2e; cache deps; deterministic subset tests.

### `fg-contract` (PR required, target <= 3 min)
- Scope: OpenAPI/route/plane ownership drift.
- Commands:
  - `make fg-contract`
  - `python tools/testing/contracts/check_contract_drift.py`

### `fg-security` (PR required, target <= 3 min)
- Scope: tenant isolation, RLS, auth scope invariants on every PR.
- Commands:
  - `make fg-security`
  - `python tools/testing/security/check_security_invariants.py`

### `fg-full` (nightly/release, 30 min budget)
- Scope: full lane, deeper integration and replay suites.
- Commands:
  - `make fg-full`

PR total budget strategy: run `fg-fast`, `fg-contract`, and `fg-security` in parallel workflow jobs; each has timeout ceilings and dependency caching.

## 4) CI workflow outline

Workflow: `.github/workflows/testing-module.yml`.
- Per-lane isolated jobs (`fg-fast`, `fg-contract`, `fg-security`) with strict timeout.
- `fg-full` only on `workflow_dispatch` and after PR lane success.
- Fail-closed behavior: any non-zero exit fails job; no soft-fail paths.
- Concurrency lock per branch/ref (`cancel-in-progress: true`) to prevent stale race approvals.
- Artifacts uploaded always (`if: always()`): lane logs/metadata/triage outputs.

## 5) Required-tests enforcement algorithm

Pseudocode:

```python
changed = git_diff(base_ref, fail_closed=True)
ownership = load_yaml("ownership_map.yaml")
required_policy = load_yaml("required_tests.yaml")

required_categories = set()
for owner_entry in ownership["owners"]:
    if any(match(path, owner_entry.path_globs) for path in changed):
        required_categories |= set(owner_entry.required_categories)

failures = []
for category in sorted(required_categories):
    patterns = required_policy.categories[category].required_test_globs
    if not any(match(path, patterns) for path in changed):
        failures.append(f"missing required test update: {category}")

new_modules = detect_new_module_paths(changed)
for module in new_modules:
    assert registry_files_changed(required_policy.module_registration.registry_files)
    assert skeleton_files_changed(module, required_policy.module_registration.required_skeleton_globs)

if failures: exit(1)
```

Policy examples are in:
- `tools/testing/policy/ownership_map.yaml`
- `tools/testing/policy/required_tests.yaml`
- `tools/testing/policy/module_manifest.yaml`

## 6) Control Tower API contract

### REST endpoints
- `GET /control-plane/v2/testing/lanes`
  - Returns lane status summary, durations, last commit, PR URL, artifact refs.
- `POST /control-plane/v2/testing/runs`
  - Starts lane run (auth scope: `testing.runs.execute`), body:
  - `{ "lane": "fg-fast", "ref": "sha-or-branch", "tenant_id": "...", "reason": "manual trigger" }`
- `GET /control-plane/v2/testing/runs?lane=fg-fast&limit=50`
  - Returns run history + failure bucket summary.
- `GET /control-plane/v2/testing/runs/{run_id}/artifacts`
  - Returns immutable artifact metadata + hashes.

### WebSocket
- `GET /control-plane/v2/testing/runs/{run_id}/stream`
  - Streams events:
  - `{ "ts":"...", "run_id":"...", "phase":"execute", "line":"...", "progress":42 }`

### Auth scopes
- `testing.runs.read`
- `testing.runs.execute`
- `testing.runs.admin` (global-only)

## 7) DB schema (multi-tenant + RLS)

```sql
create table test_runs (
  id uuid primary key,
  tenant_id text not null,
  lane text not null,
  status text not null,
  commit_sha text not null,
  branch text,
  pr_number bigint,
  trigger_actor text not null,
  trigger_reason text not null,
  started_at timestamptz not null,
  ended_at timestamptz,
  duration_ms bigint,
  failure_bucket text,
  summary jsonb not null default '{}'::jsonb,
  result_hash text not null,
  prev_hash text,
  created_at timestamptz not null default now()
);

create table test_run_artifacts (
  id uuid primary key,
  run_id uuid not null references test_runs(id) on delete cascade,
  tenant_id text not null,
  artifact_name text not null,
  artifact_uri text not null,
  sha256 text not null,
  bytes bigint not null,
  created_at timestamptz not null default now(),
  unique(run_id, artifact_name)
);
```

RLS rules:
- Tenant users can `SELECT` rows where `tenant_id = current_setting('app.tenant_id')`.
- Global admins bypass with `testing.runs.admin` and audited reason.
- `INSERT` only via service role; no direct client write.

## 8) Threat model + mitigations

- **Command injection in runner**: block arbitrary shell by fixed lane allowlist (`lane_runner.py`), parsed with `shlex` and no dynamic interpolation.
- **Artifact tampering**: compute and store SHA-256 for each lane log + metadata; include hash chaining field `prev_hash` in `test_runs`.
- **Tenant data leakage in UI/API**: enforce RLS + scope checks; default deny on missing tenant context.
- **Break-glass abuse**: explicit reason + policy-file traceability + audit event.
- **Secret leakage in logs**: sanitize logs before persistence and avoid dumping environment.
- **Registry drift**: policy gate requires module registration files updated for new modules.

## 9) Implementation phases + acceptance criteria

### Phase 0 — Foundation
- Deliver policy files + deterministic gate script.
- Acceptance: changed module path without test update fails reliably.

### Phase 1 — PR lanes
- Wire Make targets and CI workflow jobs.
- Acceptance: PR jobs parallelize and finish <=10 minutes median.

### Phase 2 — Triage and artifacts
- Enable triage bucketing and artifact hashing/metadata output.
- Acceptance: failed run emits bucket + reproduction command + hashed artifacts.

### Phase 3 — Module onboarding generator
- `tools/dev/new_spine_module.py` creates module + baseline tests + docs.
- Acceptance: generated module passes required-tests gate after policy updates.

### Phase 4 — Control Tower backend/UI
- Add run APIs, WebSocket stream, RLS-protected DB tables, and dashboard widgets.
- Acceptance: authorized users can execute lanes, watch live logs, and inspect trends/flaky categories.

### Phase 5 — Hardening
- Container isolation profile, immutable evidence storage, audit chain verification.
- Acceptance: red-team checks cannot execute non-allowlisted commands or cross tenant boundaries.
