# Validation Classification

## Four validation outcome states

| Status | Meaning | Counts as pass? |
|--------|---------|-----------------|
| `pass` | Command ran; all assertions succeeded | Yes |
| `fail` | Command ran; at least one assertion failed | No |
| `skip` | Runtime proof was skipped — services unavailable | **No** |
| `blocked` | Required dependency was explicitly unavailable | **No** |

`skip` and `blocked` are **not** equivalent to `pass`.

---

## Three check classifications

| Classification | Meaning | Requires live services? |
|----------------|---------|------------------------|
| `structural` | Offline check — static analysis, unit tests, schema validation | No |
| `runtime_proof` | Live end-to-end proof — requires running IdP, gateway, database | **Yes** |
| `environment_blocked` | Check that could not run because a required service was unavailable | N/A |

---

## Gate pass vs live proof pass

These are different:

- **`make fg-fast` passing** — all structural gates clean. Does not prove runtime paths work.
- **`bash codex_gates.sh` passing** — all structural + contract gates clean. Same caveat.
- **runtime proof passing** — live services were up, flow ran, assertions succeeded.

A gate pass with a skipped runtime proof means: *the code is structurally sound, but the live path has not been proven in this environment.*

---

## How skip is detected

Scripts that skip due to unavailable services must emit a `SKIP:` or `SKIP ` prefix on stdout or stderr before exiting 0. Example:

```
SKIP: Keycloak not reachable at http://localhost:8081 — services must be running
```

The reconcile tool (`tools/plan/reconcile_completed_tasks.py`) detects this signal and records `status: skip` — never `pass`.

---

## Declaring a task as requiring runtime proof

Add `validation_class: runtime_proof` to the task in the plan YAML:

```yaml
- id: "15.2"
  title: Non-bypass tester journey enforcement
  validation_class: runtime_proof
  validation_commands:
    - .venv/bin/pytest -q tests/test_tester_quickstart_alignment.py
    - bash tools/auth/validate_tester_flow.sh
```

Tasks without `validation_class` default to `structural`.

---

## Task completion rules

A task **may not** be marked complete based solely on a skipped runtime proof unless:
- The task explicitly sets `validation_class: structural` (offline checks only), or
- The task definition of done explicitly allows structural-only completion.

Skipped or blocked runtime proofs do not update the plan state validation entry.
