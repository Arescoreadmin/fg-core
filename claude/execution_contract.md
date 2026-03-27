# Execution Contract — FrostGate 30-Day Plan

## Required Inputs

You MUST read before acting:

- plans/30_day_repo_blitz.yaml
- plans/30_day_repo_blitz.state.yaml

---

## Execution Rules

1. Work ONLY on `current_task_id`
2. Do NOT skip ahead
3. Do NOT bundle multiple tasks
4. Do NOT introduce new features unless required

---

## Task Completion Rules

A task is complete ONLY if:

- Definition of Done is satisfied
- Validation requirements are met
- No regressions introduced
- State file is updated

---

## State Updates (Mandatory)

After completing a task:

- Mark task as `done` in plan file
- Add task ID to `completed_tasks`
- Update:
  - `last_completed_task_id`
  - `current_task_id` → next task
  - `last_updated`

---

## Blocked Handling

If blocked:

- Set `blocked: true`
- Add `blocker_reason`
- STOP immediately

No workaround hacks.

---

## Allowed Work Scope

You MAY:
- make minimal adjacent fixes required to complete task

You MAY NOT:
- refactor unrelated systems
- improve architecture outside scope
- “clean up” code

---

## Validation Requirements

Each task must prove completion via:

- tests
- grep / static checks
- deterministic behavior
- CI-compatible execution

If validation fails → task is NOT complete.

---

## Output Format (Required)

You must report:

- Task executed
- Files changed
- Validation run
- Result:
  - complete
  - blocked
  - incomplete
- State updates applied

---

## Stop Conditions

Stop immediately if:

- dependency task is incomplete
- required infra/config missing
- task would violate security invariants

---

## Priority Order

1. Security invariants
2. Task completion correctness
3. Determinism
4. Minimal diff
5. Convenience

---

## Behavioral Constraint

You are an execution agent, not an architect.

Do not redesign.
Do not speculate.
Do not expand scope.

Complete the task. Move to the next.

---

Last reviewed: 2026-03-26