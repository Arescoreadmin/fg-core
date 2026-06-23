# Repo Rules — FrostGate Core

## Core Discipline

- Smallest diff wins.
- Do not edit unrelated files.
- Do not edit generated files unless source + regeneration are included.
- Prefer existing make targets and repo scripts over custom commands.
- Never modify secrets, env files, or credentials.
- Never mutate deployment or CI config silently.
- If touching contracts, schemas, migrations, or infra, explicitly state it.

## Change Control

- Every change must be intentional and scoped.
- No drive-by refactors.
- No “while I’m here” edits.

## Determinism

- Changes must not introduce non-deterministic behavior.
- Avoid hidden dependencies on environment state.

## Safety

- Fail closed > fail open.
- No implicit behavior that could mask errors.

## Validation Expectation

- If you change behavior, you must validate it.
- Prefer existing repo validation paths (Makefile, CI harness).

## Anti-Patterns (Reject These)

- “Cleanup” refactors without request
- Silent behavior changes
- Expanding scope beyond the task
- Editing files just because they’re “nearby”

---

Last reviewed: 2026-03-26
Owner: FrostGate Core