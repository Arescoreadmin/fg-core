# Repo rules

## Before starting any work

Read these files first — they are the authoritative product state:
- `FOUNDER_DIRECTIVE.md` — **MANDATORY FIRST READ** for any agent producing planning artifacts; contains founder strategic direction that overrides defaults on competitive positioning, moat framing, and enterprise requirements
- `SYSTEM.md` — unified system reference (architecture, tech stack, what is built)
- `ROADMAP.md` — living PR tracker (what is done, what is next, client readiness blockers)
- `BLUEPRINT_STAGED.md` — governance compliance gates (authoritative for compliance decisions)

## Change rules

- Smallest diff wins.
- Do not edit unrelated files.
- Do not edit generated files unless source + regen are both included.
- Prefer make targets and scripts in this repo.
- Never modify secrets, env files, or credentials.
- Never mutate deployment or CI config silently.
- If touching contracts, schemas, migrations, or infra, say so explicitly.

## Roadmap maintenance (required on every PR)

When a PR ships a feature, fixes a product gap, or changes the client-facing story:
1. Add a row to the relevant phase table in `ROADMAP.md`
2. If it closes a P0/P1 item in Phase 2, update that row's Status and PR columns
3. If it introduces something not on the plan, add it — do not leave it untracked

`ROADMAP.md` and `SYSTEM.md` are exempt from the `docs/ai/PR_FIX_LOG.md` requirement.
