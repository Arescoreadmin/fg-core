# Repo rules

## Before starting any work

Read these files first — they are the authoritative product state:
- `FOUNDER_DIRECTIVE.md` — **MANDATORY FIRST READ** for any agent producing planning artifacts; contains founder strategic direction that overrides defaults on competitive positioning, moat framing, and enterprise requirements
- `SYSTEM.md` — unified system reference (architecture, tech stack, what is built)
- `docs/plans/customer_one_verified_governance_roadmap_20260910.md` — **Level-2 sequencing authority** (what is NEXT vs DEFERRED); run `tools/ci/check_customer_one_roadmap.py --work-class <CLASS>` before proposing new capabilities
- `ROADMAP.md` — Level-3 status ledger (merged PR tracker only; not a sequencing authority)
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

## AI development resource safety (mandatory)

Full policy: `docs/ai/AI_DEVELOPMENT_RESOURCE_SAFETY.md`

**Established 2026-11-07** after three OOM events on the development workstation (32 GB RAM,
8 GB swap) caused by concurrent unbounded `rg` processes during AI-assisted development.

### Required operating rules

**Search:**
- Maximum 1 concurrent repository-wide `rg` operation.
- Never run `rg ... &` (background). The pre-command hook blocks this.
- Always exclude `.git/`, `.venv/`, `node_modules/`, `__pycache__/`, build artifacts.
- If `pgrep -c rg` ≥ 20, stop issuing searches immediately.

**Memory:**
- Run `python tools/ci/check_dev_resource_guard.py` before heavy phases.
- Do not start heavy test suites when available RAM < 6 GiB.
- Warn and defer when available RAM < 8 GiB.
- Do not run multiple memory-intensive suites simultaneously.

**Processes:**
- Default to sequential execution for builds, test runs, and type checks.
- Do not spawn unbounded subprocesses or background jobs without exit conditions.
- Do not start unnecessary Docker stacks; check `make compose-ps` first.

**Recovery:**
- On OOM or runaway processes: stop, identify the process, preserve uncommitted changes,
  kill only the identified workload (`kill <PID>`), not `killall` or `pkill -9 rg`.
- Never use destructive commands as an automatic recovery strategy.

The hook enforcements are project-scoped (`.claude/hooks/`). These memory thresholds are
advisory instructions, not OS-level limits. See the full policy for host-level options.
