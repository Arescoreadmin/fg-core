# FrostGate — Agent Operating Instructions

Applies to: Codex, GitHub Copilot agents, and any other AI coding agents operating in this repository.
Claude Code agents: see `CLAUDE.md` (loaded automatically at session start).

---

## Before starting any work

Read these files for authoritative product state:
- `FOUNDER_DIRECTIVE.md` — strategic direction; overrides competitive/moat defaults
- `SYSTEM.md` — unified system reference (architecture, tech stack)
- `docs/plans/customer_one_verified_governance_roadmap_20260910.md` — sequencing authority (NEXT vs DEFERRED)
- `ROADMAP.md` — merged PR status ledger (not a sequencing authority)
- `BLUEPRINT_STAGED.md` — governance compliance gates

---

## Change rules

- Smallest diff wins.
- Do not edit unrelated files.
- Do not edit generated files unless source + regen are both included.
- Prefer `make` targets and scripts in this repository.
- Never modify secrets, env files, or credentials.
- Never mutate deployment or CI config silently.
- If touching contracts, schemas, migrations, or infra, say so explicitly.

---

## AI development resource safety (mandatory)

Full policy: `docs/ai/AI_DEVELOPMENT_RESOURCE_SAFETY.md`

Three OOM events occurred on 2026-11-07 (Odin: 32 GB RAM, 8 GB swap) with concurrent
unbounded `rg` processes during AI-assisted development. The following rules are mandatory.

### Search

- Run at most **1** concurrent repository-wide search at a time.
- Never launch background searches (`rg ... &` or `find ... &`).
- Always exclude `.git/`, `.venv/`, `node_modules/`, `__pycache__/`, build artifacts.
- Do not recursively scan the entire repository multiple times without narrowing scope.
- If you observe ≥ 20 active `rg` processes, stop issuing new searches.

Recommended invocation pattern:
```bash
rg <pattern> \
  --glob '!.git/**' --glob '!.venv/**' --glob '!node_modules/**' \
  --glob '!__pycache__/**' --glob '!dist/**' --glob '!build/**'
```

### Memory

- Run `python tools/ci/check_dev_resource_guard.py --phase <name>` before heavy phases.
- **Stop** if available RAM < 6 GiB. **Warn** if < 8 GiB.
- Do not run multiple memory-intensive suites (pytest full suite, mypy whole-repo) simultaneously.
- Do not start unnecessary Docker stacks. Check `make compose-ps` before adding services.

### Processes

- Default to sequential execution for expensive tasks.
- Do not spawn unbounded subprocesses or tight retry loops.
- Do not launch parallel AI agents against the same repository without coordinated scope boundaries.

### Recovery

If you encounter or cause resource exhaustion:
1. Stop all new work immediately.
2. Preserve uncommitted changes (`git diff > /tmp/wip.patch`).
3. Identify the runaway process tree (`ps aux --sort=-%mem | head -20`).
4. Terminate only the identified workload with `kill <PID>`.
5. Do **not** use `killall`, `pkill -9 rg`, or Docker shutdowns without explicit confirmation.
6. Wait for available RAM ≥ 8 GiB before resuming.

---

## Test execution safety

- Run the narrowest valid test first (single file, specific mark).
- Do not skip security gates or weaken tests to improve speed.
- If a test cannot safely run given current resources, report it as deferred — do not claim it passed.
- Preserve all existing FrostGate security controls, tenant isolation, and evidence integrity requirements.

---

## Roadmap maintenance

When shipping a feature, fixing a product gap, or changing the client-facing story:
1. Add a row to the relevant phase table in `ROADMAP.md`.
2. If it closes a P0/P1 Phase 2 item, update Status and PR columns.
3. If it introduces something not on the plan, add it — do not leave it untracked.
