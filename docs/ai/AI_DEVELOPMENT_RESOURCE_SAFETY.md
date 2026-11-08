# AI Development Resource Safety

**Applies to:** Claude Code, Codex, and all AI-assisted development tools operating in this repository.
**Established:** 2026-11-07
**Trigger:** Three OOM events on Odin (32 GB RAM, 8 GB swap) with concurrent `rg` processes while Claude, Codex, and VS Code were active.

---

## Advisory versus enforced controls

The policies in this document are **advisory operating instructions** loaded into AI agents at session start.
They are not OS-level memory limits or cgroup constraints.

| Control | Type | Mechanism |
|---------|------|-----------|
| Search concurrency rules | Advisory | CLAUDE.md / AGENTS.md instruction |
| Memory threshold rules | Advisory | CLAUDE.md / AGENTS.md instruction |
| Dangerous-command block list | Enforced | `.claude/hooks/pre_bash_guard.sh` |
| Background `rg` block | Enforced | `.claude/hooks/pre_bash_guard.sh` |
| Broad-diff warning (>5 files) | Enforced | `.claude/hooks/post_edit_guard.sh` |
| Resource preflight gate | Advisory CLI | `tools/ci/check_dev_resource_guard.py` |

For OS-level enforcement (cgroups, systemd resource limits, swap configuration), see
**Recommended Host-Level Configuration** at the end of this document. Those changes require
explicit user approval and are not applied automatically.

---

## A. Repository search safety

1. Default to sequential repository searches — one at a time.
2. Maximum concurrent repository-wide `rg` operations: **1**.
3. Maximum concurrent scoped `rg` operations (bounded path, explicit include): **2**, only when
   available memory exceeds 8 GiB and active `rg` process count is below 5.
4. Never launch unbounded background `rg` searches (`rg ... &`). The pre-command hook blocks this.
5. Never recursively search the entire repository repeatedly without narrowing scope between runs.
6. Prefer `rg --files`, explicit paths, `-g` glob limits, and `-l` (files-only) over full content
   sweeps when only file names are needed.
7. Always exclude irrelevant directories:

   ```bash
   rg <pattern> \
     --glob '!.git/**' \
     --glob '!.venv/**' \
     --glob '!node_modules/**' \
     --glob '!__pycache__/**' \
     --glob '!*.pyc' \
     --glob '!dist/**' \
     --glob '!build/**' \
     --glob '!.mypy_cache/**' \
     --glob '!.ruff_cache/**'
   ```

8. `rg` respects `.gitignore` by default. Do not pass `--no-ignore` without a specific reason.
9. Never search inside `.git/`, generated migration snapshots, or large binary assets.
10. If `pgrep -c rg` returns ≥ 20, stop issuing new searches and investigate the process tree.

---

## B. Memory safety

**Workstation baseline — Odin:**
- Physical RAM: 32 GB
- Swap: 8 GB
- Ubuntu desktop + normal development services must remain operational

**Required operating policy:**

| Condition | Action |
|-----------|--------|
| Available RAM ≥ 8 GiB | Normal operation. Heavy test suites may proceed. |
| Available RAM 6–8 GiB | Warn. Defer heavy phases. Single test shard only. |
| Available RAM < 6 GiB | Stop. Do not start new heavy operations. |
| Swap > 80% utilized | Warn. Treat as equivalent to low RAM. |

- Recheck memory after major discovery, build, and test phases.
- Never deliberately exhaust swap as a performance strategy.
- Do not run multiple memory-intensive validation suites simultaneously.
- Do not start unnecessary Docker stacks. Check `make compose-ps` before starting services.
- Preserve existing PostgreSQL volumes. Never run `docker system prune -f` without explicit approval.
- Do not automatically increase swap to work around excessive memory use — fix the root cause.

Preflight check before heavy phases:

```bash
python tools/ci/check_dev_resource_guard.py --phase <phase-name>
```

---

## C. Process safety

- Never spawn unbounded subprocesses from shell loops or agent tool calls.
- Default to sequential execution for expensive tasks (builds, full pytest runs, mypy).
- Use bounded parallelism for pytest: `pytest -n auto --maxfail=10` is acceptable;
  do not combine `-n auto` with multiple concurrent agent processes.
- Avoid uncontrolled shell background jobs (`&`) without explicit tracking of exit codes.
- Avoid recursive agent delegation loops — if a sub-agent spawns further agents over the
  same repository, that creates unbounded process multiplication.
- Never retry a failing operation in a tight loop without an explicit termination condition
  and a sleep/backoff between attempts.
- Do not launch multiple AI coding agents concurrently against the same repository unless
  each agent has a clearly bounded, non-overlapping scope.

---

## D. Test execution safety

- Run the **narrowest valid verification** first (single test file, targeted mark).
- Execute repository-wide validation gates (`make test-fast`, `pytest -q -x`) sequentially,
  not in parallel across multiple terminal sessions.
- Preserve all required acceptance criteria. Do not skip security gates.
- Do not remove or weaken tests to improve runtime.
- Do not reduce security assurance to reduce memory footprint.
- If a test cannot safely execute given current resource state, report it explicitly as
  "deferred due to resource pressure" — do not claim it passed.

Recommended order for safe test execution:

1. `ruff check <changed-files>` and `ruff format --check <changed-files>`
2. `mypy <changed-files>` (or `mypy .` for full pass)
3. `pytest <specific-test-file> -x` (targeted first)
4. `make test-fast` (fast shard) only after targeted tests pass
5. Full suite gates only via CI or with explicit resource preflight

---

## E. Resource monitoring

Before and after heavy phases, record:

```bash
# Available RAM and swap
awk '/MemAvailable|SwapFree|SwapTotal/ {printf "%s: %.1f GiB\n", $1, $2/1048576}' /proc/meminfo

# Active rg processes
pgrep -c rg 2>/dev/null || echo "0 rg processes"

# Total process count
ps aux --no-header | wc -l

# Docker resource summary (if services are running)
make compose-ps 2>/dev/null || true
```

Or use the preflight guard for a single consolidated report:

```bash
python tools/ci/check_dev_resource_guard.py --report
```

Never start a continuous monitoring loop without an explicit exit condition and sleep interval.

---

## F. Safe recovery from resource exhaustion

On OOM event, kernel-killed process, or excessive process creation:

1. **Stop** launching new work immediately.
2. **Identify** the process tree: `ps aux --sort=-%mem | head -20`
3. **Preserve** uncommitted source changes: `git stash` or `git diff > /tmp/wip.patch`
4. **Terminate** only the identified runaway workload: `kill <PID>` (not `killall`, not `pkill -9 rg`)
5. **Avoid** indiscriminate `pkill`, `killall`, Docker shutdowns, or service restarts.
6. **Report** what happened and exactly what recovery actions were taken.
7. **Wait** for memory to recover to ≥ 8 GiB available before resuming.
8. **Resume** with the targeted, narrowest-scope operation first.

Do not use destructive commands as an automatic recovery strategy.

---

## G. AI agent coordination

When multiple AI tools are active simultaneously (e.g. Claude Code + Codex + IDE extension):

- Establish which agent owns which task before starting.
- Do not run conflicting file edits from two agents concurrently.
- Do not run repository-wide searches from two agents simultaneously.
- If in doubt, serialize: finish one agent's task, review, then start the next.
- Heavy test runs (full pytest, mypy whole-repo) should be assigned to exactly one agent at a time.

---

## Recommended host-level configuration (requires explicit approval)

The following OS-level changes are **not applied automatically**. Review and apply manually
if desired:

### 1. Increase swap (if workload regularly exceeds 32 GB)
```bash
# Example: add 16 GB swapfile — review before applying
sudo fallocate -l 16G /swapfile2
sudo chmod 600 /swapfile2
sudo mkswap /swapfile2
sudo swapon /swapfile2
# To persist: add to /etc/fstab
```

### 2. Configure systemd user resource limits
```ini
# ~/.config/systemd/user/claude-code.service resource limit example
[Service]
MemoryMax=12G
TasksMax=256
```

### 3. Set kernel `vm.swappiness`
```bash
# Reduce swapping aggressiveness (default 60)
sudo sysctl vm.swappiness=10
```

### 4. Use `ulimit` per terminal session
```bash
# Limit memory for a single shell session
ulimit -v $((24 * 1024 * 1024))  # 24 GB virtual memory ceiling
```

These are advisory suggestions. Applying them requires understanding the workstation's
full workload and is outside the scope of automated repository tooling.
