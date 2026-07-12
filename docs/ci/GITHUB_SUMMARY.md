# GitHub Step Summary

The runtime intelligence package generates GitHub Actions step summaries as markdown.

## Generation

`tools/testing/runtime_intelligence/github_summary.py` — `generate_summary(result, stats, regressions)`

## Included fields

| Section | Fields |
|---------|--------|
| Core metrics table | Duration (with % vs median), Collected, Passed, Failed, Skipped, Gate, Commit (12-char SHA) |
| Rolling stats | Median, p90, p95, Min, Max, Run count (last 30 runs) |
| Regressions | Severity, field, current value, baseline value, % change, message |
| Slowest tests | Top 10: node_id (last 60 chars), duration, phase |

## PII/secrets policy

- No env var values in output
- Commit SHA truncated to 12 characters
- No hostnames, usernames, tokens, or DB URLs
- `generate_summary()` only reads dataclass fields; no `os.environ` access

## Writing to GitHub

`write_step_summary(text)` writes to `$GITHUB_STEP_SUMMARY` if set.

The CLI writes automatically when `--github-summary` flag is passed or when
`GITHUB_STEP_SUMMARY` env var is set.

## Testing locally

```bash
# Dry-run with printed summary (no file write)
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-fast \
    --dry-run \
    --github-summary

# Write to a local file for inspection
GITHUB_STEP_SUMMARY=/tmp/summary.md \
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-fast \
    --dry-run
cat /tmp/summary.md
```

## Example output

```markdown
## FG FAST Runtime Summary

| Metric | Value |
|--------|-------|
| Duration | 312s (+4% vs median) |
| Collected | 398 |
| Passed | 396 |
| Failed | 0 |
| Skipped | 2 |
| Gate | fg-fast |
| Commit | `abc123def456` |

### Rolling Statistics (last 30 runs)
| Stat | Value |
|------|-------|
| Median | 300s |
...
```
