# GitHub Step Summary

The runtime intelligence package generates GitHub Actions step summaries as markdown.

## Generation

`tools/testing/runtime_intelligence/github_summary.py` — `generate_summary(result, stats, regressions)`

## Included fields (updated PR-CI-02.1)

| Section | Fields |
|---------|--------|
| Core metrics table | Duration (with % vs median), Collected, Passed, Failed, Skipped, Gate, Commit (12-char SHA), Manifest fingerprint (when present) |
| Rolling stats | Median, p90, p95, Min, Max, Run count (last 30 runs) |
| Regressions | Severity, field, current value, baseline value, % change, message |
| Slowest tests | Top 10: sanitized node_id (brackets replaced with `[...]`), duration, phase |
| Slowest fixtures | Top 10: name, duration, plane, owner (from ownership map) |

### Example output

```
## FG FAST Runtime Summary

| Metric    | Value                        |
|-----------|------------------------------|
| Duration  | 450s (+3% vs median)         |
| Collected | 398                          |
| Passed    | 396                          |
| Failed    | 0                            |
| Skipped   | 2                            |
| Gate      | fg-fast                      |
| Commit    | `abc123def456`               |
| Manifest  | `4ab8d2cf1a3b5e70`           |

### Slowest Fixtures

| Fixture          | Duration | Plane    | Owner          |
|------------------|----------|----------|----------------|
| `identity_setup` | 2.70s    | identity | team-identity  |
```

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
