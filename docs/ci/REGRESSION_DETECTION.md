# Regression Detection

Advisory regression detection for CI gate runtimes and test counts.

## Severity thresholds

| Severity | % increase over baseline | Trigger |
|----------|--------------------------|---------|
| `low` | >= 10% | Duration exceeds median by 10-24% |
| `medium` | >= 25% | Duration exceeds median by 25-49% |
| `high` | >= 50% | Duration exceeds median by 50-99% |
| `critical` | >= 100% | Duration doubled or more |

Baseline = **median** of last 30 runs from history file.

## Fields checked

| Field | Description |
|-------|-------------|
| `duration_seconds` | Gate wall-clock time vs rolling median |
| `collected` | Test count drop vs explicit `baseline_collected` (if provided) |

## Advisory mode

- `detect_regressions()` returns a list of `Regression` objects
- Regressions are **printed to stderr** but never cause exit code 1
- The CLI exits 0 regardless of regressions found
- Regressions appear in the GitHub step summary under "Regressions Detected (Advisory)"

## Empty history

- If history has 0 runs or median == 0, no regressions are reported
- First run always passes (no baseline available)

## API

```python
from tools.testing.runtime_intelligence.regression import detect_regressions
from tools.testing.runtime_intelligence.statistics import compute_rolling_stats

stats = compute_rolling_stats(durations)  # list[float]
regressions = detect_regressions(
    gate="fg-fast",
    current_duration=450.0,
    current_collected=398,
    baseline_stats=stats,
    baseline_collected=400,  # optional
)
for reg in regressions:
    print(reg.severity, reg.message)
```

## Future enforcement path

To convert regressions from advisory to blocking:
1. Change the CLI exit code based on `regressions` severity
2. Add a threshold in `runtime_budgets.yaml` (e.g., `regression_block_severity: high`)
3. Gate in `lane_runner.py` or a new `regression_gate.py`

Do **not** modify existing gate logic without review.
