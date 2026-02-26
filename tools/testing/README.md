# Testing Module

Fail-closed testing orchestration for FrostGate Core.

## Commands
- `python tools/testing/harness/required_tests_gate.py --base-ref main`
- `python tools/testing/harness/lane_runner.py --lane fg-fast`
- `python tools/testing/harness/triage_report.py --log artifacts/testing/fg-fast.log --out artifacts/testing/triage.json`
- `python tools/testing/harness/fg_required.py --global-budget-seconds 480 --lane-timeout-seconds 480 --strict`
- `python tools/testing/harness/fg_required.py --dry-run --strict`

## Hermetic tool tests
- `tests/tools_minimal/` intentionally uses `unittest` so checks can run before app/runtime dependencies and without pytest plugin/bootstrap side effects.

## Redaction scope
- Redaction guarantee: same-line sensitive key/value pairs and known secret values are redacted; multiline structured payloads are covered by value-based matching when secret values are known.
