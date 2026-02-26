# Testing Module

Fail-closed testing orchestration for FrostGate Core.

## Commands
- `python tools/testing/harness/required_tests_gate.py --base-ref main`
- `python tools/testing/harness/lane_runner.py --lane fg-fast`
- `python tools/testing/harness/triage_report.py --log artifacts/testing/fg-fast.log --out artifacts/testing/triage.json`
