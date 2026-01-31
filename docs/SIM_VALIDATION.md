# Simulation Validation

The Simulation Validator ensures deterministic decision engine behavior by running fixed inputs through the evaluation pipeline and detecting output drift.

## Purpose

1. **Regression Detection**: Detect unintended changes to decision engine behavior
2. **Determinism Verification**: Ensure identical inputs always produce identical outputs
3. **Artifact Generation**: Produce verifiable snapshots for audit trails

## How It Works

### Fixed Simulation Inputs

The validator uses a predefined set of simulation inputs covering:

- Baseline no-threat scenarios
- Auth bruteforce detection (at and above threshold)
- Below-threshold events
- Guardian/Sentinel persona + classification combinations
- Edge cases (unknown events, missing IPs)

### Validation Process

1. Run each simulation input through `api.defend.evaluate()`
2. Apply doctrine if persona/classification specified
3. Compute deterministic output hash
4. Compare against expected values (threat level, rules)
5. Compare against golden outputs (drift detection)

### Golden Outputs

Golden outputs are version-controlled snapshots of expected results:

- Stored in `jobs/sim_validator/golden_outputs.json`
- Include output hashes for each simulation
- Version-tagged (e.g., `1.0.0`)
- Must be regenerated when decision engine intentionally changes

## Usage

### Run Validation

```bash
# Via Python
python -c "import asyncio; from jobs.sim_validator.job import job; print(asyncio.run(job()))"

# Via pytest
pytest tests/test_sim_validator.py -v
```

### Update Golden Outputs

When decision engine behavior intentionally changes:

```bash
python -c "import asyncio; from jobs.sim_validator.job import job; print(asyncio.run(job(update_golden=True)))"
```

This regenerates `golden_outputs.json` with current outputs.

## Artifacts

Each validation run produces artifacts in `state/sim_validator/run_<timestamp>/`:

| File | Contents |
|------|----------|
| `input_snapshot.json` | All simulation inputs |
| `output_snapshot.json` | All simulation outputs with hashes |
| `validation_result.json` | Pass/fail, drift detection, failures |
| `summary.txt` | Human-readable summary |

## Drift Detection

Drift occurs when:

- Output hash changes without golden version bump
- Threat level differs from previous run
- Rules triggered differ from previous run

### When Drift is Expected

Update golden outputs when:

1. Adding new rules to decision engine
2. Changing threat score thresholds
3. Modifying doctrine constraints
4. Fixing a bug that changes outputs

### When Drift is a Bug

Investigate drift when:

1. No intentional changes were made
2. Drift occurs in one simulation but not others
3. Drift appears after unrelated changes

## Simulation Inputs

| Name | Event Type | Expected Threat | Description |
|------|------------|-----------------|-------------|
| `baseline_no_threat` | http_request | none | Normal API request |
| `auth_bruteforce_5_attempts` | auth | high | At-threshold bruteforce |
| `auth_bruteforce_10_attempts` | auth.bruteforce | high | Above-threshold bruteforce |
| `auth_below_threshold` | auth | none | Below-threshold failures |
| `guardian_secret_classification` | auth | high | Guardian + SECRET doctrine |
| `sentinel_unclassified` | auth | high | Sentinel + UNCLASSIFIED |
| `unknown_event_type` | custom_event | none | Unrecognized event type |
| `no_ip_in_bruteforce` | auth | none | Missing IP, no mitigation |

## CI Integration

The simulation validator runs in CI to:

1. Prevent accidental decision engine regressions
2. Verify deterministic behavior
3. Archive artifacts for compliance

```yaml
# Example CI step
- name: Run Simulation Validation
  run: |
    pytest tests/test_sim_validator.py -v
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Initial | 8 simulation inputs, baseline decision engine |
