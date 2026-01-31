"""
Tests for the Simulation Validator job.

Tests verify:
- Deterministic output hashing
- Drift detection when outputs change
- Artifact generation
- Golden output management
"""

from datetime import datetime


from jobs.sim_validator.job import (
    GOLDEN_VERSION,
    SIMULATION_INPUTS,
    SimulationInput,
    SimulationOutput,
    ValidationResult,
    canonical_json,
    compute_input_hash,
    compute_output_hash,
    run_all_simulations,
    run_simulation,
    sha256_hex,
    validate_all,
    validate_output,
)


class TestDeterministicHashing:
    """Tests for deterministic hash functions."""

    def test_sha256_deterministic(self):
        """Same input always produces same hash."""
        data = "test data"
        hash1 = sha256_hex(data)
        hash2 = sha256_hex(data)
        assert hash1 == hash2

    def test_canonical_json_sorted_keys(self):
        """JSON keys are sorted for determinism."""
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_canonical_json_no_whitespace(self):
        """JSON has no extra whitespace."""
        obj = {"key": "value", "nested": {"inner": "data"}}
        result = canonical_json(obj)
        assert " " not in result
        assert "\n" not in result

    def test_input_hash_deterministic(self):
        """Same simulation input produces same hash."""
        sim_input = SimulationInput(
            name="test",
            tenant_id="t1",
            source="test",
            event_type="auth",
            payload={"data": "value"},
        )
        hash1 = compute_input_hash(sim_input)
        hash2 = compute_input_hash(sim_input)
        assert hash1 == hash2

    def test_input_hash_differs_for_different_inputs(self):
        """Different inputs produce different hashes."""
        input1 = SimulationInput(
            name="test1", tenant_id="t1", source="s1", event_type="e1", payload={}
        )
        input2 = SimulationInput(
            name="test2", tenant_id="t2", source="s2", event_type="e2", payload={}
        )
        assert compute_input_hash(input1) != compute_input_hash(input2)

    def test_output_hash_excludes_non_deterministic_fields(self):
        """Output hash only includes deterministic fields."""
        output = {
            "threat_level": "high",
            "rules_triggered": ["rule:test"],
            "mitigations": [],
            "anomaly_score": 0.5,
            "score": 50,
            "roe_applied": False,
            "disruption_limited": False,
            # These should be excluded
            "timestamp": datetime.now().isoformat(),
            "random_id": "abc123",
        }
        hash1 = compute_output_hash(output)

        output["timestamp"] = datetime.now().isoformat()  # Different timestamp
        output["random_id"] = "xyz789"  # Different ID
        hash2 = compute_output_hash(output)

        assert hash1 == hash2  # Hashes should match despite different timestamps


class TestSimulationExecution:
    """Tests for running simulations through the decision engine."""

    def test_run_simulation_produces_output(self):
        """Running a simulation produces valid output."""
        sim_input = SIMULATION_INPUTS[0]  # baseline_no_threat
        output = run_simulation(sim_input)

        assert isinstance(output, SimulationOutput)
        assert output.name == sim_input.name
        assert output.threat_level in ["none", "low", "medium", "high", "critical"]
        assert isinstance(output.rules_triggered, list)
        assert isinstance(output.output_hash, str)
        assert len(output.output_hash) == 64  # SHA-256 hex

    def test_run_simulation_deterministic(self):
        """Same input always produces same output."""
        sim_input = SIMULATION_INPUTS[0]

        output1 = run_simulation(sim_input)
        output2 = run_simulation(sim_input)

        assert output1.output_hash == output2.output_hash
        assert output1.threat_level == output2.threat_level
        assert output1.rules_triggered == output2.rules_triggered

    def test_bruteforce_detection(self):
        """Auth bruteforce pattern is detected."""
        # Find the bruteforce test input
        bruteforce_input = next(
            i for i in SIMULATION_INPUTS if i.name == "auth_bruteforce_5_attempts"
        )
        output = run_simulation(bruteforce_input)

        assert output.threat_level == "high"
        assert "rule:ssh_bruteforce" in output.rules_triggered
        assert len(output.mitigations) > 0
        assert output.mitigations[0]["action"] == "block_ip"

    def test_below_threshold_no_threat(self):
        """Below-threshold auth failures do not trigger."""
        below_threshold = next(
            i for i in SIMULATION_INPUTS if i.name == "auth_below_threshold"
        )
        output = run_simulation(below_threshold)

        assert output.threat_level == "none"
        assert "rule:default_allow" in output.rules_triggered
        assert len(output.mitigations) == 0

    def test_guardian_secret_doctrine_applied(self):
        """Guardian + SECRET classification applies doctrine."""
        guardian_input = next(
            i for i in SIMULATION_INPUTS if i.name == "guardian_secret_classification"
        )
        output = run_simulation(guardian_input)

        assert output.roe_applied is True

    def test_run_all_simulations(self):
        """All predefined simulations run successfully."""
        outputs = run_all_simulations()

        assert len(outputs) == len(SIMULATION_INPUTS)
        for sim_input in SIMULATION_INPUTS:
            assert sim_input.name in outputs
            output = outputs[sim_input.name]
            assert isinstance(output, SimulationOutput)


class TestValidation:
    """Tests for output validation against expected values."""

    def test_validate_expected_threat_level_pass(self):
        """Validation passes when threat level matches expected."""
        sim_input = SimulationInput(
            name="test",
            tenant_id="t1",
            source="s1",
            event_type="auth",
            payload={},
            expected_threat_level="none",
        )
        output = SimulationOutput(
            name="test",
            input_hash="abc",
            threat_level="none",
            rules_triggered=["rule:default_allow"],
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash="xyz",
        )

        passed, errors = validate_output(sim_input, output, {})
        assert passed
        assert len(errors) == 0

    def test_validate_expected_threat_level_fail(self):
        """Validation fails when threat level doesn't match expected."""
        sim_input = SimulationInput(
            name="test",
            tenant_id="t1",
            source="s1",
            event_type="auth",
            payload={},
            expected_threat_level="high",
        )
        output = SimulationOutput(
            name="test",
            input_hash="abc",
            threat_level="none",  # Doesn't match expected
            rules_triggered=["rule:default_allow"],
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash="xyz",
        )

        passed, errors = validate_output(sim_input, output, {})
        assert not passed
        assert len(errors) > 0
        assert "threat level mismatch" in errors[0].lower()

    def test_validate_expected_rules_pass(self):
        """Validation passes when rules match expected."""
        sim_input = SimulationInput(
            name="test",
            tenant_id="t1",
            source="s1",
            event_type="auth",
            payload={},
            expected_rules=["rule:default_allow"],
        )
        output = SimulationOutput(
            name="test",
            input_hash="abc",
            threat_level="none",
            rules_triggered=["rule:default_allow"],
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash="xyz",
        )

        passed, errors = validate_output(sim_input, output, {})
        assert passed

    def test_validate_expected_rules_fail(self):
        """Validation fails when rules don't match expected."""
        sim_input = SimulationInput(
            name="test",
            tenant_id="t1",
            source="s1",
            event_type="auth",
            payload={},
            expected_rules=["rule:ssh_bruteforce"],  # Expected this rule
        )
        output = SimulationOutput(
            name="test",
            input_hash="abc",
            threat_level="none",
            rules_triggered=["rule:default_allow"],  # Got different rule
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash="xyz",
        )

        passed, errors = validate_output(sim_input, output, {})
        assert not passed
        assert len(errors) > 0
        assert "rules mismatch" in errors[0].lower()


class TestDriftDetection:
    """Tests for output drift detection - CRITICAL for regression detection."""

    def test_no_drift_when_outputs_match(self):
        """No drift detected when output hash matches golden."""
        output_hash = "abc123"
        golden = {
            "outputs": {
                "test": {
                    "output_hash": output_hash,
                }
            }
        }
        sim_input = SimulationInput(
            name="test", tenant_id="t1", source="s1", event_type="e1", payload={}
        )
        output = SimulationOutput(
            name="test",
            input_hash="x",
            threat_level="none",
            rules_triggered=[],
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash=output_hash,  # Matches golden
        )

        passed, errors = validate_output(sim_input, output, golden)
        assert passed
        assert not any("drift" in e.lower() for e in errors)

    def test_drift_detected_when_outputs_differ(self):
        """Drift detected when output hash differs from golden."""
        golden = {
            "outputs": {
                "test": {
                    "output_hash": "original_hash",
                }
            }
        }
        sim_input = SimulationInput(
            name="test", tenant_id="t1", source="s1", event_type="e1", payload={}
        )
        output = SimulationOutput(
            name="test",
            input_hash="x",
            threat_level="none",
            rules_triggered=[],
            mitigations=[],
            anomaly_score=0.1,
            score=0,
            roe_applied=False,
            disruption_limited=False,
            output_hash="different_hash",  # Doesn't match golden
        )

        passed, errors = validate_output(sim_input, output, golden)
        assert not passed
        assert any("drift" in e.lower() for e in errors)

    def test_validate_all_detects_drift(self):
        """validate_all correctly identifies drift across all simulations."""
        # Run simulations to get current outputs
        # Run simulations (output used for comparison)

        # Create fake golden with one different hash
        first_name = SIMULATION_INPUTS[0].name
        fake_golden = {
            "outputs": {
                first_name: {
                    "output_hash": "fake_different_hash",
                }
            }
        }

        result = validate_all(golden=fake_golden, fail_on_drift=True)
        assert result.drift_detected is True
        assert result.failed_count > 0

    def test_drift_causes_validation_failure_when_fail_on_drift_true(self):
        """With fail_on_drift=True, drift causes validation to fail."""
        fake_golden = {
            "outputs": {SIMULATION_INPUTS[0].name: {"output_hash": "wrong_hash"}}
        }
        result = validate_all(golden=fake_golden, fail_on_drift=True)
        # Should fail because there's drift (even if expectations match)
        assert result.drift_detected is True


class TestArtifactGeneration:
    """Tests for artifact file generation."""

    def test_validation_produces_result_object(self):
        """validate_all produces a proper ValidationResult."""
        # Use empty golden so no drift detection
        result = validate_all(golden={"outputs": {}}, fail_on_drift=False)

        assert isinstance(result, ValidationResult)
        assert result.version == GOLDEN_VERSION
        assert result.total_simulations == len(SIMULATION_INPUTS)
        assert result.passed_count + result.failed_count == result.total_simulations
        assert isinstance(result.timestamp, str)

    def test_all_predefined_simulations_pass_expectations(self):
        """All predefined simulations pass their expected values."""
        # Run without golden comparison (no drift check)
        result = validate_all(golden={"outputs": {}}, fail_on_drift=False)

        # All simulations should pass their hardcoded expectations
        assert result.passed is True, f"Failures: {result.failures}"
        assert result.failed_count == 0


class TestIntegration:
    """Integration tests for the simulation validator."""

    def test_full_validation_cycle(self):
        """Test complete validation cycle: run -> validate -> artifacts."""
        # Run all simulations
        outputs = run_all_simulations()
        assert len(outputs) == len(SIMULATION_INPUTS)

        # Each output should have expected fields
        for name, output in outputs.items():
            assert output.threat_level in ["none", "low", "medium", "high", "critical"]
            assert isinstance(output.rules_triggered, list)
            assert isinstance(output.output_hash, str)

    def test_simulation_inputs_are_valid(self):
        """All predefined simulation inputs are valid and can be processed."""
        for sim_input in SIMULATION_INPUTS:
            # Should not raise
            output = run_simulation(sim_input)
            assert output.name == sim_input.name

    def test_determinism_across_multiple_runs(self):
        """Multiple validation runs produce identical results."""
        result1 = validate_all(golden={"outputs": {}}, fail_on_drift=False)
        result2 = validate_all(golden={"outputs": {}}, fail_on_drift=False)

        assert result1.passed == result2.passed
        assert result1.passed_count == result2.passed_count
        assert result1.failed_count == result2.failed_count
        # Timestamps will differ but that's expected

        # Output hashes should be identical
        outputs1 = run_all_simulations()
        outputs2 = run_all_simulations()

        for name in outputs1:
            assert outputs1[name].output_hash == outputs2[name].output_hash


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_payload(self):
        """Simulation with empty payload runs without error."""
        sim_input = SimulationInput(
            name="empty_payload",
            tenant_id="t1",
            source="test",
            event_type="unknown",
            payload={},
        )
        output = run_simulation(sim_input)
        assert output.threat_level == "none"

    def test_missing_expected_values(self):
        """Simulation without expected values passes validation."""
        sim_input = SimulationInput(
            name="no_expectations",
            tenant_id="t1",
            source="test",
            event_type="unknown",
            payload={},
            # No expected_threat_level or expected_rules
        )
        output = run_simulation(sim_input)
        passed, errors = validate_output(sim_input, output, {})
        assert passed

    def test_new_simulation_not_in_golden(self):
        """New simulation not in golden doesn't cause drift error."""
        sim_input = SimulationInput(
            name="brand_new_test",
            tenant_id="t1",
            source="test",
            event_type="test",
            payload={},
        )
        output = run_simulation(sim_input)

        # Golden doesn't have this simulation
        golden = {"outputs": {}}

        passed, errors = validate_output(sim_input, output, golden)
        # Should pass - no drift can occur if not in golden
        assert passed
        assert not any("drift" in e.lower() for e in errors)
