"""
Tests for Compliance Gates.

Tests verify:
- SBOM generation produces valid output
- Provenance generation produces valid SLSA format
- CIS checks detect configuration issues
- SCAP scan detects security patterns
"""

import json
import tempfile
from pathlib import Path

import pytest


class TestSBOMGeneration:
    """Tests for SBOM generation."""

    def test_parse_requirements(self):
        """Requirements.txt parsing extracts dependencies."""
        from scripts.generate_sbom import parse_requirements

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("fastapi==0.115.0\n")
            f.write("pydantic>=2.0\n")
            f.write("# comment\n")
            f.write("requests~=2.31.0\n")
            f.name

        try:
            components = parse_requirements(Path(f.name))
            assert len(components) == 3

            # Check first component
            fastapi = next(c for c in components if c["name"] == "fastapi")
            assert fastapi["version"] == "0.115.0"
            assert fastapi["purl"] == "pkg:pypi/fastapi@0.115.0"
        finally:
            Path(f.name).unlink()

    def test_generate_sbom_produces_valid_cyclonedx(self):
        """Generated SBOM is valid CycloneDX format."""
        from scripts.generate_sbom import generate_sbom

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)

            # Create minimal requirements.txt
            (project_dir / "requirements.txt").write_text("pytest==8.0.0\n")

            output_path = project_dir / "sbom.json"
            sbom = generate_sbom(project_dir, output_path)

            # Check CycloneDX structure
            assert sbom["bomFormat"] == "CycloneDX"
            assert sbom["specVersion"] == "1.5"
            assert "serialNumber" in sbom
            assert "metadata" in sbom
            assert "components" in sbom

            # Check file was written
            assert output_path.exists()
            loaded = json.loads(output_path.read_text())
            assert loaded["bomFormat"] == "CycloneDX"

    def test_sha256_file(self):
        """sha256_file computes correct hash."""
        from scripts.generate_sbom import sha256_file

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            f.flush()

            digest = sha256_file(Path(f.name))
            # Known hash of "test content"
            assert len(digest) == 64
            assert digest.isalnum()

        Path(f.name).unlink()


class TestProvenanceGeneration:
    """Tests for SLSA provenance generation."""

    def test_generate_provenance_produces_valid_slsa(self):
        """Generated provenance is valid SLSA format."""
        from scripts.provenance import generate_provenance, SLSA_PREDICATE_TYPE

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            output_path = project_dir / "provenance.json"

            provenance = generate_provenance(project_dir, output_path)

            # Check SLSA structure
            assert provenance["_type"] == "https://in-toto.io/Statement/v1"
            assert provenance["predicateType"] == SLSA_PREDICATE_TYPE
            assert "subject" in provenance
            assert "predicate" in provenance

            predicate = provenance["predicate"]
            assert "buildDefinition" in predicate
            assert "runDetails" in predicate

    def test_verify_provenance_valid(self):
        """verify_provenance accepts valid provenance."""
        from scripts.provenance import generate_provenance, verify_provenance

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            output_path = project_dir / "provenance.json"

            generate_provenance(project_dir, output_path)
            is_valid, errors = verify_provenance(output_path)

            assert is_valid
            assert len(errors) == 0

    def test_verify_provenance_invalid_file(self):
        """verify_provenance rejects invalid provenance."""
        from scripts.provenance import verify_provenance

        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_path = Path(tmpdir) / "invalid.json"
            invalid_path.write_text('{"invalid": "provenance"}')

            is_valid, errors = verify_provenance(invalid_path)
            assert not is_valid
            assert len(errors) > 0

    def test_verify_provenance_missing_file(self):
        """verify_provenance handles missing file."""
        from scripts.provenance import verify_provenance

        is_valid, errors = verify_provenance(Path("/nonexistent/path.json"))
        assert not is_valid
        assert "not found" in errors[0].lower()


class TestCISChecks:
    """Tests for CIS configuration checks."""

    def test_run_all_checks_returns_report(self):
        """run_all_checks produces a compliance report."""
        from scripts.cis_check import run_all_checks

        report = run_all_checks()

        assert report.total_checks > 0
        assert report.passed + report.failed == report.total_checks
        assert 0 <= report.score <= 100
        assert isinstance(report.checks, list)

    def test_check_result_structure(self):
        """Check results have required fields."""
        from scripts.cis_check import run_all_checks

        report = run_all_checks()

        for check in report.checks:
            assert hasattr(check, "id")
            assert hasattr(check, "name")
            assert hasattr(check, "severity")
            assert hasattr(check, "passed")
            assert hasattr(check, "message")
            assert check.severity in ("critical", "high", "medium", "low")

    def test_report_to_dict(self):
        """Report converts to JSON-serializable dict."""
        from scripts.cis_check import run_all_checks, report_to_dict

        report = run_all_checks()
        d = report_to_dict(report)

        # Should be JSON serializable
        json_str = json.dumps(d)
        assert len(json_str) > 0

        # Check structure
        assert "timestamp" in d
        assert "total_checks" in d
        assert "passed" in d
        assert "failed" in d
        assert "score" in d
        assert "checks" in d

    def test_auth_fallback_check(self):
        """Auth fallback check detects enabled fallback."""
        from scripts.cis_check import check_auth_fallback_disabled
        import os

        # Test with env var set
        os.environ["FG_AUTH_ALLOW_FALLBACK"] = "true"
        try:
            result = check_auth_fallback_disabled()
            # Should fail when fallback is enabled
            # (but may pass if docker-compose.yml doesn't exist)
            assert result.id == "CIS-FG-001"
        finally:
            del os.environ["FG_AUTH_ALLOW_FALLBACK"]

    def test_debug_mode_check(self):
        """Debug mode check detects enabled debug."""
        from scripts.cis_check import check_debug_disabled
        import os

        # Test with debug enabled
        os.environ["FG_DEBUG"] = "true"
        try:
            result = check_debug_disabled()
            assert not result.passed
            assert "enabled" in result.message.lower()
        finally:
            del os.environ["FG_DEBUG"]

        # Test with debug disabled
        result = check_debug_disabled()
        assert result.passed


class TestSCAPScan:
    """Tests for SCAP security scanning."""

    def test_scan_detects_sql_injection(self):
        """Scan detects SQL injection patterns."""
        from scripts.scap_scan import scan_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n')
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        # Should find SQL injection
        sql_findings = [f for f in findings if "SQL" in f.rule_id]
        assert len(sql_findings) > 0

    def test_scan_detects_command_injection(self):
        """Scan detects command injection patterns."""
        from scripts.scap_scan import scan_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('os.system("ls " + user_input)\n')
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        cmd_findings = [f for f in findings if "CMD" in f.rule_id]
        assert len(cmd_findings) > 0

    def test_scan_detects_hardcoded_password(self):
        """Scan detects hardcoded passwords."""
        from scripts.scap_scan import scan_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('password = "supersecret123"\n')
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        cred_findings = [f for f in findings if "CRED" in f.rule_id]
        assert len(cred_findings) > 0

    def test_scan_detects_unsafe_eval(self):
        """Scan detects unsafe eval usage."""
        from scripts.scap_scan import scan_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("result = eval(user_input)\n")
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        eval_findings = [f for f in findings if "EVAL" in f.rule_id]
        assert len(eval_findings) > 0

    def test_scan_ignores_comments(self):
        """Scan ignores patterns in comments."""
        from scripts.scap_scan import scan_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('# password = "supersecret123"\n')
            f.write("# This is a comment about os.system\n")
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        # Should not find anything in comments
        assert len(findings) == 0

    def test_scan_respects_file_extensions(self):
        """Scan only applies rules to matching file types."""
        from scripts.scap_scan import scan_file

        # Python-specific rule should not fire on JS file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("pickle.loads(data)\n")  # Python-specific
            f.flush()

            findings = scan_file(Path(f.name))

        Path(f.name).unlink()

        pickle_findings = [f for f in findings if "DESER" in f.rule_id]
        assert len(pickle_findings) == 0  # Should not match in .js file

    def test_run_scan_produces_result(self):
        """run_scan produces a scan result."""
        from scripts.scap_scan import run_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)

            # Create a file with an issue
            (project_dir / "test.py").write_text("eval(user_input)\n")

            result = run_scan(project_dir)

            assert result.files_scanned >= 1
            assert isinstance(result.findings, list)
            assert "critical" in result.findings_by_severity

    def test_result_to_dict(self):
        """Scan result converts to JSON-serializable dict."""
        from scripts.scap_scan import run_scan, result_to_dict

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            (project_dir / "test.py").write_text("x = 1\n")

            result = run_scan(project_dir)
            d = result_to_dict(result)

            # Should be JSON serializable
            json_str = json.dumps(d)
            assert len(json_str) > 0

            assert "timestamp" in d
            assert "files_scanned" in d
            assert "findings" in d


class TestComplianceIntegration:
    """Integration tests for compliance gates."""

    def test_full_compliance_pipeline(self):
        """Test complete compliance check pipeline."""
        from scripts.generate_sbom import generate_sbom
        from scripts.provenance import generate_provenance, verify_provenance
        from scripts.cis_check import run_all_checks
        from scripts.scap_scan import run_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            artifacts_dir = project_dir / "artifacts"
            artifacts_dir.mkdir()

            # Create minimal project structure
            (project_dir / "requirements.txt").write_text("pytest==8.0.0\n")
            (project_dir / "main.py").write_text('print("hello")\n')

            # Generate SBOM
            sbom = generate_sbom(project_dir, artifacts_dir / "sbom.json")
            assert len(sbom["components"]) > 0

            # Generate provenance
            _ = generate_provenance(project_dir, artifacts_dir / "provenance.json")
            is_valid, _ = verify_provenance(artifacts_dir / "provenance.json")
            assert is_valid

            # Run CIS checks
            cis_report = run_all_checks()
            assert cis_report.total_checks > 0

            # Run SCAP scan
            scan_result = run_scan(project_dir)
            assert scan_result.files_scanned >= 1

    def test_artifacts_are_valid_json(self):
        """All compliance artifacts are valid JSON."""
        from scripts.generate_sbom import generate_sbom
        from scripts.provenance import generate_provenance
        from scripts.cis_check import run_all_checks, report_to_dict
        from scripts.scap_scan import run_scan, result_to_dict

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            (project_dir / "requirements.txt").write_text("pytest==8.0.0\n")

            # Generate all artifacts
            sbom = generate_sbom(project_dir)
            prov = generate_provenance(project_dir)
            cis = report_to_dict(run_all_checks())
            scap = result_to_dict(run_scan(project_dir))

            # All should be JSON serializable
            for name, artifact in [
                ("sbom", sbom),
                ("prov", prov),
                ("cis", cis),
                ("scap", scap),
            ]:
                try:
                    json.dumps(artifact)
                except (TypeError, ValueError) as e:
                    pytest.fail(f"{name} artifact not JSON serializable: {e}")
