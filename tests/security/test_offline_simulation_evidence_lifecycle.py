"""
CUSTOMER-ZERO-EVIDENCE-LIFECYCLE-001 — Offline simulation evidence lifecycle regression tests.

12 mandatory tests covering the assurance boundary, freshness enforcement,
CLI verifier, and safety invariants.

Workstream F of CUSTOMER-ZERO-EVIDENCE-LIFECYCLE-001.

Tests:
  01  Fresh evidence passes the verifier
  02  Stale source_tree_hash causes verifier failure
  03  ROADMAP.md exclusion prevents spurious invalidation
  04  Missing evidence file causes verifier failure
  05  Malformed (non-JSON) evidence causes verifier failure
  06  result=FAILED simulation evidence causes verifier failure
  07  Forged GREEN flag with no execution data causes verifier failure
  08  Simulation --dry-run output is accepted by the J_CE3 validator
  09  Preauthorization (J_CE3 dimension) is blocked when evidence is stale
  10  Committed evidence contains no test-only signing key material
  11  Production environment is rejected by the simulation runner
  12  Existing credential security invariants remain intact

Scope: OFFLINE ONLY. No Vault. No AWS. No paid infrastructure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

os.environ.setdefault("FG_ENV", "test")

import pytest

from services.governance.customer_zero_readiness import (
    ReadinessStatus,
    _compute_tree_content_hash,
    _validate_offline_simulation_evidence,
)

REPO = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = REPO / "customer_one" / "offline_simulation_evidence.json"
_TREE_HASH_EXCLUDED = frozenset(
    {
        "customer_one/offline_simulation_evidence.json",
        "ROADMAP.md",
    }
)


# ---------------------------------------------------------------------------
# Helpers (mirrors helpers in test_cz_run3_readiness_integration_repair_001.py)
# ---------------------------------------------------------------------------


def _live_tree_hash() -> str:
    return _compute_tree_content_hash(REPO, _TREE_HASH_EXCLUDED)


def _make_evidence(
    *,
    result: str = "GREEN",
    source_tree_hash: str | None = None,
    checks_executed: list[str] | None = None,
    checks_passed: int | None = None,
    checks_failed: int = 0,
    schema_version: str = "1.0",
) -> dict:
    if source_tree_hash is None:
        source_tree_hash = _live_tree_hash()
    if checks_executed is None:
        checks_executed = [
            "trust_keys_generated",
            "identity_domain_sign_verify",
            "approval_domain_sign_verify",
            "acceptance_domain_sign_verify",
            "cross_domain_isolation",
            "verifier_contract_fail_closed",
        ]
    if checks_passed is None:
        checks_passed = len(checks_executed) - checks_failed
    return {
        "schema_version": schema_version,
        "simulation_id": str(uuid.uuid4()),
        "source_sha": "0" * 40,
        "source_tree_hash": source_tree_hash,
        "simulation_contract_version": "1.0",
        "result": result,
        "checks_executed": checks_executed,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "evidence_reference": "customer_one/offline_simulation_evidence.json",
        "test_only": True,
        "paid_infrastructure_required": False,
    }


def _write_evidence(tmp_path: Path, evidence: dict) -> Path:
    p = tmp_path / "customer_one" / "offline_simulation_evidence.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(evidence), encoding="utf-8")
    return p


# ===========================================================================
# Test 01 — Fresh evidence passes
# ===========================================================================


def test_lifecycle_01_fresh_evidence_passes(tmp_path: Path) -> None:
    """Evidence with the current source_tree_hash must pass the validator."""
    evidence = _make_evidence()
    p = _write_evidence(tmp_path, evidence)

    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.PASS, f"Expected PASS: {ev}"
    assert "GREEN" in ev


# ===========================================================================
# Test 02 — Stale source_tree_hash causes failure
# ===========================================================================


def test_lifecycle_02_stale_tree_hash_fails(tmp_path: Path) -> None:
    """Evidence whose source_tree_hash doesn't match the current tree must fail."""
    stale_hash = "a" * 64  # guaranteed not to match current tree
    evidence = _make_evidence(source_tree_hash=stale_hash)
    p = _write_evidence(tmp_path, evidence)

    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.FAIL, f"Expected FAIL for stale hash: {ev}"
    assert "stale" in ev.lower() or "tree" in ev.lower(), ev


# ===========================================================================
# Test 03 — ROADMAP.md exclusion prevents spurious invalidation
# ===========================================================================


def test_lifecycle_03_excluded_ledger_does_not_invalidate(tmp_path: Path) -> None:
    """ROADMAP.md must be excluded from source_tree_hash so updating it never
    invalidates committed evidence."""
    canonical_hash = _compute_tree_content_hash(REPO, _TREE_HASH_EXCLUDED)

    # Hash computed WITHOUT excluding ROADMAP.md — includes its content.
    non_canonical_hash = _compute_tree_content_hash(
        REPO,
        frozenset({"customer_one/offline_simulation_evidence.json"}),
    )

    # If ROADMAP.md is non-empty (it always is), including it changes the hash.
    roadmap = REPO / "ROADMAP.md"
    if roadmap.exists() and roadmap.stat().st_size > 0:
        assert canonical_hash != non_canonical_hash, (
            "Canonical hash must differ from non-canonical hash when ROADMAP.md "
            "is non-empty — proving it is included/excluded correctly"
        )

    # Evidence with the canonical hash (ROADMAP.md excluded) passes.
    p = _write_evidence(tmp_path, _make_evidence(source_tree_hash=canonical_hash))
    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.PASS, (
        f"Evidence with canonical hash must pass; got {status}: {ev}"
    )

    # Evidence with the non-canonical hash (ROADMAP.md included) fails.
    if canonical_hash != non_canonical_hash:
        p2 = _write_evidence(
            tmp_path, _make_evidence(source_tree_hash=non_canonical_hash)
        )
        status2, ev2, _, _ = _validate_offline_simulation_evidence(p2, REPO)
        assert status2 == ReadinessStatus.FAIL, (
            f"Evidence with non-canonical hash must fail; got {status2}: {ev2}"
        )


# ===========================================================================
# Test 04 — Missing evidence file causes failure
# ===========================================================================


def test_lifecycle_04_missing_evidence_fails(tmp_path: Path) -> None:
    """Absent evidence file must produce NOT_PROVEN, not a silent pass."""
    missing = tmp_path / "customer_one" / "offline_simulation_evidence.json"

    status, ev, _, _ = _validate_offline_simulation_evidence(missing, REPO)
    assert status == ReadinessStatus.NOT_PROVEN, (
        f"Expected NOT_PROVEN for missing file; got {status}: {ev}"
    )
    assert "not found" in ev.lower(), ev


# ===========================================================================
# Test 05 — Malformed evidence causes failure
# ===========================================================================


def test_lifecycle_05_malformed_evidence_fails(tmp_path: Path) -> None:
    """Non-JSON evidence must cause FAIL."""
    p = tmp_path / "customer_one" / "offline_simulation_evidence.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ this is not valid json }", encoding="utf-8")

    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.FAIL, (
        f"Expected FAIL for malformed JSON; got {status}"
    )
    assert "malformed" in ev.lower() or "json" in ev.lower(), ev


# ===========================================================================
# Test 06 — FAILED simulation result causes failure
# ===========================================================================


def test_lifecycle_06_failed_simulation_fails(tmp_path: Path) -> None:
    """Evidence with result=FAILED must cause FAIL even if all other fields are valid."""
    evidence = _make_evidence(result="FAILED", checks_failed=1, checks_passed=5)
    p = _write_evidence(tmp_path, evidence)

    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.FAIL, (
        f"Expected FAIL for result=FAILED; got {status}: {ev}"
    )


# ===========================================================================
# Test 07 — Forged GREEN flag with empty checks causes failure
# ===========================================================================


def test_lifecycle_07_forged_green_fails(tmp_path: Path) -> None:
    """result=GREEN with no checks_executed must be rejected as a forged flag."""
    evidence = _make_evidence(
        result="GREEN",
        checks_executed=[],
        checks_passed=0,
        checks_failed=0,
    )
    p = _write_evidence(tmp_path, evidence)

    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.FAIL, (
        f"Expected FAIL for forged GREEN; got {status}: {ev}"
    )
    assert (
        "empty" in ev.lower()
        or "no checks" in ev.lower()
        or "forged" in ev.lower()
        or "0" in ev
    ), ev


# ===========================================================================
# Test 08 — Simulation --dry-run output accepted by J_CE3 validator
# ===========================================================================


def test_lifecycle_08_generated_evidence_accepted_by_j_ce3(tmp_path: Path) -> None:
    """Evidence produced by --dry-run must be accepted by _validate_offline_simulation_evidence."""
    result = subprocess.run(
        [
            sys.executable,
            "tools/ci/run_offline_ceremony_simulation.py",
            "--repo",
            ".",
            "--dry-run",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "FG_ENV": "test"},
    )
    assert result.returncode == 0, (
        f"Simulation --dry-run failed:\n{result.stdout}\n{result.stderr}"
    )

    # Parse JSON from mixed output
    lines = result.stdout.splitlines()
    json_start = next(
        (i for i, line in enumerate(lines) if line.strip().startswith("{")), None
    )
    assert json_start is not None, f"No JSON in dry-run output:\n{result.stdout}"
    evidence = json.loads("\n".join(lines[json_start:]))

    assert evidence.get("result") == "GREEN"
    assert evidence.get("checks_failed") == 0
    assert evidence.get("checks_passed", 0) > 0

    # Write to tmp_path and validate
    p = _write_evidence(tmp_path, evidence)
    status, ev, _, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.PASS, (
        f"Validator rejected --dry-run evidence; got {status}: {ev}"
    )


# ===========================================================================
# Test 09 — Preauthorization (J_CE3 dimension) blocked when evidence is stale
# ===========================================================================


def test_lifecycle_09_preauthorization_blocked_when_stale(tmp_path: Path) -> None:
    """Stale evidence must cause the J_CE3 validator to return FAIL, blocking
    Customer-Zero preauthorization."""
    stale_evidence = _make_evidence(source_tree_hash="dead" * 16)
    p = _write_evidence(tmp_path, stale_evidence)

    status, ev, reason, _ = _validate_offline_simulation_evidence(p, REPO)
    assert status == ReadinessStatus.FAIL, (
        f"J_CE3 must return FAIL for stale evidence; got {status}: {ev}"
    )
    assert "stale" in ev.lower() or "tree" in ev.lower(), (
        f"Error message must indicate stale tree hash; got: {ev}"
    )


# ===========================================================================
# Test 10 — No test-only signing keys persisted in committed evidence
# ===========================================================================


def test_lifecycle_10_no_test_only_signing_keys_persisted() -> None:
    """The committed evidence file must not contain private key material.

    The simulation uses ephemeral TEST-ONLY Ed25519 keys. Verifies that
    those keys are not inadvertently serialised into the evidence file.
    """
    if not EVIDENCE_PATH.exists():
        pytest.skip("Committed evidence file not present — regenerate first")

    evidence_text = EVIDENCE_PATH.read_text(encoding="utf-8")

    # PEM private key markers
    pem_markers = [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]
    for marker in pem_markers:
        assert marker not in evidence_text, (
            f"Evidence file contains PEM private key marker: {marker!r}"
        )

    # Key-named fields that should never appear in evidence
    evidence = json.loads(evidence_text)
    sensitive_keys = {"private_key", "secret_key", "signing_key", "private", "secret"}

    def _scan(obj: object, path: str = "$") -> list[str]:
        violations: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in sensitive_keys:
                    violations.append(f"Sensitive key {k!r} at {path}")
                violations.extend(_scan(v, f"{path}.{k}"))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                violations.extend(_scan(item, f"{path}[{i}]"))
        return violations

    violations = _scan(evidence)
    assert not violations, (
        "Evidence file must not contain private key fields:\n" + "\n".join(violations)
    )


# ===========================================================================
# Test 11 — Production environment rejected by simulation runner
# ===========================================================================


@pytest.mark.parametrize("fg_env", ["production", "prod", "staging"])
def test_lifecycle_11_production_env_rejects_simulation(fg_env: str) -> None:
    """Simulation runner must exit 2 when FG_ENV is a production-like value."""
    env = {**os.environ, "FG_ENV": fg_env}
    result = subprocess.run(
        [
            sys.executable,
            "tools/ci/run_offline_ceremony_simulation.py",
            "--repo",
            ".",
            "--dry-run",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 2, (
        f"Expected exit 2 for FG_ENV={fg_env!r}; got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert (
        "must not be used" in result.stderr.lower()
        or "environment" in result.stderr.lower()
    ), f"Rejection message missing from stderr: {result.stderr!r}"


# ===========================================================================
# Test 12 — Existing credential security invariants remain intact
# ===========================================================================


def test_lifecycle_12_credential_security_invariants_hold() -> None:
    """Key security invariants from P0-SECURITY-BASELINE-001 must still hold
    after this PR's changes.

    Specifically:
      - FG_KEY_PEPPER is in REQUIRED_PROD_ENV_VARS
      - assert_prod_invariants rejects ci-test-pepper in prod
      - enforce_required_env raises for missing FG_KEY_PEPPER in prod
    """
    from api.config.prod_invariants import (
        ProdInvariantViolation,
        _KNOWN_TEST_PEPPERS,
        assert_prod_invariants,
    )
    from api.config.required_env import REQUIRED_PROD_ENV_VARS, enforce_required_env

    # FG_KEY_PEPPER must still be required in prod
    assert "FG_KEY_PEPPER" in REQUIRED_PROD_ENV_VARS, (
        "FG_KEY_PEPPER must remain in REQUIRED_PROD_ENV_VARS"
    )

    # ci-test-pepper must still be in the known-test-peppers set
    assert "ci-test-pepper" in _KNOWN_TEST_PEPPERS, (
        "ci-test-pepper must remain in _KNOWN_TEST_PEPPERS"
    )

    # Valid prod env (with rotation-safe pepper) must pass
    valid_env = {
        "FG_ENV": "prod",
        "FG_AUTH_ENABLED": "1",
        "FG_DB_URL": "postgresql+psycopg://user:pass@localhost/db",
        "FG_DB_BACKEND": "postgres",
        "DATABASE_URL": "postgresql://example",
        "FG_ENFORCEMENT_MODE": "enforce",
        "FG_SIGNING_SECRET": "sig-secret",
        "FG_INTERNAL_GATEWAY_SECRET": "gw-secret",
        "FG_INTERNAL_AUTH_SECRET": "auth-secret",
        "FG_API_KEY": "api-key",
        "FG_KEY_PEPPER": "rotated-prod-pepper-00000001",
        "STRIPE_SECRET_KEY": "stripe-key",
        "STRIPE_WEBHOOK_SECRET": "stripe-wh-secret",
        "FG_ANTHROPIC_API_KEY": "anthropic-key",
        "FG_OIDC_ISSUER": "https://oidc.example.com",
        "FG_DEV_AUTH_BYPASS": "0",
    }
    assert_prod_invariants(valid_env)  # must not raise

    # ci-test-pepper must be rejected in prod
    bad_env = {**valid_env, "FG_KEY_PEPPER": "ci-test-pepper"}
    with pytest.raises(ProdInvariantViolation):
        assert_prod_invariants(bad_env)

    # Missing FG_KEY_PEPPER must be rejected via required-env check
    no_pepper_env = {**valid_env}
    del no_pepper_env["FG_KEY_PEPPER"]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        enforce_required_env(no_pepper_env)
