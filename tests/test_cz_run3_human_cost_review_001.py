"""CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 — Adversarial tests for cost review package.

Tests: COST-001 through COST-028 (28 tests).
Work class: OFFLINE_PREPARATION.
Cloud mutations: 0. Spending authorization: unchanged. Live trust: unchanged.

Coverage areas:
  - COST-001–005: Authorization request schema completeness
  - COST-006–010: Pricing evidence schema and FP-001 enforcement
  - COST-011–013: Financial field null enforcement
  - COST-014–015: Historical cost not used as ceiling
  - COST-016–019: Independent verifier behavior
  - COST-020–022: Cost model correctness (Decimal arithmetic)
  - COST-023–025: Watchdog behavior
  - COST-026–028: Canonical truth preservation

All tests are deterministic and offline-only. No live infrastructure. No HCP API.
No AWS API. No network calls of any kind.
"""

from __future__ import annotations

import json
import time
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REQUEST_FILE = REPO / "customer_one" / "run3_cost_authorization_request.json"
PRICING_FILE = REPO / "customer_one" / "run3_pricing_evidence_schema.json"
FINANCIAL_RISK_FILE = REPO / "customer_one" / "run3_financial_risk_register.json"
CEREMONY_STATE_FILE = REPO / "customer_one" / "ceremony_state.yaml"
VERIFIER_MODULE = REPO / "services" / "governance" / "customer_zero_cost_review.py"
WATCHDOG_MODULE = REPO / "services" / "governance" / "run3_operator_watchdog.py"
COST_MODEL_MODULE = REPO / "services" / "governance" / "run3_cost_model.py"

CANONICAL_SOURCE_SHA = "873148e84b9d9163bb13c8e3e185f5c47d43225e"
HISTORICAL_COST_USD = 321.81

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_request() -> dict:
    return json.loads(REQUEST_FILE.read_text())

def _load_pricing() -> dict:
    return json.loads(PRICING_FILE.read_text())

def _load_risk_register() -> dict:
    return json.loads(FINANCIAL_RISK_FILE.read_text())

def _import_verifier():
    import importlib.util
    import sys
    name = "customer_zero_cost_review"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, VERIFIER_MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

def _import_watchdog():
    import importlib.util
    import sys
    name = "run3_operator_watchdog"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, WATCHDOG_MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

def _import_cost_model():
    import importlib.util
    import sys
    name = "run3_cost_model"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, COST_MODEL_MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# COST-001: Authorization request file exists
# ---------------------------------------------------------------------------

def test_cost_001_request_file_exists():
    """COST-001: run3_cost_authorization_request.json exists."""
    assert REQUEST_FILE.exists(), f"Authorization request file not found: {REQUEST_FILE}"


# ---------------------------------------------------------------------------
# COST-002: Authorization request schema fields present
# ---------------------------------------------------------------------------

def test_cost_002_request_required_fields():
    """COST-002: Authorization request contains all required schema fields."""
    req = _load_request()
    REQUIRED = [
        "request_id", "schema_version", "canonical_source_sha",
        "candidate_fingerprint", "infrastructure_fingerprint",
        "pricing_evidence_fingerprint", "pricing_valid_until",
        "hcp_organization", "hcp_project", "hcp_tier", "hcp_region",
        "aws_account", "terraform_workspace",
        "operator_identity", "approver_identity",
        "requested_max_cost_usd", "requested_max_runtime_minutes",
        "teardown_reserve_minutes", "authorization_expires_at",
        "abort_conditions", "audit_smoke_test_contract",
        "preserved_aws_resources", "evidence_manifest_reference",
        "request_created_at", "request_status",
    ]
    missing = [f for f in REQUIRED if f not in req]
    assert not missing, f"Missing required fields: {missing}"


# ---------------------------------------------------------------------------
# COST-003: Canonical SHA is bound correctly
# ---------------------------------------------------------------------------

def test_cost_003_canonical_sha_bound():
    """COST-003: canonical_source_sha is bound to 873148e84b9d9163bb13c8e3e185f5c47d43225e."""
    req = _load_request()
    assert req["canonical_source_sha"] == CANONICAL_SOURCE_SHA, (
        f"canonical_source_sha mismatch: expected {CANONICAL_SOURCE_SHA!r}, "
        f"got {req['canonical_source_sha']!r}"
    )


# ---------------------------------------------------------------------------
# COST-004: Request status is BLOCKED_PRICING_UNVERIFIED
# ---------------------------------------------------------------------------

def test_cost_004_request_status_blocked():
    """COST-004: request_status is BLOCKED_PRICING_UNVERIFIED (FP-001 open)."""
    req = _load_request()
    assert req["request_status"] == "BLOCKED_PRICING_UNVERIFIED", (
        f"Expected BLOCKED_PRICING_UNVERIFIED, got {req['request_status']!r}. "
        "FP-001 is OPEN — pricing must be confirmed before this can advance."
    )


# ---------------------------------------------------------------------------
# COST-005: Six preserved AWS resources in authorization request
# ---------------------------------------------------------------------------

def test_cost_005_six_preserved_resources():
    """COST-005: Authorization request lists all 6 preserved AWS resources."""
    req = _load_request()
    preserved = [r["address"] for r in req.get("preserved_aws_resources", [])]
    EXPECTED = [
        "aws_cloudwatch_log_group.vault_audit",
        "aws_iam_policy.vault_audit",
        "aws_iam_user.vault_audit",
        "aws_iam_user_policy_attachment.vault_audit",
        "aws_iam_role.vault_audit_reader",
        "aws_iam_role_policy_attachment.vault_audit_reader",
    ]
    for addr in EXPECTED:
        assert addr in preserved, f"Missing preserved resource: {addr}"
    assert len(preserved) == 6, f"Expected exactly 6 preserved resources, got {len(preserved)}"


# ---------------------------------------------------------------------------
# COST-006: Pricing evidence file exists
# ---------------------------------------------------------------------------

def test_cost_006_pricing_file_exists():
    """COST-006: run3_pricing_evidence_schema.json exists."""
    assert PRICING_FILE.exists(), f"Pricing evidence schema not found: {PRICING_FILE}"


# ---------------------------------------------------------------------------
# COST-007: Pricing evidence shows FP-001 as OPEN
# ---------------------------------------------------------------------------

def test_cost_007_pricing_fp001_open():
    """COST-007: Pricing schema correctly marks FP-001 as OPEN."""
    pricing = _load_pricing()
    assert pricing.get("fp_001_status") == "OPEN", (
        f"Expected fp_001_status=OPEN, got {pricing.get('fp_001_status')!r}. "
        "Pricing is UNVERIFIED — FP-001 must remain OPEN until operator confirms from HCP portal."
    )


# ---------------------------------------------------------------------------
# COST-008: All pricing evidence fields are null (unverified)
# ---------------------------------------------------------------------------

def test_cost_008_pricing_evidence_null():
    """COST-008: All pricing evidence value fields are null (pricing unverified)."""
    pricing = _load_pricing()
    evidence = pricing.get("evidence", {})
    VALUE_FIELDS = [
        "source", "source_url", "hourly_rate_usd", "billing_unit",
        "rate_confirmed_at", "rate_valid_until", "verifier_identity", "fingerprint",
    ]
    for field in VALUE_FIELDS:
        assert evidence.get(field) is None, (
            f"Pricing evidence field {field!r} should be null (unverified) but got: {evidence.get(field)!r}"
        )


# ---------------------------------------------------------------------------
# COST-009: Pricing schema has capture procedure
# ---------------------------------------------------------------------------

def test_cost_009_pricing_capture_procedure():
    """COST-009: Pricing schema contains operator capture procedure."""
    pricing = _load_pricing()
    proc = pricing.get("capture_procedure", {})
    assert proc, "capture_procedure section is missing or empty"
    assert "step_1" in proc, "capture_procedure.step_1 missing"
    assert "step_10" in proc, "capture_procedure.step_10 missing (not enough steps)"


# ---------------------------------------------------------------------------
# COST-010: Pricing product matches infra/hcp_cluster.tf configuration
# ---------------------------------------------------------------------------

def test_cost_010_pricing_product_matches_infra():
    """COST-010: Pricing schema product fields match HCP cluster Terraform config."""
    pricing = _load_pricing()
    product = pricing.get("product", {})
    assert product.get("tier") == "standard_small", (
        f"Product tier should be standard_small, got {product.get('tier')!r}"
    )
    assert product.get("region") == "us-east-1", (
        f"Product region should be us-east-1, got {product.get('region')!r}"
    )
    assert "HCP Vault Dedicated" in str(product.get("product_name", "")), (
        "Product name should contain 'HCP Vault Dedicated'"
    )


# ---------------------------------------------------------------------------
# COST-011: Financial fields are null in request
# ---------------------------------------------------------------------------

def test_cost_011_financial_fields_null():
    """COST-011: All financial fields are null until pricing is confirmed."""
    req = _load_request()
    assert req.get("requested_max_cost_usd") is None, (
        "requested_max_cost_usd must be null — human must set after pricing confirmed"
    )
    assert req.get("requested_max_runtime_minutes") is None, (
        "requested_max_runtime_minutes must be null — human must set"
    )
    assert req.get("teardown_reserve_minutes") is None, (
        "teardown_reserve_minutes must be null — human must set"
    )


# ---------------------------------------------------------------------------
# COST-012: Identity fields are null
# ---------------------------------------------------------------------------

def test_cost_012_identity_fields_null():
    """COST-012: operator_identity and approver_identity are null — AI must not fill these."""
    req = _load_request()
    assert req.get("operator_identity") is None, (
        "operator_identity must be null — a human operator must enter their own identity"
    )
    assert req.get("approver_identity") is None, (
        "approver_identity must be null — a human approver must explicitly provide approval"
    )


# ---------------------------------------------------------------------------
# COST-013: Authorization expiry is null
# ---------------------------------------------------------------------------

def test_cost_013_authorization_expiry_null():
    """COST-013: authorization_expires_at is null — human approver must set."""
    req = _load_request()
    assert req.get("authorization_expires_at") is None, (
        "authorization_expires_at must be null — human approver must set expiry"
    )


# ---------------------------------------------------------------------------
# COST-014: Historical $321.81 not used as cost ceiling
# ---------------------------------------------------------------------------

def test_cost_014_historical_cost_not_ceiling():
    """COST-014: $321.81 historical cost is not used as requested_max_cost_usd."""
    req = _load_request()
    max_cost = req.get("requested_max_cost_usd")
    assert max_cost != HISTORICAL_COST_USD, (
        f"requested_max_cost_usd is set to {HISTORICAL_COST_USD} (historical Runs 1+2 total). "
        "This figure is CONSUMED and must not be used as a cost ceiling for Run 3."
    )
    assert max_cost != str(HISTORICAL_COST_USD), (
        f"requested_max_cost_usd is set to '{HISTORICAL_COST_USD}' (historical figure as string). "
        "The $321.81 figure is CONSUMED."
    )


# ---------------------------------------------------------------------------
# COST-015: Historical cost reference is marked CONSUMED in pricing schema
# ---------------------------------------------------------------------------

def test_cost_015_historical_cost_marked_consumed():
    """COST-015: Pricing schema marks $321.81 historical reference as consumed."""
    pricing = _load_pricing()
    hist = pricing.get("historical_reference", {})
    assert hist.get("consumed") is True, (
        "historical_reference.consumed must be True — $321.81 covers Runs 1+2 only"
    )


# ---------------------------------------------------------------------------
# COST-016: Verifier returns BLOCKED for current (unverified) state
# ---------------------------------------------------------------------------

def test_cost_016_verifier_returns_blocked():
    """COST-016: Independent verifier returns BLOCKED for current package state."""
    verifier = _import_verifier()
    result = verifier.verify_cost_review(REQUEST_FILE, PRICING_FILE)
    assert result.overall_state == "BLOCKED", (
        f"Expected BLOCKED (FP-001 open, financial fields null), got {result.overall_state!r}. "
        f"Blockers: {result.blockers}"
    )
    assert result.blocker_count > 0, "Expected at least one blocker"


# ---------------------------------------------------------------------------
# COST-017: Verifier never returns APPROVED
# ---------------------------------------------------------------------------

def test_cost_017_verifier_never_approved():
    """COST-017: Independent verifier MUST NEVER return APPROVED."""
    verifier = _import_verifier()
    result = verifier.verify_cost_review(REQUEST_FILE, PRICING_FILE)
    assert result.overall_state != "APPROVED", (
        "CRITICAL: Verifier returned APPROVED. This is a defect — APPROVED is not reachable "
        "by this module. A separate human decision mechanism is required."
    )


# ---------------------------------------------------------------------------
# COST-018: Verifier detects FP-001 blocker
# ---------------------------------------------------------------------------

def test_cost_018_verifier_detects_fp001():
    """COST-018: Verifier explicitly identifies FP-001 (pricing unverified) as a blocker."""
    verifier = _import_verifier()
    result = verifier.verify_cost_review(REQUEST_FILE, PRICING_FILE)
    fp001_blocker = any(
        "C06" in b or "PRICING_FP001" in b or "FP-001" in b or "pricing" in b.lower()
        for b in result.blockers
    )
    assert fp001_blocker, (
        f"Expected FP-001 pricing blocker in verifier output. Blockers: {result.blockers}"
    )


# ---------------------------------------------------------------------------
# COST-019: Verifier with manipulated SHA fails closed
# ---------------------------------------------------------------------------

def test_cost_019_verifier_wrong_sha_fails_closed(tmp_path):
    """COST-019: Verifier rejects authorization request with wrong canonical SHA."""
    req = _load_request()
    req["canonical_source_sha"] = "0000000000000000000000000000000000000000"
    tampered = tmp_path / "tampered_request.json"
    tampered.write_text(json.dumps(req))
    verifier = _import_verifier()
    result = verifier.verify_cost_review(tampered, PRICING_FILE)
    sha_blocker = any("C05" in b or "canonical_source_sha" in b for b in result.blockers)
    assert sha_blocker, (
        f"Expected canonical SHA mismatch blocker. Blockers: {result.blockers}"
    )


# ---------------------------------------------------------------------------
# COST-020: Pending cost model outputs PENDING for all scenarios
# ---------------------------------------------------------------------------

def test_cost_020_pending_model_all_pending():
    """COST-020: Pending cost model outputs PENDING for all scenarios."""
    cost_model = _import_cost_model()
    model = cost_model.build_pending_cost_model()
    assert model.pricing_verified is False
    assert model.scenario_a.hcp_cost_usd == "PENDING"
    assert model.scenario_b.hcp_cost_usd == "PENDING"
    assert model.scenario_c.hcp_cost_usd == "PENDING"
    assert model.scenario_a.total_cost_usd == "PENDING"
    assert model.scenario_b.total_cost_usd == "PENDING"
    assert model.scenario_c.total_cost_usd == "PENDING"


# ---------------------------------------------------------------------------
# COST-021: Cost model uses Decimal arithmetic (not float)
# ---------------------------------------------------------------------------

def test_cost_021_cost_model_decimal_arithmetic():
    """COST-021: Cost model calculations use Decimal, not float."""
    cost_model = _import_cost_model()
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0.00"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    model = cost_model.build_cost_model(inputs, max_runtime_minutes=120)
    assert model.pricing_verified is True
    # Scenario A: 120 min = 2 hours * 1.50/hr = 3.00
    # The cost is expressed as a range string "X–Y" for scenarios A and B
    assert "3.00" in model.scenario_a.hcp_cost_usd, (
        f"Expected 3.00 in scenario A cost, got {model.scenario_a.hcp_cost_usd!r}"
    )
    # Scenario C: 120 min * 1.50/hr = 3.00
    assert model.scenario_c.hcp_cost_usd == "3.00", (
        f"Expected 3.00 for scenario C (120 min), got {model.scenario_c.hcp_cost_usd!r}"
    )


# ---------------------------------------------------------------------------
# COST-022: Cost model marks historical $321.81 as CONSUMED
# ---------------------------------------------------------------------------

def test_cost_022_cost_model_historical_consumed():
    """COST-022: Cost model marks historical $321.81 as CONSUMED in reference."""
    cost_model = _import_cost_model()
    model = cost_model.build_pending_cost_model()
    assert "CONSUMED" in model.historical_reference_usd, (
        f"Historical reference should be marked CONSUMED: {model.historical_reference_usd!r}"
    )
    assert "321.81" in model.historical_reference_usd


# ---------------------------------------------------------------------------
# COST-023: Watchdog warns at 75% of effective max runtime
# ---------------------------------------------------------------------------

def test_cost_023_watchdog_warns_at_75pct():
    """COST-023: Watchdog emits WARN_75 when elapsed time >= 75% of effective max."""
    watchdog = _import_watchdog()
    wdog = watchdog.OperatorWatchdog(
        max_runtime_minutes=100,
        teardown_reserve_minutes=10,  # effective_max = 90 min
    )
    wdog.start()
    # Manually manipulate start time to simulate elapsed
    # 75% of 90 min = 67.5 min; set start to 68 min ago
    wdog._start_time = time.monotonic() - (68 * 60)
    status = wdog.check("test_checkpoint")
    assert status.should_warn, (
        f"Expected should_warn=True at 68/90 min. status_code={status.status_code}"
    )
    assert status.status_code in ("WARN_75", "STOP_EFFECTIVE_MAX", "HARD_STOP")


# ---------------------------------------------------------------------------
# COST-024: Watchdog stops at 100% of effective max runtime
# ---------------------------------------------------------------------------

def test_cost_024_watchdog_stops_at_100pct():
    """COST-024: Watchdog emits should_stop=True at 100% of effective max."""
    watchdog = _import_watchdog()
    wdog = watchdog.OperatorWatchdog(
        max_runtime_minutes=100,
        teardown_reserve_minutes=10,  # effective_max = 90 min
    )
    wdog.start()
    # 91 minutes elapsed (just past effective max)
    wdog._start_time = time.monotonic() - (91 * 60)
    status = wdog.check("test_checkpoint")
    assert status.should_stop, (
        f"Expected should_stop=True at 91/90 min. status_code={status.status_code}"
    )


# ---------------------------------------------------------------------------
# COST-025: Watchdog billing disclaimer is always present
# ---------------------------------------------------------------------------

def test_cost_025_watchdog_billing_disclaimer():
    """COST-025: Watchdog always includes billing disclaimer (not a guaranteed dollar cap)."""
    watchdog = _import_watchdog()
    wdog = watchdog.OperatorWatchdog(
        max_runtime_minutes=120,
        teardown_reserve_minutes=15,
        hourly_rate_usd_estimate=1.50,
    )
    wdog.start()
    status = wdog.check("test")
    assert "billing" in status.billing_disclaimer.lower() or "delayed" in status.billing_disclaimer.lower(), (
        "Billing disclaimer must warn that cloud billing is delayed and cost is an estimate"
    )
    assert "guaranteed" in status.billing_disclaimer.lower() or "estimate" in status.billing_disclaimer.lower(), (
        "Billing disclaimer must state that the watchdog does not provide a guaranteed dollar cap"
    )


# ---------------------------------------------------------------------------
# COST-026: Canonical truth preserved in authorization request
# ---------------------------------------------------------------------------

def test_cost_026_canonical_truth_preserved():
    """COST-026: Authorization request preserves all canonical truth invariants."""
    req = _load_request()
    ct = req.get("canonical_truth_preserved", {})
    assert ct.get("CUSTOMER_ZERO_TRUST") == "NOT_PROVEN", (
        f"CUSTOMER_ZERO_TRUST must be NOT_PROVEN, got {ct.get('CUSTOMER_ZERO_TRUST')!r}"
    )
    assert ct.get("THIRD_PAID_CEREMONY") == "NOT_AUTHORIZED", (
        f"THIRD_PAID_CEREMONY must be NOT_AUTHORIZED, got {ct.get('THIRD_PAID_CEREMONY')!r}"
    )
    assert ct.get("PAID_HCP_INFRASTRUCTURE") == "ABSENT", (
        f"PAID_HCP_INFRASTRUCTURE must be ABSENT, got {ct.get('PAID_HCP_INFRASTRUCTURE')!r}"
    )
    assert ct.get("COST_AUTHORIZATION") == "NOT_AUTHORIZED", (
        f"COST_AUTHORIZATION must be NOT_AUTHORIZED, got {ct.get('COST_AUTHORIZATION')!r}"
    )


# ---------------------------------------------------------------------------
# COST-027: Ceremony state invariants unchanged
# ---------------------------------------------------------------------------

def test_cost_027_ceremony_state_invariants_unchanged():
    """COST-027: ceremony_state.yaml trust invariants are unchanged by this PR."""
    import yaml
    state = yaml.safe_load(CEREMONY_STATE_FILE.read_text())
    assert state["trust_proof_status"] == "NOT_PROVEN"
    assert state["third_paid_ceremony_status"] == "NOT_AUTHORIZED"
    assert state["infrastructure_lifecycle_status"] == "HCP_ABSENT"
    preserved = [r["address"] for r in state["cost_containment"]["preserved_aws_resources"]]
    assert len(preserved) == 6, f"Expected 6 preserved resources, got {len(preserved)}"


# ---------------------------------------------------------------------------
# COST-028: Financial risk register covers all key risks
# ---------------------------------------------------------------------------

def test_cost_028_financial_risk_register_complete():
    """COST-028: Financial risk register covers all key risks including FR-001 (pricing)."""
    risk = _load_risk_register()
    risks = risk.get("risks", [])
    assert risks, "risks list is empty"
    risk_ids = {r["id"] for r in risks}
    REQUIRED_RISK_IDS = {"FR-001", "FR-002", "FR-003", "FR-004", "FR-005"}
    missing = REQUIRED_RISK_IDS - risk_ids
    assert not missing, f"Missing required risk IDs: {missing}"
    # FR-001 must be OPEN (pricing unverified)
    fr001 = next(r for r in risks if r["id"] == "FR-001")
    assert "OPEN" in fr001.get("status", ""), (
        f"FR-001 should have OPEN status, got {fr001.get('status')!r}"
    )
