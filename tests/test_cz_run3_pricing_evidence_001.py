"""CUSTOMER-ZERO-RUN3-PRICING-EVIDENCE-001 — Adversarial tests for pricing evidence verifier.

Tests: PEVID-001 through PEVID-032.
Work class: OFFLINE_PREPARATION.
Cloud mutations: 0. Spending authorization: unchanged. Live trust: unchanged.

Coverage areas:
  - PEVID-001–002: File loading and null instance rejection
  - PEVID-003–008: Content validation (tier, region, currency, rate)
  - PEVID-009–011: Provenance validation (separation of duties)
  - PEVID-012–015: Freshness / timestamp validation
  - PEVID-016–018: Source authenticity
  - PEVID-019–022: Fingerprint verification
  - PEVID-023–026: Billing unit and unknown charges
  - PEVID-027:     Decimal precision
  - PEVID-028–029: build_cost_model_from_evidence
  - PEVID-030:     compute_bounded_exposure
  - PEVID-031:     Full pipeline returns BLOCKED_PRICING_UNVERIFIED for null instance
  - PEVID-032:     compute_bounded_exposure with pricing_snapshot=None → not defensible

All tests are deterministic and offline-only. No live infrastructure. No HCP API.
No AWS API. No network calls of any kind.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EVIDENCE_INSTANCE_FILE = REPO / "customer_one" / "run3_pricing_evidence_instance.json"
VERIFIER_MODULE = REPO / "services" / "governance" / "run3_pricing_evidence_verifier.py"
COST_MODEL_MODULE = REPO / "services" / "governance" / "run3_cost_model.py"
VERIFY_PIPELINE_SCRIPT = REPO / "tools" / "ci" / "verify_pricing_evidence.py"

# ---------------------------------------------------------------------------
# SYNTHETIC TEST FIXTURE — NOT REAL PRICING EVIDENCE
# This fixture uses fabricated values for unit testing only.
# It must never be used as a real pricing authorization input.
# ---------------------------------------------------------------------------

SYNTHETIC_VALID_EVIDENCE = {
    "schema_version": "1.0",
    "evidence_id": "SYNTHETIC-TEST-DO-NOT-USE-IN-PROD",
    "evidence_type": "pricing_observation",
    "collection_timestamp_utc": "2026-10-01T12:00:00+00:00",
    "expiry_policy": {
        "valid_for_days": 30,
        "expires_at_utc": "2099-12-31T23:59:59+00:00",
    },
    "provider": {
        "name": "HashiCorp Cloud Platform",
        "product": "HCP Vault Dedicated",
        "tier": "standard_small",
        "region": "us-east-1",
        "organization": "Frostgate-org",
        "project": "frostgate-production",
    },
    "pricing": {
        "currency": "USD",
        "hourly_rate_usd": "1.50",  # SYNTHETIC — NOT REAL
        "billing_unit": "hourly",
        "billing_unit_minutes": 60,
        "minimum_billable_unit": "1 hour",
        "minimum_charge_usd": "1.50",
        "additional_charges": [],
        "unknown_charges_acknowledged": True,
        "unknown_charges_notes": "Synthetic fixture — no real charges",
    },
    "source": {
        "classification": "hcp_pricing_page",
        "reference_url": "https://www.hashicorp.com/products/vault/pricing",
        "screenshot_sha256": None,
        "collection_method": "manual_observation",
    },
    "provenance": {
        "collector_identity": "test-collector@example.com",
        "collection_method": "manual_observation",
        "independent_reviewer_identity": "test-reviewer@example.com",
        "reviewer_notes": "Synthetic fixture for unit tests",
    },
    "integrity": {
        "evidence_fingerprint_sha256": None,
        "fingerprint_covers_fields": [],
        "fingerprint_algorithm": "sha256",
    },
    "validation_status": "UNVALIDATED",
    "validation_reasons": [],
    "fp_001_status": "OPEN",
    "fp_001_note": "Synthetic test fixture.",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_verifier():
    name = "run3_pricing_evidence_verifier"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, VERIFIER_MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_cost_model():
    name = "run3_cost_model"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, COST_MODEL_MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_pipeline():
    name = "verify_pricing_evidence_pipeline"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, VERIFY_PIPELINE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _synthetic(**overrides) -> dict:
    """Return a deep copy of SYNTHETIC_VALID_EVIDENCE with nested overrides applied."""
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    for k, v in overrides.items():
        # Support dot-notation for nested keys (one level)
        if "." in k:
            outer, inner = k.split(".", 1)
            if outer not in instance:
                instance[outer] = {}
            instance[outer][inner] = v
        else:
            instance[k] = v
    return instance


def _compute_fingerprint(pricing: dict) -> str:
    canonical = json.dumps(pricing, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _with_valid_fingerprint(instance: dict) -> dict:
    """Set the correct fingerprint on the integrity sub-object."""
    inst = copy.deepcopy(instance)
    fp = _compute_fingerprint(inst["pricing"])
    inst["integrity"]["evidence_fingerprint_sha256"] = fp
    return inst


# ---------------------------------------------------------------------------
# PEVID-001: Missing evidence file → REJECTED_SCHEMA
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_001_missing_evidence_file():
    """PEVID-001: A non-existent evidence file path returns REJECTED_SCHEMA."""
    verifier = _load_verifier()
    result = verifier.verify_pricing_evidence_file(
        "/nonexistent/path/does_not_exist.json"
    )
    assert result.validation_status == "REJECTED_SCHEMA", (
        f"Expected REJECTED_SCHEMA, got {result.validation_status!r}"
    )
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-002: All-null instance → REJECTED_CONTENT (fails content checks)
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_002_all_null_instance():
    """PEVID-002: An all-null template returns REJECTED_NOT_POPULATED (not REJECTED_CONTENT).

    REJECTED_NOT_POPULATED is distinct from REJECTED_CONTENT (malformed values) and
    REJECTED_TAMPERED (fingerprint mismatch). It signals to the operator that the
    template simply hasn't been filled in yet — not that values are wrong.
    """
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    # Null out all five core value fields that _is_template_unpopulated checks
    instance["provider"]["tier"] = None
    instance["provider"]["region"] = None
    instance["pricing"]["currency"] = None
    instance["pricing"]["hourly_rate_usd"] = None
    instance["pricing"]["billing_unit_minutes"] = None
    instance["pricing"]["minimum_charge_usd"] = None
    instance["pricing"]["unknown_charges_acknowledged"] = None
    result = verifier.verify_pricing_evidence(instance)
    assert not result.is_valid
    assert result.validation_status == "REJECTED_NOT_POPULATED", (
        f"All-null template must return REJECTED_NOT_POPULATED, "
        f"got {result.validation_status!r}; findings={result.findings}"
    )
    # Finding must mention "not populated" so operator knows what to do
    assert result.findings, "REJECTED_NOT_POPULATED must include at least one finding"
    combined = " ".join(result.findings).lower()
    assert "not been populated" in combined or "null" in combined, (
        f"Finding must explain the template is unpopulated; got: {result.findings}"
    )


# ---------------------------------------------------------------------------
# PEVID-003: Wrong provider.tier → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_003_wrong_provider_tier():
    """PEVID-003: provider.tier != standard_small → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"provider.tier": "plus_medium"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("tier" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-004: Wrong provider.region → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_004_wrong_provider_region():
    """PEVID-004: provider.region != us-east-1 → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"provider.region": "eu-west-1"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("region" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-005: Wrong currency → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_005_wrong_currency():
    """PEVID-005: pricing.currency != USD → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"pricing.currency": "EUR"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("currency" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-006: Negative hourly_rate_usd → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_006_negative_hourly_rate():
    """PEVID-006: pricing.hourly_rate_usd < 0 → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"pricing.hourly_rate_usd": "-1.50"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("hourly_rate" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-007: Zero hourly_rate_usd → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_007_zero_hourly_rate():
    """PEVID-007: pricing.hourly_rate_usd == 0 → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"pricing.hourly_rate_usd": "0"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("hourly_rate" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-008: String-that-looks-like-number works when parseable
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_008_string_rate_parseable():
    """PEVID-008: hourly_rate_usd as a string '2.50' is valid and parseable."""
    verifier = _load_verifier()
    instance = _with_valid_fingerprint(
        _synthetic(**{"pricing.hourly_rate_usd": "2.50"})
    )
    result = verifier.verify_pricing_evidence(instance)
    # Should not fail on rate; may be VALIDATED or UNVALIDATED
    assert result.validation_status not in ("REJECTED_CONTENT",), (
        f"String rate '2.50' should be parseable; got {result.validation_status!r}, "
        f"findings={result.findings}"
    )
    assert "hourly_rate" not in " ".join(result.findings).lower()


# ---------------------------------------------------------------------------
# PEVID-009: collector == reviewer → REJECTED_PROVENANCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_009_same_collector_reviewer():
    """PEVID-009: collector_identity == reviewer_identity → REJECTED_PROVENANCE."""
    verifier = _load_verifier()
    instance = _synthetic(
        **{
            "provenance.collector_identity": "operator@example.com",
            "provenance.independent_reviewer_identity": "operator@example.com",
        }
    )
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_PROVENANCE"
    assert not result.is_valid
    assert any(
        "same" in f.lower() or "separation" in f.lower() for f in result.findings
    )


# ---------------------------------------------------------------------------
# PEVID-010: Null collector_identity → REJECTED_PROVENANCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_010_null_collector_identity():
    """PEVID-010: provenance.collector_identity null → REJECTED_PROVENANCE."""
    verifier = _load_verifier()
    instance = _synthetic(**{"provenance.collector_identity": None})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_PROVENANCE"
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-011: Null reviewer_identity → REJECTED_PROVENANCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_011_null_reviewer_identity():
    """PEVID-011: provenance.independent_reviewer_identity null → REJECTED_PROVENANCE."""
    verifier = _load_verifier()
    instance = _synthetic(**{"provenance.independent_reviewer_identity": None})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_PROVENANCE"
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-012: collection_timestamp_utc in the future → REJECTED_FRESHNESS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_012_future_collection_timestamp():
    """PEVID-012: collection_timestamp_utc in the future → REJECTED_FRESHNESS."""
    verifier = _load_verifier()
    instance = _synthetic(collection_timestamp_utc="2099-01-01T00:00:00+00:00")
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_FRESHNESS"
    assert not result.is_valid
    assert any("future" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-013: Naive (no tzinfo) collection_timestamp_utc → REJECTED_FRESHNESS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_013_naive_collection_timestamp():
    """PEVID-013: collection_timestamp_utc without timezone → REJECTED_FRESHNESS."""
    verifier = _load_verifier()
    instance = _synthetic(collection_timestamp_utc="2026-10-01T12:00:00")
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_FRESHNESS"
    assert not result.is_valid
    assert any("naive" in f.lower() or "timezone" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-014: expires_at_utc in the past → REJECTED_FRESHNESS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_014_expired_evidence():
    """PEVID-014: expiry_policy.expires_at_utc in the past → REJECTED_FRESHNESS."""
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    instance["expiry_policy"]["expires_at_utc"] = "2020-01-01T00:00:00+00:00"
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_FRESHNESS"
    assert not result.is_valid
    assert any("expired" in f.lower() or "past" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-015: expires_at_utc null → REJECTED_FRESHNESS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_015_null_expires_at():
    """PEVID-015: expiry_policy.expires_at_utc null → REJECTED_FRESHNESS."""
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    instance["expiry_policy"]["expires_at_utc"] = None
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_FRESHNESS"
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-016: Invalid source.classification → REJECTED_SOURCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_016_invalid_source_classification():
    """PEVID-016: source.classification invalid value → REJECTED_SOURCE."""
    verifier = _load_verifier()
    instance = _synthetic(**{"source.classification": "blog_post"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_SOURCE"
    assert not result.is_valid
    assert any("classification" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-017: source.reference_url null → REJECTED_SOURCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_017_null_reference_url():
    """PEVID-017: source.reference_url null → REJECTED_SOURCE."""
    verifier = _load_verifier()
    instance = _synthetic(**{"source.reference_url": None})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_SOURCE"
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-018: source.reference_url not starting with https:// → REJECTED_SOURCE
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_018_http_reference_url():
    """PEVID-018: source.reference_url not starting with https:// → REJECTED_SOURCE."""
    verifier = _load_verifier()
    instance = _synthetic(
        **{"source.reference_url": "http://www.hashicorp.com/pricing"}
    )
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_SOURCE"
    assert not result.is_valid
    assert any("https" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-019: Fingerprint present and correct → VALIDATED
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_019_correct_fingerprint_validated():
    """PEVID-019: Valid evidence with correct fingerprint → VALIDATED."""
    verifier = _load_verifier()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    result = verifier.verify_pricing_evidence(instance)
    assert result.is_valid, (
        f"Expected is_valid=True; findings={result.findings}, status={result.validation_status}"
    )
    assert result.validation_status == "VALIDATED"
    assert result.pricing_snapshot is not None
    assert result.pricing_snapshot["tier"] == "standard_small"
    assert result.pricing_snapshot["region"] == "us-east-1"


# ---------------------------------------------------------------------------
# PEVID-020: Fingerprint present and WRONG → REJECTED_TAMPERED
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_020_wrong_fingerprint_tampered():
    """PEVID-020: Evidence with mismatched fingerprint → REJECTED_TAMPERED."""
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    instance["integrity"]["evidence_fingerprint_sha256"] = "deadbeef" * 8  # wrong
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_TAMPERED"
    assert not result.is_valid
    assert any(
        "mismatch" in f.lower() or "tamper" in f.lower() for f in result.findings
    )


# ---------------------------------------------------------------------------
# PEVID-021: Fingerprint null → UNVALIDATED (not rejected)
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_021_null_fingerprint_unvalidated():
    """PEVID-021: Evidence with null fingerprint → UNVALIDATED (structurally valid but not fingerprinted)."""
    verifier = _load_verifier()
    # SYNTHETIC_VALID_EVIDENCE already has null fingerprint
    result = verifier.verify_pricing_evidence(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    assert result.validation_status == "UNVALIDATED"
    assert not result.is_valid  # is_valid False for UNVALIDATED
    assert not result.findings  # No hard rejections


# ---------------------------------------------------------------------------
# PEVID-022: Duplicate evidence_id → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_022_duplicate_evidence_id():
    """PEVID-022: Second call with same evidence_id and seen list → rejected."""
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    eid = "SYNTHETIC-TEST-DO-NOT-USE-IN-PROD"
    result = verifier.verify_pricing_evidence(instance, seen_evidence_ids=[eid])
    assert not result.is_valid
    assert result.validation_status == "REJECTED_SCHEMA"
    assert any("duplicate" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-023: billing_unit_minutes <= 0 → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_023_zero_billing_unit_minutes():
    """PEVID-023: pricing.billing_unit_minutes <= 0 → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"pricing.billing_unit_minutes": 0})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("billing_unit_minutes" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-024: minimum_charge_usd negative → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_024_negative_minimum_charge():
    """PEVID-024: pricing.minimum_charge_usd < 0 → REJECTED_CONTENT."""
    verifier = _load_verifier()
    instance = _synthetic(**{"pricing.minimum_charge_usd": "-0.01"})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT"
    assert not result.is_valid
    assert any("minimum_charge" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-025: unknown_charges_acknowledged False → warning (not rejected), is_defensible=False
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_025_unknown_charges_not_acknowledged():
    """PEVID-025: unknown_charges_acknowledged=False → warning issued, not rejected.
    is_defensible_upper_bound must be False AND unresolved_unknowns must be non-empty."""
    verifier = _load_verifier()
    cost_model = _load_cost_model()
    # Use fingerprinted instance so we get past fingerprint check
    instance = _with_valid_fingerprint(
        _synthetic(**{"pricing.unknown_charges_acknowledged": False})
    )
    result = verifier.verify_pricing_evidence(instance)
    # Should pass all checks (not rejected)
    assert result.validation_status in ("VALIDATED", "UNVALIDATED"), (
        f"Expected VALIDATED or UNVALIDATED; got {result.validation_status!r}, "
        f"findings={result.findings}"
    )
    # But there should be a warning
    assert any(
        "unknown_charges" in w.lower() or "defensible" in w.lower()
        for w in result.warnings
    ), f"Expected a warning about unknown_charges; got warnings={result.warnings!r}"
    # And if we build from this, is_defensible_upper_bound should be False with
    # unresolved_unknowns listing the specific gap.
    if result.is_valid and result.pricing_snapshot:
        # Pass a snapshot where unknown_charges_acknowledged=False
        snapshot = dict(result.pricing_snapshot)
        snapshot["unknown_charges_acknowledged"] = False
        inputs = cost_model.PricingInputs(
            hourly_rate_usd=Decimal("1.50"),
            billing_unit_minutes=60,
            minimum_charge_usd=Decimal("0"),
            aws_cloudwatch_per_gb_usd=Decimal("0.50"),
            estimated_audit_volume_gb=Decimal("0.001"),
        )
        exposure = cost_model.compute_bounded_exposure(
            inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
        )
        assert not exposure.is_defensible_upper_bound, (
            "is_defensible_upper_bound must be False when unknown_charges_acknowledged=False"
        )
        assert exposure.unresolved_unknowns, (
            "unresolved_unknowns must be non-empty when unknown_charges_acknowledged=False"
        )
        assert exposure.unknown_charges_warning is not None
        # Confirm the specific gap is named
        combined = " ".join(exposure.unresolved_unknowns).lower()
        assert "unknown_charges_acknowledged" in combined, (
            f"unresolved_unknowns should name the gap; got: {exposure.unresolved_unknowns}"
        )


# ---------------------------------------------------------------------------
# PEVID-026: unknown_charges_acknowledged True → no warning, is_defensible eligible
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_026_unknown_charges_acknowledged():
    """PEVID-026: complete snapshot + unknown_charges_acknowledged=True → is_defensible_upper_bound=True.

    A partial snapshot (missing billing_unit_minutes or minimum_charge_usd) must still
    produce is_defensible_upper_bound=False even when unknown_charges_acknowledged=True.
    Defensibility requires ALL billing parameters to be confirmed.
    """
    verifier = _load_verifier()
    cost_model = _load_cost_model()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    assert instance["pricing"]["unknown_charges_acknowledged"] is True
    result = verifier.verify_pricing_evidence(instance)
    assert result.is_valid
    assert not any("unknown_charges" in w.lower() for w in result.warnings), (
        f"Should have no unknown_charges warning when True; warnings={result.warnings!r}"
    )

    # Complete snapshot — all required fields present and acknowledged
    complete_snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    exposure = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=complete_snapshot
    )
    assert exposure.is_defensible_upper_bound, (
        f"Expected is_defensible_upper_bound=True with complete snapshot; "
        f"unresolved_unknowns={exposure.unresolved_unknowns}"
    )
    assert exposure.unresolved_unknowns == [], (
        f"unresolved_unknowns must be empty for complete snapshot; "
        f"got {exposure.unresolved_unknowns}"
    )

    # Partial snapshot — billing_unit_minutes missing → still False
    partial_snapshot = {
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        # billing_unit_minutes intentionally absent
    }
    exposure_partial = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=partial_snapshot
    )
    assert not exposure_partial.is_defensible_upper_bound, (
        "is_defensible_upper_bound must be False when billing_unit_minutes is missing"
    )
    assert exposure_partial.unresolved_unknowns, (
        "unresolved_unknowns must be non-empty when billing_unit_minutes is missing"
    )


# ---------------------------------------------------------------------------
# PEVID-027: Decimal precision — no float errors
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_027_decimal_precision():
    """PEVID-027: hourly_rate * hours rounds correctly with no floating point errors."""
    cost_model = _load_cost_model()
    # Use a rate that causes float rounding issues: 0.10 * 3 = 0.30000000000000004 in float
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("0.10"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    # 3 hours = 180 minutes
    model = cost_model.build_cost_model(inputs, max_runtime_minutes=180)
    # Scenario C: 3 hours * 0.10/hr = 0.30 exactly
    scenario_c_hcp = model.scenario_c.hcp_cost_usd
    assert scenario_c_hcp == "0.30", (
        f"Expected '0.30' (Decimal precision), got {scenario_c_hcp!r}"
    )


# ---------------------------------------------------------------------------
# PEVID-028: build_cost_model_from_evidence with valid evidence → real cost model
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_028_build_cost_model_from_valid_evidence():
    """PEVID-028: build_cost_model_from_evidence with valid evidence returns real CostModel."""
    verifier = _load_verifier()
    cost_model = _load_cost_model()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    result = verifier.verify_pricing_evidence(instance)
    assert result.is_valid, f"Expected valid; findings={result.findings}"

    model = cost_model.build_cost_model_from_evidence(result, max_runtime_minutes=120)
    assert model.pricing_verified is True
    assert model.scenario_a.is_pending is False
    assert model.scenario_c.hcp_cost_usd != "PENDING"


# ---------------------------------------------------------------------------
# PEVID-029: build_cost_model_from_evidence with invalid evidence → pending model
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_029_build_cost_model_from_invalid_evidence():
    """PEVID-029: build_cost_model_from_evidence with invalid evidence returns PENDING CostModel."""
    verifier = _load_verifier()
    cost_model = _load_cost_model()
    # Use all-null instance (will fail content validation)
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    instance["provider"]["tier"] = None
    result = verifier.verify_pricing_evidence(instance)
    assert not result.is_valid

    model = cost_model.build_cost_model_from_evidence(result)
    assert model.pricing_verified is False
    assert model.scenario_a.hcp_cost_usd == "PENDING"
    assert model.scenario_b.hcp_cost_usd == "PENDING"
    assert model.scenario_c.hcp_cost_usd == "PENDING"


# ---------------------------------------------------------------------------
# PEVID-030: compute_bounded_exposure returns ceiling > base_cost
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_030_bounded_exposure_ceiling_above_base():
    """PEVID-030: compute_bounded_exposure returns ceiling > base_cost.

    With a complete pricing_snapshot (billing_unit_minutes, minimum_charge_usd, and
    unknown_charges_acknowledged=True), unresolved_unknowns must be empty and
    is_defensible_upper_bound must be True.
    """
    cost_model = _load_cost_model()
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    complete_snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
    }
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=complete_snapshot
    )
    base = Decimal(report.base_cost_usd)
    ceiling = Decimal(report.bounded_ceiling_usd)
    total = Decimal(report.total_bounded_ceiling_usd)
    assert ceiling > base, f"ceiling {ceiling} should be > base {base}"
    assert total >= ceiling, f"total {total} should be >= ceiling {ceiling}"
    assert report.is_defensible_upper_bound is True, (
        f"Expected is_defensible_upper_bound=True; "
        f"unresolved_unknowns={report.unresolved_unknowns}"
    )
    assert report.unresolved_unknowns == [], (
        f"unresolved_unknowns must be empty for complete snapshot; "
        f"got {report.unresolved_unknowns}"
    )


# ---------------------------------------------------------------------------
# PEVID-031: Full pipeline returns BLOCKED_PRICING_UNVERIFIED for null instance
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_031_pipeline_blocked_for_null_instance():
    """PEVID-031: verify_pricing_evidence.py pipeline returns BLOCKED_PRICING_UNVERIFIED
    when the evidence instance has all-null fields (current repo state)."""
    pipeline = _load_pipeline()
    report = pipeline.run_verification(repo=REPO)
    overall = report.get("overall_status")
    assert overall in (
        "BLOCKED_PRICING_UNVERIFIED",
        "BLOCKED_PRICING_EVIDENCE_INVALID",
    ), (
        f"Expected BLOCKED_PRICING_UNVERIFIED or BLOCKED_PRICING_EVIDENCE_INVALID; "
        f"got {overall!r}"
    )
    # SAFETY: approved must always be False
    assert report.get("approved") is False, (
        f"approved must always be False; got {report.get('approved')!r}"
    )


# ---------------------------------------------------------------------------
# PEVID-032: compute_bounded_exposure with pricing_snapshot=None → not defensible
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_032_bounded_exposure_no_snapshot():
    """PEVID-032: compute_bounded_exposure with pricing_snapshot=None →
    is_defensible_upper_bound=False, unresolved_unknowns non-empty.

    A 10% safety margin alone does not make the ceiling defensible when no snapshot
    is provided to confirm billing parameters and charge acknowledgement.
    """
    cost_model = _load_cost_model()
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=None
    )
    assert report.is_defensible_upper_bound is False, (
        "is_defensible_upper_bound must be False when pricing_snapshot is None"
    )
    assert report.unresolved_unknowns, (
        "unresolved_unknowns must be non-empty when pricing_snapshot is None"
    )
    assert report.unknown_charges_warning is not None, (
        "unknown_charges_warning must be set when pricing_snapshot is None"
    )
    # Confirm the gap reason is specific
    combined = " ".join(report.unresolved_unknowns).lower()
    assert "pricing_snapshot" in combined or "not provided" in combined, (
        f"unresolved_unknowns should mention missing snapshot; got: {report.unresolved_unknowns}"
    )


# ---------------------------------------------------------------------------
# Additional safety: APPROVED is unreachable
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_approved_state_unreachable_from_verifier():
    """Confirmed safety: verify_pricing_evidence never produces is_valid=True for APPROVED state."""
    verifier = _load_verifier()
    # Even the best possible evidence cannot produce APPROVED from the verifier
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    result = verifier.verify_pricing_evidence(instance)
    # The verifier can return VALIDATED (is_valid=True) but this is NOT APPROVED
    # APPROVED state must not exist anywhere in the result
    result_dict = result.to_dict()
    result_str = json.dumps(result_dict).upper()
    assert "APPROVED" not in result_str, (
        f"APPROVED must never appear in verifier output; got {result_str[:200]}"
    )


@pytest.mark.contract
def test_approved_state_unreachable_from_pipeline():
    """Confirmed safety: verify_pricing_evidence.py pipeline approved field is always False."""
    pipeline = _load_pipeline()
    report = pipeline.run_verification(repo=REPO)
    assert report["approved"] is False
    # The word APPROVED may appear in status strings but the approved flag must be False
    assert report["approved"] is not True
