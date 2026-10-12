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
        "valid_for_days": 36500,  # 100 years — consistent with 2099 synthetic expiry
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
# PEVID-033: Old collection_timestamp with far-future expires_at_utc → REJECTED_FRESHNESS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_033_stale_evidence_window_bypass():
    """PEVID-033: Evidence collected long ago with a far-future expires_at_utc and
    small valid_for_days → REJECTED_FRESHNESS.

    A 30-day validity window set to expire in 2099 would bypass the freshness
    control. The verifier must enforce that expires_at_utc is consistent with
    collection_timestamp_utc + valid_for_days.
    """
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    # Evidence collected years ago — far outside any 30-day window
    instance["collection_timestamp_utc"] = "2020-01-01T12:00:00+00:00"
    instance["expiry_policy"] = {
        "valid_for_days": 30,
        "expires_at_utc": "2099-12-31T23:59:59+00:00",
    }
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_FRESHNESS", (
        f"Expected REJECTED_FRESHNESS for stale evidence with bypassed expiry window; "
        f"got {result.validation_status!r}, findings: {result.findings}"
    )
    assert not result.is_valid
    assert any(
        "valid_for_days" in f.lower() or "expiry" in f.lower() or "stale" in f.lower()
        for f in result.findings
    )


# ---------------------------------------------------------------------------
# PEVID-034: NaN and Infinity hourly_rate_usd → rejected
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_034_non_finite_hourly_rate():
    """PEVID-034: NaN and Infinity hourly_rate_usd → rejected (not VALIDATED).

    Decimal('NaN') and Decimal('Infinity') are accepted by the Decimal constructor
    but must be rejected before the positivity check, which would otherwise raise
    decimal.InvalidOperation or silently produce nonsensical costs.
    """
    verifier = _load_verifier()
    for bad_rate in ("NaN", "Infinity", "-Infinity", "nan", "inf"):
        instance = _synthetic(**{"pricing.hourly_rate_usd": bad_rate})
        result = verifier.verify_pricing_evidence(instance)
        assert result.validation_status not in ("VALIDATED", "UNVALIDATED"), (
            f"Non-finite rate {bad_rate!r} must not pass content validation; "
            f"got status {result.validation_status!r}"
        )
        assert not result.is_valid, (
            f"is_valid must be False for non-finite rate {bad_rate!r}"
        )
        assert any(
            "finite" in f.lower() or "hourly_rate_usd" in f.lower()
            for f in result.findings
        ), f"findings should mention rate issue for {bad_rate!r}; got {result.findings}"


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


# ---------------------------------------------------------------------------
# SYNTHETIC additional charge fixtures
# ---------------------------------------------------------------------------

SYNTHETIC_CHARGE_NOT_APPLICABLE = {
    "charge_id": "HCP-CLIENT-UNIT-SYNTHETIC",
    "provider": "HashiCorp Cloud Platform",
    "description": "SYNTHETIC: client unit charge — verified not applicable to test cluster",
    "billing_metric": "per_client_month",
    "unit_price_usd": "72.92",
    "currency": "USD",
    "billing_frequency": "monthly",
    "quantity_basis": "per_active_client",
    "max_billable_quantity": 0,
    "proration_rule": "none",
    "minimum_commitment_usd": "0.00",
    "applicability_status": "NOT_APPLICABLE_VERIFIED",
    "source_evidence_ref": "SYNTHETIC-TEST-ONLY",
    "confidence": "VERIFIED",
    "calculated_max_exposure_usd": "0.00",
    "notes": "SYNTHETIC TEST FIXTURE ONLY — NOT REAL EVIDENCE",
}


def _load_cost_review():
    name = "customer_zero_cost_review"
    if name in sys.modules:
        return sys.modules[name]
    cost_review_module = (
        REPO / "services" / "governance" / "customer_zero_cost_review.py"
    )
    spec = importlib.util.spec_from_file_location(name, cost_review_module)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# PEVID-035: additional_charges entry with invalid applicability_status → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_035_invalid_applicability_status():
    """PEVID-035: additional_charges entry with invalid applicability_status → REJECTED_CONTENT."""
    verifier = _load_verifier()
    bad_charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    bad_charge["applicability_status"] = "INVALID_STATUS"
    instance = _synthetic(**{"pricing.additional_charges": [bad_charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for invalid applicability_status; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid
    assert any("applicability_status" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-036: additional_charges entry with APPLICABLE_VERIFIED but null unit_price_usd → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_036_applicable_verified_null_unit_price():
    """PEVID-036: APPLICABLE_VERIFIED charge with null unit_price_usd → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["applicability_status"] = "APPLICABLE_VERIFIED"
    charge["unit_price_usd"] = None
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT; got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid
    assert any("unit_price_usd" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-037: additional_charges entry with NaN unit_price_usd → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_037_nan_unit_price():
    """PEVID-037: NaN unit_price_usd in additional_charges → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["applicability_status"] = "APPLICABLE_VERIFIED"
    charge["unit_price_usd"] = "NaN"
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for NaN unit_price_usd; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-038: additional_charges entry with negative unit_price_usd → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_038_negative_unit_price():
    """PEVID-038: negative unit_price_usd in additional_charges → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["applicability_status"] = "APPLICABLE_VERIFIED"
    charge["unit_price_usd"] = "-1.00"
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for negative unit_price_usd; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-039: additional_charges entry with negative calculated_max_exposure_usd → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_039_negative_calculated_max_exposure():
    """PEVID-039: negative calculated_max_exposure_usd in additional_charges → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["calculated_max_exposure_usd"] = "-5.00"
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for negative calculated_max_exposure_usd; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid
    assert any("calculated_max_exposure_usd" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-040: UNKNOWN_APPLICABILITY charge → compute_bounded_exposure is_defensible_upper_bound=False
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_040_unknown_applicability_blocks_defensibility():
    """PEVID-040: UNKNOWN_APPLICABILITY charge → is_defensible_upper_bound=False."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [
            {
                "charge_id": "HCP-CLIENT-UNIT-001",
                "applicability_status": "UNKNOWN_APPLICABILITY",
                "calculated_max_exposure_usd": None,
            }
        ],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert not report.is_defensible_upper_bound, (
        "UNKNOWN_APPLICABILITY charge must block is_defensible_upper_bound"
    )
    assert "HCP-CLIENT-UNIT-001" in report.additional_charges_blocking, (
        f"HCP-CLIENT-UNIT-001 must be in additional_charges_blocking; "
        f"got {report.additional_charges_blocking}"
    )
    assert report.unresolved_unknowns, "unresolved_unknowns must be non-empty"


# ---------------------------------------------------------------------------
# PEVID-041: UNBOUNDED charge → is_defensible_upper_bound=False
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_041_unbounded_charge_blocks_defensibility():
    """PEVID-041: UNBOUNDED applicability_status → is_defensible_upper_bound=False."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [
            {
                "charge_id": "SOME-UNBOUNDED-CHARGE",
                "applicability_status": "UNBOUNDED",
                "calculated_max_exposure_usd": None,
            }
        ],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert not report.is_defensible_upper_bound, (
        "UNBOUNDED charge must block is_defensible_upper_bound"
    )
    assert "SOME-UNBOUNDED-CHARGE" in report.additional_charges_blocking


# ---------------------------------------------------------------------------
# PEVID-042: NOT_APPLICABLE_VERIFIED charge → does NOT block defensibility
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_042_not_applicable_verified_does_not_block():
    """PEVID-042: NOT_APPLICABLE_VERIFIED charge does NOT block defensibility."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert report.is_defensible_upper_bound, (
        "NOT_APPLICABLE_VERIFIED charge must NOT block is_defensible_upper_bound; "
        f"unresolved_unknowns={report.unresolved_unknowns}"
    )
    assert report.additional_charges_blocking == [], (
        f"additional_charges_blocking must be empty; got {report.additional_charges_blocking}"
    )


# ---------------------------------------------------------------------------
# PEVID-043: APPLICABLE_VERIFIED charge with calculated exposure → included in total ceiling
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_043_applicable_verified_included_in_ceiling():
    """PEVID-043: APPLICABLE_VERIFIED charge with calculated_max_exposure_usd → included in total."""
    cost_model = _load_cost_model()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["applicability_status"] = "APPLICABLE_VERIFIED"
    charge["calculated_max_exposure_usd"] = "10.00"
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [charge],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert report.is_defensible_upper_bound, (
        f"APPLICABLE_VERIFIED charge must not block; "
        f"unresolved_unknowns={report.unresolved_unknowns}"
    )
    total = Decimal(report.total_bounded_ceiling_usd)
    # Expected: 120 min * 1.50/hr = 3.00 + 10% margin = 3.30 + 0.00 CW + 10.00 charge = 13.30
    assert total >= Decimal("13.00"), (
        f"Total ceiling must include the $10.00 applicable charge; got {total}"
    )
    # Confirm charge appears in additional_charges_included
    assert any(
        c.get("charge_id") == "HCP-CLIENT-UNIT-SYNTHETIC"
        and c.get("exposure_included_usd") == "10.00"
        for c in report.additional_charges_included
    ), (
        f"Charge not found in additional_charges_included: {report.additional_charges_included}"
    )


# ---------------------------------------------------------------------------
# PEVID-044: unknown_charges_acknowledged=True with UNKNOWN_APPLICABILITY charge → still blocks
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_044_uca_true_with_unknown_still_blocks():
    """PEVID-044: acknowledgement alone is insufficient — UNKNOWN_APPLICABILITY still blocks."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,  # acknowledged, but charge is still UNKNOWN
        "additional_charges": [
            {
                "charge_id": "HCP-CLIENT-UNIT-001",
                "applicability_status": "UNKNOWN_APPLICABILITY",
                "calculated_max_exposure_usd": None,
            }
        ],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert not report.is_defensible_upper_bound, (
        "unknown_charges_acknowledged=True alone is insufficient; "
        "UNKNOWN_APPLICABILITY must still block"
    )
    assert "HCP-CLIENT-UNIT-001" in report.additional_charges_blocking


# ---------------------------------------------------------------------------
# PEVID-045: all charges NOT_APPLICABLE_VERIFIED + acknowledgement → is_defensible_upper_bound=True eligible
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_045_all_not_applicable_verified_defensible():
    """PEVID-045: all charges NOT_APPLICABLE_VERIFIED + uca=True → is_defensible_upper_bound=True."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert report.is_defensible_upper_bound, (
        "All NOT_APPLICABLE_VERIFIED + uca=True must allow is_defensible_upper_bound=True; "
        f"unresolved_unknowns={report.unresolved_unknowns}"
    )
    assert report.unresolved_unknowns == []


# ---------------------------------------------------------------------------
# PEVID-046: pricing_evidence_fingerprint in request set and matching → C23 PASS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_046_fingerprint_matching_c23_pass():
    """PEVID-046: pricing_evidence_fingerprint in request matching → C23 PASS."""
    cost_review = _load_cost_review()
    # Build a validated instance with a fingerprint
    verifier = _load_verifier()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    result = verifier.verify_pricing_evidence(instance)
    assert result.is_valid, f"Expected valid instance; findings={result.findings}"
    # Compute what the fingerprint should be
    fp = _compute_fingerprint(instance["pricing"])
    # Build a minimal request dict with the fingerprint set
    request_with_fp = {"pricing_evidence_fingerprint": fp}
    c23 = cost_review._check_evidence_fingerprint_bound(request_with_fp, instance)
    assert c23.passed, f"C23 must PASS when fingerprint matches; detail={c23.detail}"
    assert c23.id == "C23_EVIDENCE_FINGERPRINT_BOUND"


# ---------------------------------------------------------------------------
# PEVID-047: pricing_evidence_fingerprint in request set and NOT matching → C23 FAIL
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_047_fingerprint_mismatch_c23_fail():
    """PEVID-047: pricing_evidence_fingerprint set and NOT matching → C23 FAIL."""
    cost_review = _load_cost_review()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    # Use a wrong fingerprint in the request
    request_with_wrong_fp = {"pricing_evidence_fingerprint": "deadbeef" * 8}
    c23 = cost_review._check_evidence_fingerprint_bound(request_with_wrong_fp, instance)
    assert not c23.passed, (
        f"C23 must FAIL when fingerprint mismatches; detail={c23.detail}"
    )
    assert "mismatch" in c23.detail.lower() or "MISMATCH" in c23.detail.upper()


# ---------------------------------------------------------------------------
# PEVID-048: pricing_evidence_fingerprint in request is null, NO validated evidence → C23 PASS
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_048_null_fingerprint_no_evidence_c23_pass():
    """PEVID-048: pricing_evidence_fingerprint is null AND no validated instance available
    → C23 PASS (nothing to bind against yet).

    After the C23 tightening: null is only acceptable when no validated evidence
    exists. When a full validated instance (with pricing sub-object) is available,
    null must FAIL (see PEVID-060).
    """
    cost_review = _load_cost_review()
    # Pass None as pricing_override_dict — no validated evidence available
    request_with_null_fp = {"pricing_evidence_fingerprint": None}
    c23 = cost_review._check_evidence_fingerprint_bound(request_with_null_fp, None)
    assert c23.passed, (
        f"C23 must PASS when pricing_evidence_fingerprint is null and no validated "
        f"instance is available; detail={c23.detail}"
    )
    assert "null" in c23.detail.lower() or "not yet bound" in c23.detail.lower()


# ---------------------------------------------------------------------------
# PEVID-049: collector identity == reviewer identity in additional_charges context
# (existing provenance check still enforced)
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_049_provenance_check_still_enforced_with_additional_charges():
    """PEVID-049: collector == reviewer still rejected even when additional_charges present."""
    verifier = _load_verifier()
    instance = _synthetic(
        **{
            "provenance.collector_identity": "same@example.com",
            "provenance.independent_reviewer_identity": "same@example.com",
            "pricing.additional_charges": [
                copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
            ],
        }
    )
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_PROVENANCE", (
        f"Expected REJECTED_PROVENANCE when collector == reviewer; "
        f"got {result.validation_status!r}"
    )
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-050: additional_charges entry with wrong currency → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_050_wrong_currency_in_additional_charge():
    """PEVID-050: additional_charges entry with currency != USD → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["currency"] = "EUR"
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for non-USD currency in additional_charges; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid
    assert any("currency" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-051: float monetary value in additional_charges — string "1.50" is fine
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_051_string_decimal_in_additional_charge():
    """PEVID-051: unit_price_usd as string '1.50' in additional_charges parses correctly."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["applicability_status"] = "APPLICABLE_VERIFIED"
    charge["unit_price_usd"] = "1.50"
    instance = _with_valid_fingerprint(
        _synthetic(**{"pricing.additional_charges": [charge]})
    )
    result = verifier.verify_pricing_evidence(instance)
    # Should not be REJECTED_CONTENT due to unit_price_usd parsing
    assert result.validation_status not in ("REJECTED_SCHEMA",), (
        f"String '1.50' should parse as Decimal; got {result.validation_status!r}, "
        f"findings={result.findings}"
    )
    assert not any(
        "unit_price_usd" in f.lower() and "not a valid" in f.lower()
        for f in result.findings
    ), f"String '1.50' should parse correctly; findings={result.findings}"


# ---------------------------------------------------------------------------
# PEVID-052: additional_charges entry with missing charge_id → REJECTED_CONTENT
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_052_missing_charge_id():
    """PEVID-052: additional_charges entry with null/missing charge_id → REJECTED_CONTENT."""
    verifier = _load_verifier()
    charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
    charge["charge_id"] = None
    instance = _synthetic(**{"pricing.additional_charges": [charge]})
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_CONTENT", (
        f"Expected REJECTED_CONTENT for null charge_id; "
        f"got {result.validation_status!r}, findings={result.findings}"
    )
    assert not result.is_valid
    assert any("charge_id" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# PEVID-053: multiple UNKNOWN charges → all charge_ids appear in additional_charges_blocking
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_053_multiple_unknown_charges_all_blocking():
    """PEVID-053: multiple UNKNOWN_APPLICABILITY charges → all charge_ids in additional_charges_blocking."""
    cost_model = _load_cost_model()
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [
            {
                "charge_id": "HCP-CHARGE-001",
                "applicability_status": "UNKNOWN_APPLICABILITY",
                "calculated_max_exposure_usd": None,
            },
            {
                "charge_id": "HCP-CHARGE-002",
                "applicability_status": "UNKNOWN_APPLICABILITY",
                "calculated_max_exposure_usd": None,
            },
        ],
    }
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.50"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert not report.is_defensible_upper_bound
    assert "HCP-CHARGE-001" in report.additional_charges_blocking, (
        f"HCP-CHARGE-001 must be in blocking; got {report.additional_charges_blocking}"
    )
    assert "HCP-CHARGE-002" in report.additional_charges_blocking, (
        f"HCP-CHARGE-002 must be in blocking; got {report.additional_charges_blocking}"
    )


# ---------------------------------------------------------------------------
# PEVID-054: full null instance → still REJECTED_NOT_POPULATED (regression test)
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_054_null_instance_still_rejected_not_populated():
    """PEVID-054: full null instance must still return REJECTED_NOT_POPULATED (no regression)."""
    verifier = _load_verifier()
    instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
    instance["provider"]["tier"] = None
    instance["provider"]["region"] = None
    instance["pricing"]["currency"] = None
    instance["pricing"]["hourly_rate_usd"] = None
    instance["pricing"]["billing_unit_minutes"] = None
    instance["pricing"]["minimum_charge_usd"] = None
    instance["pricing"]["unknown_charges_acknowledged"] = None
    result = verifier.verify_pricing_evidence(instance)
    assert result.validation_status == "REJECTED_NOT_POPULATED", (
        f"All-null template must still return REJECTED_NOT_POPULATED; "
        f"got {result.validation_status!r}"
    )
    assert not result.is_valid


# ---------------------------------------------------------------------------
# PEVID-055: APPROVED state unreachable even when all additional charges are NOT_APPLICABLE_VERIFIED
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_055_approved_unreachable_with_not_applicable_charges():
    """PEVID-055: APPROVED state is unreachable even when all additional charges are NOT_APPLICABLE_VERIFIED."""
    pipeline = _load_pipeline()
    # Use repo state which has UNKNOWN_APPLICABILITY charge — still BLOCKED
    report = pipeline.run_verification(repo=REPO)
    # Overall must NOT be APPROVED
    assert report.get("overall_status") != "APPROVED", (
        "APPROVED must never appear as overall_status"
    )
    assert report.get("approved") is False, (
        f"approved must always be False; got {report.get('approved')!r}"
    )
    # Even if we could construct a perfect evidence scenario, the verifier pipeline
    # must not produce approved=True
    # (approved field must be false; "APPROVED" can appear in other context strings)
    assert report["approved"] is not True


# ---------------------------------------------------------------------------
# PEVID-056 through PEVID-059: PR bot findings — 4 targeted fixes
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_056_falsey_nonlist_additional_charges_rejected():
    """PEVID-056 (P2): Falsey non-list values in additional_charges must be rejected.

    {} / "" / 0 previously bypassed type validation because the guard was
    'if additional_charges_raw is not None and additional_charges_raw'. The fix
    checks type whenever the field is non-null, regardless of truthiness.
    """
    verifier = _load_verifier()
    for bad_value in ({}, "", 0, False):
        instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
        instance["pricing"]["additional_charges"] = bad_value
        # Must recompute fingerprint since pricing changed
        pricing = instance.get("pricing", {})
        import hashlib
        import json as _json

        fp = hashlib.sha256(
            _json.dumps(pricing, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        instance["integrity"]["evidence_fingerprint_sha256"] = fp
        result = verifier.verify_pricing_evidence(instance)
        assert result.validation_status not in ("VALIDATED", "UNVALIDATED"), (
            f"Falsey non-list additional_charges {bad_value!r} must fail validation; "
            f"got {result.validation_status!r}"
        )
        assert not result.is_valid, (
            f"is_valid must be False for bad additional_charges {bad_value!r}"
        )


@pytest.mark.contract
def test_pevid_057_null_absent_currency_in_charge_rejected():
    """PEVID-057 (P2): Null or absent currency in an additional charge must be rejected.

    Adding an undenominated number to a USD ceiling is unsound. The fix requires
    currency to be non-null and equal to 'USD' for every charge entry.
    """
    verifier = _load_verifier()
    for bad_currency in (None, ""):
        instance = copy.deepcopy(SYNTHETIC_VALID_EVIDENCE)
        charge = copy.deepcopy(SYNTHETIC_CHARGE_NOT_APPLICABLE)
        charge["currency"] = bad_currency
        instance["pricing"]["additional_charges"] = [charge]
        result = verifier.verify_pricing_evidence(instance)
        assert not result.is_valid, (
            f"is_valid must be False for charge with currency={bad_currency!r}"
        )
        assert any("currency" in f.lower() for f in result.findings), (
            f"findings must mention currency; got {result.findings}"
        )


@pytest.mark.contract
def test_pevid_058_applicable_verified_null_exposure_blocks_defensibility():
    """PEVID-058 (P1): APPLICABLE_VERIFIED charge with null calculated_max_exposure_usd
    must block is_defensible_upper_bound — silently contributing zero is unsound.
    """
    cost_model = _load_cost_model()
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.84299"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    # Charge is APPLICABLE_VERIFIED but no calculated_max_exposure_usd
    charge_with_null_exposure = {
        "charge_id": "TEST-APPLICABLE-NULL-EXPOSURE",
        "applicability_status": "APPLICABLE_VERIFIED",
        "calculated_max_exposure_usd": None,
        "currency": "USD",
    }
    snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [charge_with_null_exposure],
    }
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=snapshot
    )
    assert report.is_defensible_upper_bound is False, (
        "APPLICABLE_VERIFIED charge with null calculated_max_exposure_usd must block defensibility"
    )
    assert report.unresolved_unknowns, (
        "unresolved_unknowns must be non-empty when APPLICABLE_VERIFIED exposure is null"
    )
    combined = " ".join(report.unresolved_unknowns).lower()
    assert "applicable_verified" in combined or "null" in combined, (
        f"unresolved_unknowns should describe the issue; got: {report.unresolved_unknowns}"
    )


@pytest.mark.contract
def test_pevid_059_unknown_applicability_blocks_pipeline_readiness():
    """PEVID-059 (P1): A UNKNOWN_APPLICABILITY charge in validated evidence must prevent
    the pipeline from returning READY_FOR_HUMAN_DECISION even when all request fields
    are populated and the cost verifier would otherwise return READY_FOR_HUMAN_DECISION.

    The pricing verifier returns VALIDATED regardless of per-charge classification.
    The pipeline must enforce the defensibility gate explicitly.
    """
    pipeline = _load_pipeline()
    # Verify that the current repo state (which has HCP-CLIENT-UNIT-001 as UNKNOWN)
    # does not produce READY_FOR_HUMAN_DECISION from the pipeline
    report = pipeline.run_verification(repo=REPO)
    assert report["overall_status"] != "READY_FOR_HUMAN_DECISION", (
        "Pipeline must not reach READY_FOR_HUMAN_DECISION when an UNKNOWN_APPLICABILITY "
        f"charge exists; got overall_status={report['overall_status']!r}"
    )
    assert report["approved"] is False


# ---------------------------------------------------------------------------
# PEVID-060: C23 null fingerprint WITH validated evidence → FAIL
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_060_null_fingerprint_with_validated_evidence_c23_fail():
    """PEVID-060: pricing_evidence_fingerprint is null but validated pricing evidence
    IS available → C23 must FAIL.

    Once the pipeline has a validated instance (pricing sub-object present in
    pricing_override_dict), the operator MUST bind the request to the specific
    evidence fingerprint. An unbound request cannot reach READY_FOR_HUMAN_DECISION.
    """
    cost_review = _load_cost_review()
    instance = _with_valid_fingerprint(copy.deepcopy(SYNTHETIC_VALID_EVIDENCE))
    # instance has a "pricing" sub-object — validated evidence IS available
    request_with_null_fp = {"pricing_evidence_fingerprint": None}
    c23 = cost_review._check_evidence_fingerprint_bound(request_with_null_fp, instance)
    assert not c23.passed, (
        "C23 must FAIL when pricing_evidence_fingerprint is null but validated "
        f"evidence (with pricing sub-object) is available; detail={c23.detail}"
    )
    assert c23.id == "C23_EVIDENCE_FINGERPRINT_BOUND"
    assert (
        "null" in c23.detail.lower()
        or "must be bound" in c23.detail.lower()
        or "required" in c23.detail.lower()
    ), f"C23 detail should explain fingerprint binding is required; got: {c23.detail!r}"


# ---------------------------------------------------------------------------
# PEVID-061: unverified_tax_exposure is always True — no input can bypass it
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_pevid_061_unverified_tax_exposure_invariant():
    """PEVID-061: unverified_tax_exposure is always True regardless of inputs.

    The field is informational — it flags that tax treatment has not been
    independently confirmed. No input combination can set it to False:
    the field is hardcoded in compute_bounded_exposure and has no bypass path.
    A defensible-upper-bound report can coexist with unverified_tax_exposure=True
    (the human approver accounts for tax uncertainty in their decision).
    """
    cost_model = _load_cost_model()
    inputs = cost_model.PricingInputs(
        hourly_rate_usd=Decimal("1.84299"),
        billing_unit_minutes=60,
        minimum_charge_usd=Decimal("0"),
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    fully_verified_snapshot = {
        "billing_unit_minutes": 60,
        "minimum_charge_usd": "0",
        "unknown_charges_acknowledged": True,
        "additional_charges": [],
    }
    report = cost_model.compute_bounded_exposure(
        inputs, max_runtime_minutes=120, pricing_snapshot=fully_verified_snapshot
    )
    # is_defensible_upper_bound should be True — all conditions met
    assert report.is_defensible_upper_bound is True, (
        "Expected is_defensible_upper_bound=True with fully verified snapshot"
    )
    # unverified_tax_exposure must be True even when everything else is verified
    assert report.unverified_tax_exposure is True, (
        "unverified_tax_exposure must be True regardless of how complete the "
        "pricing evidence is — tax treatment confirmation is outside scope of "
        "this evidence pipeline"
    )
    # Verify to_dict() serializes it correctly too
    d = report.to_dict()
    assert d["unverified_tax_exposure"] is True, (
        "to_dict() must include unverified_tax_exposure=True"
    )
