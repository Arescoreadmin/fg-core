"""CUSTOMER-ZERO-RUN3-PRICING-EVIDENCE-001 — Pricing evidence verifier.

This module loads, validates, and verifies a pricing evidence instance JSON file
for HCP Vault Dedicated (standard_small, us-east-1) before any cost authorization
decision for CUSTOMER-ZERO-TRUST-003 (Run 3).

SAFETY INVARIANTS (NON-NEGOTIABLE)
------------------------------------
1. This module NEVER fabricates, estimates, or invents pricing values.
2. This module NEVER produces APPROVED state — that is unreachable here.
3. No cloud queries, no provider tokens, no network calls of any kind.
4. No secrets, credentials, API keys, or private keys are read or written.
5. An all-null instance → UNVALIDATED / REJECTED state, never silently passes.
6. Separation of duties: collector_identity must differ from reviewer_identity.
7. Fingerprint mismatch → REJECTED_TAMPERED (hard reject, never warning-only).

VALIDATION STATES
------------------
  VALIDATED               — All required fields present and passing all checks.
  UNVALIDATED             — Fingerprint field is null (collector hasn't set it yet).
                            Not necessarily blocked; schema/content/provenance still checked.
  REJECTED_SCHEMA         — Required fields missing or non-parseable structure.
  REJECTED_NOT_POPULATED  — All core value fields are null (template not populated).
                            Operator must observe live HCP pricing and populate the file.
  REJECTED_CONTENT        — Content validation failed (wrong tier/region/currency/rate).
  REJECTED_PROVENANCE     — Provenance validation failed (null identities or same person).
  REJECTED_FRESHNESS      — Timestamps invalid, future collection, or expired evidence.
  REJECTED_SOURCE         — Source classification or reference URL invalid.
  REJECTED_TAMPERED       — Fingerprint present but does not match computed value.

USAGE
-----
  from services.governance.run3_pricing_evidence_verifier import (
      verify_pricing_evidence,
      verify_pricing_evidence_file,
  )

  result = verify_pricing_evidence_file("customer_one/run3_pricing_evidence_instance.json")
  if result.is_valid:
      snapshot = result.pricing_snapshot
  else:
      print(result.findings)
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPECTED_TIER = "standard_small"
EXPECTED_REGION = "us-east-1"
EXPECTED_CURRENCY = "USD"

VALID_APPLICABILITY_STATUSES = frozenset(
    [
        "APPLICABLE_VERIFIED",
        "NOT_APPLICABLE_VERIFIED",
        "UNKNOWN_APPLICABILITY",
        "UNBOUNDED",
        "PENDING_VERIFICATION",
    ]
)

VALID_SOURCE_CLASSIFICATIONS = frozenset(
    [
        "hcp_portal_screenshot",
        "hcp_api_response",
        "hcp_sales_quote",
        "hcp_pricing_page",
    ]
)

# Required top-level fields that must be present (non-null checked separately)
REQUIRED_FIELDS = [
    "schema_version",
    "evidence_id",
    "evidence_type",
    "collection_timestamp_utc",
    "expiry_policy",
    "provider",
    "pricing",
    "source",
    "provenance",
    "integrity",
    "validation_status",
]

# Required pricing sub-fields that must be non-null and valid
REQUIRED_PRICING_FIELDS = [
    "currency",
    "hourly_rate_usd",
    "billing_unit_minutes",
    "minimum_charge_usd",
]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class PricingEvidenceVerificationResult:
    """Result of pricing evidence verification.

    is_valid is True only when validation_status == VALIDATED.
    UNVALIDATED means the fingerprint is null — schema/content/provenance may be
    structurally valid but the evidence has not been fingerprinted yet by the collector.
    """

    is_valid: bool
    validation_status: str  # VALIDATED | UNVALIDATED | REJECTED_*
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    pricing_snapshot: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "validation_status": self.validation_status,
            "findings": self.findings,
            "warnings": self.warnings,
            "pricing_snapshot": self.pricing_snapshot,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _compute_pricing_fingerprint(pricing: dict[str, Any]) -> str:
    """Compute SHA-256 of the canonical JSON (sorted keys, no whitespace) of pricing."""
    canonical = json.dumps(pricing, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _parse_decimal(value: Any, field_name: str) -> tuple[Decimal | None, str | None]:
    """Parse a value to Decimal. Returns (decimal, error_message).

    Rejects non-finite values (NaN, Infinity) — they cannot represent prices.
    """
    if value is None:
        return None, f"{field_name} is null"
    try:
        d = Decimal(str(value))
        if not d.is_finite():
            return None, f"{field_name} must be a finite number; got {value!r} ({d})"
        return d, None
    except (InvalidOperation, ValueError):
        return None, f"{field_name} is not a valid number: {value!r}"


def _parse_datetime_aware(
    value: Any, field_name: str
) -> tuple[datetime | None, str | None]:
    """Parse an ISO-8601 timezone-aware datetime. Returns (dt, error_message)."""
    if value is None:
        return None, f"{field_name} is null"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return (
                None,
                f"{field_name} is naive (no timezone info); must be timezone-aware",
            )
        return dt, None
    except (ValueError, AttributeError) as exc:
        return None, f"{field_name} is not parseable as ISO-8601: {value!r} ({exc})"


# ---------------------------------------------------------------------------
# Validation stages
# ---------------------------------------------------------------------------


def _validate_schema(
    instance: dict[str, Any],
) -> list[str]:
    """Check structural completeness. Returns list of findings (empty = pass)."""
    findings = []
    for f in REQUIRED_FIELDS:
        if f not in instance:
            findings.append(f"Missing required field: {f!r}")
    # Check nested sub-dicts exist
    for sub in (
        "expiry_policy",
        "provider",
        "pricing",
        "source",
        "provenance",
        "integrity",
    ):
        if sub in instance and not isinstance(instance[sub], dict):
            findings.append(f"Field {sub!r} must be a dict")
    return findings


def _is_template_unpopulated(instance: dict[str, Any]) -> bool:
    """Return True if all core value fields are null (template not yet populated).

    Checks the five key pricing/provider fields that a human operator must set
    by observing live HCP portal pricing.
    """
    provider = instance.get("provider", {}) or {}
    pricing = instance.get("pricing", {}) or {}
    return all(
        v is None
        for v in [
            provider.get("tier"),
            provider.get("region"),
            pricing.get("hourly_rate_usd"),
            pricing.get("billing_unit_minutes"),
            pricing.get("currency"),
        ]
    )


def _validate_content(
    instance: dict[str, Any],
) -> tuple[list[str], list[str], dict[str, Any] | None]:
    """Validate content values. Returns (findings, warnings, snapshot)."""
    findings = []
    warnings = []
    provider = instance.get("provider", {}) or {}
    pricing = instance.get("pricing", {}) or {}

    # Provider tier and region
    tier = provider.get("tier")
    if tier is None:
        findings.append("provider.tier is null; must be standard_small")
    elif tier != EXPECTED_TIER:
        findings.append(f"provider.tier must be {EXPECTED_TIER!r}; got {tier!r}")

    region = provider.get("region")
    if region is None:
        findings.append("provider.region is null; must be us-east-1")
    elif region != EXPECTED_REGION:
        findings.append(f"provider.region must be {EXPECTED_REGION!r}; got {region!r}")

    # Currency
    currency = pricing.get("currency")
    if currency is None:
        findings.append("pricing.currency is null; must be USD")
    elif str(currency).upper() != EXPECTED_CURRENCY:
        findings.append(
            f"pricing.currency must be {EXPECTED_CURRENCY!r} (case-insensitive); got {currency!r}"
        )

    # Hourly rate
    rate_raw = pricing.get("hourly_rate_usd")
    hourly_rate, rate_err = _parse_decimal(rate_raw, "pricing.hourly_rate_usd")
    if rate_err:
        findings.append(rate_err)
    elif hourly_rate is not None and hourly_rate <= Decimal("0"):
        findings.append(f"pricing.hourly_rate_usd must be > 0; got {hourly_rate}")

    # Billing unit minutes
    bum_raw = pricing.get("billing_unit_minutes")
    if bum_raw is None:
        findings.append(
            "pricing.billing_unit_minutes is null; must be a positive integer"
        )
    else:
        try:
            bum = int(bum_raw)
            if bum <= 0:
                findings.append(f"pricing.billing_unit_minutes must be > 0; got {bum}")
        except (TypeError, ValueError):
            findings.append(
                f"pricing.billing_unit_minutes must be a positive integer; got {bum_raw!r}"
            )
            bum = None

    # Minimum charge
    min_raw = pricing.get("minimum_charge_usd")
    min_charge, min_err = _parse_decimal(min_raw, "pricing.minimum_charge_usd")
    if min_err:
        findings.append(min_err)
    elif min_charge is not None and min_charge < Decimal("0"):
        findings.append(f"pricing.minimum_charge_usd must be >= 0; got {min_charge}")

    # unknown_charges_acknowledged
    uca = pricing.get("unknown_charges_acknowledged")
    if not isinstance(uca, bool):
        findings.append(
            f"pricing.unknown_charges_acknowledged must be a boolean (True/False); got {uca!r}"
        )
    elif not uca:
        warnings.append(
            "pricing.unknown_charges_acknowledged is False — "
            "is_defensible_upper_bound will be False; bounded exposure report cannot be certified"
        )

    # Validate additional_charges entries — check type whenever non-null,
    # not just when truthy: {}, "", or 0 are all invalid non-list values.
    additional_charges_raw = pricing.get("additional_charges")
    if additional_charges_raw is not None:
        if not isinstance(additional_charges_raw, list):
            findings.append(
                "pricing.additional_charges must be a list if present; "
                f"got {type(additional_charges_raw).__name__!r}"
            )
        else:
            for idx, charge in enumerate(additional_charges_raw):
                if not isinstance(charge, dict):
                    findings.append(
                        f"pricing.additional_charges[{idx}] must be a dict; "
                        f"got {type(charge).__name__!r}"
                    )
                    continue

                charge_id = charge.get("charge_id")
                if charge_id is None or str(charge_id).strip() == "":
                    findings.append(
                        f"pricing.additional_charges[{idx}].charge_id must be a "
                        "non-null, non-empty string"
                    )

                # currency must be present and USD — a null/absent currency must
                # be rejected even when a calculated_max_exposure_usd is set,
                # because adding an undenominated number to a USD total is unsound.
                charge_currency = charge.get("currency")
                if charge_currency is None or str(charge_currency).upper() != "USD":
                    findings.append(
                        f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                        f"currency must be 'USD'; got {charge_currency!r}"
                    )

                # applicability_status must be in VALID_APPLICABILITY_STATUSES
                app_status = charge.get("applicability_status")
                if app_status not in VALID_APPLICABILITY_STATUSES:
                    findings.append(
                        f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                        f"applicability_status {app_status!r} is not valid; "
                        "must be one of: "
                        + ", ".join(sorted(VALID_APPLICABILITY_STATUSES))
                    )

                # If APPLICABLE_VERIFIED, unit_price_usd must be parseable positive Decimal
                unit_price_raw = charge.get("unit_price_usd")
                if app_status == "APPLICABLE_VERIFIED":
                    if unit_price_raw is None:
                        findings.append(
                            f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                            "applicability_status=APPLICABLE_VERIFIED requires a non-null "
                            "unit_price_usd"
                        )
                    else:
                        upd, up_err = _parse_decimal(
                            unit_price_raw, f"additional_charges[{idx}].unit_price_usd"
                        )
                        if up_err:
                            findings.append(
                                f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                                + up_err
                            )
                        elif upd is not None and upd <= Decimal("0"):
                            findings.append(
                                f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                                f"unit_price_usd must be > 0 for APPLICABLE_VERIFIED; got {upd}"
                            )
                elif unit_price_raw is not None:
                    # Not APPLICABLE_VERIFIED but unit_price_usd is set — validate if finite positive
                    upd, up_err = _parse_decimal(
                        unit_price_raw, f"additional_charges[{idx}].unit_price_usd"
                    )
                    if up_err:
                        findings.append(
                            f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                            + up_err
                        )
                    elif upd is not None and upd < Decimal("0"):
                        findings.append(
                            f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                            f"unit_price_usd must be >= 0 when set; got {upd}"
                        )

                # calculated_max_exposure_usd — if set, must be finite non-negative Decimal
                max_exp_raw = charge.get("calculated_max_exposure_usd")
                if max_exp_raw is not None:
                    med, me_err = _parse_decimal(
                        max_exp_raw,
                        f"additional_charges[{idx}].calculated_max_exposure_usd",
                    )
                    if me_err:
                        findings.append(
                            f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                            + me_err
                        )
                    elif med is not None and med < Decimal("0"):
                        findings.append(
                            f"pricing.additional_charges[{idx}] (charge_id={charge_id!r}): "
                            f"calculated_max_exposure_usd must be >= 0; got {med}"
                        )

    # Build snapshot if no findings so far (content is usable)
    snapshot = None
    if not findings and hourly_rate is not None:
        snapshot = {
            "tier": tier,
            "region": region,
            "currency": str(currency).upper() if currency else None,
            "hourly_rate_usd": str(hourly_rate),
            "billing_unit_minutes": int(bum_raw) if bum_raw is not None else None,
            "minimum_charge_usd": str(min_charge) if min_charge is not None else "0",
            "unknown_charges_acknowledged": bool(uca)
            if isinstance(uca, bool)
            else False,
            "additional_charges": list(additional_charges_raw)
            if isinstance(additional_charges_raw, list)
            else [],
        }

    return findings, warnings, snapshot


def _validate_provenance(
    instance: dict[str, Any],
) -> list[str]:
    """Validate provenance (collector/reviewer identity, separation of duties)."""
    findings = []
    prov = instance.get("provenance", {}) or {}

    collector = prov.get("collector_identity")
    reviewer = prov.get("independent_reviewer_identity")

    if collector is None or str(collector).strip() == "":
        findings.append(
            "provenance.collector_identity is null or empty; human must set"
        )
    if reviewer is None or str(reviewer).strip() == "":
        findings.append(
            "provenance.independent_reviewer_identity is null or empty; human must set"
        )

    # Separation of duties check
    if (
        collector is not None
        and str(collector).strip() != ""
        and reviewer is not None
        and str(reviewer).strip() != ""
        and str(collector).strip().lower() == str(reviewer).strip().lower()
    ):
        findings.append(
            f"provenance.collector_identity and provenance.independent_reviewer_identity "
            f"must not be the same person (separation of duties); both are {collector!r}"
        )

    return findings


def _validate_freshness(
    instance: dict[str, Any],
) -> list[str]:
    """Validate timestamps: collection not in future, expiry not in past, timezone-aware.

    Also enforces that expires_at_utc is consistent with valid_for_days relative to
    collection_timestamp_utc, preventing a far-future expiry (e.g. 2099) from bypassing
    the stated freshness window.
    """
    from datetime import timedelta

    findings = []
    now = datetime.now(UTC)

    # collection_timestamp_utc
    ts_raw = instance.get("collection_timestamp_utc")
    ts, ts_err = _parse_datetime_aware(ts_raw, "collection_timestamp_utc")
    if ts_err:
        findings.append(ts_err)
    elif ts is not None and ts > now:
        findings.append(
            f"collection_timestamp_utc {ts_raw!r} is in the future; "
            "pricing evidence cannot have been collected in the future"
        )

    # expiry_policy.expires_at_utc and valid_for_days consistency
    expiry_policy = instance.get("expiry_policy", {}) or {}
    exp_raw = expiry_policy.get("expires_at_utc")
    exp_dt: datetime | None = None
    if exp_raw is None:
        findings.append(
            "expiry_policy.expires_at_utc is null; evidence cannot be validated without expiry"
        )
    else:
        exp_dt, exp_err = _parse_datetime_aware(exp_raw, "expiry_policy.expires_at_utc")
        if exp_err:
            findings.append(exp_err)
        elif exp_dt is not None and exp_dt <= now:
            findings.append(
                f"expiry_policy.expires_at_utc {exp_raw!r} is in the past; "
                "evidence has expired and must be re-collected"
            )

    # Enforce expiry window: expires_at_utc must not exceed collection + valid_for_days + 1 day.
    # Without this, evidence collected in 2020 with expires_at_utc=2099 would pass the
    # above check while completely violating the stated freshness policy.
    valid_for_days_raw = expiry_policy.get("valid_for_days")
    if (
        valid_for_days_raw is not None
        and ts is not None
        and exp_dt is not None
        and not findings  # only check consistency when timestamps are themselves valid
    ):
        try:
            vfd = int(valid_for_days_raw)
            if vfd <= 0:
                findings.append(f"expiry_policy.valid_for_days must be > 0; got {vfd}")
            else:
                max_allowed_expiry = ts + timedelta(
                    days=vfd + 1
                )  # +1 day processing tolerance
                if exp_dt > max_allowed_expiry:
                    findings.append(
                        f"expiry_policy.expires_at_utc {exp_raw!r} is more than "
                        f"{vfd} day(s) after collection_timestamp_utc {ts_raw!r} — "
                        "the expiry window must be consistent with valid_for_days "
                        "to prevent stale pricing from bypassing the freshness control"
                    )
        except (TypeError, ValueError):
            findings.append(
                f"expiry_policy.valid_for_days must be a positive integer; "
                f"got {valid_for_days_raw!r}"
            )

    return findings


def _validate_source(
    instance: dict[str, Any],
) -> list[str]:
    """Validate source classification and reference URL."""
    findings = []
    source = instance.get("source", {}) or {}

    classification = source.get("classification")
    if classification is None:
        findings.append(
            "source.classification is null; must be one of: "
            + ", ".join(sorted(VALID_SOURCE_CLASSIFICATIONS))
        )
    elif classification not in VALID_SOURCE_CLASSIFICATIONS:
        findings.append(
            f"source.classification {classification!r} is not a valid value; "
            "must be one of: " + ", ".join(sorted(VALID_SOURCE_CLASSIFICATIONS))
        )

    ref_url = source.get("reference_url")
    if ref_url is None:
        findings.append("source.reference_url is null; must be a non-null HTTPS URL")
    elif not str(ref_url).startswith("https://"):
        findings.append(
            f"source.reference_url must start with 'https://'; got {ref_url!r}"
        )

    return findings


def _validate_fingerprint(
    instance: dict[str, Any],
    findings: list[str],
) -> tuple[str, list[str]]:
    """Validate integrity fingerprint. Returns (status, updated_findings).

    VALIDATED   — fingerprint present and matches
    UNVALIDATED — fingerprint null (not set by collector yet)
    REJECTED_TAMPERED — fingerprint present but mismatches
    """
    integrity = instance.get("integrity", {}) or {}
    stored_fp = integrity.get("evidence_fingerprint_sha256")
    pricing = instance.get("pricing", {}) or {}

    if stored_fp is None:
        # Fingerprint not yet computed — UNVALIDATED, not rejected
        return "UNVALIDATED", findings

    # Compute expected fingerprint over the pricing sub-object
    expected_fp = _compute_pricing_fingerprint(pricing)

    if stored_fp != expected_fp:
        new_findings = list(findings) + [
            f"Evidence fingerprint mismatch: expected {stored_fp!r}, "
            f"computed {expected_fp!r}. "
            "The evidence may have been altered after fingerprint computation. "
            "Re-collect evidence from the HCP portal and recompute the fingerprint."
        ]
        return "REJECTED_TAMPERED", new_findings

    return "VALIDATED", findings


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------


def verify_pricing_evidence(
    instance: dict[str, Any],
    seen_evidence_ids: list[str] | None = None,
) -> PricingEvidenceVerificationResult:
    """Verify a pricing evidence instance dict.

    Args:
        instance: The loaded pricing evidence instance (from JSON).
        seen_evidence_ids: List of previously seen evidence IDs (for duplicate detection).

    Returns:
        PricingEvidenceVerificationResult
    """
    if seen_evidence_ids is None:
        seen_evidence_ids = []

    # --- Schema validation ---
    schema_findings = _validate_schema(instance)
    if schema_findings:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_SCHEMA",
            findings=schema_findings,
        )

    # --- Duplicate detection ---
    evidence_id = instance.get("evidence_id")
    if evidence_id is not None and evidence_id in seen_evidence_ids:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_SCHEMA",
            findings=[
                f"Duplicate evidence_id {evidence_id!r}; this evidence instance has already been seen"
            ],
        )

    # --- Content validation ---
    # Detect unpopulated template (all core fields null) before field-level checks
    # so the operator gets a clear "not populated" message rather than a list of
    # individual null-field errors that look like a malformed document.
    if _is_template_unpopulated(instance):
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_NOT_POPULATED",
            findings=[
                "Pricing evidence template has not been populated — all core value fields "
                "are null. This is expected for a new instance. The human operator must "
                "observe current HCP Vault Dedicated (standard_small, us-east-1) pricing "
                "from the HCP portal and populate this file. See "
                "docs/operations/customer_zero_run3_pricing_evidence_capture.md for the "
                "capture procedure."
            ],
        )

    content_findings, content_warnings, snapshot = _validate_content(instance)
    if content_findings:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_CONTENT",
            findings=content_findings,
            warnings=content_warnings,
        )

    # --- Provenance validation ---
    prov_findings = _validate_provenance(instance)
    if prov_findings:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_PROVENANCE",
            findings=prov_findings,
            warnings=content_warnings,
        )

    # --- Freshness validation ---
    fresh_findings = _validate_freshness(instance)
    if fresh_findings:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_FRESHNESS",
            findings=fresh_findings,
            warnings=content_warnings,
        )

    # --- Source authenticity ---
    source_findings = _validate_source(instance)
    if source_findings:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_SOURCE",
            findings=source_findings,
            warnings=content_warnings,
        )

    # --- Fingerprint verification ---
    fp_status, fp_findings = _validate_fingerprint(instance, [])
    if fp_status == "REJECTED_TAMPERED":
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_TAMPERED",
            findings=fp_findings,
            warnings=content_warnings,
        )

    # fp_status is VALIDATED or UNVALIDATED
    # UNVALIDATED: fingerprint is null — structurally valid but not fingerprinted yet
    # is_valid is False for UNVALIDATED (not yet certified)
    is_valid = fp_status == "VALIDATED"

    return PricingEvidenceVerificationResult(
        is_valid=is_valid,
        validation_status=fp_status,
        findings=[],
        warnings=content_warnings,
        pricing_snapshot=snapshot if is_valid else None,
    )


def verify_pricing_evidence_file(
    path: str | Path,
    seen_evidence_ids: list[str] | None = None,
) -> PricingEvidenceVerificationResult:
    """Load a pricing evidence instance JSON file and verify it.

    Args:
        path: Path to the JSON file.
        seen_evidence_ids: List of previously seen evidence IDs.

    Returns:
        PricingEvidenceVerificationResult
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_SCHEMA",
            findings=[f"Evidence file not found: {path}"],
        )
    try:
        instance = json.loads(p.read_text())
    except Exception as exc:
        return PricingEvidenceVerificationResult(
            is_valid=False,
            validation_status="REJECTED_SCHEMA",
            findings=[f"Failed to parse evidence JSON: {exc}"],
        )
    return verify_pricing_evidence(instance, seen_evidence_ids)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python run3_pricing_evidence_verifier.py <evidence-file.json>",
            file=sys.stderr,
        )
        sys.exit(2)
    result = verify_pricing_evidence_file(sys.argv[1])
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(0 if result.is_valid else 1)
