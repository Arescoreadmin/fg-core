"""CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 — Deterministic cost model.

This module builds a deterministic cost calculation for three Run-3 scenarios
using Decimal arithmetic. All financial calculations use decimal.Decimal to
avoid floating point rounding errors.

PRICING STATUS: UNVERIFIED (FP-001 OPEN)
-----------------------------------------
All scenario costs output PENDING until the human operator confirms current
HCP Vault Dedicated (standard_small, us-east-1) pricing from the HCP portal
and provides verified inputs to this module.

USAGE
-----
When pricing IS verified:

  from decimal import Decimal
  from services.governance.run3_cost_model import build_cost_model, PricingInputs

  inputs = PricingInputs(
      hourly_rate_usd=Decimal("X.XX"),       # Confirmed from HCP portal
      billing_unit_minutes=60,                # Typically hourly
      minimum_charge_usd=Decimal("0.00"),     # Or confirmed minimum
      aws_cloudwatch_per_gb_usd=Decimal("0.50"),
      estimated_audit_volume_gb=Decimal("0.001"),
  )
  model = build_cost_model(inputs)
  print(model.to_dict())

When pricing is UNVERIFIED (current state):

  from services.governance.run3_cost_model import build_pending_cost_model
  model = build_pending_cost_model()
  # All scenario costs will show PENDING

IMPORTANT: Do NOT use $321.81 as a pricing reference for Run 3.
The historical figure is CONSUMED (Runs 1+2 only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any


# ---------------------------------------------------------------------------
# Additional charge model
# ---------------------------------------------------------------------------


@dataclass
class AdditionalCharge:
    """A structured representation of a potential additional charge component.

    Classification semantics:
    - APPLICABLE_VERIFIED: charge applies and amount is confirmed
    - NOT_APPLICABLE_VERIFIED: charge does not apply with supporting evidence
    - UNKNOWN_APPLICABILITY: cannot determine if charge applies — BLOCKS defensibility
    - UNBOUNDED: charge applies but quantity/amount cannot be bounded — BLOCKS defensibility
    - PENDING_VERIFICATION: requires further evidence collection
    """

    charge_id: str
    provider: str
    description: str
    billing_metric: str  # e.g. "per_client_month", "per_hour"
    unit_price_usd: str | None  # Decimal string, None if unknown
    currency: str  # must be "USD"
    billing_frequency: str  # "monthly", "hourly", "one_time"
    quantity_basis: str  # how quantity is determined
    max_billable_quantity: int | None  # None if unbounded
    proration_rule: str | None  # "daily", "hourly", "none", None if unknown
    minimum_commitment_usd: str | None  # Decimal string
    applicability_status: str  # one of the 5 above
    source_evidence_ref: str | None  # evidence_id or "PENDING"
    confidence: str  # "VERIFIED", "ESTIMATED", "UNKNOWN"
    calculated_max_exposure_usd: str | None  # Decimal string, None if unbounded/unknown
    notes: str | None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    @property
    def blocks_defensibility(self) -> bool:
        return self.applicability_status in (
            "UNKNOWN_APPLICABILITY",
            "UNBOUNDED",
            "PENDING_VERIFICATION",
        )


VALID_APPLICABILITY_STATUSES = frozenset(
    [
        "APPLICABLE_VERIFIED",
        "NOT_APPLICABLE_VERIFIED",
        "UNKNOWN_APPLICABILITY",
        "UNBOUNDED",
        "PENDING_VERIFICATION",
    ]
)


# ---------------------------------------------------------------------------
# Pricing inputs
# ---------------------------------------------------------------------------


@dataclass
class PricingInputs:
    """Verified pricing inputs. All monetary values are Decimal.

    These must be populated by the human operator after confirming pricing
    from the HCP portal. Do NOT use estimated or historical values here.
    """

    hourly_rate_usd: Decimal  # HCP Vault Dedicated standard_small, us-east-1
    billing_unit_minutes: int  # Billing granularity (e.g., 60 for hourly)
    minimum_charge_usd: Decimal  # Minimum billable unit (may be 0)
    aws_cloudwatch_per_gb_usd: Decimal  # CloudWatch log ingestion (us-east-1)
    estimated_audit_volume_gb: Decimal  # Expected Vault audit log volume per ceremony


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    """Cost estimate for one scenario."""

    scenario_id: str
    name: str
    description: str
    estimated_runtime_minutes_min: int
    estimated_runtime_minutes_max: int
    hcp_cost_usd: str  # "PENDING" if unverified, else Decimal string
    aws_cloudwatch_cost_usd: str
    total_cost_usd: str
    cost_note: str
    is_pending: bool


@dataclass
class CostModel:
    """Three-scenario cost model for Run 3.

    scenario_a: Successful first attempt (full ceremony + teardown)
    scenario_b: Early failure (provision + smoke test fails + abort + teardown)
    scenario_c: Worst authorized runtime (cluster runs until hard deadline)
    """

    scenario_a: ScenarioResult
    scenario_b: ScenarioResult
    scenario_c: ScenarioResult
    pricing_verified: bool
    pricing_note: str
    historical_reference_usd: str  # Always "321.81 (CONSUMED — Runs 1+2 only)"
    aws_note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pricing_verified": self.pricing_verified,
            "pricing_note": self.pricing_note,
            "historical_reference_usd": self.historical_reference_usd,
            "aws_note": self.aws_note,
            "scenarios": {
                "A_successful_first_attempt": {
                    "scenario_id": self.scenario_a.scenario_id,
                    "name": self.scenario_a.name,
                    "description": self.scenario_a.description,
                    "estimated_runtime_minutes_min": self.scenario_a.estimated_runtime_minutes_min,
                    "estimated_runtime_minutes_max": self.scenario_a.estimated_runtime_minutes_max,
                    "hcp_cost_usd": self.scenario_a.hcp_cost_usd,
                    "aws_cloudwatch_cost_usd": self.scenario_a.aws_cloudwatch_cost_usd,
                    "total_cost_usd": self.scenario_a.total_cost_usd,
                    "cost_note": self.scenario_a.cost_note,
                },
                "B_early_failure": {
                    "scenario_id": self.scenario_b.scenario_id,
                    "name": self.scenario_b.name,
                    "description": self.scenario_b.description,
                    "estimated_runtime_minutes_min": self.scenario_b.estimated_runtime_minutes_min,
                    "estimated_runtime_minutes_max": self.scenario_b.estimated_runtime_minutes_max,
                    "hcp_cost_usd": self.scenario_b.hcp_cost_usd,
                    "aws_cloudwatch_cost_usd": self.scenario_b.aws_cloudwatch_cost_usd,
                    "total_cost_usd": self.scenario_b.total_cost_usd,
                    "cost_note": self.scenario_b.cost_note,
                },
                "C_worst_authorized_runtime": {
                    "scenario_id": self.scenario_c.scenario_id,
                    "name": self.scenario_c.name,
                    "description": self.scenario_c.description,
                    "estimated_runtime_minutes_min": self.scenario_c.estimated_runtime_minutes_min,
                    "estimated_runtime_minutes_max": self.scenario_c.estimated_runtime_minutes_max,
                    "hcp_cost_usd": self.scenario_c.hcp_cost_usd,
                    "aws_cloudwatch_cost_usd": self.scenario_c.aws_cloudwatch_cost_usd,
                    "total_cost_usd": self.scenario_c.total_cost_usd,
                    "cost_note": self.scenario_c.cost_note,
                },
            },
        }


# ---------------------------------------------------------------------------
# Calculation helpers
# ---------------------------------------------------------------------------

_TWO_PLACES = Decimal("0.01")


def _round_up_to_billing_unit(minutes: int, billing_unit: int) -> int:
    """Round minutes UP to the next multiple of billing_unit.

    For hourly billing (billing_unit=60), 30 minutes → 60 minutes,
    61 minutes → 120 minutes. This prevents understating costs when
    providers bill in full units rather than prorating.
    """
    if billing_unit <= 0:
        raise ValueError("billing_unit must be > 0")
    import math

    return math.ceil(minutes / billing_unit) * billing_unit


def _cost_for_minutes(
    hourly_rate: Decimal, minutes: int, billing_unit_minutes: int = 1
) -> Decimal:
    """Compute cost for a given number of minutes at an hourly rate.

    Rounds minutes UP to the confirmed billing unit before applying the rate.
    With billing_unit_minutes=60 (hourly), 30 min → 1 billable hour.
    With billing_unit_minutes=1 (per-minute, the default), no rounding occurs.
    """
    billable_minutes = _round_up_to_billing_unit(minutes, billing_unit_minutes)
    hours = Decimal(str(billable_minutes)) / Decimal("60")
    return (hourly_rate * hours).quantize(_TWO_PLACES, rounding=ROUND_HALF_UP)


def _cloudwatch_cost(per_gb: Decimal, volume_gb: Decimal) -> Decimal:
    """Compute CloudWatch ingestion cost."""
    return (per_gb * volume_gb).quantize(_TWO_PLACES, rounding=ROUND_HALF_UP)


def _apply_minimum(cost: Decimal, minimum: Decimal) -> Decimal:
    """Apply minimum charge if greater than calculated cost."""
    return max(cost, minimum)


# ---------------------------------------------------------------------------
# Model builders
# ---------------------------------------------------------------------------


def build_pending_cost_model() -> CostModel:
    """Build a PENDING cost model for use when pricing is unverified (FP-001 OPEN).

    All scenario costs output PENDING. The calculation logic is structurally
    correct and will produce real values once pricing inputs are supplied.
    """
    pending_scenario_a = ScenarioResult(
        scenario_id="A",
        name="Successful first attempt",
        description=(
            "Full ceremony path: provision → audit smoke test → AppRole config → "
            "trust domain setup (3 domains) → signing proof families (A-F, H) → "
            "Checkpoint Q → trust determination → teardown. "
            "Estimated 120–240 minutes total paid runtime."
        ),
        estimated_runtime_minutes_min=120,
        estimated_runtime_minutes_max=240,
        hcp_cost_usd="PENDING",
        aws_cloudwatch_cost_usd="PENDING",
        total_cost_usd="PENDING",
        cost_note=(
            "PENDING — HCP pricing unverified (FP-001 OPEN). "
            "Human operator must confirm current standard_small us-east-1 hourly rate "
            "from the HCP portal before this figure can be calculated."
        ),
        is_pending=True,
    )

    pending_scenario_b = ScenarioResult(
        scenario_id="B",
        name="Early failure (abort on smoke test)",
        description=(
            "Short path: provision → audit smoke test fails → abort → teardown. "
            "No signing proofs executed. Minimum paid runtime: ~30–60 minutes "
            "(provisioning + smoke test + teardown). "
            "This is the lowest-cost failure mode and validates the audit-first gate."
        ),
        estimated_runtime_minutes_min=30,
        estimated_runtime_minutes_max=60,
        hcp_cost_usd="PENDING",
        aws_cloudwatch_cost_usd="PENDING",
        total_cost_usd="PENDING",
        cost_note=(
            "PENDING — HCP pricing unverified (FP-001 OPEN). "
            "Abort on smoke test failure minimizes cost (30–60 min paid runtime). "
            "Confirm current HCP hourly rate to compute this scenario."
        ),
        is_pending=True,
    )

    pending_scenario_c = ScenarioResult(
        scenario_id="C",
        name="Worst authorized runtime",
        description=(
            "Cluster runs until the human-authorized maximum runtime. "
            "Infrastructure hits hard deadline regardless of ceremony state. "
            "Operator executes teardown. Runtime = requested_max_runtime_minutes "
            "(set by human approver). This scenario bounds the maximum authorized spend."
        ),
        estimated_runtime_minutes_min=0,  # 0 = set by human (required_max_runtime_minutes)
        estimated_runtime_minutes_max=0,  # 0 = set by human
        hcp_cost_usd="PENDING",
        aws_cloudwatch_cost_usd="PENDING",
        total_cost_usd="PENDING",
        cost_note=(
            "PENDING — both HCP pricing (FP-001 OPEN) and requested_max_runtime_minutes "
            "(human decision required) are unset. "
            "Worst-case cost = confirmed_hourly_rate * (requested_max_runtime_minutes / 60). "
            "This is the ceiling that bounds the spending authorization."
        ),
        is_pending=True,
    )

    return CostModel(
        scenario_a=pending_scenario_a,
        scenario_b=pending_scenario_b,
        scenario_c=pending_scenario_c,
        pricing_verified=False,
        pricing_note=(
            "HCP Vault Dedicated (standard_small, us-east-1) pricing is UNVERIFIED. "
            "FP-001 from CZ-RUN3-FAILURE-PREVENTION-001 is OPEN. "
            "Human operator must confirm current pricing from HCP portal before "
            "any cost authorization decision. Do NOT use $321.81 as a reference."
        ),
        historical_reference_usd="321.81 (CONSUMED — Runs 1+2 only; not a ceiling for Run 3)",
        aws_note=(
            "AWS CloudWatch costs are negligible for ceremony-scale Vault audit traffic "
            "(KB-scale at $0.50/GB ingestion, us-east-1). IAM resources have no direct cost."
        ),
    )


def build_cost_model(
    inputs: PricingInputs,
    max_runtime_minutes: int | None = None,
) -> CostModel:
    """Build a verified cost model with calculated scenario costs.

    Args:
        inputs: Verified pricing inputs from the HCP portal.
        max_runtime_minutes: Authorized maximum runtime (scenario C). Required for C.

    Returns:
        CostModel with real Decimal calculations.
    """
    cw_cost = _cloudwatch_cost(
        inputs.aws_cloudwatch_per_gb_usd,
        inputs.estimated_audit_volume_gb,
    )

    bu = inputs.billing_unit_minutes  # confirmed billing granularity

    # Scenario A: 120–240 minutes
    a_min = _apply_minimum(
        _cost_for_minutes(inputs.hourly_rate_usd, 120, bu),
        inputs.minimum_charge_usd,
    )
    a_max = _apply_minimum(
        _cost_for_minutes(inputs.hourly_rate_usd, 240, bu),
        inputs.minimum_charge_usd,
    )

    # Scenario B: 30–60 minutes
    b_min = _apply_minimum(
        _cost_for_minutes(inputs.hourly_rate_usd, 30, bu),
        inputs.minimum_charge_usd,
    )
    b_max = _apply_minimum(
        _cost_for_minutes(inputs.hourly_rate_usd, 60, bu),
        inputs.minimum_charge_usd,
    )

    # Scenario C: max_runtime_minutes (human-set)
    if max_runtime_minutes is not None and max_runtime_minutes > 0:
        c_cost = _apply_minimum(
            _cost_for_minutes(inputs.hourly_rate_usd, max_runtime_minutes, bu),
            inputs.minimum_charge_usd,
        )
        c_total = (c_cost + cw_cost).quantize(_TWO_PLACES, rounding=ROUND_HALF_UP)
        c_hcp_str = str(c_cost)
        c_total_str = str(c_total)
        c_note = (
            f"Calculated: {inputs.hourly_rate_usd} USD/hr * "
            f"{max_runtime_minutes} min = {c_cost} USD HCP + {cw_cost} USD CloudWatch"
        )
        c_min_min = max_runtime_minutes
        c_max_min = max_runtime_minutes
    else:
        c_hcp_str = "PENDING"
        c_total_str = "PENDING"
        c_note = (
            "max_runtime_minutes not set — human approver must set before computing"
        )
        c_min_min = 0
        c_max_min = 0

    return CostModel(
        scenario_a=ScenarioResult(
            scenario_id="A",
            name="Successful first attempt",
            description=(
                "Full ceremony path: provision → audit smoke test → trust domain setup → "
                "signing proof families (A-F, H) → Checkpoint Q → teardown."
            ),
            estimated_runtime_minutes_min=120,
            estimated_runtime_minutes_max=240,
            hcp_cost_usd=f"{a_min}–{a_max}",
            aws_cloudwatch_cost_usd=str(cw_cost),
            total_cost_usd=f"{(a_min + cw_cost).quantize(_TWO_PLACES)}–{(a_max + cw_cost).quantize(_TWO_PLACES)}",
            cost_note=f"Calculated: {inputs.hourly_rate_usd} USD/hr",
            is_pending=False,
        ),
        scenario_b=ScenarioResult(
            scenario_id="B",
            name="Early failure (abort on smoke test)",
            description=(
                "Short path: provision → audit smoke test fails → abort → teardown. "
                "No signing proofs. Minimum paid runtime: ~30–60 min."
            ),
            estimated_runtime_minutes_min=30,
            estimated_runtime_minutes_max=60,
            hcp_cost_usd=f"{b_min}–{b_max}",
            aws_cloudwatch_cost_usd=str(cw_cost),
            total_cost_usd=f"{(b_min + cw_cost).quantize(_TWO_PLACES)}–{(b_max + cw_cost).quantize(_TWO_PLACES)}",
            cost_note=f"Calculated: {inputs.hourly_rate_usd} USD/hr",
            is_pending=False,
        ),
        scenario_c=ScenarioResult(
            scenario_id="C",
            name="Worst authorized runtime",
            description=(
                "Cluster runs until authorized maximum runtime. "
                "Teardown at deadline regardless of ceremony state."
            ),
            estimated_runtime_minutes_min=c_min_min,
            estimated_runtime_minutes_max=c_max_min,
            hcp_cost_usd=c_hcp_str,
            aws_cloudwatch_cost_usd=str(cw_cost),
            total_cost_usd=c_total_str,
            cost_note=c_note,
            is_pending=(max_runtime_minutes is None),
        ),
        pricing_verified=True,
        pricing_note=f"HCP Vault Dedicated standard_small us-east-1: {inputs.hourly_rate_usd} USD/hr (verified)",
        historical_reference_usd="321.81 (CONSUMED — Runs 1+2 only; not a ceiling for Run 3)",
        aws_note=(
            "AWS CloudWatch costs are negligible for ceremony-scale Vault audit traffic "
            "(KB-scale at $0.50/GB ingestion, us-east-1). IAM resources have no direct cost."
        ),
    )


# ---------------------------------------------------------------------------
# Bounded exposure report
# ---------------------------------------------------------------------------


@dataclass
class BoundedExposureReport:
    """Defensible upper-bound cost exposure report for a given max runtime.

    is_defensible_upper_bound is True only when unresolved_unknowns is empty,
    which requires that billing_unit_minutes and minimum_charge_usd are known,
    unknown_charges_acknowledged is explicitly True in the pricing snapshot,
    AND all additional_charges entries are APPLICABLE_VERIFIED or NOT_APPLICABLE_VERIFIED.
    A 10% safety margin alone is insufficient — all billing parameters must be
    confirmed and the operator must have explicitly acknowledged no additional charges.
    """

    base_cost_usd: str  # cost at max_runtime_minutes (Decimal string)
    safety_margin_usd: str  # margin amount
    bounded_ceiling_usd: str  # base + margin
    cloudwatch_cost_usd: str
    total_bounded_ceiling_usd: (
        str  # bounded_ceiling + cloudwatch + applicable verified charges
    )
    unknown_charges_warning: str | None
    is_defensible_upper_bound: bool
    unresolved_unknowns: list[str]  # specific gaps that prevent certification
    additional_charges_included: list[dict] = field(
        default_factory=list
    )  # charges included in calculation
    additional_charges_blocking: list[str] = field(
        default_factory=list
    )  # charge_ids that block defensibility
    unverified_tax_exposure: bool = (
        True  # True unless evidence explicitly confirms tax treatment
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_cost_usd": self.base_cost_usd,
            "safety_margin_usd": self.safety_margin_usd,
            "bounded_ceiling_usd": self.bounded_ceiling_usd,
            "cloudwatch_cost_usd": self.cloudwatch_cost_usd,
            "total_bounded_ceiling_usd": self.total_bounded_ceiling_usd,
            "unknown_charges_warning": self.unknown_charges_warning,
            "is_defensible_upper_bound": self.is_defensible_upper_bound,
            "unresolved_unknowns": self.unresolved_unknowns,
            "additional_charges_included": self.additional_charges_included,
            "additional_charges_blocking": self.additional_charges_blocking,
            "unverified_tax_exposure": self.unverified_tax_exposure,
        }


def compute_bounded_exposure(
    inputs: PricingInputs,
    max_runtime_minutes: int,
    pricing_snapshot: dict | None = None,
    safety_margin_pct: Decimal = Decimal("0.10"),
) -> BoundedExposureReport:
    """Compute a bounded financial exposure report with safety margin.

    is_defensible_upper_bound=True requires ALL of the following:
      1. pricing_snapshot is provided
      2. pricing_snapshot["billing_unit_minutes"] is a positive integer (> 0)
      3. pricing_snapshot["minimum_charge_usd"] is not None
      4. pricing_snapshot["unknown_charges_acknowledged"] is exactly True
      5. ALL entries in pricing_snapshot.get("additional_charges", []) have
         applicability_status in ("APPLICABLE_VERIFIED", "NOT_APPLICABLE_VERIFIED")
         — i.e., none are UNKNOWN_APPLICABILITY, UNBOUNDED, or PENDING_VERIFICATION

    A 10% safety margin alone is NOT sufficient to certify defensibility when
    billing increments, minimum commitments, or additional charges are unknown.

    APPLICABLE_VERIFIED charges with calculated_max_exposure_usd are included
    in the total ceiling. NOT_APPLICABLE_VERIFIED charges contribute zero exposure.
    UNKNOWN/UNBOUNDED/PENDING charges block defensibility.

    Args:
        inputs: Verified pricing inputs (used for arithmetic).
        max_runtime_minutes: The authorized maximum runtime (human-set).
        pricing_snapshot: The raw pricing snapshot dict for defensibility assessment.
            If None, is_defensible_upper_bound is forced False.
        safety_margin_pct: Safety margin fraction (default 10%).

    Returns:
        BoundedExposureReport with all values as Decimal strings.
    """
    if max_runtime_minutes <= 0:
        raise ValueError("max_runtime_minutes must be > 0")
    if safety_margin_pct < Decimal("0"):
        raise ValueError("safety_margin_pct must be >= 0")

    base_cost = _apply_minimum(
        _cost_for_minutes(
            inputs.hourly_rate_usd, max_runtime_minutes, inputs.billing_unit_minutes
        ),
        inputs.minimum_charge_usd,
    )
    margin = (base_cost * safety_margin_pct).quantize(
        _TWO_PLACES, rounding=ROUND_HALF_UP
    )
    ceiling = (base_cost + margin).quantize(_TWO_PLACES, rounding=ROUND_HALF_UP)
    cw_cost = _cloudwatch_cost(
        inputs.aws_cloudwatch_per_gb_usd, inputs.estimated_audit_volume_gb
    )

    # Assess defensibility using pricing_snapshot — the billing parameter values
    # on PricingInputs alone are insufficient because they don't carry the operator's
    # explicit acknowledgement that no additional charges exist.
    unresolved_unknowns: list[str] = []
    additional_charges_included: list[dict] = []
    additional_charges_blocking: list[str] = []
    additional_charges_ceiling = Decimal("0")

    if pricing_snapshot is None:
        unresolved_unknowns.append(
            "pricing_snapshot not provided — cannot assess unknown charges"
        )
    else:
        bum = pricing_snapshot.get("billing_unit_minutes")
        if bum is None or not isinstance(bum, int) or bum <= 0:
            unresolved_unknowns.append("billing_unit_minutes not confirmed")

        if pricing_snapshot.get("minimum_charge_usd") is None:
            unresolved_unknowns.append("minimum_charge_usd not confirmed")

        if pricing_snapshot.get("unknown_charges_acknowledged") is not True:
            unresolved_unknowns.append(
                "unknown_charges_acknowledged is not True — operator has not confirmed "
                "absence of additional charges"
            )

        # Process additional_charges entries
        extra_charges = pricing_snapshot.get("additional_charges") or []
        for charge in extra_charges:
            charge_id = charge.get("charge_id", "<unknown>")
            status = charge.get("applicability_status", "")
            if status in ("UNKNOWN_APPLICABILITY", "UNBOUNDED", "PENDING_VERIFICATION"):
                additional_charges_blocking.append(charge_id)
                unresolved_unknowns.append(
                    f"additional charge {charge_id!r} has applicability_status="
                    f"{status!r} — must be APPLICABLE_VERIFIED or NOT_APPLICABLE_VERIFIED"
                )
                additional_charges_included.append(
                    {
                        "charge_id": charge_id,
                        "applicability_status": status,
                        "exposure_included_usd": None,
                        "note": f"BLOCKS defensibility: applicability_status={status!r}",
                    }
                )
            elif status == "NOT_APPLICABLE_VERIFIED":
                additional_charges_included.append(
                    {
                        "charge_id": charge_id,
                        "applicability_status": status,
                        "exposure_included_usd": "0.00",
                        "note": "Not applicable — zero exposure",
                    }
                )
            elif status == "APPLICABLE_VERIFIED":
                max_exp_raw = charge.get("calculated_max_exposure_usd")
                if max_exp_raw is not None:
                    try:
                        max_exp = Decimal(str(max_exp_raw)).quantize(
                            _TWO_PLACES, rounding=ROUND_HALF_UP
                        )
                        additional_charges_ceiling += max_exp
                        additional_charges_included.append(
                            {
                                "charge_id": charge_id,
                                "applicability_status": status,
                                "exposure_included_usd": str(max_exp),
                                "note": "APPLICABLE_VERIFIED — included in total ceiling",
                            }
                        )
                    except (InvalidOperation, ValueError):
                        unresolved_unknowns.append(
                            f"additional charge {charge_id!r} has unparseable "
                            f"calculated_max_exposure_usd: {max_exp_raw!r}"
                        )
                        additional_charges_included.append(
                            {
                                "charge_id": charge_id,
                                "applicability_status": status,
                                "exposure_included_usd": None,
                                "note": "APPLICABLE_VERIFIED but unparseable exposure",
                            }
                        )
                else:
                    additional_charges_included.append(
                        {
                            "charge_id": charge_id,
                            "applicability_status": status,
                            "exposure_included_usd": "0.00",
                            "note": "APPLICABLE_VERIFIED with null calculated_max_exposure_usd — zero contribution",
                        }
                    )

    total = (ceiling + cw_cost + additional_charges_ceiling).quantize(
        _TWO_PLACES, rounding=ROUND_HALF_UP
    )

    defensible = len(unresolved_unknowns) == 0

    unknown_warning: str | None = None
    if not defensible:
        blocking_summary = []
        if additional_charges_blocking:
            blocking_summary.append(
                f"blocking additional charges: {', '.join(additional_charges_blocking)}"
            )
        other_unknowns = [
            u
            for u in unresolved_unknowns
            if not any(cid in u for cid in additional_charges_blocking)
        ]
        if other_unknowns:
            blocking_summary.append(f"other gaps: {'; '.join(other_unknowns)}")
        unknown_warning = (
            "Bounded ceiling cannot be certified as a defensible upper bound. "
            f"Unresolved gaps: {'; '.join(unresolved_unknowns)}."
        )

    return BoundedExposureReport(
        base_cost_usd=str(base_cost),
        safety_margin_usd=str(margin),
        bounded_ceiling_usd=str(ceiling),
        cloudwatch_cost_usd=str(cw_cost),
        total_bounded_ceiling_usd=str(total),
        unknown_charges_warning=unknown_warning,
        is_defensible_upper_bound=defensible,
        unresolved_unknowns=unresolved_unknowns,
        additional_charges_included=additional_charges_included,
        additional_charges_blocking=additional_charges_blocking,
        unverified_tax_exposure=True,
    )


# ---------------------------------------------------------------------------
# Evidence-based cost model builder
# ---------------------------------------------------------------------------


def build_cost_model_from_evidence(
    evidence_result: Any,
    max_runtime_minutes: int | None = None,
) -> CostModel:
    """Build cost model from a validated pricing evidence result.

    Returns pending model if evidence is not validated.
    Raises ValueError if evidence is validated but pricing snapshot is incomplete.

    Args:
        evidence_result: Result from run3_pricing_evidence_verifier.verify_pricing_evidence().
        max_runtime_minutes: Optional authorized maximum runtime for scenario C.

    Returns:
        CostModel — with real values if evidence is valid, PENDING values otherwise.
    """
    if not evidence_result.is_valid:
        return build_pending_cost_model()

    snapshot = evidence_result.pricing_snapshot
    if snapshot is None:
        raise ValueError(
            "Evidence result is_valid=True but pricing_snapshot is None — "
            "this is a verifier bug. Cannot build cost model."
        )

    required_snapshot_keys = [
        "hourly_rate_usd",
        "billing_unit_minutes",
        "minimum_charge_usd",
    ]
    missing = [k for k in required_snapshot_keys if snapshot.get(k) is None]
    if missing:
        raise ValueError(
            f"Validated pricing snapshot is missing required fields: {missing}"
        )

    try:
        hourly_rate = Decimal(str(snapshot["hourly_rate_usd"]))
        billing_unit = int(snapshot["billing_unit_minutes"])
        minimum_charge = Decimal(str(snapshot["minimum_charge_usd"]))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(
            f"Failed to convert pricing snapshot values to Decimal: {exc}"
        ) from exc

    inputs = PricingInputs(
        hourly_rate_usd=hourly_rate,
        billing_unit_minutes=billing_unit,
        minimum_charge_usd=minimum_charge,
        aws_cloudwatch_per_gb_usd=Decimal("0.50"),
        estimated_audit_volume_gb=Decimal("0.001"),
    )
    return build_cost_model(inputs, max_runtime_minutes)
