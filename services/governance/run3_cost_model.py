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

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any


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
