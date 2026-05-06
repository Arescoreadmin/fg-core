"""
api/config/billing.py — Stripe billing readiness configuration surface.

Validates STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET presence and quality
(non-blank, not a CHANGE_ME_* placeholder). Returns a structured readiness
dict for operational visibility.

No network calls. No secret values are exposed in the output.
Required-env enforcement (fail-closed at startup) is handled by
api.config.required_env / api.config.prod_invariants — this module
provides readiness visibility only.
"""

from __future__ import annotations

import os
from typing import Mapping, TypedDict

# Stable reason codes — safe for alerting rules and log scraping.
BILLING_STRIPE_SECRET_KEY_MISSING = "BILLING_STRIPE_SECRET_KEY_MISSING"
BILLING_STRIPE_WEBHOOK_SECRET_MISSING = "BILLING_STRIPE_WEBHOOK_SECRET_MISSING"


class StripeReadiness(TypedDict):
    provider: str
    ready: bool
    reasons: list[str]


def get_stripe_readiness(env: Mapping[str, str] | None = None) -> StripeReadiness:
    """Return billing readiness dict.

    Args:
        env: Optional environment mapping (defaults to os.environ). Injected
             in tests to avoid touching the real environment.

    Returns:
        dict with keys:
            provider (str): always "stripe"
            ready (bool): True only when all required keys are present and valid
            reasons (list[str]): stable reason codes explaining non-readiness

    Never exposes secret values in the return value.
    Zero network calls.
    """
    e: Mapping[str, str] = env if env is not None else os.environ
    reasons: list[str] = []

    sk = (e.get("STRIPE_SECRET_KEY") or "").strip()
    if not sk or sk.startswith("CHANGE_ME_"):
        reasons.append(BILLING_STRIPE_SECRET_KEY_MISSING)

    wh = (e.get("STRIPE_WEBHOOK_SECRET") or "").strip()
    if not wh or wh.startswith("CHANGE_ME_"):
        reasons.append(BILLING_STRIPE_WEBHOOK_SECRET_MISSING)

    return {
        "provider": "stripe",
        "ready": len(reasons) == 0,
        "reasons": reasons,
    }
