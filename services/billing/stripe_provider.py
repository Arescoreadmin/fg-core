"""services/billing/stripe_provider.py — Stripe billing provider implementation (P1.5).

Reads STRIPE_API_KEY and STRIPE_WEBHOOK_SECRET from environment.
Stripe is imported lazily so missing package does not break startup.
Never logs key values.
"""

from __future__ import annotations

import logging
import os

from services.billing.provider import BillingProvider

log = logging.getLogger("frostgate.billing.stripe")


class ProviderNotConfiguredError(RuntimeError):
    """Raised when a required provider credential or package is unavailable."""


def _get_api_key() -> str:
    return (os.environ.get("STRIPE_API_KEY") or "").strip()


def _get_webhook_secret() -> str:
    return (os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()


def _require_stripe():
    """Import stripe lazily; raise ProviderNotConfiguredError if not installed."""
    try:
        import stripe  # noqa: PLC0415

        return stripe
    except ImportError as exc:
        raise ProviderNotConfiguredError("stripe package is not installed") from exc


def _require_api_key() -> str:
    key = _get_api_key()
    if not key:
        raise ProviderNotConfiguredError("STRIPE_API_KEY is not configured")
    return key


class StripeProvider(BillingProvider):
    """Stripe-backed billing provider.

    Each method raises ProviderNotConfiguredError when STRIPE_API_KEY is absent
    or the stripe package is unavailable, so callers can treat that as a 503.
    """

    def create_customer(
        self, tenant_id: str, email: str | None, metadata: dict
    ) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        payload: dict = {"metadata": {"tenant_id": tenant_id, **metadata}}
        if email:
            payload["email"] = email
        customer = stripe.Customer.create(api_key=api_key, **payload)
        return dict(customer)

    def update_customer(
        self, provider_customer_id: str, email: str | None, metadata: dict
    ) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        payload: dict = {"metadata": metadata}
        if email is not None:
            payload["email"] = email
        customer = stripe.Customer.modify(
            provider_customer_id, api_key=api_key, **payload
        )
        return dict(customer)

    def create_subscription(
        self,
        provider_customer_id: str,
        provider_price_id: str,
        metadata: dict,
    ) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        sub = stripe.Subscription.create(
            customer=provider_customer_id,
            items=[{"price": provider_price_id}],
            metadata=metadata,
            api_key=api_key,
        )
        return dict(sub)

    def update_subscription(
        self, provider_subscription_id: str, metadata: dict
    ) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        sub = stripe.Subscription.modify(
            provider_subscription_id,
            metadata=metadata,
            api_key=api_key,
        )
        return dict(sub)

    def cancel_subscription(self, provider_subscription_id: str) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        sub = stripe.Subscription.cancel(
            provider_subscription_id,
            api_key=api_key,
        )
        return dict(sub)

    def report_usage(
        self,
        provider_subscription_id: str,
        meter_code: str,
        quantity: str,
        idempotency_key: str,
    ) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        record = stripe.SubscriptionItem.create_usage_record(
            provider_subscription_id,
            quantity=int(quantity),
            idempotency_key=idempotency_key,
            api_key=api_key,
        )
        return dict(record)

    def retrieve_invoice(self, provider_subscription_id: str) -> dict:
        stripe = _require_stripe()
        api_key = _require_api_key()
        invoices = stripe.Invoice.list(
            subscription=provider_subscription_id,
            limit=1,
            api_key=api_key,
        )
        data = list(invoices.auto_paging_iter())
        return dict(data[0]) if data else {}

    def parse_webhook(self, raw_body: bytes, sig_header: str | None) -> dict:
        stripe = _require_stripe()
        secret = _get_webhook_secret()
        if not secret:
            raise ProviderNotConfiguredError("STRIPE_WEBHOOK_SECRET is not configured")
        if not sig_header:
            return {}
        try:
            evt = stripe.Webhook.construct_event(
                payload=raw_body,
                sig_header=sig_header,
                secret=secret,
            )
            return dict(evt)
        except Exception as exc:
            log.warning("stripe.parse_webhook_failed error=%s", type(exc).__name__)
            return {}

    def verify_webhook_signature(self, raw_body: bytes, sig_header: str | None) -> bool:
        stripe = _require_stripe()
        secret = _get_webhook_secret()
        if not secret:
            raise ProviderNotConfiguredError("STRIPE_WEBHOOK_SECRET is not configured")
        if not sig_header:
            return False
        try:
            stripe.Webhook.construct_event(
                payload=raw_body,
                sig_header=sig_header,
                secret=secret,
            )
            return True
        except stripe.error.SignatureVerificationError:
            return False
        except Exception as exc:
            log.warning("stripe.verify_signature_error error=%s", type(exc).__name__)
            return False
