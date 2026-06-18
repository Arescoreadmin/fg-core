"""services/billing/provider.py — Abstract billing provider interface (P1.5).

Defines the provider contract that all concrete implementations must satisfy.
NullBillingProvider is the no-op implementation used when no provider is configured.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BillingProvider(ABC):
    """Abstract interface for billing provider implementations."""

    @abstractmethod
    def create_customer(
        self, tenant_id: str, email: str | None, metadata: dict
    ) -> dict:
        """Create a customer record in the provider."""

    @abstractmethod
    def update_customer(
        self, provider_customer_id: str, email: str | None, metadata: dict
    ) -> dict:
        """Update an existing customer record."""

    @abstractmethod
    def create_subscription(
        self,
        provider_customer_id: str,
        provider_price_id: str,
        metadata: dict,
    ) -> dict:
        """Create a subscription in the provider."""

    @abstractmethod
    def update_subscription(
        self, provider_subscription_id: str, metadata: dict
    ) -> dict:
        """Update subscription metadata in the provider."""

    @abstractmethod
    def cancel_subscription(self, provider_subscription_id: str) -> dict:
        """Cancel a subscription in the provider."""

    @abstractmethod
    def report_usage(
        self,
        provider_subscription_id: str,
        meter_code: str,
        quantity: str,
        idempotency_key: str,
    ) -> dict:
        """Report a usage event to the provider."""

    @abstractmethod
    def retrieve_invoice(self, provider_subscription_id: str) -> dict:
        """Retrieve the latest invoice for a subscription."""

    @abstractmethod
    def parse_webhook(self, raw_body: bytes, sig_header: str | None) -> dict:
        """Parse and return a provider webhook event dict."""

    @abstractmethod
    def verify_webhook_signature(self, raw_body: bytes, sig_header: str | None) -> bool:
        """Return True if the webhook signature is valid."""


class NullBillingProvider(BillingProvider):
    """No-op provider used when no billing provider is configured.

    All write operations return ok=True. Signature verification always returns False
    since there is no real provider to verify against.
    """

    def create_customer(
        self, tenant_id: str, email: str | None, metadata: dict
    ) -> dict:
        return {"ok": True}

    def update_customer(
        self, provider_customer_id: str, email: str | None, metadata: dict
    ) -> dict:
        return {"ok": True}

    def create_subscription(
        self,
        provider_customer_id: str,
        provider_price_id: str,
        metadata: dict,
    ) -> dict:
        return {"ok": True}

    def update_subscription(
        self, provider_subscription_id: str, metadata: dict
    ) -> dict:
        return {"ok": True}

    def cancel_subscription(self, provider_subscription_id: str) -> dict:
        return {"ok": True}

    def report_usage(
        self,
        provider_subscription_id: str,
        meter_code: str,
        quantity: str,
        idempotency_key: str,
    ) -> dict:
        return {"ok": True}

    def retrieve_invoice(self, provider_subscription_id: str) -> dict:
        return {"ok": True}

    def parse_webhook(self, raw_body: bytes, sig_header: str | None) -> dict:
        return {}

    def verify_webhook_signature(self, raw_body: bytes, sig_header: str | None) -> bool:
        return False
