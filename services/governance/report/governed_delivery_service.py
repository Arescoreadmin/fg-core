"""governed_delivery_service.py — GOV-DELIVERY-001 canonical delivery validation.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Stateless validation and dataclass definitions for governed delivery.
DB writes and reads live in api/field_assessment.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

ALLOWED_RECIPIENT_TYPES: frozenset[str] = frozenset(
    {
        "portal_membership",
        "portal_invitation",
        "portal_grant",
        "operator_direct",
    }
)

ALLOWED_CHANNELS: frozenset[str] = frozenset(
    {
        "portal_grant",
        "direct_download",
    }
)

ALLOWED_OUTCOMES: frozenset[str] = frozenset(
    {
        "AUTHORIZED",
        "REJECTED",
    }
)


@dataclass(frozen=True)
class DeliveryBinding:
    """Immutable tuple that must match between qualification and delivery."""

    tenant_id: str
    engagement_id: str
    report_id: str
    report_version_id: str
    report_fingerprint: str
    qualification_decision_id: str


def build_idempotency_key(
    tenant_id: str,
    engagement_id: str,
    report_version_id: str,
    recipient_id: str | None,
    channel: str,
) -> str:
    """Deterministic SHA-256 idempotency key for a delivery operation."""
    parts = "|".join(
        [
            tenant_id,
            engagement_id,
            report_version_id,
            recipient_id or "NONE",
            channel,
        ]
    )
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:64]


def validate_recipient_type(recipient_type: str) -> list[str]:
    """Return list of validation errors; empty means valid."""
    if recipient_type not in ALLOWED_RECIPIENT_TYPES:
        return [
            f"unknown recipient_type '{recipient_type}'; "
            f"allowed: {sorted(ALLOWED_RECIPIENT_TYPES)}"
        ]
    return []


def validate_channel(channel: str) -> list[str]:
    """Return list of validation errors; empty means valid."""
    if channel not in ALLOWED_CHANNELS:
        return [
            f"unknown channel '{channel}'; allowed: {sorted(ALLOWED_CHANNELS)}"
        ]
    return []


def check_delivery_binding(
    binding: DeliveryBinding,
    qualification_tenant_id: str,
    qualification_engagement_id: str,
    qualification_report_id: str,
    qualification_report_version_id: str,
    qualification_report_fingerprint: str,
) -> list[str]:
    """Verify the delivery binding matches the qualification decision.

    Returns list of violations; empty means binding is valid.
    """
    errors: list[str] = []
    if binding.tenant_id != qualification_tenant_id:
        errors.append(
            "tenant_id mismatch between delivery request and qualification"
        )
    if binding.engagement_id != qualification_engagement_id:
        errors.append(
            "engagement_id mismatch between delivery request and qualification"
        )
    if binding.report_id != qualification_report_id:
        errors.append(
            "report_id mismatch between delivery request and qualification"
        )
    if binding.report_version_id != qualification_report_version_id:
        errors.append(
            "report_version_id mismatch between delivery request and qualification"
        )
    if (
        qualification_report_fingerprint
        and binding.report_fingerprint != qualification_report_fingerprint
    ):
        errors.append(
            "report_fingerprint mismatch between delivery request and qualification"
        )
    return errors
