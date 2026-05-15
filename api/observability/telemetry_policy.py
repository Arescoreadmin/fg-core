"""Dynamic telemetry policy for FrostGate.

Controls per-tenant suppression, span attribute restriction, and external
OTLP export gating. Policy is loaded from environment variables at first use
and can be reloaded at runtime via reload_policy().

Env vars
--------
FG_OBSERVABILITY_MODE       standard (default) | regulated | strict
FG_DISABLE_EXTERNAL_OTLP   0 (default) | 1  — blocks all external OTLP export
FG_RESTRICT_TRACE_ATTRIBUTES  0 (default) | 1  — limits span attrs to approved set
FG_TELEMETRY_SUPPRESSED_TENANTS  comma-separated tenant IDs to suppress entirely

Mode semantics
--------------
standard   All attributes pass through. External OTLP allowed if endpoint set.
regulated  Restricts span attributes to the pre-approved set. External OTLP
           still allowed (use within a compliant collector boundary). Implied
           by FG_RESTRICT_TRACE_ATTRIBUTES=1.
strict     Regulated mode + external OTLP blocked. Equivalent to regulated +
           FG_DISABLE_EXTERNAL_OTLP=1. For air-gapped / GovCon / FedRAMP.
"""

from __future__ import annotations

import logging
import os
from typing import Literal, Optional

_log = logging.getLogger("frostgate.observability")

ObservabilityMode = Literal["standard", "regulated", "strict"]

# Span attribute keys approved for emission in regulated/strict mode.
# Adding a new key requires explicit security review — put it here or it is
# filtered out when FG_RESTRICT_TRACE_ATTRIBUTES=1 (or regulated/strict mode).
APPROVED_SPAN_ATTRIBUTES: frozenset[str] = frozenset(
    {
        # Request / tenant context
        "tenant.id",
        "frostgate.tenant_id",
        "frostgate.request_id",
        # Document pipeline
        "doc.type",
        "export.format",
        # Provider routing
        "provider.id",
        # Retrieval
        "retrieval.mode",
        # Provenance / policy
        "policy.version",
        # HTTP semantic conventions (OTelTracingMiddleware)
        "http.method",
        "http.route",
        "http.target",
        "http.status_code",
        "http.scheme",
        "http.url",
        "http.host",
        "http.flavor",
        # Network
        "net.peer.ip",
        # OTel error conventions — exception.type safe; message/stacktrace excluded
        # in restricted mode to prevent error-message leakage into trace backends.
        "exception.type",
    }
)


class TelemetryPolicy:
    """Immutable (post-init) telemetry policy object.

    Constructed from env vars; use get_policy() for the module-level singleton.
    """

    def __init__(self) -> None:
        self.mode: ObservabilityMode = self._parse_mode()
        self.disable_external_otlp: bool = (
            self._env_bool("FG_DISABLE_EXTERNAL_OTLP") or self.mode == "strict"
        )
        self.restrict_trace_attributes: bool = self._env_bool(
            "FG_RESTRICT_TRACE_ATTRIBUTES"
        ) or self.mode in ("regulated", "strict")
        self.suppressed_tenants: frozenset[str] = self._parse_suppressed_tenants()
        _log.debug("telemetry_policy_loaded %r", self)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def allows_external_otlp(self) -> bool:
        """Return False when exporting to external OTLP endpoints is prohibited."""
        return not self.disable_external_otlp

    def is_tenant_suppressed(self, tenant_id: str) -> bool:
        """Return True when this tenant's telemetry must be fully suppressed."""
        return bool(tenant_id) and tenant_id in self.suppressed_tenants

    def filter_span_attributes(self, attributes: dict[str, str]) -> dict[str, str]:
        """Return a filtered copy of span attributes respecting current policy.

        Standard mode: all non-empty attributes pass through.
        Regulated/strict mode: only keys in APPROVED_SPAN_ATTRIBUTES are kept.
        """
        if not self.restrict_trace_attributes:
            return {k: v for k, v in attributes.items() if v}
        return {
            k: v for k, v in attributes.items() if k in APPROVED_SPAN_ATTRIBUTES and v
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _env_bool(key: str) -> bool:
        return os.getenv(key, "0").strip().lower() in {"1", "true", "yes"}

    @staticmethod
    def _parse_mode() -> ObservabilityMode:
        raw = os.getenv("FG_OBSERVABILITY_MODE", "standard").strip().lower()
        if raw not in ("standard", "regulated", "strict"):
            _log.warning(
                "Unknown FG_OBSERVABILITY_MODE=%r — falling back to 'standard'", raw
            )
            return "standard"
        return raw  # type: ignore[return-value]

    @staticmethod
    def _parse_suppressed_tenants() -> frozenset[str]:
        raw = os.getenv("FG_TELEMETRY_SUPPRESSED_TENANTS", "").strip()
        if not raw:
            return frozenset()
        return frozenset(t.strip() for t in raw.split(",") if t.strip())

    def __repr__(self) -> str:
        return (
            f"TelemetryPolicy(mode={self.mode!r}, "
            f"disable_external_otlp={self.disable_external_otlp}, "
            f"restrict_trace_attributes={self.restrict_trace_attributes}, "
            f"suppressed_tenants={len(self.suppressed_tenants)})"
        )


_POLICY: Optional[TelemetryPolicy] = None


def get_policy() -> TelemetryPolicy:
    """Return the active TelemetryPolicy, constructing it on first call."""
    global _POLICY
    if _POLICY is None:
        _POLICY = TelemetryPolicy()
    return _POLICY


def reload_policy() -> TelemetryPolicy:
    """Rebuild the policy from current env vars.

    Used in tests and for operator-triggered runtime reloads.
    """
    global _POLICY
    _POLICY = TelemetryPolicy()
    _log.info("telemetry_policy_reloaded %r", _POLICY)
    return _POLICY
