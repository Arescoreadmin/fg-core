"""MS Graph connector credential pre-flight validation.

Validates that an azure_tenant_id is structurally valid and reachable via
Azure AD before initiating a device-code flow scan. Catches the most common
failure mode (bad or non-existent tenant) synchronously at scan launch time
rather than hours into a background job.

Security invariant: no credentials or tokens are acquired here — this is a
read-only probe against the public OIDC discovery endpoint.
"""

from __future__ import annotations

import logging
import re
import uuid as _uuid_module

import httpx

log = logging.getLogger("frostgate.connectors.msgraph.preflight")

_OIDC_DISCOVERY_TEMPLATE = (
    "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_PREFLIGHT_TIMEOUT_S = 8


class MsgraphPreflightError(Exception):
    """Base class for pre-flight failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class MsgraphTenantFormatError(MsgraphPreflightError):
    """azure_tenant_id is not a valid UUID."""


class MsgraphTenantNotFoundError(MsgraphPreflightError):
    """Azure AD does not recognize the tenant."""


def validate_msgraph_tenant_preflight(azure_tenant_id: str) -> None:
    """Validate azure_tenant_id before device-code flow initiation.

    Raises:
        MsgraphTenantFormatError: tenant_id is not a valid UUID format.
        MsgraphTenantNotFoundError: Azure AD returns 400/404 for this tenant.
        MsgraphPreflightError: network or unexpected error during probe.
    """
    # --- 1. UUID format check ---
    if not _UUID_RE.match(azure_tenant_id.strip()):
        raise MsgraphTenantFormatError(
            code="CONNECTOR_INVALID_TENANT_FORMAT",
            message=(
                f"azure_tenant_id '{azure_tenant_id}' is not a valid UUID. "
                "Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ),
        )

    # Normalise to canonical lower-case dashed form
    try:
        canonical = str(_uuid_module.UUID(azure_tenant_id))
    except ValueError:
        raise MsgraphTenantFormatError(
            code="CONNECTOR_INVALID_TENANT_FORMAT",
            message=f"azure_tenant_id '{azure_tenant_id}' failed UUID normalisation.",
        )

    # --- 2. OIDC discovery probe ---
    url = _OIDC_DISCOVERY_TEMPLATE.format(tenant_id=canonical)
    log.info("msgraph preflight: probing OIDC discovery for tenant %s", canonical)
    try:
        resp = httpx.get(url, timeout=_PREFLIGHT_TIMEOUT_S, follow_redirects=False)
    except httpx.TimeoutException as exc:
        raise MsgraphPreflightError(
            code="CONNECTOR_PREFLIGHT_TIMEOUT",
            message=(
                f"Pre-flight probe timed out after {_PREFLIGHT_TIMEOUT_S}s contacting "
                "Azure AD. Check network connectivity and try again."
            ),
        ) from exc
    except Exception as exc:
        raise MsgraphPreflightError(
            code="CONNECTOR_PREFLIGHT_FAILED",
            message=f"Pre-flight probe failed: {exc}",
        ) from exc

    if resp.status_code == 200:
        log.info("msgraph preflight: tenant %s verified (OIDC 200)", canonical)
        return

    if resp.status_code in (400, 404):
        raise MsgraphTenantNotFoundError(
            code="CONNECTOR_TENANT_NOT_FOUND",
            message=(
                f"Azure AD does not recognise tenant '{canonical}'. "
                "Verify the azure_tenant_id matches the customer's Entra ID directory."
            ),
        )

    # Any other non-200 is treated as a transient external failure.
    raise MsgraphPreflightError(
        code="CONNECTOR_PREFLIGHT_FAILED",
        message=(
            f"Pre-flight probe returned unexpected status {resp.status_code} from Azure AD. "
            "Try again or contact support if the issue persists."
        ),
    )
