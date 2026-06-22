"""Tenant isolation enforcement.

RULE-SEC-004: tenant_id never in request bodies
RULE-SEC-008: tenant_id stored only as sha256 hash
RULE-SEC-010: TenantLock held for entire scan duration

TenantLock validates every Graph response's tenant context against the
authorized tenant_id.  Any mismatch triggers TenantIsolationError and
scan abort.
"""

from __future__ import annotations

import hashlib
import logging
from types import TracebackType
from typing import Any

from services.connectors.msgraph.manifest import TenantIsolationError

log = logging.getLogger("frostgate.connectors.msgraph.tenant")

_TENANT_CONTEXT_KEYS = ("@odata.context",)


def hash_tenant_id(tenant_id: str) -> str:
    """sha256(tenant_id) — safe for storage."""
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()


class TenantLock:
    """Context manager that enforces tenant isolation for the scan duration.

    Usage::

        with TenantLock(tenant_id=tenant_id) as lock:
            lock.validate_response(response_json)
    """

    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._tenant_id_hash = hash_tenant_id(tenant_id)
        self._active = False

    def __enter__(self) -> "TenantLock":
        self._active = True
        log.info("tenant_lock: acquired for tenant_hash=%s", self._tenant_id_hash)
        return self

    @property
    def tenant_id_hash(self) -> str:
        return self._tenant_id_hash

    def validate_response(self, response: dict[str, Any]) -> None:
        """Validate that a Graph response belongs to the authorized tenant.

        Graph responses embed tenant context in @odata.context URLs as
        "https://graph.microsoft.com/v1.0/$metadata#...".  For responses
        that include a tenant context URL, we verify it contains the
        authorized tenant_id.  Responses without a context key pass through
        (Graph does not always include odata.context on all endpoints).
        """
        if not self._active:
            raise RuntimeError("TenantLock.validate_response called outside context")

        odata_ctx: str = response.get("@odata.context", "")
        if not odata_ctx:
            return  # no context key — cannot validate, pass through

        # The context URL for tenant-bound calls includes the tenant_id
        # e.g. "https://graph.microsoft.com/v1.0/tenants/{tenant_id}/..."
        # We check for the tenant_id in the URL only when explicitly present.
        if self._tenant_id in odata_ctx:
            return  # explicitly present and matches

        # Some endpoints return a generic URL without tenant_id in context —
        # these are cross-tenant-safe and pass through.
        # We only reject when a DIFFERENT tenant_id appears in the context.
        # Check for any UUID-like segment that differs from authorized tenant.
        import re

        uuid_re = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
        )
        found_uuids = uuid_re.findall(odata_ctx)
        canonical_tid = self._tenant_id.lower().replace("-", "")
        for uid in found_uuids:
            if uid.replace("-", "").lower() != canonical_tid:
                raise TenantIsolationError(
                    f"Graph response context contains unexpected tenant identifier. "
                    f"Expected tenant_hash={self._tenant_id_hash}. Scan aborted."
                )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._active = False
        log.info("tenant_lock: released for tenant_hash=%s", self._tenant_id_hash)
