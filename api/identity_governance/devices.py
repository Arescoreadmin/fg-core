"""api/identity_governance/devices.py — Device trust registry.

Tracks registered devices, their trust state, and a deterministic risk
score derived from the trust state. Registry is in-memory in Phase 1 —
persistence is future work (see migration ``0148_identity_governance.sql``).

Security notes
--------------
- The registry never stores raw fingerprints. Callers must pass a
  ``fingerprint_hash`` (SHA-256 or similar) — the caller-supplied hash is
  stored verbatim.
- Cross-tenant access is denied by construction: every query verifies
  ``tenant_id`` on the stored record.
"""

from __future__ import annotations

import secrets
import threading
from datetime import datetime, timezone
from typing import Optional

from api.identity_governance.models import DeviceRecord, DeviceTrustState

# Deterministic risk score per trust state.
_STATE_RISK_SCORE: dict[DeviceTrustState, float] = {
    DeviceTrustState.TRUSTED: 0.0,
    DeviceTrustState.KNOWN: 0.1,
    DeviceTrustState.UNKNOWN: 0.4,
    DeviceTrustState.SUSPICIOUS: 0.7,
    DeviceTrustState.COMPROMISED: 0.95,
    DeviceTrustState.REVOKED: 1.0,
}


class DeviceTrustRegistry:
    """In-memory, thread-safe device trust registry."""

    def __init__(self) -> None:
        # (tenant_id, device_id) -> DeviceRecord
        self._devices: dict[tuple[str, str], DeviceRecord] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Registration + updates
    # ------------------------------------------------------------------

    def register_device(
        self,
        subject: str,
        tenant_id: str,
        fingerprint_hash: str,
        user_agent_hash: str,
        ip_metadata: str,
    ) -> DeviceRecord:
        """Register a new device in the KNOWN trust state.

        Raises:
            ValueError: when required fields are empty.
        """
        self._validate_required(
            subject=subject, tenant_id=tenant_id, fingerprint_hash=fingerprint_hash
        )
        now = datetime.now(tz=timezone.utc)
        device_id = secrets.token_hex(16)
        record = DeviceRecord(
            device_id=device_id,
            tenant_id=tenant_id,
            subject=subject,
            fingerprint_hash=fingerprint_hash,
            user_agent_hash=user_agent_hash,
            ip_metadata=ip_metadata,
            trust_state=DeviceTrustState.KNOWN,
            risk_score=self._compute_risk_score(DeviceTrustState.KNOWN),
            registered_at=now,
            updated_at=now,
            last_reason="device.registered",
        )
        with self._lock:
            self._devices[(tenant_id, device_id)] = record
        return record

    def update_trust_state(
        self,
        device_id: str,
        tenant_id: str,
        new_state: DeviceTrustState,
        reason: str,
        actor: str,
    ) -> DeviceRecord:
        """Transition a device to a new trust state.

        Raises:
            ValueError: when the device does not exist for the tenant, or
                when ``reason``/``actor`` are empty.
        """
        if not reason:
            raise ValueError("reason is required to change device trust")
        if not actor:
            raise ValueError("actor is required to change device trust")
        with self._lock:
            record = self._devices.get((tenant_id, device_id))
            if record is None:
                raise ValueError(
                    f"device {device_id!r} not registered for tenant {tenant_id!r}"
                )
            updated = DeviceRecord(
                device_id=record.device_id,
                tenant_id=record.tenant_id,
                subject=record.subject,
                fingerprint_hash=record.fingerprint_hash,
                user_agent_hash=record.user_agent_hash,
                ip_metadata=record.ip_metadata,
                trust_state=new_state,
                risk_score=self._compute_risk_score(new_state),
                registered_at=record.registered_at,
                updated_at=datetime.now(tz=timezone.utc),
                last_reason=f"{reason}|actor={actor}",
            )
            self._devices[(tenant_id, device_id)] = updated
            return updated

    def revoke_device(
        self,
        device_id: str,
        tenant_id: str,
        reason: str,
        actor: str,
    ) -> DeviceRecord:
        """Force the device into the REVOKED trust state."""
        return self.update_trust_state(
            device_id, tenant_id, DeviceTrustState.REVOKED, reason, actor
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_device(self, device_id: str, tenant_id: str) -> Optional[DeviceRecord]:
        """Return the device record if it exists for the tenant, else None.

        Cross-tenant lookups return None even if the device_id exists
        under a different tenant — this is the tenant isolation guarantee.
        """
        with self._lock:
            return self._devices.get((tenant_id, device_id))

    def list_devices_for_subject(
        self, subject: str, tenant_id: str
    ) -> list[DeviceRecord]:
        """Return devices registered for the subject in this tenant.

        Results are deterministically ordered by ``device_id``.
        """
        with self._lock:
            matches = [
                record
                for (tid, _did), record in self._devices.items()
                if tid == tenant_id and record.subject == subject
            ]
        return sorted(matches, key=lambda r: r.device_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_risk_score(self, state: DeviceTrustState) -> float:
        """Deterministic risk score per trust state."""
        return _STATE_RISK_SCORE[state]

    def _validate_required(
        self, *, subject: str, tenant_id: str, fingerprint_hash: str
    ) -> None:
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not fingerprint_hash:
            raise ValueError("fingerprint_hash is required (hash before storing)")
