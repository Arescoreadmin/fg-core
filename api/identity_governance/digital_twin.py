"""api/identity_governance/digital_twin.py — Identity Digital Twin exporter.

Emits a deterministic, tenant-scoped snapshot of everything the governance
plane knows about a subject. No secrets, no raw device fingerprints. All
fields are deterministically ordered so the ``fingerprint`` is stable
across identical inputs.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, Optional

from api.identity_governance.models import (
    DeviceRecord,
    DigitalTwinSnapshot,
    IdentityLifecycleState,
    IdentityTimelineEvent,
    RiskScore,
)

_SECRET_KEYS = frozenset(
    {
        "token",
        "secret",
        "password",
        "key",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "authorization",
        "cookie",
        "fingerprint",
    }
)


def _safe_kv(items: dict[str, object]) -> tuple[tuple[str, str], ...]:
    """Deterministic ordering + strip secret-shaped keys."""
    out: list[tuple[str, str]] = []
    for k in sorted(items.keys()):
        if k.lower() in _SECRET_KEYS:
            continue
        out.append((k, str(items[k])))
    return tuple(out)


class IdentityDigitalTwinExporter:
    """Deterministic digital-twin snapshot exporter."""

    def export(
        self,
        subject: str,
        tenant_id: str,
        lifecycle_state: IdentityLifecycleState,
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        capabilities: Optional[Iterable[str]] = None,
        devices: Optional[Iterable[DeviceRecord]] = None,
        identity_summary: Optional[dict[str, object]] = None,
        active_sessions_count: int = 0,
        risk_score: Optional[RiskScore] = None,
        active_break_glass_count: int = 0,
        recent_timeline_events: Optional[Iterable[IdentityTimelineEvent]] = None,
        assessments_count: int = 0,
        evidence_count: int = 0,
    ) -> DigitalTwinSnapshot:
        """Build a deterministic digital-twin snapshot."""
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")

        # Sort collections deterministically.
        roles_t = tuple(sorted(set(roles or [])))
        perms_t = tuple(sorted(set(permissions or [])))
        caps_t = tuple(sorted(set(capabilities or [])))

        # Filter devices to tenant + drop raw fingerprint from serialization.
        device_records_t: tuple[tuple[tuple[str, str], ...], ...] = tuple(
            _safe_kv(
                {
                    "device_id": d.device_id,
                    "trust_state": d.trust_state.value,
                    "risk_score": f"{d.risk_score:.4f}",
                    "user_agent_hash": d.user_agent_hash,
                    "registered_at": d.registered_at.isoformat(),
                    "updated_at": d.updated_at.isoformat(),
                }
            )
            for d in sorted(
                (dev for dev in (devices or []) if dev.tenant_id == tenant_id),
                key=lambda x: x.device_id,
            )
        )

        # Timeline: filter to tenant, cap at 20 most recent.
        timeline_filtered = [
            e for e in (recent_timeline_events or []) if e.tenant_id == tenant_id
        ]
        timeline_t = tuple(timeline_filtered[-20:])

        identity_summary_t = _safe_kv(identity_summary or {})

        snapshot = DigitalTwinSnapshot(
            subject=subject,
            tenant_id=tenant_id,
            generated_at=datetime.now(tz=timezone.utc),
            identity_summary=identity_summary_t,
            lifecycle_state=lifecycle_state,
            roles=roles_t,
            permissions=perms_t,
            capabilities=caps_t,
            device_records=device_records_t,
            active_sessions_count=active_sessions_count,
            risk_score=risk_score,
            active_break_glass_count=active_break_glass_count,
            recent_timeline_events=timeline_t,
            assessments_count=assessments_count,
            evidence_count=evidence_count,
            fingerprint="",
        )
        fingerprint = self._fingerprint(snapshot)
        return DigitalTwinSnapshot(
            subject=snapshot.subject,
            tenant_id=snapshot.tenant_id,
            generated_at=snapshot.generated_at,
            identity_summary=snapshot.identity_summary,
            lifecycle_state=snapshot.lifecycle_state,
            roles=snapshot.roles,
            permissions=snapshot.permissions,
            capabilities=snapshot.capabilities,
            device_records=snapshot.device_records,
            active_sessions_count=snapshot.active_sessions_count,
            risk_score=snapshot.risk_score,
            active_break_glass_count=snapshot.active_break_glass_count,
            recent_timeline_events=snapshot.recent_timeline_events,
            assessments_count=snapshot.assessments_count,
            evidence_count=snapshot.evidence_count,
            fingerprint=fingerprint,
        )

    def _fingerprint(self, snapshot: DigitalTwinSnapshot) -> str:
        """Deterministic SHA-256 fingerprint over structural content."""
        h = hashlib.sha256()
        h.update(snapshot.subject.encode())
        h.update(b"|")
        h.update(snapshot.tenant_id.encode())
        h.update(b"|")
        h.update(snapshot.lifecycle_state.value.encode())
        h.update(b"|")
        for k, v in snapshot.identity_summary:
            h.update(k.encode())
            h.update(b"=")
            h.update(v.encode())
            h.update(b";")
        h.update(b"|roles:")
        for r in snapshot.roles:
            h.update(r.encode())
            h.update(b",")
        h.update(b"|perms:")
        for p in snapshot.permissions:
            h.update(p.encode())
            h.update(b",")
        h.update(b"|caps:")
        for c in snapshot.capabilities:
            h.update(c.encode())
            h.update(b",")
        h.update(b"|devices:")
        for dev in snapshot.device_records:
            for k, v in dev:
                h.update(k.encode())
                h.update(b"=")
                h.update(v.encode())
                h.update(b";")
            h.update(b"|")
        h.update(b"|sessions:")
        h.update(str(snapshot.active_sessions_count).encode())
        h.update(b"|bg:")
        h.update(str(snapshot.active_break_glass_count).encode())
        h.update(b"|assessments:")
        h.update(str(snapshot.assessments_count).encode())
        h.update(b"|evidence:")
        h.update(str(snapshot.evidence_count).encode())
        if snapshot.risk_score is not None:
            h.update(b"|risk:")
            h.update(f"{snapshot.risk_score.score:.6f}".encode())
            h.update(b":")
            h.update(snapshot.risk_score.band.value.encode())
        for evt in snapshot.recent_timeline_events:
            h.update(b"|evt:")
            h.update(evt.event_hash.encode())
        return h.hexdigest()
