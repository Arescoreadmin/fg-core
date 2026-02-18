from __future__ import annotations

from services.compliance_registry import ComplianceRegistry, FindingCreateItem
from services.compliance_cp_extension.models import ComplianceCPEvidenceIngestRequest


class ComplianceControlPlaneService:
    def __init__(self) -> None:
        self.registry = ComplianceRegistry()

    def summary(self, tenant_id: str) -> dict[str, object]:
        try:
            snap = self.registry.snapshot(tenant_id)
        except Exception:
            snap = {}
        return {
            "tenant_id": tenant_id,
            "coverage": snap.get("coverage", {}),
            "finding_counts": snap.get("findings", {}),
            "decision": snap.get("decision", "unknown"),
        }

    def portfolio(self, tenant_id: str) -> dict[str, object]:
        try:
            snap = self.registry.snapshot(tenant_id)
        except Exception:
            snap = {}
        return {
            "tenant_id": tenant_id,
            "waiver_expiring": snap.get("waiver_expiring", []),
            "stale_sources": snap.get("stale_sources", []),
            "unknown_critical_count": snap.get("unknown_critical_count", 0),
        }

    def controls(self, tenant_id: str) -> list[dict[str, object]]:
        try:
            diff = self.registry.requirements_diff(tenant_id, since="1970-01-01T00:00:00Z")
        except Exception:
            diff = []
        return [
            {
                "req_id": row.get("req_id"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "status": row.get("status"),
                "source": row.get("source"),
            }
            for row in diff
        ]

    def ingest_evidence(
        self, tenant_id: str, payload: ComplianceCPEvidenceIngestRequest
    ) -> dict[str, object]:
        finding = FindingCreateItem(
            finding_id=payload.finding_id,
            req_ids=payload.req_ids,
            title=payload.title,
            details=payload.details,
            severity=payload.severity,
            status="open",
            waiver=None,
            detected_at_utc=payload.detected_at_utc,
            evidence_refs=payload.control_refs or [],
        )
        created = self.registry.add_findings(tenant_id, [finding])
        return {"created": created, "count": len(created)}
