from __future__ import annotations

from services.plane_registry.models import EvidenceDef, PlaneDef


PLANE_REGISTRY: list[PlaneDef] = [
    PlaneDef(
        plane_id="compliance_cp",
        route_prefixes=["/compliance-cp"],
        mount_flag="FG_COMPLIANCE_CP_ENABLED",
        required_make_targets=["compliance-cp-spot"],
        evidence=[],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
    PlaneDef(
        plane_id="enterprise_controls",
        route_prefixes=["/enterprise-controls"],
        mount_flag="FG_ENTERPRISE_CONTROLS_ENABLED",
        required_make_targets=["enterprise-controls-spot"],
        evidence=[],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
    PlaneDef(
        plane_id="breakglass",
        route_prefixes=["/exceptions", "/breakglass"],
        mount_flag="FG_BREAKGLASS_ENABLED",
        required_make_targets=["breakglass-spot"],
        evidence=[],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
    PlaneDef(
        plane_id="evidence_anchor",
        route_prefixes=["/evidence/anchors"],
        mount_flag="FG_EVIDENCE_ANCHOR_ENABLED",
        required_make_targets=["evidence-anchor-spot"],
        evidence=[
            EvidenceDef(
                schema_path="contracts/artifacts/anchor_receipt.schema.json",
                generator_script="scripts/generate_ai_plane_evidence.py",
            )
        ],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
    PlaneDef(
        plane_id="federation",
        route_prefixes=["/auth/federation"],
        mount_flag="FG_FEDERATION_ENABLED",
        required_make_targets=["federation-spot"],
        evidence=[],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
    PlaneDef(
        plane_id="ai_plane",
        route_prefixes=["/ai", "/ai-plane"],
        mount_flag="FG_AI_PLANE_ENABLED",
        required_make_targets=["ai-plane-spot", "ai-plane-full"],
        evidence=[
            EvidenceDef(
                schema_path="contracts/artifacts/ai_plane_evidence.schema.json",
                generator_script="scripts/generate_ai_plane_evidence.py",
            )
        ],
        required_route_invariants=["auth", "tenant_bound", "scoped"],
    ),
]


def list_planes() -> list[dict[str, object]]:
    return [p.model_dump(mode="python") for p in PLANE_REGISTRY]
