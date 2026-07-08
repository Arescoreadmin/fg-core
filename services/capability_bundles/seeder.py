"""services/capability_bundles/seeder.py — Seed canonical bundle catalog (P1.2).

Call seed_bundle_catalog(db) at application startup (or via admin endpoint) to
ensure the policy_bundles, capabilities, and policy_bundle_capabilities tables
contain the authoritative catalog.  Idempotent — safe to call repeatedly.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from api.db_models import (
    Capability,
    CapabilityDependency,
    CapabilityMeterMapping,
    PolicyBundle,
    PolicyBundleCapability,
)

log = logging.getLogger("frostgate.capability_bundles.seeder")

# ---------------------------------------------------------------------------
# Canonical bundle catalog
# ---------------------------------------------------------------------------

BUNDLE_CATALOG: dict[str, dict] = {
    "portal_only": {
        "name": "Portal Only",
        "description": "Basic portal access with API connectivity.",
        "capabilities": ["portal.access", "api.access"],
    },
    "portal_remediation": {
        "name": "Portal + Remediation",
        "description": "Portal access with remediation workflow capabilities.",
        "capabilities": ["portal.access", "portal.remediation", "api.access"],
    },
    "portal_ai": {
        "name": "Portal + AI",
        "description": "Portal access with AI workspace and chat.",
        "capabilities": [
            "portal.access",
            "portal.ai",
            "ai.workspace",
            "ai.chat",
            "api.access",
        ],
    },
    "portal_ai_rag": {
        "name": "Portal + AI + RAG",
        "description": "Portal access with AI workspace, chat, RAG, and document ingestion.",
        "capabilities": [
            "portal.access",
            "portal.ai",
            "portal.rag",
            "ai.workspace",
            "ai.chat",
            "ai.rag",
            "ai.document_ingestion",
            "api.access",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "description": "Full enterprise capability set.",
        "capabilities": [
            "portal.access",
            "portal.remediation",
            "portal.ai",
            "ai.workspace",
            "ai.chat",
            "ai.governance",
            "identity.sso",
            "reports.executive",
            "reports.regulatory",
            "api.access",
            "audit.view",
            "audit.export",
            "tenant.multi_region",
        ],
    },
    "government": {
        "name": "Government",
        "description": "Government-grade bundle with FedRAMP/CJIS capabilities.",
        "capabilities": [
            "portal.access",
            "portal.remediation",
            "identity.sso",
            "identity.scim",
            "reports.executive",
            "reports.regulatory",
            "government.fedramp",
            "government.cjis",
            "api.access",
        ],
    },
    "msp": {
        "name": "MSP",
        "description": "Managed Service Provider multi-tenant and white-label bundle.",
        "capabilities": [
            "portal.access",
            "portal.remediation",
            "msp.multi_tenant",
            "msp.white_label",
            "identity.sso",
            "reports.executive",
            "api.access",
        ],
    },
}

# ---------------------------------------------------------------------------
# Capability metadata
# Fields: name, category, billing_category, launch_stage, visibility
#   launch_stage: 'alpha'|'beta'|'ga'|'deprecated'
#   visibility:   'public'|'internal'|'hidden'
# ---------------------------------------------------------------------------

_CAP_META: dict[str, dict] = {
    # portal.*
    "portal.access": {
        "name": "Portal Access",
        "category": "portal",
        "billing_category": "portal",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "portal.remediation": {
        "name": "Portal Remediation",
        "category": "portal",
        "billing_category": "portal",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "portal.ai": {
        "name": "Portal AI",
        "category": "portal",
        "billing_category": "ai",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "portal.rag": {
        "name": "Portal RAG",
        "category": "portal",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    # ai.*
    "ai.workspace": {
        "name": "AI Workspace",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "ai.chat": {
        "name": "AI Chat",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "ai.rag": {
        "name": "AI RAG",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "ai.document_ingestion": {
        "name": "AI Document Ingestion",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "ai.agent_builder": {
        "name": "AI Agent Builder",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    "ai.multi_agent": {
        "name": "AI Multi-Agent",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    "ai.private_models": {
        "name": "AI Private Models",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "hidden",
    },
    "ai.fine_tuning": {
        "name": "AI Fine Tuning",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "hidden",
    },
    "ai.governance": {
        "name": "AI Governance",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    "ai.compliance_assistant": {
        "name": "AI Compliance Assistant",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    "ai.executive_advisor": {
        "name": "AI Executive Advisor",
        "category": "ai",
        "billing_category": "ai",
        "launch_stage": "beta",
        "visibility": "public",
    },
    # api.*
    "api.access": {
        "name": "API Access",
        "category": "api",
        "billing_category": "api",
        "launch_stage": "ga",
        "visibility": "public",
    },
    # identity.*
    "identity.sso": {
        "name": "Identity SSO",
        "category": "identity",
        "billing_category": "identity",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "identity.scim": {
        "name": "Identity SCIM",
        "category": "identity",
        "billing_category": "identity",
        "launch_stage": "ga",
        "visibility": "public",
    },
    # reports.*
    "reports.executive": {
        "name": "Executive Reports",
        "category": "reports",
        "billing_category": "reports",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "reports.regulatory": {
        "name": "Regulatory Reports",
        "category": "reports",
        "billing_category": "reports",
        "launch_stage": "ga",
        "visibility": "public",
    },
    # tenant.*
    "tenant.multi_region": {
        "name": "Tenant Multi-Region",
        "category": "tenant",
        "billing_category": "tenant",
        "launch_stage": "beta",
        "visibility": "public",
    },
    # msp.*
    "msp.multi_tenant": {
        "name": "MSP Multi-Tenant",
        "category": "msp",
        "billing_category": "msp",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "msp.white_label": {
        "name": "MSP White Label",
        "category": "msp",
        "billing_category": "msp",
        "launch_stage": "ga",
        "visibility": "public",
    },
    # government.*
    "government.fedramp": {
        "name": "Government FedRAMP",
        "category": "government",
        "billing_category": "government",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "government.cjis": {
        "name": "Government CJIS",
        "category": "government",
        "billing_category": "government",
        "launch_stage": "ga",
        "visibility": "public",
    },
    "government.itar": {
        "name": "Government ITAR",
        "category": "government",
        "billing_category": "government",
        "launch_stage": "beta",
        "visibility": "hidden",
    },
    "government.airgap": {
        "name": "Government Air Gap",
        "category": "government",
        "billing_category": "government",
        "launch_stage": "beta",
        "visibility": "hidden",
    },
    "government.private_llm": {
        "name": "Government Private LLM",
        "category": "government",
        "billing_category": "government",
        "launch_stage": "beta",
        "visibility": "hidden",
    },
    # audit.*
    "audit.view": {
        "name": "Audit View",
        "category": "audit",
        "billing_category": None,
        "launch_stage": "ga",
        "visibility": "public",
    },
    "audit.export": {
        "name": "Audit Export",
        "category": "audit",
        "billing_category": None,
        "launch_stage": "ga",
        "visibility": "public",
    },
}

# ---------------------------------------------------------------------------
# Capability dependency graph (capability_id → [requires_id, ...])
# ---------------------------------------------------------------------------

_CAP_DEPENDENCIES: dict[str, list[str]] = {
    "portal.ai": ["ai.workspace"],
    "portal.rag": ["ai.rag"],
    "ai.rag": ["ai.workspace"],
    "ai.document_ingestion": ["ai.workspace"],
    "ai.agent_builder": ["ai.workspace"],
    "ai.multi_agent": ["ai.agent_builder"],
    "ai.governance": ["ai.workspace"],
    "ai.compliance_assistant": ["ai.workspace"],
    "ai.executive_advisor": ["ai.workspace"],
    "identity.scim": ["identity.sso"],
}

# ---------------------------------------------------------------------------
# Meter mappings (capability_key → [meter_key, ...])
# ---------------------------------------------------------------------------

_CAP_METERS: dict[str, list[str]] = {
    "ai.chat": ["token_meter"],
    "ai.rag": ["token_meter"],
    "ai.document_ingestion": ["document_meter"],
    "ai.agent_builder": ["token_meter"],
    "ai.multi_agent": ["token_meter"],
    "ai.fine_tuning": ["token_meter"],
    "ai.compliance_assistant": ["token_meter"],
    "ai.executive_advisor": ["token_meter"],
    "ai.governance": ["token_meter"],
}


def seed_bundle_catalog(db: Session) -> None:
    """Insert the canonical bundle catalog if rows are not already present.

    Idempotent — existing rows are not modified.
    """
    # 1. Ensure all capability rows exist
    for cap_key, meta in _CAP_META.items():
        existing = (
            db.query(Capability).filter(Capability.capability_key == cap_key).first()
        )
        if existing is None:
            db.add(
                Capability(
                    id=str(uuid.uuid4()),
                    capability_key=cap_key,
                    capability_name=meta["name"],
                    capability_category=meta["category"],
                    billing_category=meta.get("billing_category"),
                    launch_stage=meta.get("launch_stage", "ga"),
                    visibility=meta.get("visibility", "public"),
                    active=True,
                )
            )

    db.flush()

    # 2. Ensure all bundle rows and their capability associations exist
    for bundle_key, bundle_info in BUNDLE_CATALOG.items():
        bundle = (
            db.query(PolicyBundle).filter(PolicyBundle.bundle_key == bundle_key).first()
        )
        if bundle is None:
            bundle = PolicyBundle(
                id=str(uuid.uuid4()),
                bundle_key=bundle_key,
                bundle_name=bundle_info["name"],
                description=bundle_info.get("description"),
                active=True,
            )
            db.add(bundle)
            db.flush()

        # Ensure capability associations
        for cap_key in bundle_info["capabilities"]:
            cap_row = (
                db.query(Capability)
                .filter(Capability.capability_key == cap_key)
                .first()
            )
            if cap_row is None:
                log.warning(
                    "seeder.missing_capability bundle=%s cap=%s", bundle_key, cap_key
                )
                continue
            assoc = (
                db.query(PolicyBundleCapability)
                .filter(
                    PolicyBundleCapability.bundle_id == bundle.id,
                    PolicyBundleCapability.capability_id == cap_row.id,
                )
                .first()
            )
            if assoc is None:
                db.add(
                    PolicyBundleCapability(
                        bundle_id=bundle.id,
                        capability_id=cap_row.id,
                    )
                )

    db.flush()

    # 3. Ensure capability dependency rows exist
    for cap_key, requires_keys in _CAP_DEPENDENCIES.items():
        cap_row = (
            db.query(Capability).filter(Capability.capability_key == cap_key).first()
        )
        if cap_row is None:
            continue
        for req_key in requires_keys:
            req_row = (
                db.query(Capability)
                .filter(Capability.capability_key == req_key)
                .first()
            )
            if req_row is None:
                log.warning(
                    "seeder.missing_dep_target cap=%s requires=%s", cap_key, req_key
                )
                continue
            existing = (
                db.query(CapabilityDependency)
                .filter(
                    CapabilityDependency.capability_id == cap_row.id,
                    CapabilityDependency.requires_id == req_row.id,
                )
                .first()
            )
            if existing is None:
                db.add(
                    CapabilityDependency(
                        capability_id=cap_row.id,
                        requires_id=req_row.id,
                    )
                )

    db.flush()

    # 4. Ensure capability meter mapping rows exist
    for cap_key, meter_keys in _CAP_METERS.items():
        cap_row = (
            db.query(Capability).filter(Capability.capability_key == cap_key).first()
        )
        if cap_row is None:
            continue
        for meter_key in meter_keys:
            existing = (
                db.query(CapabilityMeterMapping)
                .filter(
                    CapabilityMeterMapping.capability_id == cap_row.id,
                    CapabilityMeterMapping.meter_key == meter_key,
                )
                .first()
            )
            if existing is None:
                db.add(
                    CapabilityMeterMapping(
                        id=str(uuid.uuid4()),
                        capability_id=cap_row.id,
                        meter_key=meter_key,
                    )
                )

    db.commit()
    log.info(
        "capability_bundles.seeded bundles=%d caps=%d deps=%d meters=%d",
        len(BUNDLE_CATALOG),
        len(_CAP_META),
        sum(len(v) for v in _CAP_DEPENDENCIES.values()),
        sum(len(v) for v in _CAP_METERS.values()),
    )
