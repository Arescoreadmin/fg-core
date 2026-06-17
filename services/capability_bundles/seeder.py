"""services/capability_bundles/seeder.py — Seed canonical bundle catalog (P1.2).

Call seed_bundle_catalog(db) at application startup (or via admin endpoint) to
ensure the policy_bundles, capabilities, and policy_bundle_capabilities tables
contain the authoritative catalog.  Idempotent — safe to call repeatedly.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from api.db_models import Capability, PolicyBundle, PolicyBundleCapability

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
# Capability metadata (name + category for DB catalog)
# ---------------------------------------------------------------------------

_CAP_META: dict[str, tuple[str, str]] = {
    # portal.*
    "portal.access": ("Portal Access", "portal"),
    "portal.remediation": ("Portal Remediation", "portal"),
    "portal.ai": ("Portal AI", "portal"),
    "portal.rag": ("Portal RAG", "portal"),
    # ai.*
    "ai.workspace": ("AI Workspace", "ai"),
    "ai.chat": ("AI Chat", "ai"),
    "ai.rag": ("AI RAG", "ai"),
    "ai.document_ingestion": ("AI Document Ingestion", "ai"),
    "ai.agent_builder": ("AI Agent Builder", "ai"),
    "ai.multi_agent": ("AI Multi-Agent", "ai"),
    "ai.private_models": ("AI Private Models", "ai"),
    "ai.fine_tuning": ("AI Fine Tuning", "ai"),
    "ai.governance": ("AI Governance", "ai"),
    "ai.compliance_assistant": ("AI Compliance Assistant", "ai"),
    "ai.executive_advisor": ("AI Executive Advisor", "ai"),
    # api.*
    "api.access": ("API Access", "api"),
    # identity.*
    "identity.sso": ("Identity SSO", "identity"),
    "identity.scim": ("Identity SCIM", "identity"),
    # reports.*
    "reports.executive": ("Executive Reports", "reports"),
    "reports.regulatory": ("Regulatory Reports", "reports"),
    # tenant.*
    "tenant.multi_region": ("Tenant Multi-Region", "tenant"),
    # msp.*
    "msp.multi_tenant": ("MSP Multi-Tenant", "msp"),
    "msp.white_label": ("MSP White Label", "msp"),
    # government.*
    "government.fedramp": ("Government FedRAMP", "government"),
    "government.cjis": ("Government CJIS", "government"),
    "government.itar": ("Government ITAR", "government"),
    "government.airgap": ("Government Air Gap", "government"),
    "government.private_llm": ("Government Private LLM", "government"),
    # existing capabilities referenced by bundles
    "audit.view": ("Audit View", "audit"),
    "audit.export": ("Audit Export", "audit"),
}


def seed_bundle_catalog(db: Session) -> None:
    """Insert the canonical bundle catalog if rows are not already present.

    Idempotent — existing rows are not modified.
    """
    # 1. Ensure all capability rows exist
    for cap_key, (cap_name, cap_category) in _CAP_META.items():
        existing = (
            db.query(Capability).filter(Capability.capability_key == cap_key).first()
        )
        if existing is None:
            db.add(
                Capability(
                    id=str(uuid.uuid4()),
                    capability_key=cap_key,
                    capability_name=cap_name,
                    capability_category=cap_category,
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

    db.commit()
    log.info("capability_bundles.seeded bundles=%d", len(BUNDLE_CATALOG))
