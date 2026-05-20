"""Governance Asset Registry — shadow asset detection.

Cross-references fa_scan_results against governance_assets by external_id
and asset_type inference from source_type.

Shadow assets are AI vendors, OAuth apps, or models found in scan evidence
that have no matching registered governance_asset.  They carry a 50-point
discovery_penalty in risk scoring and are surfaced via GET /governance/assets/shadow.

Source-type to asset_type inference:
  microsoft_graph  → oauth_app (apps), ai_vendor (services)
  aws              → ai_system (SageMaker), ai_vendor (Bedrock)
  crowdstrike      → ai_system, automation
  google_workspace → oauth_app
  oauth_inventory  → oauth_app
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaScanResult
from api.db_models_governance_assets import GaAsset

# Mapping from scan source_type → likely asset_type(s) to surface
_SOURCE_TO_ASSET_TYPES: dict[str, list[str]] = {
    "microsoft_graph": ["oauth_app", "ai_vendor"],
    "aws": ["ai_system", "ai_vendor"],
    "crowdstrike": ["ai_system", "automation"],
    "google_workspace": ["oauth_app"],
    "oauth_inventory": ["oauth_app"],
}


def detect_shadow_assets(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return scan-discovered assets not yet registered in governance_assets.

    Compares fa_scan_results.raw_payload identifiers against
    governance_assets.external_id (tenant-scoped).

    Returns a list of shadow candidate dicts with source context.
    """
    # Gather all registered external_ids for this tenant
    stmt = select(GaAsset.external_id).where(
        GaAsset.tenant_id == tenant_id,
        GaAsset.external_id.isnot(None),
    )
    registered_external_ids: set[str] = {
        row for (row,) in db.execute(stmt).all() if row
    }

    # Gather recent scan results
    stmt2 = (
        select(FaScanResult)
        .where(FaScanResult.tenant_id == tenant_id)
        .order_by(FaScanResult.created_at.desc())
        .limit(500)
    )
    scans = db.execute(stmt2).scalars().all()

    shadow_candidates: list[dict[str, Any]] = []
    seen_external_ids: set[str] = set()

    for scan in scans:
        inferred_types = _SOURCE_TO_ASSET_TYPES.get(scan.source_type, [])
        if not inferred_types:
            continue

        raw = scan.raw_payload or {}
        # Best-effort extraction of identifiable items from common scan schemas
        items = _extract_identifiable_items(raw, scan.source_type)

        for item in items:
            ext_id = item.get("external_id", "")
            if (
                not ext_id
                or ext_id in registered_external_ids
                or ext_id in seen_external_ids
            ):
                continue
            seen_external_ids.add(ext_id)
            shadow_candidates.append(
                {
                    "external_id": ext_id,
                    "suggested_name": item.get("name", ext_id),
                    "suggested_asset_types": inferred_types,
                    "source_type": scan.source_type,
                    "source_scan_id": scan.id,
                    "found_at": scan.created_at,
                    "discovery_source": "discovered",
                    "risk_note": "Shadow asset — not in governance registry. +50 risk penalty applies.",
                }
            )
            if len(shadow_candidates) >= limit:
                break
        if len(shadow_candidates) >= limit:
            break

    return shadow_candidates


def _extract_identifiable_items(
    payload: dict[str, Any],
    source_type: str,
) -> list[dict[str, Any]]:
    """Best-effort extraction of named/identified items from scan payloads."""
    items: list[dict[str, Any]] = []

    # microsoft_graph: typically {apps: [{appId, displayName}], services: [...]}
    if source_type == "microsoft_graph":
        for key in ("apps", "services", "servicePrincipals"):
            for entry in payload.get(key, []):
                if isinstance(entry, dict):
                    ext_id = entry.get("appId") or entry.get("id") or ""
                    name = entry.get("displayName") or entry.get("name") or ext_id
                    if ext_id:
                        items.append({"external_id": str(ext_id), "name": str(name)})

    # aws: typically {accounts: [{accountId, services: [...]}]}
    elif source_type == "aws":
        for account in payload.get("accounts", []):
            if isinstance(account, dict):
                for svc in account.get("services", []):
                    if isinstance(svc, dict):
                        ext_id = svc.get("serviceArn") or svc.get("id") or ""
                        name = svc.get("serviceName") or svc.get("name") or ext_id
                        if ext_id:
                            items.append(
                                {"external_id": str(ext_id), "name": str(name)}
                            )

    # crowdstrike: typically {users: [...], endpoints: [...]}
    elif source_type == "crowdstrike":
        for key in ("endpoints", "services"):
            for entry in payload.get(key, []):
                if isinstance(entry, dict):
                    ext_id = entry.get("device_id") or entry.get("id") or ""
                    name = entry.get("hostname") or entry.get("name") or ext_id
                    if ext_id:
                        items.append({"external_id": str(ext_id), "name": str(name)})

    # oauth_inventory / google_workspace: {clients: [{client_id, client_name}]}
    else:
        for key in ("clients", "apps", "applications"):
            for entry in payload.get(key, []):
                if isinstance(entry, dict):
                    ext_id = entry.get("client_id") or entry.get("id") or ""
                    name = entry.get("client_name") or entry.get("name") or ext_id
                    if ext_id:
                        items.append({"external_id": str(ext_id), "name": str(name)})

    return items
