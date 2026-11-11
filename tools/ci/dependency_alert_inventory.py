#!/usr/bin/env python3
"""DEP-INV-001 — classify open Dependabot alerts by real deployment exposure.

GitHub reports alerts per *manifest*. A manifest being present in the repo does
not mean it is installed or deployed. This tool joins each alert with the
manifest authority recorded in ``MANIFEST_AUTHORITY`` (evidence for every entry
is in ``docs/security/DEPENDENCY_INVENTORY_DEP_INV_001.md``) and emits a
deterministic machine-readable inventory.

It is offline and read-only. Inputs are exports produced by the operator:

    gh api --paginate \
      "repos/Arescoreadmin/fg-core/dependabot/alerts?state=open&per_page=100" \
      | jq -s 'add' > alerts.json
    gh pr list --repo Arescoreadmin/fg-core --state open --author app/dependabot \
      --limit 200 --json number,title,headRefName,files,body > prs.json   # optional

    python tools/ci/dependency_alert_inventory.py --alerts alerts.json \
      [--prs prs.json] [--out inventory.json]

Fail-closed: an alert on a manifest with no recorded authority is UNCLASSIFIED
and the tool exits 1 — a new manifest must be classified, never silently
treated as harmless. Invalid input exits 2. The tool never dismisses alerts
and never contacts GitHub.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "fg.dependency_alert_inventory/v1"

# Manifest authority (DEP-INV-001, verified 2026-11-11).
#   AUTHORITATIVE_DEPLOYED      installed by the deploy pipeline and live
#   AUTHORITATIVE_DEPLOY_STALE  authoritative, but production runs an older build
#   STALE_UNUSED                committed, never installed by any pipeline
#   OBSOLETE_DUPLICATE_TREE     legacy copy of an app; not built or deployed
#   DEV_TOOLING                 repository tooling only, never shipped
#   RUNTIME_NOT_REPO_DEPLOYED   runtime code with no repo-managed deploy path
#   RETIRED                     deleted; alerts on historical exports stay
#                               NOT_INSTALLED, and check_lockfile_authority.py
#                               fails if the file reappears
MANIFEST_AUTHORITY: dict[str, dict[str, str]] = {
    "apps/console/package-lock.json": {
        "status": "AUTHORITATIVE_DEPLOYED",
        "deployed_as": "console.frostgate.ai (Vercel, npm install); docker-compose console",
    },
    "apps/console/pnpm-lock.yaml": {
        "status": "RETIRED",
        "deployed_as": "deleted in DEP-REMEDIATE-002 (never installed: Vercel installCommand "
        "is npm install; Dockerfile/Makefile/CI use npm); must not reappear",
    },
    "apps/console/console/package-lock.json": {
        "status": "RETIRED",
        "deployed_as": "deleted with the whole apps/console/console/ tree in DEP-REMEDIATE-003 "
        "(never installed or deployed; not a Next.js app root); must not reappear",
    },
    "apps/portal/package-lock.json": {
        "status": "AUTHORITATIVE_DEPLOY_STALE",
        "deployed_as": "app.frostgate.ai (Vercel) — production still serves ec56641 (next 14.2.5)",
    },
    "apps/web/package-lock.json": {
        "status": "AUTHORITATIVE_DEPLOY_STALE",
        "deployed_as": "frostgate.ai (Vercel fg-web) — production is a 2026-05-29 CLI upload (next 14.2.35)",
    },
    "package-lock.json": {
        "status": "DEV_TOOLING",
        "deployed_as": "none (markdownlint-cli only)",
    },
    "agent/requirements.txt": {
        "status": "RUNTIME_NOT_REPO_DEPLOYED",
        "deployed_as": "agent/Dockerfile only; not in release-images or docker-compose",
    },
}

_DEPLOYED = {"AUTHORITATIVE_DEPLOYED"}
_NOT_INSTALLED = {"STALE_UNUSED", "OBSOLETE_DUPLICATE_TREE", "RETIRED"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class InventoryInputError(ValueError):
    """Raised for malformed alert or PR exports."""


def exposure_for(status: str | None, scope: str | None) -> str:
    """Map manifest authority + dependency scope to a runtime exposure class."""
    if status is None:
        return "UNCLASSIFIED"
    if status in _NOT_INSTALLED:
        return "NOT_INSTALLED"
    if scope == "development" or status == "DEV_TOOLING":
        return "DEVELOPMENT_ONLY"
    if status in _DEPLOYED:
        return "PRODUCTION_RUNTIME"
    if status == "AUTHORITATIVE_DEPLOY_STALE":
        # The repo lockfile is not what production runs; the alert describes
        # the next deploy, and production exposure must be assessed separately.
        return "REPO_RUNTIME_PRODUCTION_DIVERGES"
    return "RUNTIME_NOT_REPO_DEPLOYED"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryInputError(f"cannot read {path}: {exc}") from exc


def _alert_row(alert: dict[str, Any], prs: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        dep = alert["dependency"]
        adv = alert["security_advisory"]
        vuln = alert["security_vulnerability"]
        manifest = dep["manifest_path"]
        package = vuln["package"]["name"]
        number = int(alert["number"])
        severity = str(adv["severity"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InventoryInputError(f"malformed alert record: {exc}") from exc
    authority = MANIFEST_AUTHORITY.get(manifest)
    status = authority["status"] if authority else None
    scope = dep.get("scope")
    patched = (vuln.get("first_patched_version") or {}).get("identifier")
    manifest_dir = manifest.rsplit("/", 1)[0] if "/" in manifest else ""
    pkg_re = re.compile(rf"(?<![\w@/.-]){re.escape(package)}(?![\w/-])")
    candidate_prs = sorted(
        int(p["number"])
        for p in prs
        if manifest in {f.get("path") for f in p.get("files") or []}
        and pkg_re.search(f"{p.get('title', '')}\n{p.get('body') or ''}")
    )
    return {
        "alert": number,
        "severity": severity,
        "ghsa": adv.get("ghsa_id"),
        "cve": adv.get("cve_id"),
        "package": package,
        "ecosystem": vuln["package"].get("ecosystem"),
        "manifest": manifest,
        "manifest_dir": manifest_dir,
        "manifest_status": status or "UNCLASSIFIED",
        "scope": scope,
        "relationship": dep.get("relationship"),
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "first_patched": patched,
        "remediation": "PATCH_AVAILABLE" if patched else "NO_PATCH",
        "exposure": exposure_for(status, scope),
        "summary": adv.get("summary"),
        "candidate_prs": candidate_prs,
    }


def build_inventory(
    alerts: Any, prs: Any = None, *, alerts_sha256: str = ""
) -> dict[str, Any]:
    if not isinstance(alerts, list):
        raise InventoryInputError("alerts export must be a JSON array")
    pr_list = prs or []
    if not isinstance(pr_list, list):
        raise InventoryInputError("PR export must be a JSON array")
    rows = sorted(
        (_alert_row(a, pr_list) for a in alerts),
        key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["manifest"], r["alert"]),
    )
    by_exposure: dict[str, Counter[str]] = {}
    for r in rows:
        by_exposure.setdefault(r["exposure"], Counter())[r["severity"]] += 1
    unclassified = sorted(
        {r["manifest"] for r in rows if r["exposure"] == "UNCLASSIFIED"}
    )
    return {
        "schema": SCHEMA,
        "alerts_export_sha256": alerts_sha256,
        "total_open_alerts": len(rows),
        "by_severity": dict(sorted(Counter(r["severity"] for r in rows).items())),
        "by_manifest": {
            m: dict(
                sorted(
                    Counter(r["severity"] for r in rows if r["manifest"] == m).items()
                )
            )
            for m in sorted({r["manifest"] for r in rows})
        },
        "by_exposure": {
            k: dict(sorted(v.items())) for k, v in sorted(by_exposure.items())
        },
        "manifest_authority": MANIFEST_AUTHORITY,
        "unclassified_manifests": unclassified,
        "alerts": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--alerts", type=Path, required=True)
    ap.add_argument("--prs", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    try:
        raw = args.alerts.read_bytes()
        alerts = _load_json(args.alerts)
        prs = _load_json(args.prs) if args.prs else None
        inv = build_inventory(
            alerts, prs, alerts_sha256=hashlib.sha256(raw).hexdigest()
        )
    except (InventoryInputError, OSError) as exc:
        print(f"dependency-alert-inventory: INVALID_INPUT: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(inv, indent=2, sort_keys=False) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(
        f"dependency-alert-inventory: {inv['total_open_alerts']} alerts; "
        f"by_exposure={json.dumps(inv['by_exposure'], sort_keys=True)}",
        file=sys.stderr,
    )
    if inv["unclassified_manifests"]:
        print(
            "dependency-alert-inventory: UNCLASSIFIED manifests (record authority first): "
            + ", ".join(inv["unclassified_manifests"]),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
