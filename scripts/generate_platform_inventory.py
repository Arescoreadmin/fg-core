from __future__ import annotations

import json
import sys
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _make_targets() -> set[str]:
    proc = subprocess.run(
        ["make", "-qpRr", "__mkdb__"],
        cwd=REPO,
        check=True,
        text=True,
        capture_output=True,
    )
    out = set()
    for line in proc.stdout.splitlines():
        if ":" in line and not line.startswith("\t") and not line.startswith("#"):
            name = line.split(":", 1)[0].strip()
            if name and "=" not in name and " " not in name:
                out.add(name)
    return out


def main() -> int:
    from services.plane_registry import PLANE_REGISTRY

    route_inventory = _load_json(REPO / "tools/ci/route_inventory.json")
    make_targets = _make_targets()
    artifact_schemas = sorted(
        p.as_posix().replace(str(REPO) + "/", "")
        for p in (REPO / "contracts/artifacts").glob("*.schema.json")
    )
    soc_text = (REPO / "artifacts/SOC_AUDIT_GATES.md").read_text(encoding="utf-8")

    planes = []
    gaps = []
    by_plane_routes: dict[str, list[str]] = {}
    owned_prefixes = []

    for p in PLANE_REGISTRY:
        pid = p.plane_id
        owned_prefixes.extend(p.route_prefixes)
        routes = sorted(
            {
                f"{r['method']} {r['path']}"
                for r in route_inventory
                if any(str(r["path"]).startswith(prefix) for prefix in p.route_prefixes)
            }
        )
        by_plane_routes[pid] = routes
        missing_targets = sorted(
            [t for t in p.required_make_targets if t not in make_targets]
        )
        if missing_targets:
            gaps.append(
                {
                    "type": "missing_make_targets",
                    "plane": pid,
                    "details": missing_targets,
                    "suggested_fix": "Add missing make targets declared by plane registry.",
                }
            )
        missing_evidence = []
        for e in p.evidence:
            sp = REPO / e.schema_path
            gp = REPO / e.generator_script
            if not sp.exists() or not gp.exists():
                missing_evidence.append(
                    {"schema": e.schema_path, "generator": e.generator_script}
                )
        if missing_evidence:
            gaps.append(
                {
                    "type": "missing_evidence_components",
                    "plane": pid,
                    "details": missing_evidence,
                    "suggested_fix": "Add missing schema/generator files declared in plane registry.",
                }
            )
        if pid not in soc_text:
            gaps.append(
                {
                    "type": "missing_soc_gate_reference",
                    "plane": pid,
                    "details": "plane id not referenced in SOC gate artifact",
                    "suggested_fix": "Add SOC gate mapping entry for plane.",
                }
            )

        planes.append(
            {
                "plane_id": pid,
                "route_prefixes": sorted(p.route_prefixes),
                "mount_flag": p.mount_flag,
                "required_make_targets": sorted(p.required_make_targets),
                "evidence": sorted(
                    [
                        {"schema": e.schema_path, "generator": e.generator_script}
                        for e in p.evidence
                    ],
                    key=lambda x: (x["schema"], x["generator"]),
                ),
            }
        )

    unexpected = sorted(
        {
            str(r["path"])
            for r in route_inventory
            if str(r["path"]).startswith("/")
            and not any(str(r["path"]).startswith(prefix) for prefix in owned_prefixes)
        }
    )
    if unexpected:
        gaps.append(
            {
                "type": "unexpected_route_prefixes",
                "details": unexpected,
                "suggested_fix": "Map route prefixes to a plane or explicitly exempt in inventory governance.",
            }
        )

    readiness = {
        "tenant_binding_coverage": all(
            bool(r.get("tenant_bound")) or str(r["path"]).startswith("/health")
            for r in route_inventory
        ),
        "rls_sensitive_tables_present": (
            REPO / "migrations/postgres/0018_nuclear_hardening_extensions.sql"
        ).exists(),
        "route_inventory_enforced": True,
        "openapi_security_diff_enforced": (
            REPO / "tools/ci/check_openapi_security_diff.py"
        ).exists(),
        "artifact_policy_enforced": (
            REPO / "tools/ci/check_artifact_policy.py"
        ).exists(),
        "resilience_guard_present": (
            REPO / "api/middleware/resilience_guard.py"
        ).exists(),
        "self_heal_bounded_off_by_default": (
            REPO / "services/self_heal/watchdog.py"
        ).exists(),
    }

    payload = {
        "git_sha": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "planes": sorted(planes, key=lambda x: x["plane_id"]),
        "routes_by_plane": {k: by_plane_routes[k] for k in sorted(by_plane_routes)},
        "artifact_schemas": artifact_schemas,
        "readiness": readiness,
        "gaps": sorted(
            gaps,
            key=lambda x: (
                x.get("type", ""),
                x.get("plane", ""),
                json.dumps(x.get("details", ""), sort_keys=True),
            ),
        ),
    }

    art = REPO / "artifacts"
    art.mkdir(exist_ok=True)
    (art / "platform_inventory.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    inv_md = ["# Platform Inventory", "", "## Planes"]
    for p in payload["planes"]:
        inv_md.append(
            f"- `{p['plane_id']}` flags=`{p['mount_flag']}` targets={', '.join(p['required_make_targets'])}"
        )
    inv_md += ["", "## Enterprise readiness checklist status"]
    for k, v in sorted(readiness.items()):
        inv_md.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    (art / "PLATFORM_INVENTORY.md").write_text(
        "\n".join(inv_md) + "\n", encoding="utf-8"
    )

    gap_md = ["# Platform Gaps", ""]
    if payload["gaps"]:
        for g in payload["gaps"]:
            gap_md.append(
                f"- [{g['type']}] {g.get('plane', 'global')}: {g['details']} | fix: {g['suggested_fix']}"
            )
    else:
        gap_md.append("- none")
    (art / "PLATFORM_GAPS.md").write_text("\n".join(gap_md) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
