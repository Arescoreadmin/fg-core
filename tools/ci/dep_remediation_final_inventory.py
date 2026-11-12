#!/usr/bin/env python3
"""DEP-REMEDIATE-004/005/006 — final dependency remediation inventory and guard.

Joins the committed Dependabot alert snapshot (trimmed ``gh api`` export, read
only) with the existing DEP-INV-001 manifest authority
(``dependency_alert_inventory.build_inventory``), a reviewed remediation
decision per alert (``DECISIONS``) and the versions the repository manifests
resolve *now*. It writes two deterministic artefacts:

    docs/security/dep_remediation_final_inventory.json   all open alerts
    docs/security/dep_remediate_004_reconciliation.json  the root npm alerts

and doubles as a recurrence guard: every alert whose remediation is
``IMPLEMENTED`` must resolve outside its vulnerable range in the current
manifest, or the tool exits 1.

    python tools/ci/dep_remediation_final_inventory.py            # check only
    python tools/ci/dep_remediation_final_inventory.py --write    # regenerate

Fail-closed: an alert without a recorded decision, a decision for an alert not
in the snapshot, an implemented package that no longer resolves, or an
unparseable version range exits 1 (policy) or 2 (input). The tool is offline:
it never contacts GitHub and never dismisses alerts. A clean run is local
evidence only — GitHub alert state must still be verified after merge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dependency_alert_inventory import (  # noqa: E402
    InventoryInputError,
    build_inventory,
)

SCHEMA = "fg.dep_remediation_final_inventory/v1"
RECON_SCHEMA = "fg.dep_remediate_004_reconciliation/v1"
SNAPSHOT = "docs/security/dep_remediation_alerts_snapshot_2026-11-11.json"
OUT_INVENTORY = "docs/security/dep_remediation_final_inventory.json"
OUT_RECON = "docs/security/dep_remediate_004_reconciliation.json"
BASE_COMMIT = "e1dba3a5bef390cab0cebc9a2a98fa1628199f33"  # main after #848

CLASSES = {
    "FIXED_BY_VERSION_UPDATE",
    "FIXED_BY_DEPENDENCY_REPLACEMENT",
    "FIXED_BY_MANIFEST_RETIREMENT",
    "BLOCKED_COMPATIBILITY",
    "BLOCKED_NO_FIX_AVAILABLE",
}
STATES = {"IMPLEMENTED", "PLANNED"}

# Resolved versions at BASE_COMMIT (git show e1dba3a5b:<manifest>), recorded
# because CI clones are shallow. Root lockfile sha256 at BASE_COMMIT:
BASE_ROOT_LOCK_SHA256 = (
    "4500a0efd6bd29cab3c76350099560163f40f53b42d8a6b1f1cf4c536913b393"
)
BASE_VERSIONS: dict[str, dict[str, list[str]]] = {
    "package-lock.json": {
        "brace-expansion": ["5.0.6"],
        "js-yaml": ["4.1.1"],
        "katex": ["0.16.46"],
        "linkify-it": ["5.0.0"],
        "markdown-it": ["14.1.1"],
        "minimatch": ["10.2.5"],
        "smol-toml": ["1.6.1"],
        "markdownlint": ["0.40.0"],
        "markdownlint-cli": ["0.48.0"],
    },
    "agent/requirements.txt": {"requests": ["2.32.3"]},
    "apps/console/package-lock.json": {"minimatch": ["10.2.6", "3.1.5"]},
    "apps/portal/package-lock.json": {"minimatch": ["10.2.6", "3.1.5"]},
}

_ROOT = {
    "owner": "DEP-REMEDIATE-004",
    "state": "IMPLEMENTED",
    "classification": "FIXED_BY_VERSION_UPDATE",
    "reachability": "Root devDependency chain of markdownlint-cli only. No CI job, "
    "Make target, Dockerfile or Vercel project installs the root manifest; "
    "it runs only when a developer invokes node_modules/.bin/markdownlint on "
    "repository Markdown/config. Inputs are repository-controlled.",
    "exploit_prerequisites": "Attacker-controlled Markdown, YAML or TOML (or a "
    "glob/brace pattern) processed by a developer's local markdownlint run; "
    "impact is CPU denial of service of that process (katex: prototype "
    "pollution already present in the process).",
    "breaking_change_probability": "LOW — upstream markdownlint-cli 0.50.0 "
    "declares the new majors itself; the two scoped overrides were exercised "
    "(ignore globs, YAML/TOML/JSONC config, stdin, katex load+render).",
    "impacted_workflows": ["local markdownlint (node_modules/.bin/markdownlint)"],
    "deployment_impact": "Root package-lock.json is in apps/console/vercel.json "
    "ignoreCommand: merge rebuilds the Console Vercel production project(s) "
    "from unchanged apps/console inputs. release-images republishes the root "
    "image, which carries package.json/package-lock.json as inert files "
    "(COPY .; no npm in the image).",
}


def _root(mechanism: str) -> dict[str, Any]:
    return {**_ROOT, "mechanism": mechanism}


_PARENT = "markdownlint-cli 0.48.0 -> 0.50.0 (parent update)"
_AGENT = {
    "owner": "DEP-REMEDIATE-005",
    "state": "IMPLEMENTED",
    "classification": "FIXED_BY_VERSION_UPDATE",
    "mechanism": "agent/requirements.txt requests==2.32.3 -> requests==2.34.2 "
    "(latest; >= 2.33.0 fixes both; supersedes Dependabot PR #851 at 2.33.0)",
    "reachability": "Linux agent image (agent/Dockerfile, CMD agent.app."
    "agent_main) uses agent/core_client.py: requests.Session, explicit "
    "timeout, allow_redirects=False, TLS verification on. Legacy agent/app/"
    "core_client.py follows redirects but is only reachable via agent/app/"
    "main.py, which no entrypoint launches. Not in release-images.",
    "breaking_change_probability": "LOW — no API change used by the agent; "
    "requests 2.34.2 requires Python >= 3.10 (image python:3.12-slim) and "
    "urllib3 <3, idna <4, charset_normalizer <4, certifi; the shared CI venv "
    "already runs it.",
    "impacted_workflows": [
        "agent/Dockerfile",
        "tests/agent (make agent-unit, CI Agent Linux)",
    ],
    "deployment_impact": "No repo-managed deploy: agent image is built only "
    "by agent/docker-compose.yml. Windows agent (agent/main.py, CI Agent "
    "Windows Build) uses stdlib urllib and does not install this file.",
}
_FRONT = {
    "owner": "DEP-REMEDIATE-006",
    "state": "IMPLEMENTED",
    "classification": "FIXED_BY_VERSION_UPDATE",
    "mechanism": 'scoped override "@typescript-eslint/typescript-estree": '
    '{"minimatch": "^11.0.8"}; no parent fix exists (typescript-estree '
    "8.72.2 latest still declares minimatch ^10.2.2)",
    "reachability": "ESLint/TypeScript parser glob matching during `next lint`"
    " / CI lint and next build lint; not bundled into the application.",
    "exploit_prerequisites": "Attacker-controlled glob pattern in lint "
    "configuration (repository-controlled).",
    "breaking_change_probability": "LOW — per lockfile: nested minimatch "
    "10.2.6 -> 11.0.8 plus @isaacs/nonrecursive-glob-match 1.1.0 (dev); "
    "next 15.5.29 / react 19.3.1 unchanged. typescript-estree only calls "
    "minimatch(path, pattern, {dot: true}), which v11 keeps. v11 needs node "
    "20 || >=22: CI uses 20, Vercel projects 24.x.",
}

DECISIONS: dict[int, dict[str, Any]] = {
    1: {
        **_AGENT,
        "exploit_prerequisites": "A malicious URL whose host matches a "
        ".netrc entry on the agent host; agent targets operator-configured "
        "Core URLs.",
    },
    2: {
        **_AGENT,
        "exploit_prerequisites": "Local attacker able to pre-create "
        "files in the shared temp directory while extract_zipped_paths runs "
        "(zipped/frozen installs such as PyInstaller bundles).",
    },
    88: {
        **_FRONT,
        "impacted_workflows": ["apps/console lint/build", "CI console job"],
        "deployment_impact": "apps/console/package*.json change triggers the "
        "Console Vercel production build on merge.",
    },
    170: {
        **_FRONT,
        "impacted_workflows": ["apps/portal lint/build", "CI portal job"],
        "deployment_impact": "apps/portal change passes tools/vercel/"
        "ignore_build.sh and triggers the Portal Vercel production build.",
    },
    171: _root(_PARENT + "; markdown-it 14.1.1 -> 15.0.3"),
    173: _root(_PARENT + "; js-yaml 4.1.1 -> 5.5.0"),
    174: _root("minimatch override ^11.0.8 pulls brace-expansion 5.0.13"),
    175: _root(_PARENT + "; js-yaml 4.1.1 -> 5.5.0"),
    176: _root(_PARENT + "; linkify-it 5.0.0 -> 6.1.0 via markdown-it 15"),
    179: _root(_PARENT + "; js-yaml 4.1.1 -> 5.5.0"),
    180: _root(_PARENT + "; js-yaml 4.1.1 -> 5.5.0"),
    181: _root(_PARENT + "; smol-toml 1.6.1 -> 1.9.1"),
    182: _root(_PARENT + "; markdown-it 14.1.1 -> 15.0.3"),
    185: _root("minimatch override ^11.0.8 pulls brace-expansion 5.0.13"),
    186: _root(
        'scoped override "micromark-extension-math": {"katex": "^0.18.11"} '
        "(micromark-extension-math 3.1.0, latest, declares katex ^0.16.0)"
    ),
    187: _root(_PARENT + "; smol-toml 1.6.1 -> 1.9.1"),
    188: _root(_PARENT + "; markdown-it 14.1.1 -> 15.0.3"),
    189: _root(_PARENT + "; markdown-it 14.1.1 -> 15.0.3"),
    190: _root(_PARENT + "; markdown-it 14.1.1 -> 15.0.3"),
    191: _root(
        'scoped override "markdownlint-cli": {"minimatch": "^11.0.8"} '
        "(markdownlint-cli 0.50.0, latest, declares minimatch ~10.2.6)"
    ),
}

PR_ORDER = [
    {
        "pr": "DEP-REMEDIATE-004",
        "alerts": "root package-lock.json (16)",
        "precondition": "none",
    },
    {
        "pr": "DEP-REMEDIATE-005",
        "alerts": "agent/requirements.txt (2)",
        "precondition": "DEP-004 merged and GitHub alert state verified",
    },
    {
        "pr": "DEP-REMEDIATE-006",
        "alerts": "console + portal package-lock.json (2)",
        "precondition": "DEP-005 merged; founder-approved Console/Portal production rebuild window",
    },
]

# Observed evidence for DEP-004 (this branch, npm 10.9.7, node 22.22.2).
OBSERVED_004 = {
    "npm_audit_before": {
        "critical": 0,
        "high": 6,
        "moderate": 1,
        "low": 3,
        "total": 10,
    },
    "npm_audit_after": {"critical": 0, "high": 0, "moderate": 0, "low": 0, "total": 0},
    "markdownlint_repo_run": {
        "files": 381,
        "config": ".markdownlint.json (unchanged)",
        "findings_before": 9456,
        "findings_after": 9461,
        "delta": "+5, strictly additive (MD034 +2 bare e-mail, MD036 +3); no finding lost",
    },
    "compatibility_probes": [
        "--ignore glob excludes matching files (minimatch 11)",
        "YAML config disables a rule; YAML merge keys parse (js-yaml 5)",
        "TOML config parses (smol-toml 1.9)",
        "JSONC config parses",
        "stdin linting (-s)",
        "micromark-extension-math html loads; katex 0.18.11 renderToString",
    ],
    "engine_note": "markdownlint-cli >=0.49 requires node >=22 (local tooling "
    "only; no CI job runs root markdownlint)",
}

# Root-lockfile alerts GitHub itself auto-dismissed (auto_dismissed_at
# 2026-11-11T01:15Z, not by any FrostGate action). The advisories are real and
# not withdrawn, and the BASE_COMMIT versions were inside their ranges, so they
# are tracked and guarded exactly like open alerts rather than left hidden.
AUTO_DISMISSED_ROOT: list[dict[str, Any]] = [
    {
        "alert": 172,
        "ghsa": "GHSA-22p9-wv53-3rq4",
        "cve": "CVE-2026-48801",
        "severity": "high",
        "package": "linkify-it",
        "vulnerable_range": "<= 5.0.0",
        "first_patched": "5.0.1",
        "versions_at_base": ["5.0.0"],
    },
    {
        "alert": 177,
        "ghsa": "GHSA-mh99-v99m-4gvg",
        "cve": "CVE-2026-14257",
        "severity": "high",
        "package": "brace-expansion",
        "vulnerable_range": ">= 4.0.0, < 5.0.8",
        "first_patched": "5.0.8",
        "versions_at_base": ["5.0.6"],
    },
    {
        "alert": 178,
        "ghsa": "GHSA-rgw5-rvv9-x895",
        "cve": "CVE-2026-69152",
        "severity": "high",
        "package": "brace-expansion",
        "vulnerable_range": ">= 4.0.0, < 5.0.9",
        "first_patched": "5.0.9",
        "versions_at_base": ["5.0.6"],
    },
    {
        "alert": 183,
        "ghsa": "GHSA-6j4f-fj2g-mc7p",
        "cve": "CVE-2026-102276",
        "severity": "high",
        "package": "brace-expansion",
        "vulnerable_range": ">= 4.0.0, < 5.0.10",
        "first_patched": "5.0.10",
        "versions_at_base": ["5.0.6"],
    },
    {
        "alert": 184,
        "ghsa": "GHSA-qhr7-859c-m2p7",
        "cve": "CVE-2026-102278",
        "severity": "high",
        "package": "brace-expansion",
        "vulnerable_range": ">= 4.0.0, < 5.0.11",
        "first_patched": "5.0.11",
        "versions_at_base": ["5.0.6"],
    },
]

_OPS = re.compile(r"^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+)*)$")


class RemediationError(Exception):
    """Policy violation (exit 1)."""


def _vtuple(v: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+)*", v):
        raise InventoryInputError(f"unsupported version {v!r}")
    parts = tuple(int(p) for p in v.split("."))
    return parts + (0,) * (3 - len(parts))


def in_range(version: str, spec: str) -> bool:
    """GitHub advisory range, e.g. '>= 4.0.0, < 4.3.2'. Fails closed."""
    v = _vtuple(version)
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    if not clauses:
        raise InventoryInputError(f"empty range {spec!r}")
    for c in clauses:
        m = _OPS.match(c)
        if not m:
            raise InventoryInputError(f"unparseable range clause {c!r}")
        op, bound = m.group(1) or "=", _vtuple(m.group(2))
        ok = {
            "<": v < bound,
            "<=": v <= bound,
            ">": v > bound,
            ">=": v >= bound,
            "=": v == bound,
        }[op]
        if not ok:
            return False
    return True


def resolved_versions(repo: Path, manifest: str, package: str) -> list[str]:
    path = repo / manifest
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InventoryInputError(f"cannot read {manifest}: {exc}") from exc
    if manifest.endswith("package-lock.json"):
        try:
            pkgs = json.loads(text)["packages"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InventoryInputError(f"malformed lockfile {manifest}: {exc}") from exc
        found = {
            str(v.get("version"))
            for k, v in pkgs.items()
            if k and k.rsplit("node_modules/", 1)[-1] == package
        }
    elif manifest.endswith(".txt"):
        found = set()
        for line in text.splitlines():
            m = re.match(
                rf"^\s*{re.escape(package)}\s*==\s*([\w.]+)\s*(#.*)?$", line, re.I
            )
            if m:
                found.add(m.group(1))
            elif re.match(rf"^\s*{re.escape(package)}\b", line, re.I):
                raise InventoryInputError(f"{manifest}: {package} is not ==pinned")
    else:
        raise InventoryInputError(f"unsupported manifest type {manifest}")
    return sorted(found, key=_vtuple)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(
    repo: Path, snapshot: Path
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    try:
        raw = snapshot.read_bytes()
        alerts = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryInputError(f"cannot read snapshot {snapshot}: {exc}") from exc
    base = build_inventory(alerts, alerts_sha256=hashlib.sha256(raw).hexdigest())
    if base["unclassified_manifests"]:
        raise RemediationError(
            f"unclassified manifests: {base['unclassified_manifests']}"
        )
    numbers = {r["alert"] for r in base["alerts"]}
    problems: list[str] = []
    missing = sorted(numbers - set(DECISIONS))
    extra = sorted(set(DECISIONS) - numbers)
    if missing:
        problems.append(f"alerts without a remediation decision: {missing}")
    if extra:
        problems.append(f"decisions for alerts absent from snapshot: {extra}")
    rows = []
    for r in sorted(base["alerts"], key=lambda r: r["alert"]):
        d = DECISIONS.get(r["alert"])
        if d is None:
            continue
        if d["classification"] not in CLASSES or d["state"] not in STATES:
            problems.append(f"alert {r['alert']}: invalid classification/state")
        now = resolved_versions(repo, r["manifest"], r["package"])
        vulnerable_now = [v for v in now if in_range(v, r["vulnerable_range"])]
        before = BASE_VERSIONS.get(r["manifest"], {}).get(r["package"], [])
        vulnerable_before = [v for v in before if in_range(v, r["vulnerable_range"])]
        if not vulnerable_before:
            problems.append(
                f"alert {r['alert']}: baseline version not in vulnerable range"
            )
        if d["state"] == "IMPLEMENTED":
            if not now:
                problems.append(
                    f"alert {r['alert']}: {r['package']} no longer resolves "
                    f"in {r['manifest']}; reclassify the decision"
                )
            if vulnerable_now:
                problems.append(
                    f"alert {r['alert']}: {r['package']} {vulnerable_now} still "
                    f"in {r['vulnerable_range']} ({r['manifest']})"
                )
        rows.append(
            {
                "alert": r["alert"],
                "ghsa": r["ghsa"],
                "cve": r["cve"],
                "severity": r["severity"],
                "package": r["package"],
                "manifest": r["manifest"],
                "manifest_status": r["manifest_status"],
                "relationship": r["relationship"],
                "scope": r["scope"],
                "exposure": r["exposure"],
                "vulnerable_range": r["vulnerable_range"],
                "first_patched": r["first_patched"],
                "summary": r["summary"],
                "versions_at_base": before,
                "versions_now": now,
                "vulnerable_now": vulnerable_now,
                **{
                    k: d[k]
                    for k in (
                        "owner",
                        "state",
                        "classification",
                        "mechanism",
                        "reachability",
                        "exploit_prerequisites",
                        "breaking_change_probability",
                        "impacted_workflows",
                        "deployment_impact",
                    )
                },
            }
        )
    auto_rows = []
    for a in AUTO_DISMISSED_ROOT:
        now = resolved_versions(repo, "package-lock.json", a["package"])
        vulnerable_now = [v for v in now if in_range(v, a["vulnerable_range"])]
        if not [v for v in a["versions_at_base"] if in_range(v, a["vulnerable_range"])]:
            problems.append(
                f"alert {a['alert']}: baseline version not in vulnerable range"
            )
        if not now:
            problems.append(
                f"alert {a['alert']}: {a['package']} no longer resolves "
                "in package-lock.json; reclassify the decision"
            )
        if vulnerable_now:
            problems.append(
                f"alert {a['alert']}: {a['package']} {vulnerable_now} still "
                f"in {a['vulnerable_range']} (package-lock.json)"
            )
        auto_rows.append(
            {
                **a,
                "github_state": "auto_dismissed",
                "versions_now": now,
                "vulnerable_now": vulnerable_now,
                "owner": "DEP-REMEDIATE-004",
                "classification": "FIXED_BY_VERSION_UPDATE",
                "mechanism": "minimatch override ^11.0.8 pulls brace-expansion 5.0.13"
                if a["package"] == "brace-expansion"
                else _PARENT + "; linkify-it 5.0.0 -> 6.1.0 via markdown-it 15",
            }
        )
    inventory = {
        "schema": SCHEMA,
        "base_commit": BASE_COMMIT,
        "alert_snapshot": SNAPSHOT,
        "alert_snapshot_sha256": base["alerts_export_sha256"],
        "total_open_alerts": base["total_open_alerts"],
        "by_manifest": base["by_manifest"],
        "by_severity": base["by_severity"],
        "by_exposure": base["by_exposure"],
        "by_owner": {
            o: sorted(x["alert"] for x in rows if x["owner"] == o)
            for o in sorted({x["owner"] for x in rows})
        },
        "pr_order": PR_ORDER,
        "policy": "No dismissals. An alert is closed only when GitHub reports "
        "state=fixed with no dismissed_at after the owning PR merges.",
        "alerts": rows,
        "auto_dismissed_by_github_tracked": auto_rows,
    }
    root_rows = [x for x in rows if x["manifest"] == "package-lock.json"]
    lock = repo / "package-lock.json"
    recon = {
        "schema": RECON_SCHEMA,
        "pr": "DEP-REMEDIATE-004",
        "base_commit": BASE_COMMIT,
        "root_lock_sha256_base": BASE_ROOT_LOCK_SHA256,
        "root_lock_sha256_now": _sha(lock) if lock.exists() else None,
        "app_lockfiles_untouched": [
            "apps/console/package-lock.json",
            "apps/portal/package-lock.json",
            "apps/web/package-lock.json",
        ],
        "targeted_alerts": [x["alert"] for x in root_rows],
        "observed": OBSERVED_004,
        "expected_github_outcome": "each targeted alert state=fixed, dismissed_at "
        "null, after merge and default-branch rescan (not yet verified)",
        "alerts": [
            {
                k: x[k]
                for k in (
                    "alert",
                    "ghsa",
                    "cve",
                    "severity",
                    "package",
                    "vulnerable_range",
                    "first_patched",
                    "versions_at_base",
                    "versions_now",
                    "vulnerable_now",
                    "classification",
                    "mechanism",
                )
            }
            for x in root_rows
        ],
        "auto_dismissed_by_github_also_remediated": [
            {
                k: x[k]
                for k in (
                    "alert",
                    "ghsa",
                    "package",
                    "vulnerable_range",
                    "versions_at_base",
                    "versions_now",
                    "vulnerable_now",
                )
            }
            for x in auto_rows
        ],
        "auto_dismissed_note": "GitHub auto-dismissed these on 2026-11-11T01:15Z; "
        "no FrostGate action dismissed them. They may stay auto_dismissed after "
        "the rescan; the guard proves their resolution instead.",
    }
    return inventory, recon, problems


def render(obj: dict[str, Any]) -> str:
    return json.dumps(obj, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--snapshot", type=Path)
    ap.add_argument(
        "--write", action="store_true", help="regenerate the JSON artefacts"
    )
    args = ap.parse_args(argv)
    repo = args.repo
    try:
        inventory, recon, problems = build(repo, args.snapshot or repo / SNAPSHOT)
    except InventoryInputError as exc:
        print(f"dep-remediation-inventory: INVALID_INPUT: {exc}", file=sys.stderr)
        return 2
    except RemediationError as exc:
        print(f"dep-remediation-inventory: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.write:
        (repo / OUT_INVENTORY).write_text(render(inventory), encoding="utf-8")
        (repo / OUT_RECON).write_text(render(recon), encoding="utf-8")
    for p in problems:
        print(f"dep-remediation-inventory: FAIL: {p}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"dep-remediation-inventory: OK {inventory['total_open_alerts']} alerts; "
        f"by_owner={json.dumps(inventory['by_owner'])}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
