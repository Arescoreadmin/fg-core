#!/usr/bin/env python3
"""DEP-REMEDIATE-002 — one authoritative lockfile and package manager per JS app.

Policy: .github/security/lockfile-authority.json. For each listed app:

  * the canonical lockfile is tracked;
  * no second lockfile (pnpm/yarn/bun/shrinkwrap) is tracked in the app root;
  * package.json "packageManager", if set, names the policy's manager;
  * vercel.json, when the policy requires it, sets an explicit installCommand
    from the allow-list (no package-manager autodetection);
  * the Dockerfile, when listed, installs with the policy's manager, copies the
    canonical lockfile and never invokes another manager or corepack;
  * no second application/package root (package.json, next.config.*,
    tsconfig.json or lockfile) is tracked anywhere below the app root
    (DEP-REMEDIATE-003: the nested apps/console/console/ tree).

Repo-wide:

  * every tracked JS lockfile is classified in DEP-INV-001
    (tools/ci/dependency_alert_inventory.py MANIFEST_AUTHORITY);
  * a manifest classified RETIRED must not exist (no silent reappearance);
  * no tracked file may exist under a policy "retired_roots" directory.

Apps not listed in the policy may use any package manager; they are only held
to the repo-wide classification rule.

Exit 0 OK · 1 violation · 2 unreadable policy. Read-only; offline.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / ".github/security/lockfile-authority.json"
INVENTORY_TOOL = REPO / "tools/ci/dependency_alert_inventory.py"

LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lockb": "bun",
    "bun.lock": "bun",
}
MANAGERS = ("npm", "pnpm", "yarn", "bun")
ROOT_MARKERS = re.compile(
    r"^(package\.json|tsconfig\.json|next\.config\.(js|mjs|cjs|ts|mts))$"
)


def tracked_files(repo: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p for p in out.decode().split("\0") if p]


def load_manifest_authority(tool: Path = INVENTORY_TOOL) -> dict[str, dict[str, str]]:
    spec = importlib.util.spec_from_file_location("_dep_inv_authority", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {tool}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_dep_inv_authority"] = mod
    spec.loader.exec_module(mod)
    return dict(mod.MANIFEST_AUTHORITY)


def _invokes(text: str, manager: str) -> bool:
    return (
        re.search(rf"(?<![\w./-]){re.escape(manager)}\s+(install|ci|i|add)\b", text)
        is not None
    )


def check(
    repo: Path, policy: dict[str, Any], authority: dict[str, dict[str, str]]
) -> list[str]:
    errors: list[str] = []
    files = tracked_files(repo)
    tracked = set(files)

    for app, rule in sorted(policy.get("apps", {}).items()):
        manager = rule["package_manager"]
        canonical = f"{app}/{rule['lockfile']}"
        if LOCKFILES.get(rule["lockfile"]) != manager:
            errors.append(
                f"{app}: policy lockfile {rule['lockfile']} does not belong to {manager}"
            )
        if canonical not in tracked:
            errors.append(f"{app}: canonical lockfile {canonical} is not tracked")
        for name in LOCKFILES:
            path = f"{app}/{name}"
            if path in tracked and path != canonical:
                errors.append(
                    f"{app}: second lockfile {path} — only {canonical} is authoritative"
                )

        pkg_path = repo / app / "package.json"
        if pkg_path.exists():
            pm = json.loads(pkg_path.read_text()).get("packageManager")
            if pm is not None and not str(pm).startswith(f"{manager}@"):
                errors.append(
                    f"{app}: package.json packageManager={pm!r} but policy is {manager}"
                )

        allowed = rule.get("vercel_install_commands")
        if allowed is not None:
            vpath = repo / app / "vercel.json"
            install = (
                json.loads(vpath.read_text()).get("installCommand")
                if vpath.exists()
                else None
            )
            if install is None:
                errors.append(
                    f"{app}: vercel.json must set an explicit installCommand (no autodetection)"
                )
            elif install not in allowed:
                errors.append(
                    f"{app}: vercel.json installCommand {install!r} not in {allowed}"
                )

        dname = rule.get("dockerfile")
        if dname:
            dpath = repo / app / dname
            if not dpath.exists():
                errors.append(f"{app}: policy Dockerfile {dname} missing")
            else:
                text = dpath.read_text()
                if not _invokes(text, manager):
                    errors.append(f"{app}/{dname}: does not install with {manager}")
                if rule["lockfile"] not in text:
                    errors.append(f"{app}/{dname}: does not copy {rule['lockfile']}")
                for other in MANAGERS:
                    if other != manager and _invokes(text, other):
                        errors.append(f"{app}/{dname}: invokes {other}")
                if re.search(r"\bcorepack\b", text):
                    errors.append(f"{app}/{dname}: uses corepack")

        prefix = f"{app}/"
        for path in files:
            if not path.startswith(prefix) or "/node_modules/" in f"/{path}":
                continue
            rel = path[len(prefix) :]
            name = Path(rel).name
            if "/" in rel and (ROOT_MARKERS.match(name) or name in LOCKFILES):
                errors.append(
                    f"{app}: nested application root {path} — {app} must be the only "
                    "package root (DEP-REMEDIATE-003)"
                )

    for root in policy.get("retired_roots", []):
        under = [p for p in files if p.startswith(f"{root.rstrip('/')}/")]
        if under:
            errors.append(
                f"{root}: retired tree has reappeared ({len(under)} tracked files, "
                f"e.g. {under[0]})"
            )

    for path in files:
        if Path(path).name in LOCKFILES and "/node_modules/" not in f"/{path}":
            entry = authority.get(path)
            if entry is None:
                errors.append(
                    f"{path}: lockfile not classified in DEP-INV-001 MANIFEST_AUTHORITY"
                )
            elif entry.get("status") == "RETIRED":
                errors.append(
                    f"{path}: RETIRED lockfile has reappeared ({entry.get('deployed_as', '')})"
                )
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--policy", type=Path, default=POLICY)
    args = ap.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text())
        if not isinstance(policy.get("apps"), dict) or not policy["apps"]:
            raise ValueError("policy has no apps")
        retired = policy.get("retired_roots", [])
        if not isinstance(retired, list) or not all(
            isinstance(r, str) and r.strip("/") for r in retired
        ):
            raise ValueError("retired_roots must be a list of non-empty paths")
        authority = load_manifest_authority()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"lockfile-authority: INVALID_POLICY: {exc}", file=sys.stderr)
        return 2
    try:
        errors = check(args.repo, policy, authority)
    except (KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"lockfile-authority: INVALID_POLICY: {exc}", file=sys.stderr)
        return 2
    for e in errors:
        print(f"lockfile-authority: FAIL {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"lockfile-authority: OK ({len(policy['apps'])} apps)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
