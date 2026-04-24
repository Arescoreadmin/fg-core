from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

ROOT = Path(__file__).resolve().parents[2]

# Services are not allowed to import API router/bootstrap modules.
FORBIDDEN_IMPORTS = {
    "api.main",
    "api.middleware",
    "api.admin",
    "api.connectors_control_plane",
}

# frostgate-core must remain on the internal network only.
# Attaching it to the public network allows containers on that network to
# bypass the admin-gateway and reach core directly.
_CORE_SERVICE = "frostgate-core"
_FORBIDDEN_CORE_NETWORKS = {"public"}

# Compose files to inspect for network policy.
_COMPOSE_FILES = [
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.lockdown.yml",
]


def _iter_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


def _check_import_boundaries() -> list[str]:
    violations: list[str] = []
    for py in (ROOT / "services").rglob("*.py"):
        rel = py.relative_to(ROOT)
        for name in _iter_imports(py):
            if any(name == f or name.startswith(f + ".") for f in FORBIDDEN_IMPORTS):
                violations.append(f"{rel}: forbidden import {name}")
    return violations


def _check_compose_network_boundaries() -> list[str]:
    """Verify frostgate-core is not attached to the public network in any compose file."""
    if not _YAML_AVAILABLE:
        return ["SKIP: PyYAML not installed — compose network check skipped"]

    violations: list[str] = []
    for compose_path in _COMPOSE_FILES:
        if not compose_path.exists():
            continue
        data: Any = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        services: dict[str, Any] = data.get("services") or {}
        core_cfg = services.get(_CORE_SERVICE)
        if core_cfg is None:
            continue
        networks_cfg = core_cfg.get("networks") or {}
        # networks can be a list (bare names) or dict (name → options)
        if isinstance(networks_cfg, dict):
            attached = set(networks_cfg.keys())
        elif isinstance(networks_cfg, list):
            attached = set(networks_cfg)
        else:
            attached = set()
        forbidden_attached = _FORBIDDEN_CORE_NETWORKS & attached
        if forbidden_attached:
            rel = compose_path.relative_to(ROOT)
            violations.append(
                f"{rel}: {_CORE_SERVICE!r} is attached to forbidden network(s) "
                f"{sorted(forbidden_attached)} — core must be internal-only"
            )
    return violations


def main() -> int:
    violations: list[str] = []
    violations.extend(_check_import_boundaries())
    violations.extend(_check_compose_network_boundaries())
    if violations:
        for v in violations:
            print(v)
        return 1
    print("plane boundaries: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
