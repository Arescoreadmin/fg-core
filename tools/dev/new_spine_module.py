#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from string import Template

REPO = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO / "tools/testing/templates"


def _render(template_name: str, **kwargs: str) -> str:
    text = (TEMPLATE_DIR / template_name).read_text(encoding="utf-8")
    return Template(text).substitute(**kwargs)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate fail-closed spine module scaffolding")
    parser.add_argument("--module-id", required=True)
    parser.add_argument("--plane", required=True)
    parser.add_argument("--route-prefix", default="/v1/<module>")
    args = parser.parse_args()

    module_id = args.module_id.strip().lower().replace("-", "_")
    route_prefix = args.route_prefix.replace("<module>", module_id)

    _write(
        REPO / f"services/{module_id}_extension/__init__.py",
        f'"""{module_id} spine module."""\n',
    )
    _write(
        REPO / f"tests/modules/test_{module_id}_unit.py",
        _render("test_module_unit.py.tmpl", module_id=module_id),
    )
    _write(
        REPO / f"tests/security/test_{module_id}_tenant_binding.py",
        _render("test_module_security.py.tmpl", module_id=module_id),
    )
    _write(
        REPO / f"docs/modules/{module_id}.md",
        _render("module_doc.md.tmpl", module_id=module_id, plane=args.plane, route_prefixes=route_prefix),
    )

    print(f"generated module skeleton for {module_id}")
    print("next steps:")
    print(f"  1) append module to tools/testing/policy/ownership_map.yaml")
    print(f"  2) append module to tools/testing/policy/module_manifest.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
