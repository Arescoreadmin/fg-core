# tools/tenants/__main__.py

from __future__ import annotations

import argparse
import json
import sys

from .registry import (
    ensure_tenant,
    list_tenants,
    rotate_api_key,
    revoke_tenant,
)


def _print_json(payload) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def cmd_add(args: argparse.Namespace) -> None:
    rec = ensure_tenant(tenant_id=args.tenant_id, name=args.name)
    _print_json(
        {
            "tenant_id": rec.tenant_id,
            "name": rec.name,
            "api_key": rec.api_key,
            "status": rec.status,
        }
    )


def cmd_rotate(args: argparse.Namespace) -> None:
    rec = rotate_api_key(tenant_id=args.tenant_id)
    _print_json(
        {
            "tenant_id": rec.tenant_id,
            "api_key": rec.api_key,
            "status": rec.status,
        }
    )


def cmd_revoke(args: argparse.Namespace) -> None:
    rec = revoke_tenant(tenant_id=args.tenant_id)
    _print_json(
        {
            "tenant_id": rec.tenant_id,
            "status": rec.status,
        }
    )


def cmd_list(args: argparse.Namespace) -> None:
    tenants = list_tenants(include_revoked=args.include_revoked)
    _print_json(
        [
            {
                "tenant_id": r.tenant_id,
                "name": r.name,
                "status": r.status,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
            for r in tenants
        ]
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tools.tenants",
        description="FrostGate core tenant registry tooling",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Create tenant if missing (idempotent)")
    p_add.add_argument("tenant_id", help="Tenant identifier (string)")
    p_add.add_argument("--name", help="Human-readable tenant name", default=None)
    p_add.set_defaults(func=cmd_add)

    p_rotate = sub.add_parser("rotate-key", help="Rotate tenant API key")
    p_rotate.add_argument("tenant_id", help="Tenant identifier")
    p_rotate.set_defaults(func=cmd_rotate)

    p_revoke = sub.add_parser("revoke", help="Mark tenant revoked")
    p_revoke.add_argument("tenant_id", help="Tenant identifier")
    p_revoke.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="List tenants")
    p_list.add_argument(
        "--include-revoked",
        action="store_true",
        help="Include revoked tenants in output",
    )
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
