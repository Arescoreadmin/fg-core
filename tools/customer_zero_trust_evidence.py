#!/usr/bin/env python3
"""Validate retained, non-secret Customer-Zero trust provisioning evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.cgin.key_management.trust_evidence import (  # noqa: E402
    EvidenceState,
    aggregate_states,
    fingerprint_manifest,
    load_manifest,
    validate_manifest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "inspect",
            "validate",
            "fingerprint",
            "status",
            "verify-anchors",
            "verify-role-separation",
            "verify-provenance",
            "verify-complete",
        ),
    )
    parser.add_argument("manifest")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        result = validate_manifest(manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps({"state": EvidenceState.FAIL.value, "reasons": [str(exc)]})
            if args.as_json
            else f"FAIL: {exc}"
        )
        return 1
    output: dict[str, Any]
    if args.command == "fingerprint":
        output = {"evidence_fingerprint": fingerprint_manifest(manifest)}
    elif args.command == "inspect":
        output = {
            "schema_version": manifest.get("schema_version"),
            "work_item": manifest.get("work_item"),
            "ceremony_id": manifest.get("ceremony_id"),
            "evidence_fingerprint": result.fingerprint,
            "trust_roles": [
                r.get("trust_role")
                for r in manifest.get("trust_roles", [])
                if isinstance(r, dict)
            ],
        }
    elif args.command == "verify-anchors":
        output = {
            "state": result.dimensions.get(
                "PUBLIC_ANCHORS", EvidenceState.NOT_PROVEN
            ).value,
            "reasons": list(result.reasons),
        }
    elif args.command == "verify-role-separation":
        output = {
            "state": result.dimensions.get(
                "ROLE_SEPARATION", EvidenceState.NOT_PROVEN
            ).value,
            "reasons": list(result.reasons),
        }
    elif args.command == "verify-provenance":
        provenance_state = aggregate_states(
            {
                "SOURCE_IDENTITY": result.dimensions.get(
                    "SOURCE_IDENTITY", EvidenceState.NOT_PROVEN
                ),
                "DEPLOYMENT_IDENTITY": result.dimensions.get(
                    "DEPLOYMENT_IDENTITY", EvidenceState.NOT_PROVEN
                ),
            }
        )
        output = {"state": provenance_state.value, "reasons": list(result.reasons)}
    else:
        output = result.as_dict()
    print(
        json.dumps(output, sort_keys=True)
        if args.as_json
        else _text(args.command, output)
    )
    return (
        0 if output.get("state", result.state.value) == EvidenceState.PASS.value else 1
    )


def _text(command: str, output: dict[str, Any]) -> str:
    if command == "fingerprint":
        return str(output["evidence_fingerprint"])
    lines = [str(output.get("state", "PASS"))]
    if "evidence_fingerprint" in output:
        lines.append(f"fingerprint: {output['evidence_fingerprint']}")
    for reason in output.get("reasons", []):
        lines.append(f"reason: {reason}")
    if "dimensions" in output:
        lines.extend(f"{key}: {value}" for key, value in output["dimensions"].items())  # type: ignore[union-attr]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
