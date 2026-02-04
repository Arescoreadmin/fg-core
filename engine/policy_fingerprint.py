from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

POLICY_ID = "doctrine-v1"

_DISRUPTIVE_ACTIONS = ["block", "block_ip", "quarantine", "terminate"]

_POLICY_DEFINITION: dict[str, Any] = {
    "policy_id": POLICY_ID,
    "policy_kind": "doctrine",
    "disruptive_actions": _DISRUPTIVE_ACTIONS,
    "baseline_impact": {"service_impact": 0.35, "user_impact": 0.20},
    "impact_reduction_on_limit": {"service_impact": 0.10, "user_impact": 0.05},
    "rules": [
        {
            "persona": "guardian",
            "classification": "SECRET",
            "roe_applied": True,
            "ao_required": True,
            "disruptive_action_cap": 1,
            "gating_decision": "require_approval_if_disruptive",
        },
        {
            "persona": "sentinel",
            "classification": "*",
            "disruptive_action_cap": 3,
        },
    ],
}


@dataclass(frozen=True)
class PolicyFingerprint:
    policy_id: str
    policy_hash: str
    policy_bytes: bytes


def _canonical_policy_bytes() -> bytes:
    payload = json.dumps(
        _POLICY_DEFINITION,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return payload.encode("utf-8")


def _opa_policy_dir() -> Path:
    return Path("policy") / "opa"


def build_opa_bundle_bytes(policy_dir: Path | None = None) -> bytes:
    policy_root = policy_dir or _opa_policy_dir()
    if not policy_root.exists():
        return _canonical_policy_bytes()

    files = sorted(
        [p for p in policy_root.rglob("*") if p.is_file() and not p.name.startswith(".")]
    )
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in files:
            rel = path.relative_to(policy_root)
            data = path.read_bytes()
            info = tarfile.TarInfo(name=str(rel))
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@lru_cache(maxsize=1)
def get_active_policy_fingerprint() -> PolicyFingerprint:
    policy_bytes = build_opa_bundle_bytes()
    return PolicyFingerprint(
        policy_id=POLICY_ID,
        policy_hash=_sha256_hex(policy_bytes),
        policy_bytes=policy_bytes,
    )
