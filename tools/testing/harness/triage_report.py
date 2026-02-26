#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.testing.harness.triage_taxonomy import TriageCategory

TRIAGE_SCHEMA_VERSION = "2.0"


@dataclass(frozen=True)
class TriageRule:
    category: TriageCategory
    pattern: re.Pattern[str]
    confidence: float
    summary: str
    commands: tuple[str, ...]
    files: tuple[str, ...]
    links: tuple[str, ...]


_RULES: tuple[TriageRule, ...] = (
    TriageRule(TriageCategory.CONTRACT_DRIFT, re.compile(r"contract|openapi|schema|snapshot", re.IGNORECASE), 0.92, "Contract or schema drift detected.", ("make fg-contract", "python tools/testing/contracts/check_contract_drift.py"), ("contracts/", "tools/testing/contracts/check_contract_drift.py"), ("tools/testing/README.md",)),
    TriageRule(TriageCategory.DUPLICATE_ROUTES, re.compile(r"duplicate route|route conflict", re.IGNORECASE), 0.95, "Duplicate route registration detected.", ("python tools/ci/check_route_inventory.py",), ("api/main.py", "tools/ci/check_route_inventory.py"), ("CONTRACT.md",)),
    TriageRule(TriageCategory.PLANE_REGISTRY_DRIFT, re.compile(r"plane registry|ownership_map", re.IGNORECASE), 0.9, "Plane registry and ownership map diverged.", ("python tools/ci/check_plane_registry.py",), ("tools/testing/policy/ownership_map.yaml", "services/plane_registry/registry.py"), ("SPINE_INVARIANTS.md",)),
    TriageRule(TriageCategory.AUTH_SCOPE_MISMATCH, re.compile(r"scope|forbidden|permission", re.IGNORECASE), 0.88, "Auth scope mismatch or missing permission.", ("pytest -q tests/security/test_scope_enforcement.py",), ("api/auth_scopes.py", "tests/security/test_scope_enforcement.py"), ("HARDENING_PLAN.md",)),
    TriageRule(TriageCategory.TENANT_ISOLATION_BREACH, re.compile(r"tenant|cross-tenant|isolation", re.IGNORECASE), 0.9, "Potential cross-tenant isolation breach.", ("pytest -q tests/security/test_tenant_binding_global.py",), ("api/control_plane.py", "tests/security/test_tenant_binding_global.py"), ("SPINE_INVARIANTS.md",)),
    TriageRule(TriageCategory.RLS_MISSING_OR_WEAK, re.compile(r"\brls\b|row level security", re.IGNORECASE), 0.9, "RLS policy missing or weak.", ("python tools/ci/check_agent_phase2_rls.py",), ("migrations/", "api/db.py"), ("HARDENING_PLAN.md",)),
    TriageRule(TriageCategory.SSRF_GUARD_FAILURE, re.compile(r"ssrf|metadata endpoint|169\.254\.169\.254", re.IGNORECASE), 0.94, "SSRF guard failed or missing coverage.", ("pytest -q tests/security -k ssrf",), ("api/middleware/", "security/"), ("MOAT_STRATEGY.md",)),
    TriageRule(TriageCategory.MIGRATION_RISK, re.compile(r"migration|ddl|sql|rollback", re.IGNORECASE), 0.89, "Migration safety regression detected.", ("make test-pg-migrations-replay",), ("migrations/", "tools/testing/integration/smoke_suite.py"), ("DRIFT_LEDGER.md",)),
    TriageRule(TriageCategory.TIME_BUDGET_EXCEEDED, re.compile(r"time budget exceeded|timeout|budget-exhausted", re.IGNORECASE), 0.97, "Lane exceeded strict runtime budget.", ("python tools/testing/harness/lane_runner.py --lane fg-fast",), ("tools/testing/policy/runtime_budgets.yaml", "tools/testing/harness/lane_runner.py"), ("tools/testing/README.md",)),
    TriageRule(TriageCategory.FLAKE_SUSPECTED, re.compile(r"flaky|intermittent|rerun|oscillat", re.IGNORECASE), 0.86, "Flaky test suspected from inconsistent outcomes.", ("python tools/testing/harness/flake_detect.py --lane fg-flake-detect",), ("tools/testing/policy/flaky_tests.yaml", "artifacts/testing/flake-report.json"), ("tools/testing/README.md",)),
)


def _excerpt(lines: list[str], pattern: re.Pattern[str], max_lines: int = 30) -> list[str]:
    matches = [idx for idx, line in enumerate(lines) if pattern.search(line)]
    if not matches:
        return lines[:max_lines]
    start = max(0, matches[0] - 3)
    end = min(len(lines), start + max_lines)
    return lines[start:end]


def _top_frames(lines: list[str]) -> list[str]:
    frames = [line.strip() for line in lines if line.lstrip().startswith("File ") or "::" in line]
    deduped = sorted({frame for frame in frames if frame})
    return deduped[:8]


def _classify(lines: list[str], lane: str = "unknown") -> dict[str, object]:
    for rule in _RULES:
        if rule.pattern.search("\n".join(lines)):
            excerpt = _excerpt(lines, rule.pattern)
            report = {
                "triage_schema_version": TRIAGE_SCHEMA_VERSION,
                "triage_schema_version": TRIAGE_SCHEMA_VERSION,
        "lane": lane,
                "category": rule.category.value,
                "confidence": rule.confidence,
                "primary_error": excerpt[0] if excerpt else "no log lines available",
                "evidence": {
                    "top_frames": _top_frames(excerpt),
                    "matched_patterns": [rule.pattern.pattern],
                    "log_excerpt": excerpt[:30],
                },
                "suggested_fix": {
                    "summary": rule.summary,
                    "commands": list(rule.commands),
                    "files": list(rule.files),
                    "links": list(rule.links),
                },
            }
            digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest()
            report["evidence"]["stable_hash"] = digest
            return report

    excerpt = lines[:30]
    report = {
        "triage_schema_version": TRIAGE_SCHEMA_VERSION,
        "lane": lane,
        "category": TriageCategory.UNKNOWN.value,
        "confidence": 0.0,
        "primary_error": excerpt[0] if excerpt else "no log lines available",
        "evidence": {
            "top_frames": _top_frames(excerpt),
            "matched_patterns": [],
            "log_excerpt": excerpt,
        },
        "suggested_fix": {
            "summary": "No known signatures matched; inspect log excerpt and route to owner.",
            "commands": ["make fg-fast"],
            "files": ["tools/testing/harness/triage_report.py"],
            "links": ["tools/testing/README.md"],
        },
    }
    report["evidence"]["stable_hash"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic triage output from test logs")
    parser.add_argument("--log", required=True, help="Path to lane log file")
    parser.add_argument("--out", required=True, help="Path to write triage JSON")
    parser.add_argument("--lane", required=False, default="unknown", help="Lane name")
    args = parser.parse_args()

    log_path = Path(args.log)
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    report = _classify(lines, lane=args.lane)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
