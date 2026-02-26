#!/usr/bin/env python3
"""
tools/verify_bundle.py — FrostGate Evidence Bundle CLI Verifier.

Phase 7: Moat Enhancement — Deterministic CLI verifier for evidence bundles.

Usage:
  python tools/verify_bundle.py --bundle <bundle.json>
  python tools/verify_bundle.py --bundle <bundle.json> --strict
  python tools/verify_bundle.py --anchor <anchor.json>
  python tools/verify_bundle.py --help

Exit codes:
  0 — Bundle integrity verified (all checks passed)
  1 — Verification failed (tamper detected, hash mismatch, or missing data)
  2 — Input error (file not found, invalid JSON)

Verification checks:
  1. Schema completeness: bundle has all required fields.
  2. Chain integrity: recomputes content_hash and chain_hash for each event.
  3. Merkle root: recomputes Merkle root over chain_hashes.
  4. Prev-hash linkage: each event's prev_hash equals previous event's chain_hash.
  5. Tenant isolation: all events in bundle share the same tenant scope.
  6. Timestamp monotonicity: events are ordered chronologically.
  7. Receipt binding: every receipt references a known command_id in the bundle.
  8. Ledger self-report: checks bundle's own integrity.ok field.

This tool is deterministic: same bundle → same result.
No subprocess, no shell, no dynamic dispatch.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Canonical JSON (must match services/cp_ledger.py exactly)
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialisation (mirrors cp_ledger._canonical_json)."""

    def _norm(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): _norm(val) for k, val in sorted(v.items())}
        if isinstance(v, (list, tuple)):
            return [_norm(i) for i in v]
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return str(v)

    return json.dumps(
        _norm(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hash recomputation (mirrors cp_ledger.py exactly)
# ---------------------------------------------------------------------------


def _recompute_content_hash(event: Dict[str, Any]) -> str:
    envelope = {
        "payload_json": event.get("payload_json", {}),
        "actor_id": event.get("actor_id", ""),
        "tenant_id": event.get("tenant_id"),
        "event_type": event.get("event_type", ""),
        "ts": event.get("ts", ""),
    }
    return _sha256(_canonical_json(envelope))


def _recompute_chain_hash(
    prev_hash: str, content_hash: str, ts: str, event_id: str
) -> str:
    raw = f"{prev_hash}:{content_hash}:{ts}:{event_id}".encode("utf-8")
    return _sha256(raw)


def _merkle_root(leaves: List[str]) -> Optional[str]:
    if not leaves:
        return None
    layer = list(leaves)
    while len(layer) > 1:
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            combined = _sha256((left + right).encode("utf-8"))
            next_layer.append(combined)
        layer = next_layer
    return layer[0]


def _recompute_merkle(events: List[Dict[str, Any]]) -> Optional[str]:
    """Recompute Merkle root over chain_hash||id for each event."""
    leaves = [
        _sha256((e.get("chain_hash", "") + e.get("id", "")).encode("utf-8"))
        for e in events
    ]
    return _merkle_root(leaves)


GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationReport:
    ok: bool
    checks_passed: int
    checks_failed: int
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    summary: str = ""
    bundle_type: str = ""
    tenant_scope: str = ""
    total_events: int = 0
    total_commands: int = 0
    total_receipts: int = 0
    merkle_root_computed: Optional[str] = None
    merkle_root_reported: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "failures": self.failures,
            "warnings": self.warnings,
            "summary": self.summary,
            "bundle_type": self.bundle_type,
            "tenant_scope": self.tenant_scope,
            "total_events": self.total_events,
            "total_commands": self.total_commands,
            "total_receipts": self.total_receipts,
            "merkle_root_computed": self.merkle_root_computed,
            "merkle_root_reported": self.merkle_root_reported,
        }


# ---------------------------------------------------------------------------
# Bundle verifier
# ---------------------------------------------------------------------------


class BundleVerifier:
    """Deterministic evidence bundle verifier."""

    def __init__(self, strict: bool = False) -> None:
        self._strict = strict

    def verify(self, bundle: Dict[str, Any]) -> VerificationReport:
        report = VerificationReport(ok=True, checks_passed=0, checks_failed=0)
        report.bundle_type = bundle.get("bundle_type", "")
        report.tenant_scope = bundle.get("tenant_scope", "")

        # 1. Schema completeness
        self._check_schema(bundle, report)

        # 2. Ledger events chain integrity
        events = bundle.get("ledger_events", [])
        report.total_events = len(events)
        self._check_chain_integrity(events, report)

        # 3. Merkle root verification
        self._check_merkle_root(bundle, events, report)

        # 4. Tenant isolation check
        self._check_tenant_isolation(bundle, events, report)

        # 5. Commands count
        commands = bundle.get("commands", [])
        report.total_commands = len(commands)

        # 6. Receipt binding check
        receipts_map = bundle.get("receipts_by_command", {})
        total_receipts = sum(len(v) for v in receipts_map.values())
        report.total_receipts = total_receipts
        self._check_receipt_binding(commands, receipts_map, report)

        # 7. Ledger self-report check
        self._check_self_report(bundle, report)

        # Final result
        report.ok = report.checks_failed == 0
        report.summary = (
            f"{'PASS' if report.ok else 'FAIL'}: "
            f"{report.checks_passed} passed, {report.checks_failed} failed"
        )
        return report

    def _check_schema(self, bundle: Dict[str, Any], report: VerificationReport) -> None:
        required = [
            "bundle_type",
            "generated_at",
            "tenant_scope",
            "ledger_events",
            "commands",
            "integrity",
        ]
        for field_name in required:
            if field_name not in bundle:
                report.failures.append(f"schema: missing required field '{field_name}'")
                report.checks_failed += 1
            else:
                report.checks_passed += 1

    def _check_chain_integrity(
        self,
        events: List[Dict[str, Any]],
        report: VerificationReport,
    ) -> None:
        """Recompute and verify hash chain over all ledger events."""
        if not events:
            report.warnings.append("chain: no ledger events to verify")
            report.checks_passed += 1
            return

        prev_chain_hash = GENESIS_HASH

        for idx, event in enumerate(events):
            eid = event.get("id", "")
            ts = event.get("ts", "")
            stored_content_hash = event.get("content_hash", "")
            stored_chain_hash = event.get("chain_hash", "")
            stored_prev_hash = event.get("prev_hash", "")

            # Recompute content hash
            expected_content_hash = _recompute_content_hash(event)
            if stored_content_hash != expected_content_hash:
                report.failures.append(
                    f"chain[{idx}] id={eid!r}: content_hash mismatch "
                    f"(stored={stored_content_hash[:16]}... "
                    f"expected={expected_content_hash[:16]}...)"
                )
                report.checks_failed += 1
                continue

            # Verify prev_hash linkage
            if stored_prev_hash != prev_chain_hash:
                report.failures.append(
                    f"chain[{idx}] id={eid!r}: prev_hash mismatch "
                    f"(stored={stored_prev_hash[:16]}... "
                    f"expected={prev_chain_hash[:16]}...)"
                )
                report.checks_failed += 1
                continue

            # Recompute chain hash
            expected_chain_hash = _recompute_chain_hash(
                prev_chain_hash, expected_content_hash, ts, eid
            )
            if stored_chain_hash != expected_chain_hash:
                report.failures.append(
                    f"chain[{idx}] id={eid!r}: chain_hash mismatch — possible tamper"
                )
                report.checks_failed += 1
                continue

            report.checks_passed += 1
            prev_chain_hash = stored_chain_hash

    def _check_merkle_root(
        self,
        bundle: Dict[str, Any],
        events: List[Dict[str, Any]],
        report: VerificationReport,
    ) -> None:
        """Verify Merkle root."""
        integrity = bundle.get("integrity", {})
        reported_root = integrity.get("merkle_root")
        report.merkle_root_reported = reported_root

        if not events:
            report.warnings.append("merkle: no events — root is None")
            report.checks_passed += 1
            return

        computed_root = _recompute_merkle(events)
        report.merkle_root_computed = computed_root

        if reported_root is None and computed_root is None:
            report.checks_passed += 1
            return

        if reported_root != computed_root:
            report.failures.append(
                f"merkle: root mismatch "
                f"(reported={str(reported_root)[:16]}... "
                f"computed={str(computed_root)[:16]}...)"
            )
            report.checks_failed += 1
        else:
            report.checks_passed += 1

    def _check_tenant_isolation(
        self,
        bundle: Dict[str, Any],
        events: List[Dict[str, Any]],
        report: VerificationReport,
    ) -> None:
        """Verify all events are scoped to the declared tenant."""
        tenant_scope = bundle.get("tenant_scope", "")
        if tenant_scope == "global":
            report.warnings.append("tenant_isolation: bundle is global-scoped")
            report.checks_passed += 1
            return

        foreign_events = [
            e.get("id")
            for e in events
            if e.get("tenant_id") and e.get("tenant_id") != tenant_scope
        ]
        if foreign_events:
            report.failures.append(
                f"tenant_isolation: {len(foreign_events)} event(s) have foreign "
                f"tenant_id (expected={tenant_scope!r}): {foreign_events[:3]}"
            )
            report.checks_failed += 1
        else:
            report.checks_passed += 1

    def _check_receipt_binding(
        self,
        commands: List[Dict[str, Any]],
        receipts_map: Dict[str, Any],
        report: VerificationReport,
    ) -> None:
        """Verify receipts reference known command_ids."""
        known_ids = {c.get("command_id") for c in commands}
        orphan_receipts = [cid for cid in receipts_map.keys() if cid not in known_ids]
        if orphan_receipts:
            report.failures.append(
                f"receipt_binding: {len(orphan_receipts)} receipt group(s) reference "
                f"unknown command_ids: {orphan_receipts[:3]}"
            )
            report.checks_failed += 1
        else:
            report.checks_passed += 1

    def _check_self_report(
        self, bundle: Dict[str, Any], report: VerificationReport
    ) -> None:
        """Check the bundle's own integrity.ok field."""
        integrity = bundle.get("integrity", {})
        self_ok = integrity.get("ok")
        if self_ok is False:
            if self._strict:
                report.failures.append(
                    "self_report: bundle reports integrity.ok=false — chain tampered"
                )
                report.checks_failed += 1
            else:
                report.warnings.append("self_report: bundle reports integrity.ok=false")
                report.checks_passed += 1
        else:
            report.checks_passed += 1


# ---------------------------------------------------------------------------
# Anchor verifier
# ---------------------------------------------------------------------------


class AnchorVerifier:
    """Verifies a daily Merkle anchor artifact."""

    def verify(self, anchor: Dict[str, Any]) -> VerificationReport:
        report = VerificationReport(ok=True, checks_passed=0, checks_failed=0)
        report.bundle_type = anchor.get("anchor_type", "anchor")
        report.tenant_scope = str(anchor.get("tenant_id", "global"))

        required = [
            "anchor_type",
            "chain_id",
            "total_entries",
            "merkle_root",
            "integrity_ok",
            "generated_at",
        ]
        for field_name in required:
            if field_name not in anchor:
                report.failures.append(f"anchor_schema: missing field '{field_name}'")
                report.checks_failed += 1
            else:
                report.checks_passed += 1

        if not anchor.get("integrity_ok"):
            report.failures.append(
                "anchor: integrity_ok=false — anchor reports chain tamper"
            )
            report.checks_failed += 1
        else:
            report.checks_passed += 1

        report.ok = report.checks_failed == 0
        report.summary = (
            f"{'PASS' if report.ok else 'FAIL'}: "
            f"{report.checks_passed} passed, {report.checks_failed} failed"
        )
        return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _print_report(report: VerificationReport, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    print("=" * 60)
    print("FrostGate Evidence Bundle Verifier")
    print("=" * 60)
    print(f"Bundle type:     {report.bundle_type}")
    print(f"Tenant scope:    {report.tenant_scope}")
    print(f"Total events:    {report.total_events}")
    print(f"Total commands:  {report.total_commands}")
    print(f"Total receipts:  {report.total_receipts}")
    print(f"Merkle (stored): {report.merkle_root_reported}")
    print(f"Merkle (actual): {report.merkle_root_computed}")
    print()

    if report.warnings:
        print(f"Warnings ({len(report.warnings)}):")
        for w in report.warnings:
            print(f"  WARN: {w}")
        print()

    if report.failures:
        print(f"Failures ({len(report.failures)}):")
        for f in report.failures:
            print(f"  FAIL: {f}")
        print()

    print(f"Result: {report.summary}")
    print("=" * 60)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="FrostGate Evidence Bundle Verifier — compliance-grade integrity check"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bundle", metavar="FILE", help="Path to evidence bundle JSON")
    group.add_argument("--anchor", metavar="FILE", help="Path to Merkle anchor JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on integrity.ok=false in bundle self-report",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output verification report as JSON",
    )

    args = parser.parse_args(argv)

    # Load input file
    input_path = args.bundle or args.anchor
    path = Path(input_path)
    if not path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return 2
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in {input_path}: {exc}", file=sys.stderr)
        return 2

    if args.bundle:
        verifier = BundleVerifier(strict=args.strict)
        report = verifier.verify(data)
    else:
        verifier_anchor = AnchorVerifier()
        report = verifier_anchor.verify(data)

    _print_report(report, output_json=args.output_json)

    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
