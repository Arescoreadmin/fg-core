"""
tests/control_plane/test_control_plane_phase7.py — Phase 7: CLI Verifier Tests.

Tests cover:
  - Evidence bundle schema completeness check
  - Hash chain integrity verification (correct bundle)
  - Hash chain tamper detection
  - Merkle root recomputation and mismatch detection
  - Tenant isolation check in bundle
  - Receipt binding validation
  - Anchor artifact verification
  - CLI main() exit codes
  - Deterministic output (same bundle → same result)

Security invariants verified:
  - Tampered chain detected
  - Merkle mismatch detected
  - Schema completeness enforced
  - Foreign-tenant events detected
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tools.verify_bundle import (
    BundleVerifier,
    AnchorVerifier,
    _recompute_content_hash,
    _recompute_chain_hash,
    _recompute_merkle,
    GENESIS_HASH,
)


# ---------------------------------------------------------------------------
# Bundle builder helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _make_event(
    *,
    tenant_id: Optional[str] = "tenant-alpha",
    event_type: str = "cp_command_created",
    actor_id: str = "actor-001",
    payload: Optional[Dict[str, Any]] = None,
    prev_hash: str = GENESIS_HASH,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a correctly-hashed ledger event."""
    eid = event_id or str(uuid.uuid4())
    ts = _ts()
    pj = payload or {}
    content_hash = _recompute_content_hash({
        "id": eid,
        "ts": ts,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "actor_role": "operator",
        "event_type": event_type,
        "payload_json": pj,
        "content_hash": "",
        "prev_hash": prev_hash,
        "chain_hash": "",
        "trace_id": "",
        "severity": "info",
        "source": "api",
    })
    chain_hash = _recompute_chain_hash(prev_hash, content_hash, ts, eid)
    return {
        "id": eid,
        "ts": ts,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "actor_role": "operator",
        "event_type": event_type,
        "payload_json": pj,
        "content_hash": content_hash,
        "prev_hash": prev_hash,
        "chain_hash": chain_hash,
        "trace_id": "",
        "severity": "info",
        "source": "api",
    }


def _build_chain(n: int, tenant_id: str = "tenant-alpha") -> List[Dict[str, Any]]:
    """Build a correctly-linked chain of n events."""
    events = []
    prev_hash = GENESIS_HASH
    for i in range(n):
        evt = _make_event(
            tenant_id=tenant_id,
            event_type="cp_command_created",
            payload={"seq": i},
            prev_hash=prev_hash,
        )
        events.append(evt)
        prev_hash = evt["chain_hash"]
    return events


def _make_bundle(
    events: List[Dict[str, Any]],
    tenant_scope: str = "tenant-alpha",
    commands: Optional[List[Dict[str, Any]]] = None,
    receipts: Optional[Dict[str, Any]] = None,
    integrity_ok: bool = True,
    merkle_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a minimal evidence bundle."""
    computed_merkle = _recompute_merkle(events) if events else None
    return {
        "bundle_type": "control_plane_v2_evidence",
        "generated_at": _ts(),
        "tenant_scope": tenant_scope,
        "actor_id": "actor-001",
        "time_range": {"since": None, "until": None},
        "ledger_events": events,
        "commands": commands or [],
        "receipts_by_command": receipts or {},
        "integrity": {
            "ok": integrity_ok,
            "chain_id": "control_plane_v2",
            "total_entries": len(events),
            "first_tampered_id": None,
            "first_tampered_index": None,
            "error_detail": None,
            "verified_at": _ts(),
            "merkle_root": merkle_root if merkle_root is not None else computed_merkle,
        },
        "trace_id": "trace-001",
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

class TestBundleSchemaCheck:
    """Test schema completeness enforcement."""

    def test_valid_bundle_passes_schema(self):
        """Complete valid bundle passes schema check."""
        events = _build_chain(3)
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is True

    def test_missing_bundle_type_fails(self):
        """Bundle without bundle_type fails schema check."""
        events = _build_chain(1)
        bundle = _make_bundle(events)
        del bundle["bundle_type"]
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("bundle_type" in f for f in report.failures)

    def test_missing_integrity_fails(self):
        """Bundle without integrity field fails."""
        events = _build_chain(1)
        bundle = _make_bundle(events)
        del bundle["integrity"]
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False

    def test_missing_ledger_events_fails(self):
        """Bundle without ledger_events field fails."""
        events = _build_chain(1)
        bundle = _make_bundle(events)
        del bundle["ledger_events"]
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False


class TestChainIntegrity:
    """Test hash chain integrity verification."""

    def test_valid_chain_passes(self):
        """Correctly hashed chain passes integrity check."""
        events = _build_chain(5)
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is True
        assert report.checks_failed == 0

    def test_empty_chain_passes(self):
        """Empty chain (no events) passes with warning."""
        bundle = _make_bundle([])
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is True

    def test_tampered_payload_detected(self):
        """
        NEGATIVE: Tampered payload_json detected via content_hash mismatch.
        """
        events = _build_chain(3)
        # Tamper with event 1's payload without updating hash
        events[1]["payload_json"] = {"tampered": "data"}
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("content_hash mismatch" in f for f in report.failures)

    def test_tampered_chain_hash_detected(self):
        """
        NEGATIVE: Tampered chain_hash detected.
        """
        events = _build_chain(3)
        # Directly tamper chain_hash of event 0
        events[0]["chain_hash"] = "a" * 64
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False

    def test_broken_prev_hash_linkage_detected(self):
        """
        NEGATIVE: Broken prev_hash linkage detected.
        Event 2's prev_hash doesn't match event 1's chain_hash.
        """
        events = _build_chain(3)
        # Break linkage: event 2's prev_hash is wrong
        events[2]["prev_hash"] = "b" * 64
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("prev_hash mismatch" in f or "content_hash mismatch" in f
                   for f in report.failures)


class TestMerkleVerification:
    """Test Merkle root verification."""

    def test_correct_merkle_root_passes(self):
        """Correctly computed Merkle root passes."""
        events = _build_chain(4)
        # Bundle uses auto-computed Merkle
        bundle = _make_bundle(events)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is True
        assert report.merkle_root_computed == report.merkle_root_reported

    def test_tampered_merkle_root_detected(self):
        """
        NEGATIVE: Tampered Merkle root detected.
        """
        events = _build_chain(4)
        bundle = _make_bundle(events, merkle_root="x" * 64)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("merkle" in f for f in report.failures)


class TestTenantIsolation:
    """Test tenant isolation check in bundle."""

    def test_single_tenant_bundle_passes(self):
        """Bundle with single tenant scope passes isolation check."""
        events = _build_chain(3, tenant_id="tenant-alpha")
        bundle = _make_bundle(events, tenant_scope="tenant-alpha")
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is True

    def test_foreign_tenant_events_detected(self):
        """
        NEGATIVE: Events from foreign tenant detected in bundle.
        Cross-tenant contamination is a critical integrity failure.
        """
        events = _build_chain(2, tenant_id="tenant-alpha")
        # Inject a foreign-tenant event
        foreign_event = _make_event(tenant_id="tenant-beta", prev_hash=events[-1]["chain_hash"])
        events.append(foreign_event)
        bundle = _make_bundle(events, tenant_scope="tenant-alpha")
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("tenant_isolation" in f or "foreign tenant" in f.lower()
                   for f in report.failures)

    def test_global_bundle_skips_isolation_check(self):
        """Global bundle (tenant_scope=global) skips isolation check."""
        events_a = _build_chain(2, tenant_id="tenant-alpha")
        events_b = _build_chain(2, tenant_id="tenant-beta")
        bundle = _make_bundle(events_a + events_b, tenant_scope="global")
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        # Isolation check skipped for global bundles (warning only)
        assert any("global-scoped" in w for w in report.warnings)


class TestReceiptBinding:
    """Test receipt binding validation."""

    def test_receipts_referencing_known_commands_pass(self):
        """Receipts for known commands pass validation."""
        cmd_id = str(uuid.uuid4())
        commands = [{"command_id": cmd_id, "command": "restart", "status": "completed"}]
        receipts = {cmd_id: [{"receipt_id": str(uuid.uuid4()), "ok": True}]}
        events = _build_chain(1)
        bundle = _make_bundle(events, commands=commands, receipts=receipts)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.total_commands == 1
        assert report.total_receipts == 1

    def test_orphan_receipts_detected(self):
        """
        NEGATIVE: Receipts referencing unknown command_ids detected.
        """
        orphan_cmd_id = str(uuid.uuid4())
        receipts = {orphan_cmd_id: [{"receipt_id": str(uuid.uuid4()), "ok": True}]}
        events = _build_chain(1)
        bundle = _make_bundle(events, commands=[], receipts=receipts)
        verifier = BundleVerifier()
        report = verifier.verify(bundle)
        assert report.ok is False
        assert any("receipt_binding" in f for f in report.failures)


class TestAnchorVerification:
    """Test Merkle anchor artifact verification."""

    def test_valid_anchor_passes(self):
        """Valid anchor artifact passes verification."""
        anchor = {
            "anchor_type": "cp_ledger_daily_anchor",
            "chain_id": "control_plane_v2",
            "tenant_id": "tenant-alpha",
            "total_entries": 42,
            "merkle_root": "a" * 64,
            "integrity_ok": True,
            "generated_at": _ts(),
        }
        verifier = AnchorVerifier()
        report = verifier.verify(anchor)
        assert report.ok is True

    def test_anchor_integrity_false_fails(self):
        """Anchor with integrity_ok=false fails."""
        anchor = {
            "anchor_type": "cp_ledger_daily_anchor",
            "chain_id": "control_plane_v2",
            "tenant_id": "tenant-alpha",
            "total_entries": 42,
            "merkle_root": "a" * 64,
            "integrity_ok": False,
            "generated_at": _ts(),
        }
        verifier = AnchorVerifier()
        report = verifier.verify(anchor)
        assert report.ok is False

    def test_anchor_missing_merkle_root_fails(self):
        """Anchor without merkle_root fails schema check."""
        anchor = {
            "anchor_type": "cp_ledger_daily_anchor",
            "chain_id": "control_plane_v2",
            "total_entries": 42,
            "integrity_ok": True,
            "generated_at": _ts(),
            # missing merkle_root
        }
        verifier = AnchorVerifier()
        report = verifier.verify(anchor)
        assert report.ok is False


class TestDeterministicOutput:
    """Test that verification is deterministic."""

    def test_same_bundle_same_result(self):
        """Same bundle always produces same verification result."""
        events = _build_chain(5)
        bundle = _make_bundle(events)

        verifier = BundleVerifier()
        r1 = verifier.verify(bundle)
        r2 = verifier.verify(bundle)

        assert r1.ok == r2.ok
        assert r1.checks_passed == r2.checks_passed
        assert r1.checks_failed == r2.checks_failed
        assert r1.merkle_root_computed == r2.merkle_root_computed

    def test_tampered_bundle_always_fails(self):
        """
        Tampered bundle always fails — no non-deterministic bypass.
        """
        events = _build_chain(3)
        events[0]["payload_json"] = {"tampered": True}
        bundle = _make_bundle(events)

        verifier = BundleVerifier()
        for _ in range(3):
            report = verifier.verify(bundle)
            assert report.ok is False


class TestCLIMainExitCodes:
    """Test CLI main() function exit codes."""

    def test_main_file_not_found_returns_2(self, tmp_path):
        """Non-existent file returns exit code 2."""
        from tools.verify_bundle import main
        rc = main(["--bundle", str(tmp_path / "nonexistent.json")])
        assert rc == 2

    def test_main_invalid_json_returns_2(self, tmp_path):
        """Invalid JSON file returns exit code 2."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all {{{")
        from tools.verify_bundle import main
        rc = main(["--bundle", str(bad_file)])
        assert rc == 2

    def test_main_valid_bundle_returns_0(self, tmp_path):
        """Valid bundle returns exit code 0."""
        events = _build_chain(3)
        bundle = _make_bundle(events)
        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text(json.dumps(bundle))
        from tools.verify_bundle import main
        rc = main(["--bundle", str(bundle_file)])
        assert rc == 0

    def test_main_tampered_bundle_returns_1(self, tmp_path):
        """Tampered bundle returns exit code 1."""
        events = _build_chain(2)
        events[0]["payload_json"] = {"tampered": True}
        bundle = _make_bundle(events)
        bundle_file = tmp_path / "bad_bundle.json"
        bundle_file.write_text(json.dumps(bundle))
        from tools.verify_bundle import main
        rc = main(["--bundle", str(bundle_file)])
        assert rc == 1

    def test_main_json_output_flag(self, tmp_path):
        """--json flag produces JSON output."""
        import io
        import sys
        events = _build_chain(2)
        bundle = _make_bundle(events)
        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text(json.dumps(bundle))
        from tools.verify_bundle import main
        # Capture stdout
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            rc = main(["--bundle", str(bundle_file), "--json"])
        finally:
            sys.stdout = old_stdout
        assert rc == 0
        output = captured.getvalue()
        result_json = json.loads(output)
        assert "ok" in result_json
        assert result_json["ok"] is True
