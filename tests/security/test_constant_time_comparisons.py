"""Regression tests: all secret/hash/token comparisons use hmac.compare_digest.

Each test monkeypatches hmac.compare_digest, exercises the code path, and
asserts the patched function was actually invoked.  This catches accidental
regressions to ``==`` / ``!=`` operators on security-sensitive values.
"""

from __future__ import annotations

import ast
import hmac
import types
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _CompareDigestTracker:
    """Drop-in for hmac.compare_digest that records every call."""

    def __init__(self):
        self.calls: list[tuple] = []
        self._real = hmac.compare_digest

    def __call__(self, a, b):
        self.calls.append((a, b))
        return self._real(a, b)

    @property
    def called(self) -> bool:
        return len(self.calls) > 0


# ---------------------------------------------------------------------------
# 1) OIDC nonce verification
# ---------------------------------------------------------------------------


def test_nonce_uses_compare_digest():
    """admin_gateway/auth.py verify_id_token must use compare_digest for nonce.

    The file is shadowed by the admin_gateway/auth/ package so it cannot be
    imported normally.  We parse the AST and verify the function body calls
    hmac.compare_digest (and never uses == / != on the nonce).
    """
    auth_py = Path(__file__).resolve().parents[2] / "admin_gateway" / "auth.py"
    source = auth_py.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(auth_py))

    # Locate the verify_id_token function
    func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "verify_id_token":
            func = node
            break
    assert func is not None, "verify_id_token not found in admin_gateway/auth.py"

    # Walk the function body and collect:
    # 1. All calls to *.compare_digest(...)
    # 2. All == / != Compare nodes where an operand is a nonce-related Name
    nonce_names = {"nonce", "claim_nonce"}
    found_compare_digest = False
    found_timing_unsafe_nonce = False

    for node in ast.walk(func):
        # Structural check: call to <anything>.compare_digest(...)
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "compare_digest":
                found_compare_digest = True

        # Structural check: Compare node with Eq/NotEq where an operand
        # is a Name node whose id matches a nonce variable.
        if isinstance(node, ast.Compare):
            has_unsafe_op = any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops)
            if has_unsafe_op:
                operands = [node.left] + list(node.comparators)
                for operand in operands:
                    if isinstance(operand, ast.Name) and operand.id in nonce_names:
                        found_timing_unsafe_nonce = True

    assert found_compare_digest, (
        "verify_id_token does not call hmac.compare_digest — "
        "nonce comparison is timing-vulnerable"
    )
    assert not found_timing_unsafe_nonce, (
        "verify_id_token uses == or != on nonce — must use hmac.compare_digest"
    )


# ---------------------------------------------------------------------------
# 2) CSRF token comparison (ui_dashboards._ensure_csrf)
# ---------------------------------------------------------------------------


def test_csrf_uses_compare_digest(monkeypatch):
    """api.ui_dashboards._ensure_csrf must use compare_digest."""
    tracker = _CompareDigestTracker()
    monkeypatch.setattr(hmac, "compare_digest", tracker)

    import api.ui_dashboards as ui_mod

    csrf_token = "random-csrf-token-value"

    # Build a minimal request stub
    request = types.SimpleNamespace(
        headers={ui_mod.CSRF_HEADER_NAME: csrf_token},
        cookies={ui_mod.CSRF_COOKIE_NAME: csrf_token},
    )

    # Should not raise — tokens match
    ui_mod._ensure_csrf(request)

    assert tracker.called, "hmac.compare_digest was NOT called for CSRF comparison"
    assert any(csrf_token in pair for pair in tracker.calls), (
        f"CSRF token not found in compare_digest calls: {tracker.calls}"
    )


# ---------------------------------------------------------------------------
# 3) Evidence chain verification
# ---------------------------------------------------------------------------


def test_chain_verify_uses_compare_digest(monkeypatch):
    """api.evidence_chain.verify_chain_for_tenant must use compare_digest."""
    tracker = _CompareDigestTracker()
    monkeypatch.setattr(hmac, "compare_digest", tracker)

    import api.evidence_chain as chain_mod

    # Build a minimal in-memory chain of one record
    now = datetime.now(timezone.utc)
    prev_hash = chain_mod.GENESIS_HASH
    payload = chain_mod.build_chain_payload(
        tenant_id="t1",
        request_json={"action": "test"},
        response_json={"decision": "allow"},
        threat_level="low",
        chain_ts=now,
        event_id="evt-1",
    )
    chain_hash = chain_mod.compute_chain_hash(prev_hash, payload)

    # Create a fake record object (mimics SQLAlchemy row)
    record = types.SimpleNamespace(
        id=1,
        tenant_id="t1",
        chain_hash=chain_hash,
        chain_alg=chain_mod.CHAIN_ALG,
        chain_ts=now,
        prev_hash=prev_hash,
        request_json={"action": "test"},
        response_json={"decision": "allow"},
        threat_level="low",
        event_id="evt-1",
    )

    # Patch the DB query to yield our fake record
    class FakeQuery:
        def filter(self, *_a):
            return self

        def order_by(self, *_a):
            return self

        def limit(self, *_a):
            return self

        def __iter__(self):
            return iter([record])

    class FakeDB:
        def query(self, *_a):
            return FakeQuery()

    result = chain_mod.verify_chain_for_tenant(FakeDB(), "t1")

    assert result["ok"] is True
    assert tracker.called, "hmac.compare_digest was NOT called for chain verification"
    # Should have been called at least twice: prev_hash + chain_hash
    assert len(tracker.calls) >= 2, (
        f"Expected >= 2 compare_digest calls (prev_hash + chain_hash), "
        f"got {len(tracker.calls)}"
    )


# ---------------------------------------------------------------------------
# 4) Merkle anchor verification
# ---------------------------------------------------------------------------


def test_anchor_verify_uses_compare_digest(monkeypatch):
    """jobs.merkle_anchor.job.verify_anchor_record must use compare_digest."""
    tracker = _CompareDigestTracker()
    monkeypatch.setattr(hmac, "compare_digest", tracker)

    import jobs.merkle_anchor.job as anchor_mod

    # Build a valid anchor record
    leaf_hashes = [
        anchor_mod.sha256_hex("entry-1"),
        anchor_mod.sha256_hex("entry-2"),
    ]
    tree = anchor_mod.MerkleTree(leaf_hashes)

    record_without_hash = {
        "window_start": "2025-01-01T00:00:00Z",
        "window_end": "2025-01-01T01:00:00Z",
        "entry_count": 2,
        "leaf_hashes": leaf_hashes,
        "merkle_root": tree.root,
        "prev_anchor_hash": None,
    }
    anchor_hash = anchor_mod.sha256_hex(anchor_mod.canonical_json(record_without_hash))
    record = {**record_without_hash, "anchor_hash": anchor_hash}

    is_valid, msg = anchor_mod.verify_anchor_record(record)

    assert is_valid, f"Anchor record should be valid: {msg}"
    assert tracker.called, "hmac.compare_digest was NOT called for anchor verification"
    # Should be called at least twice: anchor_hash + merkle_root
    assert len(tracker.calls) >= 2, (
        f"Expected >= 2 compare_digest calls (anchor_hash + merkle_root), "
        f"got {len(tracker.calls)}"
    )
