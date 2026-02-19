from __future__ import annotations

from services.agent_log_integrity import IntegrityLogChain


def test_chain_continuity_verified(tmp_path):
    path = tmp_path / "integrity.log"
    chain = IntegrityLogChain(str(path))
    chain.append("boot", {"ok": True})
    chain.append("heartbeat", {"n": 1})
    assert chain.verify()


def test_log_modification_detected(tmp_path):
    path = tmp_path / "integrity.log"
    chain = IntegrityLogChain(str(path))
    chain.append("boot", {"ok": True})
    raw = path.read_text().replace("boot", "tamper")
    path.write_text(raw)
    assert not chain.verify()


def test_anchor_mismatch_detected(tmp_path):
    path = tmp_path / "integrity.log"
    chain = IntegrityLogChain(str(path))
    chain.append("boot", {"ok": True})
    asserted_anchor = "0" * 64
    assert chain.latest_hash() != asserted_anchor
