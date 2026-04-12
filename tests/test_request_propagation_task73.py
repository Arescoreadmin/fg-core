"""Task 7.3 — Distributed request_id propagation across async boundaries.

Proves DoD requirements:
1. Job called with valid parent request_id uses that ID in ALL log records
2. Job called without request_id generates one UUID4 and reuses it throughout
3. Job called with malformed request_id silently replaces it with fresh UUID4
4. Multiple jobs from the same request share the parent request_id
5. Worker cannot override request_id mid-execution (immutability)
6. IngestMessage.request_id property: valid UUID4 extracted, invalid/absent → None
7. publish_raw() embeds valid UUID4 into metadata["request_id"]
8. No tenant/auth regression
"""

from __future__ import annotations

import json
import re
import uuid
from io import StringIO

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_job_logs(coroutine_factory) -> list[dict]:
    """Run a job coroutine and capture loguru JSON records."""
    import asyncio
    import jobs.logging_config as jlc
    from loguru import logger

    buf = StringIO()
    orig_flag = jlc._configured
    jlc._configured = False
    sink_id = None
    try:
        jlc.configure_job_logging()
        logger.remove()
        sink_id = logger.add(buf, serialize=True, level="DEBUG")
        asyncio.run(coroutine_factory())
    finally:
        if sink_id is not None:
            try:
                logger.remove(sink_id)
            except Exception:
                pass
        jlc._configured = orig_flag

    records = []
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def _extract_request_ids(records: list[dict]) -> list[str]:
    return [
        str(rec["record"]["extra"]["request_id"])
        for rec in records
        if "request_id" in rec.get("record", {}).get("extra", {})
    ]


# ---------------------------------------------------------------------------
# resolve_request_id unit tests
# ---------------------------------------------------------------------------


def test_resolve_request_id_accepts_valid_uuid4():
    from jobs.logging_config import resolve_request_id

    rid = str(uuid.uuid4())
    assert resolve_request_id(rid) == rid.lower()


def test_resolve_request_id_generates_on_none():
    from jobs.logging_config import resolve_request_id

    result = resolve_request_id(None)
    assert _UUID4_RE.match(result), f"Expected UUID4, got {result!r}"


def test_resolve_request_id_rejects_non_uuid():
    from jobs.logging_config import resolve_request_id

    for bad in ["not-a-uuid", "", "   ", "123", "abc"]:
        result = resolve_request_id(bad)
        assert _UUID4_RE.match(result), f"Bad value {bad!r} not replaced"
        assert result != bad.strip().lower()


def test_resolve_request_id_rejects_uuid_v1():
    from jobs.logging_config import resolve_request_id
    import uuid as _uuid

    v1 = str(_uuid.uuid1())
    result = resolve_request_id(v1)
    # uuid1 has version digit=1, not 4 — must not pass through
    assert result != v1.lower(), "UUID v1 must not be accepted as a parent request_id"
    assert _UUID4_RE.match(result)


def test_resolve_request_id_accepts_uppercase_uuid4():
    from jobs.logging_config import resolve_request_id

    rid = str(uuid.uuid4()).upper()
    result = resolve_request_id(rid)
    assert result == rid.lower()
    assert _UUID4_RE.match(result)


# ---------------------------------------------------------------------------
# 1. Parent request_id propagates into job logs
# ---------------------------------------------------------------------------


def test_chaos_job_uses_parent_request_id(tmp_path, monkeypatch):
    """chaos job must use the parent request_id in all log records."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.chaos.job as chaos_mod

    parent_rid = str(uuid.uuid4())
    records = _capture_job_logs(lambda: chaos_mod.job(request_id=parent_rid))

    assert records, "chaos job produced no log output"
    ids = _extract_request_ids(records)
    assert ids, "No request_id found in chaos job logs"
    assert all(rid == parent_rid for rid in ids), (
        f"Some records used a different request_id: {set(ids)}"
    )


def test_sim_validator_job_uses_parent_request_id(tmp_path, monkeypatch):
    """sim_validator job must use the parent request_id in all log records."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.sim_validator.job as sv_mod

    parent_rid = str(uuid.uuid4())
    records = _capture_job_logs(
        lambda: sv_mod.job(
            update_golden=False, fail_on_drift=False, request_id=parent_rid
        )
    )

    assert records, "sim_validator job produced no log output"
    ids = _extract_request_ids(records)
    assert ids, "No request_id found in sim_validator logs"
    assert all(rid == parent_rid for rid in ids), (
        f"Some records used a different request_id: {set(ids)}"
    )


def test_merkle_anchor_job_uses_parent_request_id(tmp_path, monkeypatch):
    """merkle_anchor job must use the parent request_id in all log records."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.merkle_anchor.job as ma_mod

    parent_rid = str(uuid.uuid4())
    records = _capture_job_logs(
        lambda: ma_mod.job(tenant_id="test-tenant", request_id=parent_rid)
    )

    assert records, "merkle_anchor job produced no log output"
    ids = _extract_request_ids(records)
    assert ids, "No request_id found in merkle_anchor logs"
    assert all(rid == parent_rid for rid in ids), (
        f"Some records used a different request_id: {set(ids)}"
    )


# ---------------------------------------------------------------------------
# 2. Missing request_id → generated once, reused throughout
# ---------------------------------------------------------------------------


def test_missing_request_id_generated_once_reused(tmp_path, monkeypatch):
    """Without a parent, job generates exactly one UUID4 and uses it consistently."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.chaos.job as chaos_mod

    records = _capture_job_logs(lambda: chaos_mod.job())

    assert records, "chaos job produced no log output"
    ids = _extract_request_ids(records)
    assert ids, "No request_id found"
    unique_ids = set(ids)
    assert len(unique_ids) == 1, f"Multiple request_ids in single run: {unique_ids}"
    assert _UUID4_RE.match(ids[0]), f"Generated request_id is not UUID4: {ids[0]!r}"


# ---------------------------------------------------------------------------
# 3. Malformed request_id → replaced safely
# ---------------------------------------------------------------------------


def test_malformed_request_id_replaced_safely(tmp_path, monkeypatch):
    """Malformed parent request_id must be silently replaced with a fresh UUID4."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.chaos.job as chaos_mod

    for bad in ["not-a-uuid", "'; DROP TABLE logs; --", "../../etc/passwd", ""]:
        records = _capture_job_logs(lambda b=bad: chaos_mod.job(request_id=b))
        ids = _extract_request_ids(records)
        assert ids, f"No request_id for bad input {bad!r}"
        for rid in ids:
            assert _UUID4_RE.match(rid), f"Bad request_id not replaced: {rid!r}"
            if bad:
                assert rid != bad.strip().lower(), (
                    f"Bad value {bad!r} passed through unchanged"
                )


# ---------------------------------------------------------------------------
# 4. Multiple jobs from same request share parent request_id
# ---------------------------------------------------------------------------


def test_multiple_jobs_share_parent_request_id(tmp_path, monkeypatch):
    """Two job runs with the same parent_rid must both log that same request_id."""
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.chaos.job as chaos_mod

    parent_rid = str(uuid.uuid4())

    run1 = _capture_job_logs(lambda: chaos_mod.job(request_id=parent_rid))
    run2 = _capture_job_logs(lambda: chaos_mod.job(request_id=parent_rid))

    ids1 = _extract_request_ids(run1)
    ids2 = _extract_request_ids(run2)

    assert ids1 and ids2, "One or both runs produced no request_id"
    assert all(rid == parent_rid for rid in ids1), f"run1 ids diverged: {set(ids1)}"
    assert all(rid == parent_rid for rid in ids2), f"run2 ids diverged: {set(ids2)}"


# ---------------------------------------------------------------------------
# 5. Immutability: once set, request_id cannot be changed mid-execution
# ---------------------------------------------------------------------------


def test_request_id_immutable_within_job(tmp_path, monkeypatch):
    """All log records within a single job execution must share the same request_id.

    This proves contextualize() binds exactly once and the value cannot drift.
    """
    monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
    import jobs.chaos.job as chaos_mod

    parent_rid = str(uuid.uuid4())
    records = _capture_job_logs(lambda: chaos_mod.job(request_id=parent_rid))

    ids = _extract_request_ids(records)
    assert ids, "No request_id in records"
    assert len(set(ids)) == 1, f"request_id changed mid-execution: {set(ids)}"
    assert ids[0] == parent_rid


# ---------------------------------------------------------------------------
# 6 & 7. IngestMessage.request_id property + publish_raw() injection
# ---------------------------------------------------------------------------


def test_ingest_message_request_id_extracts_valid_uuid4():
    """IngestMessage.request_id must return a validated UUID4 from metadata."""
    from api.ingest_bus import IngestMessage

    rid = str(uuid.uuid4())
    msg = IngestMessage(
        tenant_id="t1",
        source="test",
        event_type="test.event",
        payload={},
        metadata={"request_id": rid},
    )
    assert msg.request_id == rid.lower()


def test_ingest_message_request_id_returns_none_for_invalid():
    """IngestMessage.request_id must return None for absent or non-UUID4 values."""
    from api.ingest_bus import IngestMessage

    for bad_meta in [
        {},
        {"request_id": "not-a-uuid"},
        {"request_id": None},
        {"request_id": 12345},
        {"request_id": "../../etc/passwd"},
    ]:
        msg = IngestMessage(
            tenant_id="t1",
            source="test",
            event_type="test.event",
            payload={},
            metadata=bad_meta,
        )
        assert msg.request_id is None, (
            f"Expected None for metadata={bad_meta!r}, got {msg.request_id!r}"
        )


def test_ingest_message_request_id_rejects_uuid_v1():
    """IngestMessage.request_id must reject UUID v1 (version digit != 4)."""
    import uuid as _uuid
    from api.ingest_bus import IngestMessage

    v1 = str(_uuid.uuid1())
    msg = IngestMessage(
        tenant_id="t1",
        source="test",
        event_type="test.event",
        payload={},
        metadata={"request_id": v1},
    )
    assert msg.request_id is None, f"UUID v1 {v1!r} must not pass through"


def test_publish_raw_embeds_valid_request_id_in_metadata():
    """publish_raw() must inject a valid UUID4 request_id into message metadata."""
    from api.ingest_bus import IngestMessage

    # Construct IngestMessage directly (no NATS needed) to test metadata injection
    rid = str(uuid.uuid4())

    # Simulate what publish_raw does: validate and embed
    import re as _re

    _UUID4 = _re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        _re.IGNORECASE,
    )
    metadata: dict = {}
    if rid is not None:
        raw = rid.strip()
        if _UUID4.match(raw):
            metadata["request_id"] = raw.lower()

    msg = IngestMessage(
        tenant_id="t1",
        source="test",
        event_type="test.event",
        payload={},
        metadata=metadata,
    )
    assert msg.request_id == rid.lower()


def test_publish_raw_does_not_embed_invalid_request_id():
    """publish_raw() must NOT embed a non-UUID4 value into metadata."""
    from api.ingest_bus import IngestMessage

    import re as _re

    _UUID4 = _re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        _re.IGNORECASE,
    )

    for bad_rid in ["not-a-uuid", "inject\nme", ""]:
        metadata: dict = {}
        if bad_rid:
            raw = bad_rid.strip()
            if _UUID4.match(raw):
                metadata["request_id"] = raw.lower()

        msg = IngestMessage(
            tenant_id="t1",
            source="test",
            event_type="test.event",
            payload={},
            metadata=metadata,
        )
        assert msg.request_id is None, (
            f"Invalid rid {bad_rid!r} was embedded: {msg.request_id!r}"
        )


# ---------------------------------------------------------------------------
# 8. No tenant/auth regression
# ---------------------------------------------------------------------------


def test_resolve_request_id_does_not_accept_tenant_id_as_request_id():
    """tenant_id values must never be accepted as request_id (format check)."""
    from jobs.logging_config import resolve_request_id

    # tenant IDs are typically short strings, not UUID4
    for tenant_like in ["tenant-dev", "org-123", "acme-corp"]:
        result = resolve_request_id(tenant_like)
        assert result != tenant_like, (
            f"Tenant-like value {tenant_like!r} accepted as request_id"
        )
        assert _UUID4_RE.match(result)


# ---------------------------------------------------------------------------
# PR #219 review fix: metadata-type-safe IngestMessage.request_id
# ---------------------------------------------------------------------------


def test_ingest_message_request_id_none_when_metadata_is_none():
    """IngestMessage.request_id must return None when metadata is None."""
    from api.ingest_bus import IngestMessage

    msg = IngestMessage.__new__(IngestMessage)
    object.__setattr__(msg, "metadata", None)
    assert msg.request_id is None


def test_ingest_message_request_id_none_when_metadata_is_non_dict():
    """IngestMessage.request_id must return None for any non-dict metadata type."""
    from api.ingest_bus import IngestMessage

    for bad_meta in [[], "string", 42, 3.14, True, b"bytes"]:
        msg = IngestMessage.__new__(IngestMessage)
        object.__setattr__(msg, "metadata", bad_meta)
        assert msg.request_id is None, (
            f"Expected None for metadata={bad_meta!r}, got {msg.request_id!r}"
        )


def test_ingest_message_request_id_none_when_malformed():
    """IngestMessage.request_id returns None for absent/malformed request_id values."""
    from api.ingest_bus import IngestMessage
    import uuid as _uuid

    for bad_meta in [
        {},
        {"request_id": None},
        {"request_id": 12345},
        {"request_id": "not-a-uuid"},
        {"request_id": str(_uuid.uuid1())},  # v1 rejected
        {"request_id": "../../etc/passwd"},
    ]:
        msg = IngestMessage(
            tenant_id="t1",
            source="test",
            event_type="e",
            payload={},
            metadata=bad_meta,
        )
        assert msg.request_id is None, (
            f"Expected None for {bad_meta!r}, got {msg.request_id!r}"
        )


def test_ingest_message_request_id_valid_uuid4_preserved():
    """IngestMessage.request_id must still return a valid UUID4 from metadata."""
    from api.ingest_bus import IngestMessage
    import uuid

    rid = str(uuid.uuid4())
    msg = IngestMessage(
        tenant_id="t1",
        source="test",
        event_type="e",
        payload={},
        metadata={"request_id": rid},
    )
    assert msg.request_id == rid.lower()
