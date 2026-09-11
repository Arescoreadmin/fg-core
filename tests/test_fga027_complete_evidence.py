from types import SimpleNamespace

import pytest

from api import field_assessment as fa


def _rows(count: int, tenant: str = "tenant-a", engagement: str = "eng-a"):
    return [
        SimpleNamespace(
            id=f"ev-{i:04d}",
            source_type="scan",
            collected_at=f"2026-01-01T00:00:{i % 60:02d}+00:00",
            evidence_hash=f"hash-{i:04d}",
            tenant_id=tenant,
            engagement_id=engagement,
        )
        for i in range(count)
    ]


def test_complete_population_exceeds_100_and_is_canonical(monkeypatch):
    rows = _rows(205)

    def fetch(*, limit, offset, **kwargs):
        assert kwargs == {"db": "db", "engagement_id": "eng-a", "tenant_id": "tenant-a"}
        return list(reversed(rows))[offset : offset + limit]

    monkeypatch.setattr(fa, "list_scan_results", fetch)
    result, metadata = fa._fetch_complete_scan_evidence(
        db="db", engagement_id="eng-a", tenant_id="tenant-a"
    )

    assert len(result) == 205
    assert [row.id for row in result] == sorted(row.id for row in rows)
    assert metadata["eligible_count"] == 205
    assert metadata["excluded_count"] == 0


def test_population_fingerprint_is_order_invariant(monkeypatch):
    rows = _rows(3)
    order = [rows, list(reversed(rows))]

    def fetch(*, limit, offset, **kwargs):
        return order.pop(0)[offset : offset + limit]

    monkeypatch.setattr(fa, "list_scan_results", fetch)
    _, first = fa._fetch_complete_scan_evidence(
        db="db", engagement_id="eng-a", tenant_id="tenant-a"
    )
    _, second = fa._fetch_complete_scan_evidence(
        db="db", engagement_id="eng-a", tenant_id="tenant-a"
    )
    assert first["fingerprint"] == second["fingerprint"]


def test_partial_page_failure_fails_closed(monkeypatch):
    rows = _rows(101)

    def fetch(*, limit, offset, **kwargs):
        if offset >= 100:
            raise RuntimeError("backend unavailable")
        return rows[offset : offset + limit]

    monkeypatch.setattr(fa, "list_scan_results", fetch)
    with pytest.raises(RuntimeError, match="backend unavailable"):
        fa._fetch_complete_scan_evidence(
            db="db", engagement_id="eng-a", tenant_id="tenant-a"
        )


def test_duplicate_evidence_identity_fails_closed(monkeypatch):
    rows = _rows(2)
    rows[1].id = rows[0].id
    monkeypatch.setattr(fa, "list_scan_results", lambda **kwargs: rows)
    with pytest.raises(RuntimeError, match="duplicate identity"):
        fa._fetch_complete_scan_evidence(
            db="db", engagement_id="eng-a", tenant_id="tenant-a"
        )
