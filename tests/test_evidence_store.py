from __future__ import annotations

import pytest

from api.evidence_store import EvidenceStoreAccessError, LocalFileEvidenceStore


def test_evidence_store_scope_and_tenant_guard(tmp_path):
    store = LocalFileEvidenceStore(tmp_path)
    uri, size = store.put_atomic(tenant_id="t1", export_id="job-1-abc", content=b"{}")
    assert uri.startswith("file://")
    assert size == 2

    with pytest.raises(EvidenceStoreAccessError):
        store.get_bytes(tenant_id="t1", export_id="job-1-abc", scopes={"audit:read"})

    got = store.get_bytes(tenant_id="t1", export_id="job-1-abc", scopes={"audit:evidence:read"})
    assert got == b"{}"


def test_evidence_store_list_requires_job_filter(tmp_path):
    store = LocalFileEvidenceStore(tmp_path)
    store.put_atomic(tenant_id="t1", export_id="job-2-a", content=b"{}")
    store.put_atomic(tenant_id="t1", export_id="job-2-b", content=b"{}")

    with pytest.raises(EvidenceStoreAccessError):
        store.list_export_ids(tenant_id="t1", job_id="", scopes={"audit:evidence:read"})

    listed = store.list_export_ids(tenant_id="t1", job_id="job-2", scopes={"audit:evidence:read"})
    assert listed == ["job-2-a", "job-2-b"]
