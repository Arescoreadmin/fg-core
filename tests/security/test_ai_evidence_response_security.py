from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.db import get_sessionmaker
from services.ai.providers.base import ProviderResponse
from tests.test_ai_plane_extension import _seed_persisted_chunks, _setup_client


def test_ai_evidence_response_does_not_leak_cross_tenant_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, key_b = _setup_client(tmp_path, ai_enabled=True)
    with get_sessionmaker()() as db:
        _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[
                {
                    "text": "alpha cross tenant secret evidence",
                    "ordinal": 0,
                    "source_hash": "a" * 64,
                }
            ],
        )

    def _provider(**_kw) -> ProviderResponse:
        raise AssertionError("provider must not run without tenant-scoped evidence")

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)
    resp = client.post(
        "/ai/infer",
        json={"query": "alpha cross tenant secret"},
        headers={"X-API-Key": key_b},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == "NO_ANSWER"
    assert body["evidence"] == []
    assert body["evidence_response"]["evidence"] == []
    assert body["provenance"]["source_summaries"] == []
    assert body["risk_score"] >= 0.75
    assert "alpha cross tenant secret evidence" not in json.dumps(body, sort_keys=True)


def test_ai_evidence_response_export_surface_excludes_unsafe_internals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    with get_sessionmaker()() as db:
        chunks = _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[
                {
                    "text": "alpha export evidence secretphrase",
                    "ordinal": 0,
                    "source_hash": "b" * 64,
                }
            ],
        )
    chunk_id = str(chunks[0]["chunk_id"])

    def _provider(**_kw) -> ProviderResponse:
        return ProviderResponse(
            provider_id="simulated",
            text=f"alpha export evidence [chunk_id={chunk_id}]",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)
    resp = client.post(
        "/ai/infer",
        json={"query": "alpha export", "compliance_mode": "internal_ops"},
        headers={"X-API-Key": key_a},
    )

    assert resp.status_code == 200
    evidence_response = resp.json()["evidence_response"]
    serialized = json.dumps(evidence_response, sort_keys=True).lower()
    assert "secretphrase" not in serialized
    assert "prompt" not in serialized
    assert "provider_payload" not in serialized
    assert "embedding" not in serialized
    assert "vector" not in serialized
    assert "tenant_id" not in serialized
