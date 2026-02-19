from __future__ import annotations

import json
from pathlib import Path

SEED_PATH = Path("seeds/rag_stub_sources_v1.json")


def retrieve(tenant_id: str, query: str) -> dict[str, object]:
    if not tenant_id:
        raise ValueError("AI_TENANT_REQUIRED")
    _ = query
    if not SEED_PATH.exists():
        sources: list[dict[str, object]] = []
    else:
        payload = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        sources = payload.get("sources", []) if isinstance(payload, dict) else []
    return {
        "ok": True,
        "sources": sources,
        "retrieval_id": "stub",
    }
