from __future__ import annotations

import json
from pathlib import Path


def test_openapi_ingest_requires_event_id() -> None:
    spec = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))

    ingest_path = spec["paths"].get("/ingest", {})
    assert "post" in ingest_path

    schema_ref = ingest_path["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["$ref"]
    assert schema_ref == "#/components/schemas/IngestRequest"

    ingest_schema = spec["components"]["schemas"]["IngestRequest"]
    assert "event_id" in ingest_schema.get("required", [])

    bad_request = ingest_path["post"]["responses"].get("400")
    assert bad_request is not None
