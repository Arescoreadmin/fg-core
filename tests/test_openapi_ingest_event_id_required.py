from __future__ import annotations

import json
from pathlib import Path

from api.main import build_contract_app


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


def test_contract_app_openapi_uses_canonical_ingest_request_ref() -> None:
    spec = build_contract_app().openapi()

    schema_ref = spec["paths"]["/ingest"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    assert schema_ref == "#/components/schemas/IngestRequest"
    assert "api__ingest_schemas__IngestRequest" not in spec["components"]["schemas"]
