from __future__ import annotations

from pathlib import Path
from tools.ci.route_checks import iter_route_records

REPO = Path(__file__).resolve().parents[2]
API_DIR = REPO / "api"


def test_ai_query_is_scoped_and_tenant_bound() -> None:
    found = []
    for rec in iter_route_records(API_DIR):
        if rec.method.upper() == "POST" and rec.full_path == "/ai/query":
            found.append(rec)

    assert len(found) == 1, f"expected exactly 1 /ai/query route, got {len(found)}"
    rec = found[0]

    assert rec.route_has_scope_dependency, "/ai/query must include scope dependency"
    assert rec.tenant_bound, "/ai/query must be tenant-bound"
    # /ai/query must accept explicit tenant header for unscoped keys (dev/env)
    if hasattr(rec, "tenant_explicit_unbound"):
        assert rec.tenant_explicit_unbound, (
            "/ai/query must be explicit-unbound tenant mode"
        )
    assert rec.route_has_any_dependency, "/ai/query must have dependencies"
