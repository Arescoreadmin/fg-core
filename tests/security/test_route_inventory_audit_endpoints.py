from __future__ import annotations

from pathlib import Path

from tools.ci.route_checks import iter_route_records, is_public_path

REPO = Path(__file__).resolve().parents[2]
API_DIR = REPO / "api"

TARGETS: set[tuple[str, str]] = {
    ("GET", "/audit/exams/{exam_id}/export"),
    ("POST", "/audit/exams/{exam_id}/reproduce"),
    ("POST", "/audit/reproduce"),
}


def test_audit_reproduce_routes_are_scoped_and_tenant_bound() -> None:
    found: dict[tuple[str, str], list[object]] = {k: [] for k in TARGETS}

    for rec in iter_route_records(API_DIR):
        key = (rec.method.upper(), rec.full_path)
        if key in found:
            found[key].append(rec)

    missing = [k for k, recs in found.items() if not recs]
    assert not missing, f"Missing expected audit routes: {missing}"

    duplicates = {k: len(v) for k, v in found.items() if len(v) > 1}
    assert not duplicates, f"Duplicate route records detected: {duplicates}"

    for (method, path), recs in found.items():
        rec = recs[0]
        assert not is_public_path(rec.full_path), f"{method} {path} treated as public"
        assert rec.route_has_scope_dependency, (
            f"{method} {path} missing scope dependency"
        )
        assert rec.tenant_bound, f"{method} {path} must be tenant-bound"
        assert rec.route_has_any_dependency, f"{method} {path} must have dependencies"
