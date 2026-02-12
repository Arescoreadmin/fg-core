from __future__ import annotations

import inspect
from pathlib import Path

from api.public_paths import LINTER_PUBLIC_PATH_PREFIXES
from tools.ci.route_checks import is_public_path, iter_route_records

FIXTURE_ROOT = Path("tools/ci/fixtures")


def _records_for(file_name: str):
    all_records = iter_route_records(FIXTURE_ROOT)
    return [r for r in all_records if r.file_path.name == file_name]


def test_db_checker_fixture_catches_non_public_get_db_usage() -> None:
    records = _records_for("bad_db_dependency.py")
    bad = [
        r
        for r in records
        if not is_public_path(r.full_path) and r.route_has_db_dependency
    ]
    assert bad, "Expected fixture to be detected as Depends(get_db) violation"


def test_scope_checker_fixture_catches_missing_scope() -> None:
    records = _records_for("missing_scope_route.py")
    missing = [
        r
        for r in records
        if not is_public_path(r.full_path) and not r.route_has_scope_dependency
    ]
    assert missing, "Expected fixture to be detected as missing scope dependency"


def test_scope_checker_fixture_accepts_good_route() -> None:
    records = _records_for("good_scoped_route.py")
    assert records and all(r.route_has_scope_dependency for r in records)


def test_public_route_exemptions_allow_get_db() -> None:
    records = _records_for("public_route.py")
    assert records and all(is_public_path(r.full_path) for r in records)
    assert records[0].route_has_db_dependency


def test_route_checker_uses_canonical_public_paths() -> None:
    from tools.ci import route_checks

    assert route_checks.PUBLIC_PATH_PREFIXES == LINTER_PUBLIC_PATH_PREFIXES
    assert (
        "from api.public_paths import LINTER_PUBLIC_PATH_PREFIXES"
        in inspect.getsource(route_checks)
    )
