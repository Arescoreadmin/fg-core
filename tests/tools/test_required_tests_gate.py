from __future__ import annotations

from tools.testing.harness.required_tests_gate import (
    ChangedFile,
    _category_input_paths,
    _required_categories,
    _verify_required_tests_changed,
)


def test_required_categories_from_ownership_map() -> None:
    ownership = {
        "owners": [
            {"path_globs": ["api/**"], "required_categories": ["unit", "security"]},
            {"path_globs": ["docs/**"], "required_categories": ["contract"]},
        ]
    }
    changed = ["api/control_plane_v2.py"]
    assert _required_categories(changed, ownership) == {"unit", "security"}


def test_missing_required_test_changes_fails() -> None:
    policy = {
        "categories": {
            "security": {"required_test_globs": ["tests/security/**/*.py"]},
        }
    }
    failures = _verify_required_tests_changed(
        ["api/control_plane_v2.py"], {"security"}, policy
    )
    assert failures
    assert failures[0].category == "security"


def test_category_paths_ignore_deleted_and_include_renamed_from_path() -> None:
    changed = [
        ChangedFile(status="D", path="api/deleted.py"),
        ChangedFile(status="R100", path="api/new.py", previous_path="api/old.py"),
    ]
    assert _category_input_paths(changed) == ["api/new.py", "api/old.py"]


def test_unit_glob_matches_top_level_tests_dir() -> None:
    # Regression: PurePosixPath.match("tests/**/*.py") returns False for
    # files directly under tests/ in Python 3.12 (** requires >=1 intermediate
    # dir). Policy must include tests/*.py so that tests/test_foo.py satisfies
    # the unit category.
    policy = {
        "categories": {
            "unit": {"required_test_globs": ["tests/*.py", "tests/**/*.py"]},
        }
    }
    top_level = ["tests/test_main_integrity.py"]
    failures = _verify_required_tests_changed(top_level, {"unit"}, policy)
    assert not failures, f"Expected unit satisfied by tests/*.py, got: {failures}"

    nested = ["tests/tools/test_triage_v2.py"]
    failures = _verify_required_tests_changed(nested, {"unit"}, policy)
    assert not failures, f"Expected unit satisfied by tests/**/*.py, got: {failures}"


def test_testing_module_security_category_accepts_recognized_tools_test() -> None:
    # The testing_module ownership entry maps tools/testing/** and selected
    # tooling surfaces to required categories including security. This keeps a
    # recognized tests/tools delta tied to that module so the gate does not
    # treat tooling-only changes as missing security coverage.
    policy = {
        "categories": {
            "security": {
                "required_test_globs": [
                    "tests/tools/*.py",
                    "tests/tools/**/*.py",
                ]
            },
        }
    }

    changed = ["tests/tools/test_required_tests_gate.py"]
    failures = _verify_required_tests_changed(changed, {"security"}, policy)

    assert not failures, (
        "Expected tests/tools/test_required_tests_gate.py to satisfy the "
        f"security category for testing-module coverage, got: {failures}"
    )
