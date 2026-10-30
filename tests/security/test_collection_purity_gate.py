"""Tests for the collection-purity AST gate (SHARD2-COLLECTION-ISOLATION-002).

Verifies that check_collection_purity.py correctly:
  - Rejects module-scope os.environ.setdefault with security-critical vars
  - Rejects module-scope os.environ direct assignment
  - Rejects module-scope os.environ.update / pop / clear
  - Permits module-scope setdefault for explicitly-allowed vars
  - Permits function-scoped mutations (fixture isolation pattern)
  - Permits ordinary environment reads
  - Passes on the current test suite (zero violations)
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

# Ensure tools/ci is importable before the local import below.
_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.ci.check_collection_purity import check_file, main  # noqa: E402


def _write(tmp_path: Path, source: str) -> Path:
    p = tmp_path / "test_fake.py"
    p.write_text(textwrap.dedent(source))
    return p


# ---------------------------------------------------------------------------
# Rejection tests
# ---------------------------------------------------------------------------


class TestModuleScopeRejected:
    def test_rejects_setdefault_fg_auth_enabled_zero(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1
        assert "FG_AUTH_ENABLED" in violations[0][1]

    def test_rejects_setdefault_fg_auth_enabled_one(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_AUTH_ENABLED", "1")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1
        assert "FG_AUTH_ENABLED" in violations[0][1]

    def test_rejects_direct_assignment(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ["FG_AUTH_ENABLED"] = "0"
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1
        assert "direct assignment" in violations[0][1]

    def test_rejects_update(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.update({"FG_AUTH_ENABLED": "0"})
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_pop(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.pop("FG_SOME_KEY", None)
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_clear(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.clear()
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_putenv(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.putenv("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_unknown_var_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_SOME_NEW_SECURITY_VAR", "secret")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1
        assert "FG_SOME_NEW_SECURITY_VAR" in violations[0][1]


# ---------------------------------------------------------------------------
# Control-flow at module scope (bot finding: traverse if/try/with/for bodies)
# ---------------------------------------------------------------------------


class TestControlFlowAtModuleScope:
    def test_rejects_if_block_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            if True:
                os.environ.setdefault("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1
        assert "FG_AUTH_ENABLED" in violations[0][1]

    def test_rejects_try_body_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            try:
                os.environ.setdefault("FG_AUTH_ENABLED", "0")
            except Exception:
                pass
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_except_handler_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            try:
                pass
            except Exception:
                os.environ.setdefault("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_with_block_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            with open("/dev/null") as _f:
                os.environ.setdefault("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_rejects_for_loop_setdefault(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            for _ in []:
                os.environ.setdefault("FG_AUTH_ENABLED", "0")
            """,
        )
        violations = check_file(f)
        assert len(violations) == 1

    def test_permits_function_def_inside_if_block(self, tmp_path: Path) -> None:
        """Function body inside a module-level if is still fixture-scoped."""
        f = _write(
            tmp_path,
            """\
            import os
            if True:
                def helper():
                    os.environ["FG_AUTH_ENABLED"] = "0"
            """,
        )
        assert check_file(f) == []


# ---------------------------------------------------------------------------
# Permit tests
# ---------------------------------------------------------------------------


class TestPermitted:
    def test_permits_setdefault_fg_env(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_ENV", "test")
            """,
        )
        assert check_file(f) == []

    def test_permits_setdefault_fg_acknowledgment_key(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly!!!!!!")
            """,
        )
        assert check_file(f) == []

    def test_permits_setdefault_fg_report_signing_key(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)
            """,
        )
        assert check_file(f) == []

    def test_permits_fixture_scoped_monkeypatch(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import pytest

            @pytest.fixture()
            def client(monkeypatch):
                monkeypatch.setenv("FG_AUTH_ENABLED", "0")
                yield
            """,
        )
        assert check_file(f) == []

    def test_permits_function_scoped_os_environ_mutation(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os

            def test_something():
                os.environ["FG_AUTH_ENABLED"] = "0"
                try:
                    pass
                finally:
                    os.environ.pop("FG_AUTH_ENABLED", None)
            """,
        )
        assert check_file(f) == []

    def test_permits_environment_read(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            _KEY = os.environ.get("FG_API_KEY", "")
            _VAL = os.environ["FG_ENV"] if "FG_ENV" in os.environ else "test"
            """,
        )
        assert check_file(f) == []

    def test_permits_patch_dict_inside_function(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path,
            """\
            import os
            from unittest.mock import patch

            def test_something():
                with patch.dict(os.environ, {"FG_AUTH_ENABLED": "0"}):
                    pass
            """,
        )
        assert check_file(f) == []


# ---------------------------------------------------------------------------
# Integration: current test suite must have zero violations
# ---------------------------------------------------------------------------


def test_current_test_suite_has_zero_violations() -> None:
    """The live test suite must pass the collection-purity guard."""
    result = main(["--repo", str(_REPO)])
    assert result == 0, (
        "Collection-purity guard found violations in the current test suite. "
        "Run: python tools/ci/check_collection_purity.py --repo . --verbose"
    )
