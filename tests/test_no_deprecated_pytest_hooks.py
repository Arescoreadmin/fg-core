"""Guard: ensure no conftest or plugin re-introduces the deprecated
``pytest_ignore_collect(path: py.path.local, ...)`` signature.

pytest >= 7.0 replaced the ``path`` (py.path.local) parameter with
``collection_path`` (pathlib.Path).  Using the old ``path`` parameter
triggers PytestRemovedIn9Warning, which is fatal under filterwarnings=error.

This test scans every conftest.py and pytest plugin file in the repo for
the deprecated pattern so CI catches it before it reaches Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Patterns that indicate the deprecated hook signature.
_DEPRECATED_SIGNATURE = re.compile(
    r"def\s+pytest_ignore_collect\s*\([^)]*\bpath\b",
)

# Any use of py.path.local in test infrastructure is a smell.
_PY_PATH_LOCAL = re.compile(r"\bpy\.path\.local\b")


def _conftest_and_plugin_files() -> list[Path]:
    """Collect all conftest.py and pytest plugin .py files in the repo."""
    files: list[Path] = []
    for pattern in ("**/conftest.py", "**/pytest_plugins.py", "**/plugin.py"):
        files.extend(_REPO_ROOT.glob(pattern))
    # Exclude vendored / venv directories
    return [
        f
        for f in files
        if ".venv" not in f.parts
        and "node_modules" not in f.parts
        and "site-packages" not in f.parts
    ]


class TestNoDeprecatedPytestHooks:
    """Prevent re-introduction of deprecated pytest hook signatures."""

    @pytest.fixture()
    def conftest_files(self) -> list[Path]:
        files = _conftest_and_plugin_files()
        assert files, "Expected to find at least one conftest.py in the repo"
        return files

    def test_no_deprecated_pytest_ignore_collect_signature(
        self, conftest_files: list[Path]
    ) -> None:
        """Fail if any conftest defines pytest_ignore_collect with the
        deprecated ``path`` parameter instead of ``collection_path``."""
        violations: list[str] = []
        for path in conftest_files:
            content = path.read_text()
            match = _DEPRECATED_SIGNATURE.search(content)
            if match:
                # Find the line number
                lineno = content[: match.start()].count("\n") + 1
                rel = path.relative_to(_REPO_ROOT)
                violations.append(
                    f"  {rel}:{lineno} -> use 'collection_path: pathlib.Path' "
                    f"instead of 'path: py.path.local'"
                )
        assert not violations, (
            "Deprecated pytest_ignore_collect(path=...) signature found.\n"
            "This triggers PytestRemovedIn9Warning (fatal with filterwarnings=error).\n"
            "Use 'collection_path: pathlib.Path' instead:\n"
            + "\n".join(violations)
        )

    def test_no_py_path_local_in_conftest(
        self, conftest_files: list[Path]
    ) -> None:
        """Fail if any conftest uses py.path.local (deprecated in favor of
        pathlib.Path since pytest 7)."""
        violations: list[str] = []
        for path in conftest_files:
            content = path.read_text()
            for i, line in enumerate(content.splitlines(), start=1):
                if _PY_PATH_LOCAL.search(line):
                    rel = path.relative_to(_REPO_ROOT)
                    violations.append(f"  {rel}:{i} -> {line.strip()}")
        assert not violations, (
            "py.path.local usage found in conftest/plugin files.\n"
            "Use pathlib.Path instead (py.path.local is removed in pytest 9):\n"
            + "\n".join(violations)
        )
