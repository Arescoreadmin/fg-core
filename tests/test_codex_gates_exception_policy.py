from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _prepare_sandbox(tmp_path: Path, exception_content: str | None) -> Path:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    (sandbox / "codex_gates.sh").write_text(
        (ROOT / "codex_gates.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    venv_bin = sandbox / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    _write_executable(venv_bin / "python", "#!/usr/bin/env bash\nexit 0\n")
    (venv_bin / "activate").write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    stub_bin = sandbox / "stub-bin"
    stub_bin.mkdir()
    _write_executable(stub_bin / "ruff", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(stub_bin / "mypy", "#!/usr/bin/env bash\nexit 1\n")
    _write_executable(stub_bin / "pytest", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(stub_bin / "pip", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(stub_bin / "pip-audit", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(stub_bin / "rg", '#!/usr/bin/env bash\n/usr/bin/rg "$@"\n')

    docs_ai = sandbox / "docs" / "ai"
    docs_ai.mkdir(parents=True)
    if exception_content is not None:
        (docs_ai / "CODEX_GATE_EXCEPTIONS.md").write_text(
            exception_content, encoding="utf-8"
        )

    return sandbox


def _run_gates(sandbox: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'stub-bin'}:{env['PATH']}"
    return subprocess.run(
        ["bash", "codex_gates.sh"],
        cwd=sandbox,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_mypy_exception_missing_is_blocking(tmp_path: Path) -> None:
    sandbox = _prepare_sandbox(tmp_path, exception_content=None)
    result = _run_gates(sandbox)
    assert result.returncode != 0
    assert "no codex gate exception is active" in (result.stdout + result.stderr)


def test_mypy_exception_malformed_is_blocking(tmp_path: Path) -> None:
    sandbox = _prepare_sandbox(
        tmp_path,
        exception_content="GATE_EXCEPTION|mypy|active|reason=missing-fields-only\n",
    )
    result = _run_gates(sandbox)
    assert result.returncode != 0
    assert "malformed or ambiguous mypy exception entry" in (
        result.stdout + result.stderr
    )


def test_mypy_exception_valid_allows_progress(tmp_path: Path) -> None:
    sandbox = _prepare_sandbox(
        tmp_path,
        exception_content=(
            "GATE_EXCEPTION|mypy|active|reason=r|scope=s|follow_up=f|owner=o|expires=2026-06-30\n"
        ),
    )
    result = _run_gates(sandbox)
    assert result.returncode == 0
    assert "mypy failed under active codex gate exception" in (
        result.stdout + result.stderr
    )
