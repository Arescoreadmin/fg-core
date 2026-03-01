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
    _write_executable(
        stub_bin / "rg",
        """#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

args = sys.argv[1:]
show_line = False
pattern: str | None = None
paths: list[str] = []

it = iter(args)
for arg in it:
    if arg == "-n":
        show_line = True
        continue
    if arg in {"--hidden", "--no-ignore-vcs"}:
        # supported no-op flags for sandbox compatibility
        continue
    if arg == "-g":
        # consume glob arg as no-op
        _ = next(it, None)
        continue
    if arg.startswith("-"):
        continue
    if pattern is None:
        pattern = arg
    else:
        paths.append(arg)

if pattern is None or not paths:
    raise SystemExit(2)

try:
    regex = re.compile(pattern)
except re.error:
    raise SystemExit(2)

matched = False
for raw_path in paths:
    path = Path(raw_path)
    if path.is_dir():
        # sandbox secret-scan path; deterministic no-match
        continue
    if not path.is_file():
        continue
    for line_no, line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
    ):
        if regex.search(line):
            matched = True
            if show_line:
                print(f"{path}:{line_no}:{line}")
            else:
                print(line)

raise SystemExit(0 if matched else 1)
""",
    )

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
