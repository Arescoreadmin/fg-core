"""test_subprocess_interpreter_isolation_001.py — Regression guard: subprocess must use sys.executable.

This module is NOT standalone. It is a component of the FrostGate governance platform
and CI test execution correctness.

Root cause addressed:
  PR #778 shards 0 and 1 failed because tests called subprocess.run(["python", ...]) which
  resolved to the system Python (lacking PyYAML) instead of the active venv interpreter.
  Two confirmed failures (shard 0: test_cz_repair_closeout_001::test_c1_checker_authorizes_final_readiness,
  shard 1: test_customer_zero_final_readiness_001::test_a1_authorized_work_item_passes)
  both produced: stderr='ERROR: PyYAML not installed — pip install pyyaml\\n'

Invariant: all subprocess calls invoking tools/ci/*.py must use sys.executable, not bare "python".
sys.executable always resolves to the active interpreter where requirements are installed.

Scope boundary: offline-only. No live infrastructure. No secrets accessed.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_CHECKER = REPO / "tools" / "ci" / "check_customer_one_roadmap.py"


class TestInterpreterIsolation:
    """Verify that sys.executable always has PyYAML and that bare 'python' may not."""

    def test_venv_interpreter_has_pyyaml(self) -> None:
        """sys.executable must have pyyaml installed."""
        result = subprocess.run(
            [sys.executable, "-c", "import yaml; print('OK')"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"sys.executable ({sys.executable}) must have pyyaml installed; "
            f"got rc={result.returncode}, stderr={result.stderr!r}"
        )
        assert result.stdout.strip() == "OK"

    def test_checker_succeeds_with_venv_interpreter(self) -> None:
        """check_customer_one_roadmap.py must not produce a PyYAML import error when
        invoked with sys.executable — even if a system Python without PyYAML is first on PATH."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake "python" that simulates a system interpreter without PyYAML.
            fake_python = Path(tmpdir) / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "echo 'ERROR: PyYAML not installed — pip install pyyaml' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            fake_python.chmod(
                fake_python.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )

            env = os.environ.copy()
            env["PATH"] = tmpdir + ":" + env.get("PATH", "")

            # Bare "python" from the fake PATH must fail with the simulated PyYAML error.
            r_fake = subprocess.run(
                ["python", str(_CHECKER), "--work-item", "SOME-NONEXISTENT-ITEM"],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                env=env,
            )
            assert "PyYAML not installed" in r_fake.stderr, (
                "Simulated system Python must produce the PyYAML error — "
                "confirms the isolation test setup is valid"
            )

            # sys.executable bypasses PATH lookup — must have PyYAML even with the fake PATH.
            r_venv = subprocess.run(
                [sys.executable, str(_CHECKER), "--work-item", "SOME-NONEXISTENT-ITEM"],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                env=env,
            )
            assert "PyYAML not installed" not in r_venv.stderr, (
                f"sys.executable ({sys.executable}) must use the venv interpreter with "
                f"PyYAML installed, ignoring the fake system Python on PATH. "
                f"Got stderr={r_venv.stderr!r}"
            )

    def test_checker_invocation_files_use_sys_executable(self) -> None:
        """Source-code audit: test files that invoke check_customer_one_roadmap.py
        must use sys.executable, not bare 'python' string."""
        affected_test_files = [
            "tests/test_cz_repair_closeout_001.py",
            "tests/test_customer_zero_final_readiness_001.py",
            "tests/test_cz_run3_operator_preflight_closeout_001.py",
            "tests/test_cz_final_readiness_closeout_001.py",
            "tests/test_cz_run3_preauth_closeout_001.py",
            "tests/test_cz_reconcile_001.py",
        ]
        violations: list[str] = []
        for rel_path in affected_test_files:
            path = REPO / rel_path
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8")
            # Check for bare "python" strings in subprocess context near roadmap checker
            lines = content.splitlines()
            for i, line in enumerate(lines):
                # Flag if a line contains '"python"' and is adjacent to check_customer_one_roadmap
                if '"python"' in line:
                    # Look at a window of nearby lines for roadmap checker context
                    window = lines[max(0, i - 5) : min(len(lines), i + 5)]
                    window_text = "\n".join(window)
                    if (
                        "check_customer_one_roadmap" in window_text
                        or "subprocess" in window_text
                    ):
                        violations.append(
                            f"{rel_path}:{i + 1}: bare 'python' near subprocess call"
                        )
        assert not violations, (
            "Found bare 'python' in subprocess calls — use sys.executable:\n"
            + "\n".join(violations)
        )
