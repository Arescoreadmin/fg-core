"""FG-855-REPAIR-001 — the Agent lane's per-test timeout really bounds hangs.

`make agent-unit` loads tools/testing/harness/pytest_per_test_timeout.py. Each
case runs a throwaway pytest session in a subprocess, so a hang (or the
backstop's process exit) can never stall or kill this session.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN = "tools.testing.harness.pytest_per_test_timeout"

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="SIGALRM layer is POSIX-only"
)


def _run(tmp_path: Path, body: str, *extra: str, limit: float = 60.0):
    (tmp_path / "test_case.py").write_text(textwrap.dedent(body))
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        + ["-p", PLUGIN, *extra, "test_case.py"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=limit,
    )
    return proc, time.monotonic() - started


@posix_only
def test_hung_test_fails_and_session_continues(tmp_path):
    proc, elapsed = _run(
        tmp_path,
        """
        import time

        def test_hangs():
            time.sleep(600)

        def test_after():
            assert True
        """,
        "--fg-per-test-timeout=1",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "FG per-test timeout: test_case.py::test_hangs call exceeded 1s" in out
    assert "1 failed, 1 passed" in out
    assert elapsed < 30


@posix_only
def test_lock_deadlock_fails(tmp_path):
    # The #853 class of defect: a non-reentrant lock acquired twice.
    proc, _ = _run(
        tmp_path,
        """
        import threading

        def test_deadlock():
            lock = threading.Lock()
            lock.acquire()
            lock.acquire()
        """,
        "--fg-per-test-timeout=1",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "FG per-test timeout" in out and "1 failed" in out


@posix_only
def test_hang_in_fixture_setup_fails(tmp_path):
    proc, _ = _run(
        tmp_path,
        """
        import time
        import pytest

        @pytest.fixture
        def slow():
            time.sleep(600)

        def test_uses_slow(slow):
            pass
        """,
        "--fg-per-test-timeout=1",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "test_uses_slow setup exceeded 1s" in out


def test_backstop_exits_when_signals_are_blocked(tmp_path):
    # Signal layer defeated: the faulthandler backstop must still end the run.
    proc, elapsed = _run(
        tmp_path,
        """
        import signal
        import time

        def test_ignores_alarm():
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, signal.SIG_IGN)
            time.sleep(600)
        """,
        "--fg-per-test-timeout=1",
    )
    assert proc.returncode != 0
    assert "Timeout" in proc.stderr and "test_ignores_alarm" in proc.stderr
    assert elapsed < 30


def test_inert_without_option(tmp_path):
    proc, _ = _run(
        tmp_path,
        """
        import time

        def test_short_sleep():
            time.sleep(1.5)
        """,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 passed" in proc.stdout
