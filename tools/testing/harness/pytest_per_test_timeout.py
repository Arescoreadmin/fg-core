"""FG-855-REPAIR-001 — dependency-free per-test timeout for required pytest lanes.

Load with ``-p tools.testing.harness.pytest_per_test_timeout`` (repo root on
``PYTHONPATH``) and enable with ``--fg-per-test-timeout=SECONDS``. Without the
option the plugin is inert, so loading it never changes other lanes.

Two layers, so a hang always fails the lane instead of stalling it:

1. Per phase (setup, call, teardown) on POSIX main threads: ``SIGALRM`` raises
   ``pytest.fail`` inside the blocked test. That test fails with a clear
   message and the session continues with the next test. Blocking calls that
   honour signals (sleep, lock acquire, socket I/O) are interrupted.
2. Backstop on every platform: ``faulthandler.dump_traceback_later(exit=True)``
   dumps every thread's stack and exits the process (non-zero) if a test
   exceeds twice the budget plus 5 s. This covers code that blocks signals
   or never returns to the interpreter (e.g. a C-level deadlock).

Neither layer marks a test as skipped or passed; a timeout is always a failure.
"""

from __future__ import annotations

import faulthandler
import os
import signal
import sys
import threading
from collections.abc import Generator
from typing import Any

import pytest

OPTION = "--fg-per-test-timeout"
BACKSTOP_GRACE_SECONDS = 5.0


def _open_backstop_stream() -> Any:
    # pytest's fd-level capture swaps fd 2 while a test runs, which would send
    # the backstop's stack dump to a capture file that is lost on exit. `-p`
    # plugins are imported before capture starts, so keep a duplicate of the
    # real stderr for the dump. faulthandler takes the raw descriptor, so no
    # file object is left open at interpreter exit.
    try:
        return os.dup(sys.stderr.fileno())
    except (AttributeError, OSError, ValueError):
        return sys.stderr


_BACKSTOP_STREAM = _open_backstop_stream()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        OPTION,
        dest="fg_per_test_timeout",
        type=float,
        default=0.0,
        help="Fail any test phase that runs longer than SECONDS (0 disables).",
    )


def _budget(item: pytest.Item) -> float:
    value = float(item.config.getoption("fg_per_test_timeout") or 0.0)
    return value if value > 0 else 0.0


def _alarm_available() -> bool:
    return (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )


def _guard_phase(item: pytest.Item, phase: str) -> Generator[None, Any, None]:
    budget = _budget(item)
    if not budget or not _alarm_available():
        yield
        return

    def _on_alarm(signum: int, frame: Any) -> None:
        pytest.fail(
            f"FG per-test timeout: {item.nodeid} {phase} exceeded {budget:g}s",
            pytrace=False,
        )

    previous = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, budget)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, Any, None]:
    budget = _budget(item)
    if budget:
        faulthandler.dump_traceback_later(
            budget * 2 + BACKSTOP_GRACE_SECONDS, exit=True, file=_BACKSTOP_STREAM
        )
    try:
        yield
    finally:
        if budget:
            faulthandler.cancel_dump_traceback_later()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item: pytest.Item) -> Generator[None, Any, None]:
    yield from _guard_phase(item, "setup")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None, Any, None]:
    yield from _guard_phase(item, "call")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, Any, None]:
    yield from _guard_phase(item, "teardown")
