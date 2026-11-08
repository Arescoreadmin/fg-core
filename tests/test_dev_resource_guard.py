"""Tests for the AI development resource preflight guard.

Uses --meminfo-path and --mock-rg-count to inject deterministic system state
without requiring /proc/meminfo or live pgrep on the test host.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_GUARD = str(
    Path(__file__).parent.parent / "tools" / "ci" / "check_dev_resource_guard.py"
)


def _run(
    *extra_args: str,
    meminfo_content: str | None = None,
    tmp_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, _GUARD]
    if meminfo_content is not None and tmp_path is not None:
        mf = tmp_path / "meminfo"
        mf.write_text(meminfo_content)
        cmd += ["--meminfo-path", str(mf)]
    cmd += list(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _meminfo(
    *, available_gib: float, swap_total_gib: float = 8.0, swap_free_gib: float = 8.0
) -> str:
    available_kib = int(available_gib * 1024 * 1024)
    swap_total_kib = int(swap_total_gib * 1024 * 1024)
    swap_free_kib = int(swap_free_gib * 1024 * 1024)
    return (
        f"MemTotal:       33554432 kB\n"
        f"MemFree:        {available_kib // 2} kB\n"
        f"MemAvailable:   {available_kib} kB\n"
        f"SwapTotal:      {swap_total_kib} kB\n"
        f"SwapFree:       {swap_free_kib} kB\n"
    )


class TestOkConditions:
    def test_sufficient_memory_exits_zero(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0

    def test_ok_at_exactly_warn_threshold(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=8.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0

    def test_ok_with_low_rg_count(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "3",
            meminfo_content=_meminfo(available_gib=20.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "CRITICAL" not in result.stdout
        assert "CRITICAL" not in result.stderr


class TestBlockedConditions:
    def test_blocked_when_available_ram_below_minimum(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=4.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1
        assert "CRITICAL" in result.stdout or "CRITICAL" in result.stderr
        assert "BLOCKED" in result.stderr

    def test_blocked_at_exactly_minimum_threshold(self, tmp_path: Path) -> None:
        # 5.9 GiB is below 6.0 GiB minimum
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=5.9),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1

    def test_blocked_when_rg_procs_at_limit(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "20",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1
        assert "CRITICAL" in result.stdout or "CRITICAL" in result.stderr

    def test_blocked_when_rg_procs_exceed_limit(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "35",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1

    def test_both_low_memory_and_high_rg_blocked(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "25",
            meminfo_content=_meminfo(available_gib=3.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1
        # Both CRITICAL lines should appear
        assert result.stdout.count("CRITICAL") >= 2


class TestWarningConditions:
    def test_warn_when_memory_between_6_and_8_gib(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=7.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "WARNING" in result.stdout

    def test_warn_when_swap_heavily_utilized(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(
                available_gib=16.0, swap_total_gib=8.0, swap_free_gib=1.0
            ),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "WARNING" in result.stdout

    def test_warn_when_rg_procs_at_advisory_limit(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "10",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "WARNING" in result.stdout


class TestCLIFlags:
    def test_report_flag_prints_diagnostics(self, tmp_path: Path) -> None:
        result = _run(
            "--report",
            "--mock-rg-count",
            "2",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "available RAM" in result.stdout
        assert "rg processes" in result.stdout

    def test_phase_label_appears_in_output(self, tmp_path: Path) -> None:
        result = _run(
            "--report",
            "--phase",
            "mypy-full",
            "--mock-rg-count",
            "0",
            meminfo_content=_meminfo(available_gib=16.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 0
        assert "mypy-full" in result.stdout

    def test_missing_meminfo_file_exits_zero(self, tmp_path: Path) -> None:
        result = _run(
            "--meminfo-path",
            str(tmp_path / "nonexistent"),
            "--mock-rg-count",
            "0",
        )
        # Missing /proc/meminfo (non-Linux host) should not block work
        assert result.returncode == 0

    def test_blocked_message_includes_phase(self, tmp_path: Path) -> None:
        result = _run(
            "--mock-rg-count",
            "0",
            "--phase",
            "full-pytest",
            meminfo_content=_meminfo(available_gib=2.0),
            tmp_path=tmp_path,
        )
        assert result.returncode == 1
        assert "full-pytest" in result.stderr
