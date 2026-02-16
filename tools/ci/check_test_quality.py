#!/usr/bin/env python3
from __future__ import annotations

from datetime import date
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_MAX_SUPPRESSIONS = 10
SUPPRESSION_RE = re.compile(
    r'^\s*#\s*SOC:ALLOW_VACUOUS_ASSERT\s+reason="(?P<reason>[^"]+)"\s+remove_by="(?P<remove_by>\d{4}-\d{2}-\d{2})"\s*$'
)


def _max_suppressions() -> int:
    # CI is always hard-capped at DEFAULT_MAX_SUPPRESSIONS.
    if os.getenv("CI", "").strip().lower() in {"1", "true", "yes"}:
        return DEFAULT_MAX_SUPPRESSIONS

    raw = os.getenv("FG_TEST_QUALITY_SUPPRESSION_CAP", "").strip()
    if not raw:
        return DEFAULT_MAX_SUPPRESSIONS
    try:
        cap = int(raw)
        return cap if cap > 0 else DEFAULT_MAX_SUPPRESSIONS
    except ValueError:
        return DEFAULT_MAX_SUPPRESSIONS


def _iter_protected_tests() -> list[Path]:
    files: set[Path] = set()
    files.update((REPO / "tests" / "security").glob("**/test_*.py"))
    files.update((REPO / "tests").glob("**/test_*invariant*.py"))
    return sorted(path for path in files if path.is_file())


def _find_nearest_suppression(
    lines: list[str], assert_line: int
) -> tuple[int, re.Match[str] | None]:
    for idx in range(max(0, assert_line - 4), assert_line):
        match = SUPPRESSION_RE.match(lines[idx])
        if match:
            return idx + 1, match
    return -1, None


def _todo_skip_line(line: str) -> bool:
    return 'pytest.skip("TODO"' in line or 'pytest.mark.skip(reason="TODO"' in line


def main() -> int:
    failures: list[str] = []
    suppression_count = 0
    suppression_cap = _max_suppressions()
    today = date.today()

    for test_file in _iter_protected_tests():
        rel = test_file.relative_to(REPO)
        lines = test_file.read_text(encoding="utf-8").splitlines()

        for idx, line in enumerate(lines, start=1):
            if "SOC:ALLOW_VACUOUS_ASSERT" in line and not SUPPRESSION_RE.match(line):
                failures.append(
                    f"{rel}:{idx} suppression marker has invalid format; expected "
                    '# SOC:ALLOW_VACUOUS_ASSERT reason="..." remove_by="YYYY-MM-DD"'
                )

            if "assert True" in line:
                sup_line, sup_match = _find_nearest_suppression(lines, idx - 1)
                if sup_match is None:
                    failures.append(
                        f"{rel}:{idx} vacuous assert without suppression marker"
                    )
                    continue

                reason = sup_match.group("reason").strip()
                remove_by_raw = sup_match.group("remove_by")
                if not reason:
                    failures.append(f"{rel}:{sup_line} suppression reason is empty")
                try:
                    remove_by = date.fromisoformat(remove_by_raw)
                    if remove_by < today:
                        failures.append(
                            f"{rel}:{sup_line} suppression expired on {remove_by_raw}"
                        )
                except ValueError:
                    failures.append(
                        f"{rel}:{sup_line} suppression remove_by is not valid YYYY-MM-DD"
                    )
                suppression_count += 1

            if _todo_skip_line(line):
                failures.append(
                    f"{rel}:{idx} TODO skip marker is forbidden in protected suites"
                )

    if suppression_count > suppression_cap:
        failures.append(
            f"suppression cap exceeded: {suppression_count} > {suppression_cap}"
        )

    if failures:
        print("test-quality gate: FAILED")
        for item in failures:
            print(f" - {item}")
        return 1

    print("test-quality gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
