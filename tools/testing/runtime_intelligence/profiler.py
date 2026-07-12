"""Extract slow test information from --durations output or junit XML."""

from __future__ import annotations

import re

from .models import SlowFixture, SlowTest

# Pattern: "0.123s call tests/foo/test_bar.py::test_baz"
_DURATION_LINE = re.compile(
    r"^\s*(?P<dur>[\d.]+)s\s+(?P<phase>call|setup|teardown)\s+(?P<node>.+)$"
)


def parse_durations_output(
    text: str, top_n: int = 25
) -> tuple[tuple[SlowTest, ...], tuple[SlowFixture, ...]]:
    """Parse pytest --durations output lines into SlowTest tuples."""
    tests: list[SlowTest] = []
    for line in text.splitlines():
        m = _DURATION_LINE.match(line)
        if m:
            tests.append(
                SlowTest(
                    node_id=m.group("node").strip(),
                    duration_seconds=float(m.group("dur")),
                    phase=m.group("phase"),
                )
            )
    # Sort descending by duration, take top N
    tests.sort(key=lambda t: t.duration_seconds, reverse=True)
    slow_tests = tuple(tests[:top_n])

    # Extract fixture-like patterns (setup phase, fixture name heuristic)
    fixtures: list[SlowFixture] = []
    seen: dict[str, float] = {}
    for t in tests:
        if t.phase == "setup":
            # Best effort: node_id often contains fixture context
            name = t.node_id.split("::")[-1] if "::" in t.node_id else t.node_id
            if name not in seen or t.duration_seconds > seen[name]:
                seen[name] = t.duration_seconds
    for name, dur in sorted(seen.items(), key=lambda x: -x[1])[:top_n]:
        fixtures.append(SlowFixture(name=name, duration_seconds=dur))

    return slow_tests, tuple(fixtures[:top_n])
