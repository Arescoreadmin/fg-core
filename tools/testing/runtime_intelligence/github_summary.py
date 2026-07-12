"""Generate GitHub Actions step summary markdown. No PII. No secrets."""

from __future__ import annotations

import os
from pathlib import Path

from .models import Regression, RollingStats, RuntimeResult

_SEVERITY_EMOJI = {"low": "⚠️", "medium": "⚠️", "high": "🔴", "critical": "🔴"}


def generate_summary(
    result: RuntimeResult,
    stats: RollingStats | None = None,
    regressions: list[Regression] | None = None,
) -> str:
    lines: list[str] = []
    gate = result.meta.gate.upper().replace("-", " ")
    lines.append(f"## {gate} Runtime Summary\n")

    # Core metrics
    pct_vs_median = ""
    if stats and stats.median > 0:
        pct = ((result.duration_seconds - stats.median) / stats.median) * 100
        sign = "+" if pct >= 0 else ""
        pct_vs_median = f" ({sign}{pct:.0f}% vs median)"

    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Duration | {result.duration_seconds:.0f}s{pct_vs_median} |")
    lines.append(f"| Collected | {result.collected} |")
    lines.append(f"| Passed | {result.passed} |")
    lines.append(f"| Failed | {result.failed} |")
    lines.append(f"| Skipped | {result.skipped} |")
    lines.append(f"| Gate | {result.meta.gate} |")
    lines.append(f"| Commit | `{result.meta.commit_sha[:12]}` |")
    lines.append("")

    # Rolling stats
    if stats and stats.count > 0:
        lines.append("### Rolling Statistics (last 30 runs)\n")
        lines.append("| Stat | Value |")
        lines.append("|------|-------|")
        lines.append(f"| Median | {stats.median:.0f}s |")
        lines.append(f"| p90 | {stats.p90:.0f}s |")
        lines.append(f"| p95 | {stats.p95:.0f}s |")
        lines.append(f"| Min | {stats.minimum:.0f}s |")
        lines.append(f"| Max | {stats.maximum:.0f}s |")
        lines.append(f"| Runs | {stats.count} |")
        lines.append("")

    # Regressions
    if regressions:
        lines.append("### Regressions Detected (Advisory)\n")
        for reg in regressions:
            emoji = _SEVERITY_EMOJI.get(reg.severity, "⚠️")
            lines.append(f"- {emoji} **{reg.severity.upper()}**: {reg.message}")
        lines.append("")
    else:
        lines.append("### Regressions\n")
        lines.append("✅ None detected\n")

    # Slowest tests
    if result.slowest_tests:
        lines.append("### Slowest Tests\n")
        lines.append("| Test | Duration | Phase |")
        lines.append("|------|----------|-------|")
        for t in result.slowest_tests[:10]:
            short = t.node_id[-60:] if len(t.node_id) > 60 else t.node_id
            lines.append(f"| `{short}` | {t.duration_seconds:.2f}s | {t.phase} |")
        lines.append("")

    return "\n".join(lines)


def write_step_summary(text: str) -> None:
    """Write to GITHUB_STEP_SUMMARY if available."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        Path(summary_path).write_text(text, encoding="utf-8")
