"""Generate GitHub Actions step summary markdown. No PII. No secrets."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Regression, RollingStats, RuntimeResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .manifest import ValidationManifest

_SEVERITY_EMOJI = {"low": "⚠️", "medium": "⚠️", "high": "🔴", "critical": "🔴"}
_PARAM_RE = re.compile(r"\[.*?\]")


def generate_summary(
    result: RuntimeResult,
    stats: RollingStats | None = None,
    regressions: list[Regression] | None = None,
    manifest: ValidationManifest | None = None,
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
    if result.manifest_fingerprint:
        lines.append(f"| Manifest | `{result.manifest_fingerprint}` |")
    lines.append("")

    # Validation manifest (signed integrity record)
    if manifest is not None:
        lines.append("### Validation Manifest\n")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Manifest ID | `{manifest.manifest_id[:16]}...` |")
        lines.append(f"| Manifest Hash | `{manifest.manifest_hash[:16]}...` |")
        if manifest.signature_algorithm == "ed25519" and manifest.signature:
            sig_display = "Ed25519 ✓"
        elif manifest.signature_algorithm == "unsigned" or not manifest.signature:
            sig_display = "unsigned"
        else:
            sig_display = manifest.signature_algorithm
        lines.append(f"| Signature | {sig_display} |")
        lines.append(f"| Verification | {manifest.verification_status} |")
        identity_display = manifest.signing_identity or "—"
        lines.append(f"| Signing Identity | `{identity_display}` |")
        if manifest.previous_manifest_hash:
            chain_display = "✓ linked"
        else:
            chain_display = "✓ root"
        lines.append(f"| Chain | {chain_display} |")
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
            sanitized = _PARAM_RE.sub("[...]", t.node_id)
            short = sanitized[-60:] if len(sanitized) > 60 else sanitized
            lines.append(f"| `{short}` | {t.duration_seconds:.2f}s | {t.phase} |")
        lines.append("")

    # Slowest fixtures — grouped by plane when ownership is present
    if result.slowest_fixtures:
        lines.append("### Slowest Fixtures\n")
        lines.append("| Fixture | Duration | Plane | Owner |")
        lines.append("|---------|----------|-------|-------|")
        for f in result.slowest_fixtures[:10]:
            plane = f.plane or "—"
            owner = f.owner or "—"
            lines.append(
                f"| `{f.name}` | {f.duration_seconds:.2f}s | {plane} | {owner} |"
            )
        lines.append("")

    return "\n".join(lines)


def write_step_summary(text: str) -> None:
    """Write to GITHUB_STEP_SUMMARY if available."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        Path(summary_path).write_text(text, encoding="utf-8")
