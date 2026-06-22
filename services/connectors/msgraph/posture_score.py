"""Posture score computation from msgraph scan findings.

Score: 0–100 integer.
  100 = no actionable findings
  0   = saturated with critical findings

Formula: 100 - sum(weight[severity] * min(count, cap[severity]))
Per-severity caps prevent a single category from collapsing the score to zero alone.
Informational findings carry zero weight — they are visibility items, not deductions.

All arithmetic is deterministic and pure. No I/O, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass

from services.connectors.msgraph.schema.scan_result import Finding

# Deduction per finding, by severity
_WEIGHTS: dict[str, float] = {
    "critical": 12.0,
    "high": 6.0,
    "medium": 2.0,
    "low": 0.5,
    "informational": 0.0,
}

# Maximum findings counted per severity (excess findings do not increase deduction)
_CAPS: dict[str, int] = {
    "critical": 5,
    "high": 8,
    "medium": 15,
    "low": 20,
    "informational": 0,
}

# Keyword sets for domain classification — matched against lowercased finding title.
# Longer / more specific terms checked first to avoid false positives.
_AI_KEYWORDS: frozenset[str] = frozenset(
    {
        "copilot",
        "shadow ai",
        "unapproved ai",
        "dlp exposure",
        "ai app",
        "ai signal",
        "artificial intelligence",
    }
)
_COMPLIANCE_KEYWORDS: frozenset[str] = frozenset(
    {
        "oauth",
        "consent",
        "enterprise app",
        "unverified publisher",
        "stale app",
        "user-delegated consent",
        "admin-consented",
    }
)
# Security is the default domain — anything not matched above falls here.


@dataclass(frozen=True)
class PostureScore:
    """Composite governance posture score for a single msgraph scan.

    overall: composite across all findings.
    security: MFA, Conditional Access, Privileged Roles, Guest Exposure.
    compliance: Enterprise Apps, OAuth Consent grants.
    ai_governance: AI/Copilot signals, DLP exposure.
    band: human-readable tier derived from overall.
    """

    overall: int  # 0–100
    security: int  # 0–100
    compliance: int  # 0–100
    ai_governance: int  # 0–100
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    finding_count: int

    @property
    def band(self) -> str:
        if self.overall >= 85:
            return "good"
        if self.overall >= 65:
            return "fair"
        if self.overall >= 40:
            return "poor"
        return "critical"


def _score_findings(findings: list[Finding]) -> int:
    """Compute 0–100 score from a subset of findings."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    deduction = sum(
        _WEIGHTS.get(sev, 0.0) * min(count, _CAPS.get(sev, count))
        for sev, count in counts.items()
    )
    return max(0, min(100, round(100.0 - deduction)))


def _classify_finding(finding: Finding) -> str:
    """Return 'ai', 'compliance', or 'security' for a finding based on its title."""
    title = finding.title.lower()
    if any(k in title for k in _AI_KEYWORDS):
        return "ai"
    if any(k in title for k in _COMPLIANCE_KEYWORDS):
        return "compliance"
    return "security"


def compute_posture_score(findings: list[Finding]) -> PostureScore:
    """Compute composite posture score from a list of msgraph findings.

    Domain scores use title-keyword classification:
      - ai: Copilot, shadow AI, DLP exposure
      - compliance: OAuth grants, enterprise apps
      - security: everything else (MFA, CA, PRIV, GUEST)

    Empty domain finding lists yield 100 for that domain (no deductions).
    """
    by_domain: dict[str, list[Finding]] = {"security": [], "compliance": [], "ai": []}
    severity_counts: dict[str, int] = {}

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        by_domain[_classify_finding(f)].append(f)

    return PostureScore(
        overall=_score_findings(findings),
        security=_score_findings(by_domain["security"])
        if by_domain["security"]
        else 100,
        compliance=_score_findings(by_domain["compliance"])
        if by_domain["compliance"]
        else 100,
        ai_governance=_score_findings(by_domain["ai"]) if by_domain["ai"] else 100,
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        informational_count=severity_counts.get("informational", 0),
        finding_count=len(findings),
    )
