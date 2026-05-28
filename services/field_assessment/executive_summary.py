"""Executive summary generator for field assessment governance reports.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Generates a plain-language executive summary from structured engagement data.
Uses the Anthropic provider (call_provider) when available; degrades gracefully
to a deterministic template if the provider is unavailable.

The summary is intentionally separate from the deterministic GovernanceReport model.
It is generated at report-compile time and included in the signed report JSON.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("frostgate.fa.executive_summary")

_GENERATION_NOTE = (
    "AI-generated narrative from structured engagement findings. "
    "Deterministic findings data above is authoritative."
)

_SYSTEM_PROMPT = """\
You are a governance analyst writing an executive summary for a field assessment report
delivered to a client in a regulated industry. Your audience is a non-technical executive
(CEO, CFO, or Board member).

Rules:
- Write 2–3 short paragraphs (plain English, no jargon).
- Lead with the overall risk posture and what it means for the organization.
- Name the most critical governance gaps without technical control IDs.
- Close with a forward-looking sentence about the path to improvement.
- Never say "certified" or "compliant with" — use "aligned with" or "designed to support compliance with".
- Do not invent findings that are not in the data you receive.
- Return ONLY valid JSON matching the schema below — no markdown, no commentary.

Schema:
{
  "narrative": "<2–3 paragraph plain-language summary>",
  "risk_posture": "<critical|high|medium|low>",
  "key_concerns": ["<up to 3 short phrases, each under 12 words>"]
}"""


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _risk_posture_from_counts(counts: dict[str, int]) -> str:
    if counts["critical"] > 0:
        return "critical"
    if counts["high"] > 0:
        return "high"
    if counts["medium"] > 0:
        return "medium"
    return "low"


def _template_summary(
    severity_counts: dict[str, int],
    framework_names: list[str],
    finding_count: int,
    risk_posture: str,
) -> dict[str, Any]:
    fw_str = ", ".join(framework_names[:3]) if framework_names else "NIST AI RMF"
    gap_line = (
        f"{severity_counts['critical']} critical and {severity_counts['high']} high-severity"
        if severity_counts["critical"] + severity_counts["high"] > 0
        else f"{finding_count}"
    )
    narrative = (
        f"This field assessment identified {finding_count} governance finding"
        f"{'s' if finding_count != 1 else ''} with an overall risk posture of {risk_posture.upper()}. "
        f"The assessment reviewed controls aligned with {fw_str}. "
        f"{gap_line.capitalize()} gap{'s' if finding_count != 1 else ''} require attention before "
        f"governance milestone eligibility can be established.\n\n"
        f"Remediation steps have been prioritized and linked to each finding in the report. "
        f"Addressing the highest-severity items first will yield the greatest improvement "
        f"in governance posture and reduce exposure."
    )
    key_concerns: list[str] = []
    if severity_counts["critical"] > 0:
        key_concerns.append(
            f"{severity_counts['critical']} critical-severity control gap(s) identified"
        )
    if severity_counts["high"] > 0:
        key_concerns.append(
            f"{severity_counts['high']} high-severity finding(s) require remediation"
        )
    if framework_names:
        key_concerns.append(f"Gaps mapped to {framework_names[0]} controls")
    return {
        "narrative": narrative.strip(),
        "risk_posture": risk_posture,
        "key_concerns": key_concerns[:3],
        "generation_note": _GENERATION_NOTE,
    }


def generate_executive_summary(
    *,
    engagement_id: str,
    tenant_id: str,
    findings: list[dict[str, Any]],
    framework_summary: dict[str, list[str]],
    confidence_overall: float,
) -> dict[str, Any]:
    """Generate a plain-language executive summary for a governance report.

    Calls the Anthropic provider when available. Falls back to a deterministic
    template on any provider error so report generation never blocks.

    Args:
        engagement_id: The engagement being reported on.
        tenant_id: Tenant that owns this report.
        findings: List of GovernanceFinding dicts from the report.
        framework_summary: {framework_name: [control_refs]} from the report.
        confidence_overall: Overall confidence score 0.0–1.0.

    Returns:
        Dict with keys: narrative, risk_posture, key_concerns, generation_note.
    """
    import json
    import uuid

    severity_counts = _severity_counts(findings)
    finding_count = len(findings)
    risk_posture = _risk_posture_from_counts(severity_counts)
    framework_names = sorted(framework_summary.keys())

    try:
        from services.ai.dispatch import call_provider
    except ImportError:
        logger.warning("executive_summary.provider_unavailable — using template")
        return _template_summary(
            severity_counts, framework_names, finding_count, risk_posture
        )

    user_prompt = (
        f"Engagement: {engagement_id}\n"
        f"Total findings: {finding_count}\n"
        f"Severity breakdown: "
        f"critical={severity_counts['critical']}, "
        f"high={severity_counts['high']}, "
        f"medium={severity_counts['medium']}, "
        f"low={severity_counts['low']}\n"
        f"Frameworks with gaps: {', '.join(framework_names) or 'none'}\n"
        f"Confidence score: {confidence_overall:.0%}\n\n"
        f"Write the executive summary JSON."
    )

    request_id = uuid.uuid4().hex

    try:
        resp = call_provider(
            provider_id="anthropic",
            prompt=user_prompt,
            max_tokens=600,
            request_id=request_id,
            tenant_id=tenant_id,
            system_prompt=_SYSTEM_PROMPT,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "executive_summary.provider_error engagement=%s exc=%s — using template",
            engagement_id,
            exc,
        )
        return _template_summary(
            severity_counts, framework_names, finding_count, risk_posture
        )

    raw = getattr(resp, "text", None)
    if raw is None:
        raw = getattr(resp, "content", None)
    if not isinstance(raw, str) or not raw.strip():
        logger.warning(
            "executive_summary.empty_response engagement=%s — using template",
            engagement_id,
        )
        return _template_summary(
            severity_counts, framework_names, finding_count, risk_posture
        )

    # Extract JSON from response
    try:
        # Strip markdown fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        parsed = json.loads(text.strip())
    except (json.JSONDecodeError, IndexError):
        logger.warning(
            "executive_summary.parse_error engagement=%s — using template",
            engagement_id,
        )
        return _template_summary(
            severity_counts, framework_names, finding_count, risk_posture
        )

    # Validate and sanitize
    narrative = str(parsed.get("narrative", "")).strip()
    posture = str(parsed.get("risk_posture", risk_posture)).lower()
    if posture not in ("critical", "high", "medium", "low"):
        posture = risk_posture
    concerns_raw = parsed.get("key_concerns", [])
    key_concerns = [str(c).strip() for c in concerns_raw if isinstance(c, str)][:3]

    if not narrative:
        return _template_summary(
            severity_counts, framework_names, finding_count, risk_posture
        )

    return {
        "narrative": narrative,
        "risk_posture": posture,
        "key_concerns": key_concerns,
        "generation_note": _GENERATION_NOTE,
    }
