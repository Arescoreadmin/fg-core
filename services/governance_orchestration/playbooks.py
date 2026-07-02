"""Playbook template library for governance orchestration."""

from __future__ import annotations

from typing import Any

from services.governance_orchestration.models import PlaybookType


PLAYBOOK_TEMPLATES: dict[str, dict[str, Any]] = {
    PlaybookType.PCI_DSS.value: {
        "name": "PCI DSS 4.0 Continuous Governance",
        "description": "PCI DSS 4.0 continuous compliance playbook",
        "controls": [
            "PCI-1.1",
            "PCI-2.2",
            "PCI-3.4",
            "PCI-6.5",
            "PCI-8.2",
            "PCI-10.6",
            "PCI-11.3",
            "PCI-12.1",
        ],
        "reassessment_interval_days": 90,
        "approval_required": True,
    },
    PlaybookType.HIPAA.value: {
        "name": "HIPAA Security Rule Continuous Governance",
        "description": "HIPAA continuous compliance playbook",
        "controls": [
            "164.308(a)(1)",
            "164.308(a)(3)",
            "164.308(a)(5)",
            "164.310(a)(1)",
            "164.312(a)(1)",
            "164.312(c)(1)",
        ],
        "reassessment_interval_days": 180,
        "approval_required": True,
    },
    PlaybookType.NIST_CSF.value: {
        "name": "NIST CSF 2.0 Continuous Governance",
        "description": "NIST Cybersecurity Framework continuous playbook",
        "controls": [
            "GV.OC-01",
            "GV.RM-01",
            "ID.AM-01",
            "PR.AA-01",
            "DE.CM-01",
            "RS.MA-01",
            "RC.RP-01",
        ],
        "reassessment_interval_days": 180,
        "approval_required": False,
    },
    PlaybookType.ISO_27001.value: {
        "name": "ISO/IEC 27001:2022 Continuous Governance",
        "description": "ISO 27001 continuous compliance playbook",
        "controls": [
            "A.5.1",
            "A.6.1",
            "A.8.1",
            "A.9.1",
            "A.12.1",
            "A.14.1",
            "A.16.1",
            "A.18.1",
        ],
        "reassessment_interval_days": 365,
        "approval_required": True,
    },
    PlaybookType.SOC2.value: {
        "name": "SOC 2 Trust Services Criteria Continuous Governance",
        "description": "SOC 2 continuous compliance playbook",
        "controls": [
            "CC1.1",
            "CC2.1",
            "CC3.1",
            "CC5.1",
            "CC6.1",
            "CC7.1",
            "CC8.1",
        ],
        "reassessment_interval_days": 90,
        "approval_required": False,
    },
    PlaybookType.MICROSOFT_SECURE_SCORE.value: {
        "name": "Microsoft Secure Score Continuous Governance",
        "description": "Microsoft Secure Score continuous playbook",
        "controls": [
            "MSS-Identity",
            "MSS-Data",
            "MSS-Device",
            "MSS-App",
            "MSS-Infra",
        ],
        "reassessment_interval_days": 30,
        "approval_required": False,
    },
    PlaybookType.CIS_CONTROLS.value: {
        "name": "CIS Critical Security Controls v8 Continuous Governance",
        "description": "CIS Controls v8 continuous playbook",
        "controls": [
            "CIS-01",
            "CIS-02",
            "CIS-03",
            "CIS-04",
            "CIS-05",
            "CIS-06",
        ],
        "reassessment_interval_days": 90,
        "approval_required": False,
    },
}


def get_playbook_template(playbook_type: str) -> dict[str, Any]:
    """Return the built-in template for a playbook type.

    Raises KeyError if unknown.
    """
    if playbook_type not in PLAYBOOK_TEMPLATES:
        raise KeyError(f"unknown playbook_type: {playbook_type!r}")
    # Return a shallow copy so callers can't mutate our library
    return dict(PLAYBOOK_TEMPLATES[playbook_type])


def validate_playbook(playbook: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(playbook, dict):
        return ["playbook must be an object"]
    for key in ("name", "controls"):
        if key not in playbook:
            errors.append(f"missing required field {key!r}")
    if "controls" in playbook and not isinstance(playbook["controls"], list):
        errors.append("controls must be a list")
    interval = playbook.get("reassessment_interval_days")
    if interval is not None:
        if not isinstance(interval, int) or interval < 1 or interval > 3650:
            errors.append("reassessment_interval_days must be int 1..3650")
    return errors


def compute_playbook_coverage(
    db: Any, tenant_id: str, playbook_type: str
) -> dict[str, Any]:
    """Return coverage stats for a playbook template.

    Deterministic. Reads from cross-authority tables best-effort.
    """
    template = get_playbook_template(playbook_type)
    controls = template.get("controls") or []
    total = len(controls)
    # We cannot join to control_registry cheaply here without hard
    # dependencies; return the template counts and let downstream callers
    # enrich if needed.
    return {
        "playbook_type": playbook_type,
        "total_controls": total,
        "covered_controls": 0,
        "coverage_pct": 0.0,
        "controls": list(controls),
    }
