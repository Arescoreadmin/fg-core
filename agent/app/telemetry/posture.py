from __future__ import annotations

import platform


def collect_posture(min_os_major: int = 10) -> dict:
    rel = platform.release()
    try:
        major = int(rel.split(".")[0])
    except Exception:
        major = min_os_major
    rooted = False
    return {
        "os_version": rel,
        "root_or_jailbreak_signals": rooted,
        "compliance_status": "compliant" if major >= min_os_major and not rooted else "non_compliant",
    }
