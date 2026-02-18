from __future__ import annotations

import json
from pathlib import Path


def _payload() -> dict[str, object]:
    return json.loads(
        Path("tools/ci/artifact_policy_allowlist.json").read_text(encoding="utf-8")
    )


def test_artifact_policy_allowlist_has_expected_keys():
    payload = _payload()
    assert "allowed_committed_artifacts" in payload
    assert "generated_patterns_prohibited" in payload
    assert any(
        x.endswith("SOC_AUDIT_GATES.md") for x in payload["allowed_committed_artifacts"]
    )


def test_artifact_policy_patterns_nonempty():
    payload = _payload()
    assert payload["generated_patterns_prohibited"]
