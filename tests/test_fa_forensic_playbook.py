from __future__ import annotations

from services.field_assessment.models import AssessmentType
from services.field_assessment.playbooks import get_playbook


def test_every_assessment_type_has_a_versioned_playbook_with_unique_steps() -> None:
    """Every registered assessment type must resolve to a pinned playbook without duplicate required steps."""
    for assessment_type in AssessmentType:
        playbook = get_playbook(assessment_type.value)
        assert playbook is not None
        assert playbook.version == "1.0"
        assert playbook.playbook_id
        assert len(playbook.required_steps) == len(set(playbook.required_steps))
