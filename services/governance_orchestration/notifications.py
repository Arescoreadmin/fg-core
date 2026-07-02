"""Notification delegation stubs for governance orchestration.

All functions are no-ops that intentionally never raise. They exist so the
engine can express intent even when the notification authority is not
wired for a particular tenant.
"""

from __future__ import annotations

import logging
from typing import Any


_log = logging.getLogger(__name__)


def notify_reassessment_started(tenant_id: str, reassessment_id: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_reassessment_started tenant=%s id=%s",
            tenant_id,
            reassessment_id,
        )
    except Exception:
        pass


def notify_policy_violation(tenant_id: str, policy_id: str, violation: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_policy_violation tenant=%s policy=%s reason=%s",
            tenant_id,
            policy_id,
            violation,
        )
    except Exception:
        pass


def notify_approval_requested(
    tenant_id: str, workflow_id: str, actor_id: str
) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_approval_requested tenant=%s workflow=%s actor=%s",
            tenant_id,
            workflow_id,
            actor_id,
        )
    except Exception:
        pass


def notify_approval_expired(tenant_id: str, approval_id: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_approval_expired tenant=%s id=%s",
            tenant_id,
            approval_id,
        )
    except Exception:
        pass


def notify_maintenance_window_opened(tenant_id: str, window_id: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_maintenance_window_opened tenant=%s id=%s",
            tenant_id,
            window_id,
        )
    except Exception:
        pass


def notify_maintenance_window_closed(tenant_id: str, window_id: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_maintenance_window_closed tenant=%s id=%s",
            tenant_id,
            window_id,
        )
    except Exception:
        pass


def notify_executive_alert(
    tenant_id: str, alert_type: str, context: dict[str, Any]
) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_executive_alert tenant=%s type=%s",
            tenant_id,
            alert_type,
        )
    except Exception:
        pass


def notify_automation_paused(tenant_id: str, reason: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_automation_paused tenant=%s reason=%s",
            tenant_id,
            reason,
        )
    except Exception:
        pass


def notify_automation_resumed(tenant_id: str) -> None:
    try:
        _log.debug(
            "governance_orchestration.notify_automation_resumed tenant=%s",
            tenant_id,
        )
    except Exception:
        pass
