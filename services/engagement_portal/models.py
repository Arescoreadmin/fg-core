"""Enums, exceptions, and constants for the Engagement Portal (PR 18.2)."""

from __future__ import annotations

from enum import Enum

PORTAL_SCHEMA_VERSION: str = "1.0"
ACTIVITY_LOG_RETENTION_DAYS: int = 365


class PortalWorkspaceType(str, Enum):
    EVIDENCE = "evidence"
    VERIFICATION = "verification"
    REPORTS = "reports"
    REMEDIATION = "remediation"
    TRUST = "trust"
    TRANSPARENCY = "transparency"
    TIMELINE = "timeline"
    SEARCH = "search"


class PortalActivityEventType(str, Enum):
    DASHBOARD_VIEWED = "dashboard_viewed"
    EVIDENCE_VIEWED = "evidence_viewed"
    REPORT_VIEWED = "report_viewed"
    REPORT_DOWNLOADED = "report_downloaded"
    REMEDIATION_VIEWED = "remediation_viewed"
    TRUST_VIEWED = "trust_viewed"
    TRANSPARENCY_VIEWED = "transparency_viewed"
    VERIFICATION_VIEWED = "verification_viewed"
    SEARCH_PERFORMED = "search_performed"
    NOTIFICATION_SENT = "notification_sent"
    PREFERENCE_UPDATED = "preference_updated"
    TIMELINE_VIEWED = "timeline_viewed"


class PortalNotificationStatus(str, Enum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"


class PortalNotificationType(str, Enum):
    REPORT_READY = "report_ready"
    EVIDENCE_REQUESTED = "evidence_requested"
    EVIDENCE_APPROVED = "evidence_approved"
    EVIDENCE_REJECTED = "evidence_rejected"
    VERIFICATION_REQUESTED = "verification_requested"
    REMEDIATION_OVERDUE = "remediation_overdue"
    ASSESSMENT_COMPLETED = "assessment_completed"
    REMINDER = "reminder"


# Exception hierarchy (model-level)
class PortalError(Exception):
    """Base exception for the Engagement Portal models."""


class PortalEntityNotFound(PortalError):
    """Requested entity not found for tenant."""


class PortalAccessDenied(PortalError):
    """Tenant scope violation or missing tenant context."""


class PortalSearchError(PortalError):
    """Search request invalid or backend unavailable."""
