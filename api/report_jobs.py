"""
api/report_jobs.py — Report job state definitions and stable reason codes.

These are shared by the reports engine and by tests so that reason codes
are tested against constants, not raw strings.
"""

from __future__ import annotations

from enum import Enum


class ReportJobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


# Stable reason codes — treat these as a public contract; tests assert on them.
REPORT_GENERATION_TIMEOUT = "REPORT_GENERATION_TIMEOUT"
REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
