"""FrostGate alert condition definitions.

Alert rules are expressed in two layers:
  1. Prometheus alerting rules (YAML) — primary, evaluated by Prometheus Alertmanager.
     See deploy/prometheus/alerts.yml for the canonical definitions.
  2. Python alert hooks (this module) — for in-process alert callbacks and
     integration with PagerDuty, OpsGenie, Datadog Monitors, SIEM, etc.

AlertHook.on_fire() is called synchronously when an alert condition crosses
its threshold. Hooks MUST be non-blocking (offload async work to a thread/task).

Supported routing destinations (selected by FG_ALERT_BACKEND env var):
  - "log"          — structured log entry only (default, safe for all envs)
  - "webhook"      — HTTP POST to FG_ALERT_WEBHOOK_URL
  - "pagerduty"    — PagerDuty Events API v2 (requires FG_PAGERDUTY_ROUTING_KEY)
  - "opsgenie"     — OpsGenie Alerts API (requires FG_OPSGENIE_API_KEY)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

log = logging.getLogger("frostgate.alerts")


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class AlertCondition:
    name: str
    severity: AlertSeverity
    description: str
    # Human-readable runbook reference
    runbook: str = ""


# ---------------------------------------------------------------------------
# Canonical alert conditions (mirrors deploy/prometheus/alerts.yml)
# ---------------------------------------------------------------------------

ALERT_PROVIDER_FAILURE = AlertCondition(
    name="FrostgateProviderFailureHigh",
    severity=AlertSeverity.CRITICAL,
    description="Provider failure rate exceeded threshold",
    runbook="https://docs.frostgate.io/runbooks/provider-failure",
)

ALERT_RETRIEVAL_DEGRADATION = AlertCondition(
    name="FrostgateRetrievalLatencyHigh",
    severity=AlertSeverity.WARNING,
    description="Retrieval p99 latency exceeded 2s",
    runbook="https://docs.frostgate.io/runbooks/retrieval-degradation",
)

ALERT_INGESTION_FAILURE = AlertCondition(
    name="FrostgateIngestionFailureHigh",
    severity=AlertSeverity.CRITICAL,
    description="Ingestion failure rate exceeded threshold",
    runbook="https://docs.frostgate.io/runbooks/ingestion-failure",
)

ALERT_AUDIT_PIPELINE_FAILURE = AlertCondition(
    name="FrostgateAuditPipelineFailure",
    severity=AlertSeverity.CRITICAL,
    description="Audit pipeline failure detected",
    runbook="https://docs.frostgate.io/runbooks/audit-pipeline",
)

ALERT_DB_CONNECTIVITY = AlertCondition(
    name="FrostgateDBConnectivityFailure",
    severity=AlertSeverity.CRITICAL,
    description="Database connectivity failure detected",
    runbook="https://docs.frostgate.io/runbooks/db-connectivity",
)

ALERT_5XX_RATE_HIGH = AlertCondition(
    name="FrostgateHttp5xxRateHigh",
    severity=AlertSeverity.WARNING,
    description="HTTP 5xx rate exceeded 5% over 5 minutes",
    runbook="https://docs.frostgate.io/runbooks/5xx-rate",
)

ALERT_LATENCY_ABNORMAL = AlertCondition(
    name="FrostgateRequestLatencyAbnormal",
    severity=AlertSeverity.WARNING,
    description="p99 request latency exceeded 5s",
    runbook="https://docs.frostgate.io/runbooks/latency-abnormal",
)

ALERT_PROVENANCE_FAILURE_SPIKE = AlertCondition(
    name="FrostgateProvenanceFailureSpike",
    severity=AlertSeverity.CRITICAL,
    description="Provenance validation failure rate spike detected",
    runbook="https://docs.frostgate.io/runbooks/provenance-failures",
)

ALL_ALERTS = [
    ALERT_PROVIDER_FAILURE,
    ALERT_RETRIEVAL_DEGRADATION,
    ALERT_INGESTION_FAILURE,
    ALERT_AUDIT_PIPELINE_FAILURE,
    ALERT_DB_CONNECTIVITY,
    ALERT_5XX_RATE_HIGH,
    ALERT_LATENCY_ABNORMAL,
    ALERT_PROVENANCE_FAILURE_SPIKE,
]


# ---------------------------------------------------------------------------
# Alert event + routing
# ---------------------------------------------------------------------------


@dataclass
class AlertEvent:
    condition: AlertCondition
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    fired_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert": self.condition.name,
            "severity": self.condition.severity.value,
            "description": self.condition.description,
            "runbook": self.condition.runbook,
            "labels": self.labels,
            "annotations": self.annotations,
            "fired_at": self.fired_at,
        }


_ALERT_LOCK = threading.Lock()
_RECENT_ALERTS: list[AlertEvent] = []
_MAX_RECENT = 100


def fire_alert(
    condition: AlertCondition,
    labels: Optional[dict[str, str]] = None,
    annotations: Optional[dict[str, str]] = None,
) -> None:
    """Fire an alert event. Routes to configured backend; always emits a structured log."""
    event = AlertEvent(
        condition=condition,
        labels=labels or {},
        annotations=annotations or {},
    )

    with _ALERT_LOCK:
        _RECENT_ALERTS.append(event)
        if len(_RECENT_ALERTS) > _MAX_RECENT:
            _RECENT_ALERTS.pop(0)

    log.warning(
        "alert_fired",
        extra={
            "alert_name": condition.name,
            "alert_severity": condition.severity.value,
            "alert_description": condition.description,
            "alert_labels": labels or {},
        },
    )

    backend = os.getenv("FG_ALERT_BACKEND", "log").strip().lower()
    if backend == "webhook":
        _route_webhook(event)
    elif backend == "pagerduty":
        _route_pagerduty(event)
    elif backend == "opsgenie":
        _route_opsgenie(event)


def get_recent_alerts(limit: int = 20) -> list[dict[str, Any]]:
    with _ALERT_LOCK:
        return [e.to_dict() for e in _RECENT_ALERTS[-limit:]]


def _route_webhook(event: AlertEvent) -> None:
    url = os.getenv("FG_ALERT_WEBHOOK_URL", "").strip()
    if not url:
        log.debug("alert_webhook_url_not_set; skipping webhook delivery")
        return
    try:
        import json
        import urllib.request

        data = json.dumps(event.to_dict()).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        log.warning("alert_webhook_delivery_failed error=%s", exc)


def _route_pagerduty(event: AlertEvent) -> None:
    routing_key = os.getenv("FG_PAGERDUTY_ROUTING_KEY", "").strip()
    if not routing_key:
        log.debug("FG_PAGERDUTY_ROUTING_KEY not set; skipping PagerDuty delivery")
        return
    try:
        import json
        import urllib.request

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": event.condition.description,
                "severity": event.condition.severity.value,
                "source": "frostgate-core",
                "custom_details": event.to_dict(),
            },
            "links": [{"href": event.condition.runbook, "text": "Runbook"}]
            if event.condition.runbook
            else [],
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://events.pagerduty.com/v2/enqueue",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        log.warning("alert_pagerduty_delivery_failed error=%s", exc)


def _route_opsgenie(event: AlertEvent) -> None:
    api_key = os.getenv("FG_OPSGENIE_API_KEY", "").strip()
    if not api_key:
        log.debug("FG_OPSGENIE_API_KEY not set; skipping OpsGenie delivery")
        return
    try:
        import json
        import urllib.request

        priority_map = {
            AlertSeverity.CRITICAL: "P1",
            AlertSeverity.WARNING: "P3",
            AlertSeverity.INFO: "P5",
        }
        payload = {
            "message": event.condition.description,
            "alias": event.condition.name,
            "priority": priority_map.get(event.condition.severity, "P3"),
            "details": {k: str(v) for k, v in event.labels.items()},
            "source": "frostgate-core",
            "tags": ["frostgate", event.condition.severity.value],
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.opsgenie.com/v2/alerts",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"GenieKey {api_key}",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        log.warning("alert_opsgenie_delivery_failed error=%s", exc)
