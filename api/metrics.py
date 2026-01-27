"""
Enhanced Prometheus metrics for FrostGate Core.

Provides comprehensive observability for:
- Decision processing (latency, throughput, threat levels)
- Anomaly detection (scores, detections)
- Rate limiting (requests, rejections)
- Merkle anchoring (status, timing)
- System health (errors, queue depth)
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# =============================================================================
# Decision Metrics
# =============================================================================

# Total /defend requests by threat level
DECISION_REQUESTS = Counter(
    "frostgate_decision_requests_total",
    "Total /defend requests processed by Frostgate Core",
    ["threat_level"],
)

# Latency of /defend in seconds, bucketed by threat level
DECISION_LATENCY_SECONDS = Histogram(
    "frostgate_decision_latency_seconds",
    "Latency of /defend decisions in seconds",
    ["threat_level"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# DB logging failures (we never want these, but they will happen)
DECISION_DB_ERRORS = Counter(
    "frostgate_decision_db_errors_total",
    "Count of failed decision log writes to the database",
)

# Decisions by action taken
DECISION_ACTIONS = Counter(
    "frostgate_decision_actions_total",
    "Count of decisions by action type",
    ["action"],  # block, allow, flag, quarantine
)

# Mitigations issued
MITIGATIONS_ISSUED = Counter(
    "frostgate_mitigations_issued_total",
    "Count of mitigation actions issued",
    ["action", "target_type"],  # action: block/flag, target_type: ip/session/user
)

# =============================================================================
# Anomaly Detection Metrics
# =============================================================================

# Anomaly score distribution
ANOMALY_SCORE = Histogram(
    "frostgate_anomaly_score",
    "Distribution of anomaly scores",
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

# AI adversarial score distribution
AI_ADVERSARIAL_SCORE = Histogram(
    "frostgate_ai_adversarial_score",
    "Distribution of AI adversarial detection scores",
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

# Anomaly indicators triggered
ANOMALY_INDICATORS = Counter(
    "frostgate_anomaly_indicators_total",
    "Count of anomaly indicators triggered",
    ["indicator"],  # ip_reputation, user_agent, temporal, failed_auth, etc.
)

# Rules triggered
RULES_TRIGGERED = Counter(
    "frostgate_rules_triggered_total",
    "Count of rules triggered",
    ["rule"],
)

# =============================================================================
# Rate Limiting Metrics
# =============================================================================

# Rate limit checks
RATE_LIMIT_CHECKS = Counter(
    "frostgate_rate_limit_checks_total",
    "Total rate limit checks performed",
    ["result"],  # allowed, rejected
)

# Rate limit rejections by client type
RATE_LIMIT_REJECTIONS = Counter(
    "frostgate_rate_limit_rejections_total",
    "Rate limit rejections by client identifier type",
    ["client_type"],  # ip, api_key
)

# Current rate limit utilization (gauge)
RATE_LIMIT_UTILIZATION = Gauge(
    "frostgate_rate_limit_utilization_ratio",
    "Current rate limit utilization (0-1)",
    ["client_key"],
)

# =============================================================================
# Merkle Anchor Metrics
# =============================================================================

# Anchor status
ANCHOR_STATUS = Gauge(
    "frostgate_anchor_status",
    "Merkle anchor status (1=ok, 0=deferred, -1=error)",
)

# Time since last anchor (seconds)
ANCHOR_AGE_SECONDS = Gauge(
    "frostgate_anchor_age_seconds",
    "Seconds since last successful Merkle anchor",
)

# Records anchored per batch
ANCHOR_RECORDS_BATCH = Histogram(
    "frostgate_anchor_records_batch",
    "Number of records anchored per batch",
    buckets=[1, 10, 50, 100, 500, 1000, 5000, 10000],
)

# Anchor chain length
ANCHOR_CHAIN_LENGTH = Gauge(
    "frostgate_anchor_chain_length",
    "Total number of anchors in chain",
)

# =============================================================================
# Authentication Metrics
# =============================================================================

# Auth attempts by result
AUTH_ATTEMPTS = Counter(
    "frostgate_auth_attempts_total",
    "Authentication attempts by result",
    ["result", "method"],  # result: success/failure, method: header/cookie/db
)

# Active API keys
ACTIVE_API_KEYS = Gauge(
    "frostgate_active_api_keys",
    "Number of active API keys",
)

# =============================================================================
# Feed & Query Metrics
# =============================================================================

# Feed queries
FEED_QUERIES = Counter(
    "frostgate_feed_queries_total",
    "Feed endpoint queries",
    ["endpoint"],  # /feed/live, /feed/stream
)

# Feed query latency
FEED_QUERY_LATENCY = Histogram(
    "frostgate_feed_query_latency_seconds",
    "Feed query latency in seconds",
    ["endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

# =============================================================================
# System Health Metrics
# =============================================================================

# Database connection pool status
DB_POOL_SIZE = Gauge(
    "frostgate_db_pool_size",
    "Database connection pool size",
)

DB_POOL_CHECKED_OUT = Gauge(
    "frostgate_db_pool_checked_out",
    "Database connections currently checked out",
)

# Error counts by type
ERRORS = Counter(
    "frostgate_errors_total",
    "Total errors by type",
    ["error_type"],  # db, auth, validation, internal
)

# Request queue depth (if using async processing)
QUEUE_DEPTH = Gauge(
    "frostgate_queue_depth",
    "Current request queue depth",
    ["queue_name"],
)

# =============================================================================
# Build Info
# =============================================================================

BUILD_INFO = Info(
    "frostgate_build",
    "Build information for FrostGate Core",
)


# =============================================================================
# Helper Functions
# =============================================================================


def record_decision(
    threat_level: str,
    latency_seconds: float,
    anomaly_score: float,
    ai_score: float,
    rules: list,
    mitigations: list,
):
    """Record metrics for a decision."""
    DECISION_REQUESTS.labels(threat_level=threat_level).inc()
    DECISION_LATENCY_SECONDS.labels(threat_level=threat_level).observe(latency_seconds)
    ANOMALY_SCORE.observe(anomaly_score)
    AI_ADVERSARIAL_SCORE.observe(ai_score)

    for rule in rules:
        RULES_TRIGGERED.labels(rule=rule).inc()
        # Also track anomaly indicators separately
        if rule.startswith("anomaly:"):
            indicator = rule.split(":")[1] if ":" in rule else rule
            ANOMALY_INDICATORS.labels(indicator=indicator).inc()

    for mitigation in mitigations:
        action = (
            mitigation.get("action", "unknown")
            if isinstance(mitigation, dict)
            else getattr(mitigation, "action", "unknown")
        )
        target = (
            mitigation.get("target", "")
            if isinstance(mitigation, dict)
            else getattr(mitigation, "target", "")
        )
        target_type = "ip" if "." in str(target) else "other"
        MITIGATIONS_ISSUED.labels(action=action, target_type=target_type).inc()


def record_rate_limit(allowed: bool, client_type: str = "ip"):
    """Record rate limit check result."""
    result = "allowed" if allowed else "rejected"
    RATE_LIMIT_CHECKS.labels(result=result).inc()
    if not allowed:
        RATE_LIMIT_REJECTIONS.labels(client_type=client_type).inc()


def record_anchor_status(status: str, age_seconds: float, records_count: int = 0):
    """Record Merkle anchor status."""
    status_value = 1 if status == "ok" else (0 if status == "deferred" else -1)
    ANCHOR_STATUS.set(status_value)
    ANCHOR_AGE_SECONDS.set(age_seconds)
    if records_count > 0:
        ANCHOR_RECORDS_BATCH.observe(records_count)


def record_auth_attempt(success: bool, method: str = "header"):
    """Record authentication attempt."""
    result = "success" if success else "failure"
    AUTH_ATTEMPTS.labels(result=result, method=method).inc()


def record_error(error_type: str):
    """Record an error by type."""
    ERRORS.labels(error_type=error_type).inc()


def set_build_info(version: str, commit: str, env: str):
    """Set build information."""
    BUILD_INFO.info(
        {
            "version": version,
            "commit": commit,
            "environment": env,
        }
    )
