"""
Anomaly Detection Engine for FrostGate.

Provides statistical anomaly detection for security telemetry using:
- Moving average baseline tracking
- Z-score based anomaly detection
- Behavioral pattern analysis
- IP reputation scoring

This is a lightweight, production-ready implementation that doesn't require
external ML libraries while still providing meaningful anomaly scores.
"""

from __future__ import annotations

import hashlib
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

# Configuration
ANOMALY_ENABLED = os.getenv("FG_ANOMALY_ENABLED", "1").strip() == "1"
BASELINE_WINDOW_SECONDS = int(os.getenv("FG_ANOMALY_BASELINE_WINDOW", "3600"))  # 1 hour
Z_SCORE_THRESHOLD = float(os.getenv("FG_ANOMALY_Z_THRESHOLD", "2.5"))


@dataclass
class BaselineStats:
    """Rolling statistics for baseline tracking."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0  # For Welford's online variance
    last_updated: float = field(default_factory=time.time)

    def update(self, value: float) -> None:
        """Update stats using Welford's online algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.last_updated = time.time()

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        if self.stddev == 0:
            return 0.0
        return (value - self.mean) / self.stddev

    def is_stale(self, max_age: float = 3600.0) -> bool:
        return (time.time() - self.last_updated) > max_age


@dataclass
class IPProfile:
    """Behavioral profile for an IP address."""

    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    failed_auth_count: int = 0
    unique_endpoints: set = field(default_factory=set)
    event_types: Dict[str, int] = field(default_factory=dict)
    hourly_counts: List[int] = field(default_factory=lambda: [0] * 24)

    def update(
        self,
        endpoint: str = "",
        event_type: str = "",
        is_failed_auth: bool = False,
    ) -> None:
        now = time.time()
        self.last_seen = now
        self.request_count += 1

        if endpoint:
            self.unique_endpoints.add(endpoint)

        if event_type:
            self.event_types[event_type] = self.event_types.get(event_type, 0) + 1

        if is_failed_auth:
            self.failed_auth_count += 1

        # Track hourly distribution
        hour = int((now % 86400) / 3600)
        self.hourly_counts[hour] += 1

    @property
    def age_seconds(self) -> float:
        return time.time() - self.first_seen

    @property
    def failed_auth_ratio(self) -> float:
        if self.request_count == 0:
            return 0.0
        return self.failed_auth_count / self.request_count

    @property
    def endpoint_diversity(self) -> int:
        return len(self.unique_endpoints)

    def hourly_entropy(self) -> float:
        """Calculate entropy of hourly request distribution."""
        total = sum(self.hourly_counts)
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in self.hourly_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy


class AnomalyDetector:
    """
    Statistical anomaly detector for FrostGate telemetry.

    Maintains baselines and profiles for:
    - Request rate per source
    - Failed authentication patterns
    - Behavioral anomalies (time-of-day, endpoint diversity)
    """

    def __init__(self):
        # Baselines by metric type
        self._baselines: Dict[str, BaselineStats] = defaultdict(BaselineStats)
        # IP behavioral profiles
        self._ip_profiles: Dict[str, IPProfile] = {}
        # Known malicious patterns (simple blocklist for MVP)
        self._malicious_patterns: set = {
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "zgrab",
            "nuclei",
        }
        # Suspicious user agents
        self._suspicious_agents: set = {
            "python-requests",
            "curl",
            "wget",
            "go-http-client",
        }

    def _get_ip_profile(self, ip: str) -> IPProfile:
        if ip not in self._ip_profiles:
            self._ip_profiles[ip] = IPProfile()
        return self._ip_profiles[ip]

    def _extract_features(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from telemetry for analysis."""
        payload = telemetry.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}

        features = {
            "source_ip": (
                payload.get("src_ip")
                or payload.get("source_ip")
                or payload.get("ip")
                or payload.get("client_ip")
                or "unknown"
            ),
            "user_agent": payload.get("user_agent", ""),
            "endpoint": payload.get("endpoint", payload.get("path", "")),
            "event_type": telemetry.get("event_type", "unknown"),
            "failed_auths": int(
                payload.get("failed_auths")
                or payload.get("failed_attempts")
                or payload.get("count")
                or 0
            ),
            "timestamp": payload.get("timestamp", time.time()),
            "tenant_id": telemetry.get("tenant_id", "default"),
        }
        return features

    def _score_ip_reputation(self, profile: IPProfile) -> float:
        """Score IP based on behavioral profile (0-1, higher = more suspicious)."""
        score = 0.0

        # New IPs are slightly suspicious
        if profile.age_seconds < 60:
            score += 0.1

        # High failed auth ratio is very suspicious
        if profile.failed_auth_ratio > 0.5:
            score += 0.4
        elif profile.failed_auth_ratio > 0.2:
            score += 0.2

        # Scanning behavior (many endpoints, low depth)
        if profile.endpoint_diversity > 20 and profile.request_count < 100:
            score += 0.2

        # Low entropy in timing (bot-like regular patterns)
        entropy = profile.hourly_entropy()
        if entropy < 1.0 and profile.request_count > 10:
            score += 0.15

        # Very high request rate
        if profile.request_count > 1000 and profile.age_seconds < 300:
            score += 0.3

        return min(1.0, score)

    def _score_user_agent(self, user_agent: str) -> float:
        """Score user agent suspiciousness (0-1)."""
        if not user_agent:
            return 0.2  # Missing UA is slightly suspicious

        ua_lower = user_agent.lower()

        # Check for known malicious tools
        for pattern in self._malicious_patterns:
            if pattern in ua_lower:
                return 0.9

        # Check for automated tools (not necessarily malicious)
        for agent in self._suspicious_agents:
            if agent in ua_lower:
                return 0.3

        return 0.0

    def _score_temporal_anomaly(self, timestamp: float, tenant_id: str) -> float:
        """Score based on temporal patterns."""
        # Get hour of day
        hour = int((timestamp % 86400) / 3600)

        # Track requests per hour baseline
        baseline_key = f"hourly:{tenant_id}:{hour}"
        baseline = self._baselines[baseline_key]

        # Update baseline
        baseline.update(1.0)

        # Not enough data yet
        if baseline.count < 10:
            return 0.0

        # Check if this hour has anomalous activity
        z = baseline.z_score(baseline.count)
        if abs(z) > Z_SCORE_THRESHOLD:
            return min(0.5, abs(z) / 10.0)

        return 0.0

    def _score_failed_auth_pattern(
        self, failed_auths: int, profile: IPProfile
    ) -> float:
        """Score based on authentication failure patterns."""
        if failed_auths == 0:
            return 0.0

        score = 0.0

        # Immediate high count
        if failed_auths >= 10:
            score += 0.6
        elif failed_auths >= 5:
            score += 0.3
        elif failed_auths >= 3:
            score += 0.1

        # Historical pattern from this IP
        if profile.failed_auth_count > 20:
            score += 0.2

        return min(1.0, score)

    def analyze(self, telemetry: Dict[str, Any]) -> Tuple[float, float, List[str]]:
        """
        Analyze telemetry and return anomaly scores.

        Returns:
            anomaly_score: Overall anomaly score (0-1)
            ai_adversarial_score: Score indicating AI-assisted attack likelihood (0-1)
            indicators: List of triggered anomaly indicators
        """
        if not ANOMALY_ENABLED:
            return 0.0, 0.0, []

        features = self._extract_features(telemetry)
        indicators: List[str] = []

        # Get/update IP profile
        ip = features["source_ip"]
        profile = self._get_ip_profile(ip)
        profile.update(
            endpoint=features["endpoint"],
            event_type=features["event_type"],
            is_failed_auth=features["failed_auths"] > 0,
        )

        # Component scores
        scores: List[Tuple[str, float, float]] = []  # (name, score, weight)

        # IP reputation
        ip_score = self._score_ip_reputation(profile)
        if ip_score > 0.3:
            indicators.append(f"anomaly:ip_reputation:{ip_score:.2f}")
        scores.append(("ip_reputation", ip_score, 0.25))

        # User agent analysis
        ua_score = self._score_user_agent(features["user_agent"])
        if ua_score > 0.3:
            indicators.append(f"anomaly:user_agent:{ua_score:.2f}")
        scores.append(("user_agent", ua_score, 0.15))

        # Temporal patterns
        temporal_score = self._score_temporal_anomaly(
            features["timestamp"], features["tenant_id"]
        )
        if temporal_score > 0.2:
            indicators.append(f"anomaly:temporal:{temporal_score:.2f}")
        scores.append(("temporal", temporal_score, 0.2))

        # Failed auth patterns
        auth_score = self._score_failed_auth_pattern(features["failed_auths"], profile)
        if auth_score > 0.3:
            indicators.append(f"anomaly:failed_auth:{auth_score:.2f}")
        scores.append(("failed_auth", auth_score, 0.4))

        # Calculate weighted anomaly score
        total_weight = sum(w for _, _, w in scores)
        anomaly_score = sum(s * w for _, s, w in scores) / total_weight

        # AI adversarial score (based on specific patterns)
        ai_score = 0.0
        event_type = features["event_type"].lower()

        # Check for LLM-related events
        if "llm" in event_type or "ai" in event_type or "gpt" in event_type:
            ai_score = 0.5
            indicators.append("anomaly:ai_related_event")

        # Check for polymorphic/evasion patterns
        if profile.event_types and len(profile.event_types) > 10:
            ai_score = max(ai_score, 0.3)
            indicators.append("anomaly:polymorphic_behavior")

        # High velocity with varied payloads suggests automation
        if profile.request_count > 50 and profile.age_seconds < 60:
            ai_score = max(ai_score, 0.4)
            indicators.append("anomaly:high_velocity_attack")

        logger.debug(
            "anomaly.analyze",
            extra={
                "ip": ip,
                "anomaly_score": round(anomaly_score, 3),
                "ai_score": round(ai_score, 3),
                "indicators": indicators,
            },
        )

        return round(anomaly_score, 3), round(ai_score, 3), indicators


# Global detector instance
_detector: Optional[AnomalyDetector] = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        logger.info("anomaly: detector initialized")
    return _detector


def analyze_telemetry(telemetry: Dict[str, Any]) -> Tuple[float, float, List[str]]:
    """
    Convenience function to analyze telemetry.

    Returns:
        anomaly_score: Overall anomaly score (0-1)
        ai_adversarial_score: AI-assisted attack likelihood (0-1)
        indicators: List of triggered indicators
    """
    return get_detector().analyze(telemetry)
