"""
Golden Telemetry Test Dataset for FrostGate.

Provides canonical test cases covering:
- Benign traffic patterns
- Brute-force attacks
- Scanning/reconnaissance
- AI-assisted attacks
- Polymorphic patterns
- Edge cases

Each sample includes expected outcomes for validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class GoldenSample:
    """A test telemetry sample with expected outcomes."""

    name: str
    description: str
    telemetry: Dict[str, Any]
    expected_threat_level: str
    expected_min_anomaly_score: float
    expected_max_anomaly_score: float
    expected_rules: List[str]  # Rules that should be triggered
    expected_mitigations: int  # Number of mitigations expected
    category: str  # benign, bruteforce, scanning, ai_attack, polymorphic, edge_case


# =============================================================================
# Benign Traffic Samples
# =============================================================================

BENIGN_LOGIN_SUCCESS = GoldenSample(
    name="benign_login_success",
    description="Normal successful login from known user",
    telemetry={
        "event_type": "auth.login",
        "tenant_id": "acme-corp",
        "source": "web-app",
        "payload": {
            "src_ip": "192.168.1.100",
            "user_id": "user123",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "endpoint": "/api/v1/login",
            "failed_auths": 0,
            "timestamp": 1706000000,
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,
    expected_max_anomaly_score=0.3,
    expected_rules=[],
    expected_mitigations=0,
    category="benign",
)

BENIGN_API_REQUEST = GoldenSample(
    name="benign_api_request",
    description="Normal API request from authenticated service",
    telemetry={
        "event_type": "api.request",
        "tenant_id": "acme-corp",
        "source": "backend-svc",
        "payload": {
            "src_ip": "10.0.0.50",
            "service_name": "inventory-service",
            "user_agent": "python-requests/2.31.0",
            "endpoint": "/api/v2/inventory/list",
            "method": "GET",
            "timestamp": 1706000100,
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,
    expected_max_anomaly_score=0.4,  # python-requests UA is slightly suspicious
    expected_rules=[],
    expected_mitigations=0,
    category="benign",
)

BENIGN_FAILED_LOGIN_FEW = GoldenSample(
    name="benign_failed_login_few",
    description="User with a few failed login attempts (forgot password)",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "acme-corp",
        "source": "web-app",
        "payload": {
            "src_ip": "192.168.1.105",
            "user_id": "forgetful_user",
            "failed_auths": 3,
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
            "endpoint": "/login",
            "timestamp": 1706000200,
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,
    expected_max_anomaly_score=0.4,
    expected_rules=[],
    expected_mitigations=0,
    category="benign",
)

# =============================================================================
# Brute-Force Attack Samples
# =============================================================================

BRUTEFORCE_SSH_BASIC = GoldenSample(
    name="bruteforce_ssh_basic",
    description="Classic SSH brute-force attack with 10+ failed attempts",
    telemetry={
        "event_type": "auth.bruteforce",
        "tenant_id": "acme-corp",
        "source": "sshd",
        "payload": {
            "src_ip": "45.33.32.156",
            "failed_auths": 15,
            "target_user": "root",
            "user_agent": "",
            "timestamp": 1706000300,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.6,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="bruteforce",
)

BRUTEFORCE_SSH_EXTREME = GoldenSample(
    name="bruteforce_ssh_extreme",
    description="High-volume SSH brute-force attack",
    telemetry={
        "event_type": "ssh.bruteforce",
        "tenant_id": "acme-corp",
        "source": "sshd",
        "payload": {
            "src_ip": "185.220.101.42",
            "failed_auths": 500,
            "target_users": ["root", "admin", "ubuntu", "centos"],
            "timestamp": 1706000400,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.8,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="bruteforce",
)

BRUTEFORCE_WEB_LOGIN = GoldenSample(
    name="bruteforce_web_login",
    description="Web application login brute-force",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "acme-corp",
        "source": "nginx",
        "payload": {
            "src_ip": "104.236.198.48",
            "failed_auths": 25,
            "endpoint": "/wp-login.php",
            "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "timestamp": 1706000500,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.6,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],  # Uses same rule for high failed_auths
    expected_mitigations=1,
    category="bruteforce",
)

BRUTEFORCE_DISTRIBUTED = GoldenSample(
    name="bruteforce_distributed",
    description="Distributed brute-force (single IP, many attempts)",
    telemetry={
        "event_type": "brute_force",
        "tenant_id": "enterprise",
        "source": "auth-service",
        "payload": {
            "src_ip": "203.0.113.50",
            "failures": 50,  # Alternative field name
            "target_accounts": 10,
            "timestamp": 1706000600,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.7,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="bruteforce",
)

# =============================================================================
# Scanning/Reconnaissance Samples
# =============================================================================

SCAN_NMAP_DETECTED = GoldenSample(
    name="scan_nmap_detected",
    description="nmap scanner detected via user agent",
    telemetry={
        "event_type": "network.scan",
        "tenant_id": "acme-corp",
        "source": "firewall",
        "payload": {
            "src_ip": "192.0.2.100",
            "user_agent": "Nmap Scripting Engine",
            "ports_scanned": 1000,
            "timestamp": 1706000700,
        },
    },
    expected_threat_level="low",  # Rules don't elevate for scanning alone
    expected_min_anomaly_score=0.0,  # Fresh detector starts with lower scores
    expected_max_anomaly_score=1.0,
    expected_rules=[],  # No specific scan rule yet
    expected_mitigations=0,
    category="scanning",
)

SCAN_NIKTO = GoldenSample(
    name="scan_nikto",
    description="Nikto web vulnerability scanner",
    telemetry={
        "event_type": "http.request",
        "tenant_id": "acme-corp",
        "source": "waf",
        "payload": {
            "src_ip": "198.51.100.25",
            "user_agent": "Nikto/2.1.6",
            "endpoint": "/admin/.htaccess",
            "method": "GET",
            "timestamp": 1706000800,
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,  # Fresh detector
    expected_max_anomaly_score=1.0,
    expected_rules=[],
    expected_mitigations=0,
    category="scanning",
)

SCAN_SQLMAP = GoldenSample(
    name="scan_sqlmap",
    description="SQLmap injection scanner detected",
    telemetry={
        "event_type": "http.suspicious",
        "tenant_id": "acme-corp",
        "source": "waf",
        "payload": {
            "src_ip": "198.51.100.30",
            "user_agent": "sqlmap/1.7",
            "endpoint": "/api/users?id=1' OR '1'='1",
            "method": "GET",
            "timestamp": 1706000900,
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,  # Fresh detector
    expected_max_anomaly_score=1.0,
    expected_rules=[],
    expected_mitigations=0,
    category="scanning",
)

# =============================================================================
# AI-Assisted Attack Samples
# =============================================================================

AI_LLM_SUSPICIOUS = GoldenSample(
    name="ai_llm_suspicious",
    description="Suspicious LLM usage pattern detected",
    telemetry={
        "event_type": "suspicious_llm_usage",
        "tenant_id": "acme-corp",
        "source": "llm-gateway",
        "payload": {
            "src_ip": "10.0.0.200",
            "model": "gpt-4",
            "prompt_category": "code_generation",
            "risk_indicators": ["privilege_escalation", "credential_harvesting"],
            "timestamp": 1706001000,
        },
    },
    expected_threat_level="medium",
    expected_min_anomaly_score=0.0,  # Fresh detector
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ai-assisted-attack"],
    expected_mitigations=0,
    category="ai_attack",
)

AI_PROMPT_INJECTION = GoldenSample(
    name="ai_prompt_injection",
    description="Potential prompt injection attack",
    telemetry={
        "event_type": "llm.prompt_injection",
        "tenant_id": "acme-corp",
        "source": "llm-firewall",
        "payload": {
            "src_ip": "172.16.0.50",
            "prompt_hash": "abc123",
            "injection_score": 0.85,
            "user_agent": "python-requests/2.28.0",
            "timestamp": 1706001100,
        },
    },
    expected_threat_level="low",  # No specific rule yet
    expected_min_anomaly_score=0.0,  # Fresh detector
    expected_max_anomaly_score=1.0,
    expected_rules=[],
    expected_mitigations=0,
    category="ai_attack",
)

# =============================================================================
# Polymorphic/Evasion Samples
# =============================================================================

POLYMORPHIC_ROTATING_UA = GoldenSample(
    name="polymorphic_rotating_ua",
    description="Attack with rotating user agents",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "acme-corp",
        "source": "web-app",
        "payload": {
            "src_ip": "203.0.113.100",
            "failed_auths": 12,
            "user_agents_seen": 8,  # Many different UAs
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "timestamp": 1706001200,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.6,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="polymorphic",
)

POLYMORPHIC_SLOW_BURN = GoldenSample(
    name="polymorphic_slow_burn",
    description="Slow brute-force evading rate limits",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "enterprise",
        "source": "auth-service",
        "payload": {
            "src_ip": "198.51.100.200",
            "failed_auths": 10,
            "time_span_minutes": 120,  # Spread over 2 hours
            "timestamp": 1706001300,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.5,
    expected_max_anomaly_score=0.9,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="polymorphic",
)

# =============================================================================
# Edge Cases
# =============================================================================

EDGE_EMPTY_PAYLOAD = GoldenSample(
    name="edge_empty_payload",
    description="Telemetry with empty payload",
    telemetry={
        "event_type": "unknown",
        "tenant_id": "test",
        "source": "test",
        "payload": {},
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,
    expected_max_anomaly_score=0.3,
    expected_rules=[],
    expected_mitigations=0,
    category="edge_case",
)

EDGE_MISSING_IP = GoldenSample(
    name="edge_missing_ip",
    description="Telemetry with no source IP",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "test",
        "source": "internal",
        "payload": {
            "failed_auths": 5,
            "user_id": "internal_service",
        },
    },
    expected_threat_level="low",
    expected_min_anomaly_score=0.0,
    expected_max_anomaly_score=0.4,
    expected_rules=[],
    expected_mitigations=0,
    category="edge_case",
)

EDGE_MALFORMED_BRUTEFORCE = GoldenSample(
    name="edge_malformed_bruteforce",
    description="Bruteforce event type but no count",
    telemetry={
        "event_type": "auth.bruteforce",
        "tenant_id": "test",
        "source": "test",
        "payload": {
            "src_ip": "10.0.0.1",
            # Missing failed_auths
        },
    },
    expected_threat_level="medium",
    expected_min_anomaly_score=0.3,
    expected_max_anomaly_score=0.6,
    expected_rules=["rule:missing_failed_count"],
    expected_mitigations=0,
    category="edge_case",
)

EDGE_EXTREME_VALUES = GoldenSample(
    name="edge_extreme_values",
    description="Extreme numeric values",
    telemetry={
        "event_type": "auth.failed",
        "tenant_id": "test",
        "source": "test",
        "payload": {
            "src_ip": "10.0.0.1",
            "failed_auths": 999999,
        },
    },
    expected_threat_level="high",
    expected_min_anomaly_score=0.7,
    expected_max_anomaly_score=1.0,
    expected_rules=["rule:ssh_bruteforce"],
    expected_mitigations=1,
    category="edge_case",
)

# =============================================================================
# All Samples Collection
# =============================================================================

ALL_GOLDEN_SAMPLES: List[GoldenSample] = [
    # Benign
    BENIGN_LOGIN_SUCCESS,
    BENIGN_API_REQUEST,
    BENIGN_FAILED_LOGIN_FEW,
    # Bruteforce
    BRUTEFORCE_SSH_BASIC,
    BRUTEFORCE_SSH_EXTREME,
    BRUTEFORCE_WEB_LOGIN,
    BRUTEFORCE_DISTRIBUTED,
    # Scanning
    SCAN_NMAP_DETECTED,
    SCAN_NIKTO,
    SCAN_SQLMAP,
    # AI Attacks
    AI_LLM_SUSPICIOUS,
    AI_PROMPT_INJECTION,
    # Polymorphic
    POLYMORPHIC_ROTATING_UA,
    POLYMORPHIC_SLOW_BURN,
    # Edge Cases
    EDGE_EMPTY_PAYLOAD,
    EDGE_MISSING_IP,
    EDGE_MALFORMED_BRUTEFORCE,
    EDGE_EXTREME_VALUES,
]

SAMPLES_BY_CATEGORY: Dict[str, List[GoldenSample]] = {}
for sample in ALL_GOLDEN_SAMPLES:
    if sample.category not in SAMPLES_BY_CATEGORY:
        SAMPLES_BY_CATEGORY[sample.category] = []
    SAMPLES_BY_CATEGORY[sample.category].append(sample)


def get_samples_by_category(category: str) -> List[GoldenSample]:
    """Get all samples for a specific category."""
    return SAMPLES_BY_CATEGORY.get(category, [])


def get_all_samples() -> List[GoldenSample]:
    """Get all golden samples."""
    return ALL_GOLDEN_SAMPLES
