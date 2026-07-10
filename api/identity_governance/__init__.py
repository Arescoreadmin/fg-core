"""api/identity_governance/ — FrostGate Identity Governance Foundation.

Pure Python service layer sitting on top of the Identity Authority. Provides
the deterministic building blocks required for identity governance:

- Lifecycle state machine for subjects (CREATED -> ARCHIVED/DELETED)
- Device trust registry with deterministic risk scoring
- Continuous session evaluation pipeline
- Conditional access policy engine (deterministic JSON policies)
- Hash-chained identity event timeline
- Identity graph snapshot / export
- Delegated administration authority boundaries
- Break-glass emergency access workflow
- Deterministic risk engine
- Identity digital twin exporter

No FastAPI routes are added by this package — it is a pure service layer.
Persistence tables exist in ``migrations/postgres/0148_identity_governance.sql``
for future integration, but the Phase 1 implementation operates in-memory.
"""

from api.identity_governance.break_glass import BreakGlassAuthority
from api.identity_governance.delegated_admin import (
    ADMIN_LEVEL_ORDER,
    DelegatedAdminAuthority,
)
from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.digital_twin import IdentityDigitalTwinExporter
from api.identity_governance.graph import IdentityGraphExporter
from api.identity_governance.lifecycle import (
    VALID_TRANSITIONS,
    IdentityLifecycleManager,
)
from api.identity_governance.models import (
    BreakGlassRequest,
    BreakGlassStatus,
    DelegatedAdminLevel,
    DelegatedAdminRecord,
    DelegatedAdminScope,
    DeviceRecord,
    DeviceTrustState,
    DigitalTwinSnapshot,
    GraphEdge,
    GraphNode,
    IdentityGraphSnapshot,
    IdentityLifecycleRecord,
    IdentityLifecycleState,
    IdentityTimelineEvent,
    IdentityTimelineEventType,
    PolicyCondition,
    PolicyDecision,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
    PolicyRecord,
    RiskBand,
    RiskContext,
    RiskScore,
    SessionEvaluationContext,
    SessionEvaluationDecision,
    SessionEvaluationResult,
)
from api.identity_governance.error_codes import (
    IDENTITY_ERROR_MESSAGES,
    IdentityErrorCode,
    error_body,
)
from api.identity_governance.policy_engine import ConditionalAccessPolicyEngine
from api.identity_governance.risk import EVALUATOR_VERSION, IdentityRiskEngine
from api.identity_governance.services import (
    GovernanceServices,
    get_services,
    reset_services,
)
from api.identity_governance.session_evaluation import SessionEvaluator
from api.identity_governance.timeline import IdentityTimeline

__all__ = [
    "ADMIN_LEVEL_ORDER",
    "BreakGlassAuthority",
    "BreakGlassRequest",
    "BreakGlassStatus",
    "ConditionalAccessPolicyEngine",
    "DelegatedAdminAuthority",
    "DelegatedAdminLevel",
    "DelegatedAdminRecord",
    "DelegatedAdminScope",
    "DeviceRecord",
    "DeviceTrustRegistry",
    "DeviceTrustState",
    "DigitalTwinSnapshot",
    "EVALUATOR_VERSION",
    "GovernanceServices",
    "GraphEdge",
    "GraphNode",
    "IDENTITY_ERROR_MESSAGES",
    "IdentityDigitalTwinExporter",
    "IdentityErrorCode",
    "IdentityGraphExporter",
    "IdentityGraphSnapshot",
    "IdentityLifecycleManager",
    "IdentityLifecycleRecord",
    "IdentityLifecycleState",
    "IdentityRiskEngine",
    "IdentityTimeline",
    "IdentityTimelineEvent",
    "IdentityTimelineEventType",
    "PolicyCondition",
    "PolicyDecision",
    "PolicyEvaluationContext",
    "PolicyEvaluationResult",
    "PolicyRecord",
    "RiskBand",
    "RiskContext",
    "RiskScore",
    "SessionEvaluationContext",
    "SessionEvaluationDecision",
    "SessionEvaluationResult",
    "SessionEvaluator",
    "VALID_TRANSITIONS",
    "error_body",
    "get_services",
    "reset_services",
]
