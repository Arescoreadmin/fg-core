"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Evidence-strength classification taxonomy.

Defines the evidence-strength taxonomy for all pre-ceremony claims.  Each claim
carries an explicit strength level so that offline engineering proofs cannot be
misrepresented as live operational proofs.

SAFETY BOUNDARY
---------------
  DECLARED_ONLY does NOT automatically become PASS.
  STATIC_VERIFIED does NOT prove production behavior.
  Offline tests do NOT prove live HCP availability.
  TEST_PROVEN does NOT authorize paid ceremony spending.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


# ---------------------------------------------------------------------------
# Evidence-strength taxonomy
# ---------------------------------------------------------------------------


class EvidenceStrength(str, Enum):
    """Ordered evidence-strength levels from highest to lowest confidence."""

    RUNTIME_PROVEN = "RUNTIME_PROVEN"
    """Live operational proof in production/staging against real infrastructure."""

    TEST_PROVEN = "TEST_PROVEN"
    """Deterministic adversarial test proof (offline, real crypto, no mocks)."""

    STATIC_VERIFIED = "STATIC_VERIFIED"
    """Static source analysis — structure proven, runtime behavior not proven."""

    DECLARED_ONLY = "DECLARED_ONLY"
    """Human declaration; no automated verification performed."""

    NOT_PROVEN = "NOT_PROVEN"
    """Proof is required but has not been obtained."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """Requirement legitimately does not apply in this context."""


# Proof categories — execution stage boundaries
ProofStage = Literal[
    "OFFLINE_ENGINEERING",
    "PRE_PROVISIONING",
    "LIVE_CEREMONY",
]


@dataclass(frozen=True)
class PreAuthClaim:
    """A single critical pre-authorization claim with explicit evidence binding."""

    claim_id: str
    claim: str
    evidence_strength: EvidenceStrength
    evidence_source: str
    source_sha: str
    verification_method: str
    result: str
    limitations: str
    required_for_preauth: bool
    required_before_provisioning: bool
    required_during_ceremony: bool
    execution_stage: ProofStage

    def is_blocking_preauth(self) -> bool:
        """Return True if this claim is required but NOT_PROVEN/DECLARED_ONLY."""
        if not self.required_for_preauth:
            return False
        return self.evidence_strength in (
            EvidenceStrength.NOT_PROVEN,
            EvidenceStrength.DECLARED_ONLY,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "claim": self.claim,
            "evidence_strength": self.evidence_strength.value,
            "evidence_source": self.evidence_source,
            "source_sha": self.source_sha,
            "verification_method": self.verification_method,
            "result": self.result,
            "limitations": self.limitations,
            "required_for_preauth": self.required_for_preauth,
            "required_before_provisioning": self.required_before_provisioning,
            "required_during_ceremony": self.required_during_ceremony,
            "execution_stage": self.execution_stage,
        }


# ---------------------------------------------------------------------------
# Separation of proof categories — canonical boundary declaration
# ---------------------------------------------------------------------------

PROOF_CATEGORIES = {
    "OFFLINE_ENGINEERING_PROOF": (
        "Claims that MUST be proven in this PR via deterministic offline tests. "
        "No live HCP infrastructure required. Real cryptography only (no mocked True). "
        "Failure here BLOCKS preauth result."
    ),
    "PRE_PROVISIONING_OPERATIONAL_PROOF": (
        "Claims that MUST be verified by an authorized human operator during preflight, "
        "BEFORE billable infrastructure is created. Cannot be satisfied offline. "
        "Deferred from this PR. Must be in deferred_live_checks."
    ),
    "LIVE_CEREMONY_PROOF": (
        "Claims that require paid HCP Vault infrastructure in operation. "
        "Cannot be claimed offline. Cannot be deferred to post-ceremony. "
        "Presence of this PR does NOT satisfy these claims."
    ),
}
