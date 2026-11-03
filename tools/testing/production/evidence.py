"""tools/testing/production/evidence.py — MODE-B-PROOF-HARDENING-001 evidence schema v2.

Machine-readable evidence records for production authentication verification.
PASS / FAIL / NOT_PROVEN / BLOCKED classification with deterministic acceptance logic.
Fingerprinted with SHA-256.

Never write tokens, cookies, passwords, or authorization headers into evidence.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "mode-b-proof-hardening-001/v2"
# Backward-compat alias used by historical consumers reading old artifacts
SCHEMA_VERSION_V1 = "prod-auth-automation-001/v1"
WORK_ITEM = "PROD-AUTH-AUTOMATION-001"

# Canonical minimum check sets per actor profile (semantic 15).
# The stored required_check_manifest must be a superset of this set.
# Evidence with a profile not listed here is not subject to completeness
# enforcement — allowing forward-compat with future profiles.
CANONICAL_CHECK_MANIFESTS: dict[str, list[str]] = {
    "internal_operator": [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "AUTH-004",
        "AUTH-005",
        "AUTH-006",
        "AUTH-007",
        "AUTH-008",
        "AUTH-009",
    ],
    "client_executive": [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "CLIENT-001",
        "CLIENT-002",
        "CLIENT-003",
        "CLIENT-004",
        "CLIENT-005",
        "CLIENT-006",
        "CLIENT-007",
        "AUTH-006",
        "AUTH-007",
        "AUTH-008",
        "AUTH-009",
    ],
    # Portal named-user profile (PORTAL-AUTH-E2E-001 / MODE-B-E2E-ACCEPTANCE-001)
    # 21 checks spanning the invitation → enrollment → access → revocation lifecycle.
    "portal_named_user": [
        "INV-001",
        "ENROLL-001",
        "ENROLL-002",
        "ENROLL-003",
        "ENROLL-004",
        "ENROLL-005",
        "BIND-001",
        "BIND-002",
        "BIND-003",
        "ACCESS-001",
        "ACCESS-002",
        "ACCESS-003",
        "REPORT-001",
        "DELIV-001",
        "REVOKE-001",
        "REVOKE-002",
        "LOGOUT-001",
        "LOGOUT-002",
        "XTENANT-001",
        "XENGAG-001",
        "REPLAY-001",
    ],
}

VALID_PROFILES: list[str] = list(CANONICAL_CHECK_MANIFESTS.keys())


class EvidenceResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_PROVEN = "NOT_PROVEN"
    # Prerequisite prevents execution; harness cannot establish the check.
    BLOCKED = "BLOCKED"


class AcceptanceDecision(str, Enum):
    # All required checks PASS.
    ACCEPTED = "ACCEPTED"
    # One or more checks are FAIL.
    REJECTED_FAIL = "REJECTED_FAIL"
    # Required checks are NOT_PROVEN, BLOCKED, or missing.
    REJECTED_INCOMPLETE = "REJECTED_INCOMPLETE"
    # Check collection is empty — no evidence was produced.
    REJECTED_EMPTY = "REJECTED_EMPTY"


@dataclass
class CheckResult:
    id: str
    description: str
    expected: str
    observed: str
    result: EvidenceResult
    timestamp: str
    diagnostic: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "description": self.description,
            "expected": self.expected,
            "observed": self.observed,
            "result": self.result.value,
            "timestamp": self.timestamp,
        }
        if self.diagnostic:
            d["diagnostic"] = self.diagnostic
        return d


@dataclass
class EvidenceRecord:
    schema_version: str = field(default_factory=lambda: SCHEMA_VERSION)
    work_item: str = field(default_factory=lambda: WORK_ITEM)
    # Actor profile that this record was produced for.
    verification_profile: str = "unknown"
    # Target environment (production, staging, preview).
    environment: str = "production"
    # Console origin URL (e.g. https://console.frostgate.ai).
    console_origin: str = ""
    # Core service identifier when applicable.
    core_service_id: str = "NOT_APPLICABLE"
    timestamp: str = ""
    run_id: str = ""
    # GitHub Actions run ID (or empty for local runs).
    workflow_run_id: str = ""
    # Source commit SHA of the code under test.
    repo_sha: str = "UNKNOWN"
    # Deployed SHA resolved via Vercel API (or NOT_PROVEN).
    deployed_sha: str = "NOT_PROVEN"
    deployment_id: str = "NOT_PROVEN"
    # Broad environment descriptor: public_smoke | authenticated_playwright | simulation.
    verification_environment: str = "public_smoke"
    # How this evidence was produced: automated | operator_assisted | simulation.
    test_execution_mode: str = "automated"
    # Human-readable provenance note.
    evidence_provenance: str = ""
    # Sanitized reference to the test identity (never the real email or credentials).
    test_identity_ref: str = "NOT_APPLICABLE"
    # Ordered list of check IDs that MUST be PASS for acceptance.
    # Empty list: fall back to all-PASS semantics over all recorded checks.
    required_check_manifest: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    unverified_production_checks: list[str] = field(default_factory=list)
    # Summary over individual check statuses.
    overall_result: EvidenceResult = field(default=EvidenceResult.NOT_PROVEN)
    # Authoritative launch-gate decision produced by verify_acceptance().
    acceptance_decision: str = field(
        default=AcceptanceDecision.REJECTED_INCOMPLETE.value
    )
    evidence_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "work_item": self.work_item,
            "verification_profile": self.verification_profile,
            "environment": self.environment,
            "console_origin": self.console_origin,
            "core_service_id": self.core_service_id,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "workflow_run_id": self.workflow_run_id,
            "repo_sha": self.repo_sha,
            "deployed_sha": self.deployed_sha,
            "deployment_id": self.deployment_id,
            "verification_environment": self.verification_environment,
            "test_execution_mode": self.test_execution_mode,
            "evidence_provenance": self.evidence_provenance,
            "test_identity_ref": self.test_identity_ref,
            "required_check_manifest": self.required_check_manifest,
            "checks": [c.to_dict() for c in self.checks],
            "unverified_production_checks": self.unverified_production_checks,
            "overall_result": self.overall_result.value,
            "acceptance_decision": self.acceptance_decision,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


# ---------------------------------------------------------------------------
# Acceptance logic — Phase 1 semantics
# ---------------------------------------------------------------------------


def verify_acceptance(record: EvidenceRecord) -> AcceptanceDecision:
    """Central deterministic acceptance function.

    Implements all 15 required semantics:
    1.  Overall PASS requires every required, applicable check to be PASS.
    2.  Any FAIL causes overall failure.
    3.  Any NOT_PROVEN causes overall nonacceptance.
    4.  Any BLOCKED causes overall nonacceptance.
    5.  Missing evidence causes overall nonacceptance.
    6.  Empty check collections cannot pass.
    7.  Unknown check IDs cannot satisfy required checks.
    8.  Duplicate check IDs cannot hide a failure.
    9.  Unexpected exceptions cannot produce PASS (enforced at harness level).
    10. Authentication failure cannot produce PASS (enforced at harness level).
    11. MFA challenge cannot produce PASS without completed auth (harness level).
    12. Workflow cancellation/timeout/missing artifacts not recordable as PASS.
    13. Check status evaluated by this central deterministic function.
    14. Exit status must agree with the acceptance state (enforced by caller).
    15. Manifest completeness: stored manifest must cover all canonical checks
        for the declared verification_profile. A reduced manifest cannot clear
        the gate with incomplete proof.
    """
    checks = record.checks

    # Semantic 6: Empty check collections cannot pass.
    if not checks:
        return AcceptanceDecision.REJECTED_EMPTY

    # Semantic 8: Duplicate check IDs cannot hide a failure.
    seen_ids: dict[str, list[EvidenceResult]] = {}
    for c in checks:
        seen_ids.setdefault(c.id, []).append(c.result)
    for cid, results in seen_ids.items():
        if len(results) > 1:
            return AcceptanceDecision.REJECTED_INCOMPLETE

    result_by_id: dict[str, EvidenceResult] = {c.id: c.result for c in checks}

    # Semantic 2: Any FAIL causes overall failure — check ALL checks, not just manifest.
    if any(r == EvidenceResult.FAIL for r in result_by_id.values()):
        return AcceptanceDecision.REJECTED_FAIL

    # Semantic 15: Manifest completeness against the canonical actor profile.
    # If the profile is known, every canonical check ID must appear in the
    # stored manifest. Evidence produced with a stripped manifest (e.g. by
    # a manual operator template that omits CLIENT-002 through CLIENT-007)
    # cannot clear the gate even if all listed checks are PASS.
    canonical = CANONICAL_CHECK_MANIFESTS.get(record.verification_profile)
    if canonical:
        stored_manifest_set = set(record.required_check_manifest)
        for canonical_id in canonical:
            if canonical_id not in stored_manifest_set:
                return AcceptanceDecision.REJECTED_INCOMPLETE

    required = list(record.required_check_manifest)

    if required:
        # Semantics 1, 3, 4, 5, 7: Each required check must exist and be PASS.
        for req_id in required:
            # Semantic 7: Unknown check IDs cannot satisfy required checks.
            # Semantic 5: Missing evidence causes nonacceptance.
            if req_id not in result_by_id:
                return AcceptanceDecision.REJECTED_INCOMPLETE
            result = result_by_id[req_id]
            # Semantic 3: Any NOT_PROVEN causes nonacceptance.
            if result == EvidenceResult.NOT_PROVEN:
                return AcceptanceDecision.REJECTED_INCOMPLETE
            # Semantic 4: Any BLOCKED causes nonacceptance.
            if result == EvidenceResult.BLOCKED:
                return AcceptanceDecision.REJECTED_INCOMPLETE
            # Semantic 1: Required check must be PASS.
            if result != EvidenceResult.PASS:
                return AcceptanceDecision.REJECTED_INCOMPLETE
    else:
        # No manifest: all recorded checks must PASS.
        for r in result_by_id.values():
            if r in (EvidenceResult.NOT_PROVEN, EvidenceResult.BLOCKED):
                return AcceptanceDecision.REJECTED_INCOMPLETE

    return AcceptanceDecision.ACCEPTED


def _compute_overall_result(checks: list[CheckResult]) -> EvidenceResult:
    """Summarise individual check results."""
    results = [c.result for c in checks]
    if not results:
        return EvidenceResult.NOT_PROVEN
    if any(r == EvidenceResult.FAIL for r in results):
        return EvidenceResult.FAIL
    if all(r == EvidenceResult.PASS for r in results):
        return EvidenceResult.PASS
    return EvidenceResult.NOT_PROVEN


# ---------------------------------------------------------------------------
# Fingerprinting and serialisation
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    def _norm(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): _norm(val) for k, val in sorted(v.items())}
        if isinstance(v, (list, tuple)):
            return [_norm(i) for i in v]
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return str(v)

    return json.dumps(
        _norm(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def fingerprint(record: EvidenceRecord) -> str:
    """SHA-256 fingerprint of the evidence record (excluding the fingerprint field)."""
    d = record.to_dict()
    d["evidence_fingerprint"] = ""
    return "sha256:" + hashlib.sha256(_canonical_json(d)).hexdigest()


def finalize(record: EvidenceRecord) -> EvidenceRecord:
    """Compute overall_result, acceptance_decision, and evidence_fingerprint. Mutates in place."""
    record.overall_result = _compute_overall_result(record.checks)
    decision = verify_acceptance(record)
    record.acceptance_decision = decision.value
    record.evidence_fingerprint = fingerprint(record)
    return record


def write_evidence(record: EvidenceRecord, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_evidence(path: Path) -> EvidenceRecord:
    """Load and reconstruct an EvidenceRecord from a JSON file (for verification)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    checks = [
        CheckResult(
            id=c["id"],
            description=c.get("description", ""),
            expected=c.get("expected", ""),
            observed=c.get("observed", ""),
            result=EvidenceResult(c["result"]),
            timestamp=c.get("timestamp", ""),
            diagnostic=c.get("diagnostic"),
        )
        for c in data.get("checks", [])
    ]
    return EvidenceRecord(
        schema_version=data.get("schema_version", SCHEMA_VERSION),
        work_item=data.get("work_item", WORK_ITEM),
        verification_profile=data.get("verification_profile", "unknown"),
        environment=data.get("environment", "production"),
        console_origin=data.get("console_origin", ""),
        core_service_id=data.get("core_service_id", "NOT_APPLICABLE"),
        timestamp=data.get("timestamp", ""),
        run_id=data.get("run_id", ""),
        workflow_run_id=data.get("workflow_run_id", ""),
        repo_sha=data.get("repo_sha", "UNKNOWN"),
        deployed_sha=data.get("deployed_sha", "NOT_PROVEN"),
        deployment_id=data.get("deployment_id", "NOT_PROVEN"),
        verification_environment=data.get("verification_environment", "public_smoke"),
        test_execution_mode=data.get("test_execution_mode", "automated"),
        evidence_provenance=data.get("evidence_provenance", ""),
        test_identity_ref=data.get("test_identity_ref", "NOT_APPLICABLE"),
        required_check_manifest=data.get("required_check_manifest", []),
        checks=checks,
        unverified_production_checks=data.get("unverified_production_checks", []),
        overall_result=EvidenceResult(
            data.get("overall_result", EvidenceResult.NOT_PROVEN.value)
        ),
        acceptance_decision=data.get(
            "acceptance_decision", AcceptanceDecision.REJECTED_INCOMPLETE.value
        ),
        evidence_fingerprint=data.get("evidence_fingerprint", ""),
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def repo_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN"
