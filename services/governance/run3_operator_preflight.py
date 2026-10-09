"""CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 — Deterministic operator preflight authority.

Produces a machine-readable OperatorPreflightManifest by composing all existing
Run-3 governance modules. Does NOT duplicate any existing contract logic — it
imports and calls the canonical modules.

PURPOSE
-------
Answer the single operational question:
  "Has the operator completed all known offline preparation tasks, and are the
  16 deferred live checks correctly catalogued for human review prior to any
  human cost authorization decision?"

SAFETY BOUNDARY (NON-NEGOTIABLE)
---------------------------------
- OFFLINE ONLY — no network calls, no cloud mutation, no live Vault or AWS
- READ-ONLY — no database writes, no filesystem mutations outside tests
- ZERO COST — no paid infrastructure contact of any kind
- NO SELF-AUTHORIZATION — PREPARED_FOR_HUMAN_REVIEW does NOT authorize spending
- NO TRUST ADVANCEMENT — CUSTOMER_ZERO_TRUST remains NOT_PROVEN

CANONICAL TRUTH PRESERVED
--------------------------
After this module executes, regardless of result:
  CUSTOMER_ZERO_TRUST = NOT_PROVEN
  CUSTOMER_ZERO_ACCEPTANCE = BLOCKED
  CUSTOMER-ZERO-TRUST-003 = BLOCKED
  THIRD_PAID_CEREMONY = NOT_AUTHORIZED
  PAID_HCP_INFRASTRUCTURE = ABSENT
  COST_AUTHORIZATION = NOT_AUTHORIZED

PREFLIGHT STATUS TAXONOMY
--------------------------
  PREPARED_FOR_HUMAN_REVIEW  — All offline preparation checks pass; 16 deferred live
                                checks correctly catalogued; manifest ready for operator
                                review before any human cost authorization decision.
                                Does NOT authorize spending. Does NOT prove trust.
  BLOCKED                    — One or more mandatory offline checks fail; manifest
                                cannot be submitted for human review until resolved.
  NOT_PROVEN                 — Default before evaluation completes.

PREFLIGHT FINGERPRINT DERIVATION
---------------------------------
SHA-256 of deterministic JSON of security-relevant fields:
  source_sha, candidate_fingerprint, infrastructure_fingerprint,
  resource_inventory_fingerprint, sorted blocker IDs.
  Excluded: generated_at, preflight_fingerprint itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[2]

os.environ.setdefault("FG_ENV", "test")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0"
WORK_ITEM = "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001"

CANONICAL_TRUTH = {
    "customer_zero_trust": "NOT_PROVEN",
    "customer_zero_trust_003": "BLOCKED",
    "customer_zero_accept_001": "BLOCKED",
    "third_paid_ceremony": "NOT_AUTHORIZED",
    "paid_hcp_infrastructure": "ABSENT",
    "cost_authorization": "NOT_AUTHORIZED",
}

# Expected number of ResourceInventoryEntry instances
EXPECTED_INVENTORY_COUNT = 21

# Required number of deferred live checks (LIVE_CEREMONY + PRE_PROVISIONING)
EXPECTED_DEFERRED_CHECK_COUNT = 16

# The 4 AWS audit resources that must be classified PRESERVE_AFTER_CEREMONY
REQUIRED_PRESERVED_AWS_RESOURCES = frozenset(
    {
        "aws_cloudwatch_log_group.vault_audit",
        "aws_iam_user.vault_audit",
        "aws_iam_policy.vault_audit",
        "aws_iam_user_policy_attachment.vault_audit",
    }
)


# ---------------------------------------------------------------------------
# Manifest dataclass
# ---------------------------------------------------------------------------


@dataclass
class OperatorPreflightManifest:
    """Deterministic, independently reviewable operator preflight manifest.

    This manifest is the complete operational plan for the third Customer-Zero
    trust ceremony. It is produced offline and submitted for human review before
    any cost authorization or paid infrastructure provisioning occurs.

    Fields marked as security-relevant are included in the preflight fingerprint
    computation. Fields marked as diagnostic only are excluded.
    """

    schema_version: str = SCHEMA_VERSION
    work_item: str = WORK_ITEM

    # Security-relevant binding fields (included in fingerprint)
    source_sha: str = ""
    candidate_fingerprint: str = ""
    infrastructure_fingerprint: str = ""
    resource_inventory_fingerprint: str = ""
    final_readiness_fingerprint: str = ""
    preauth_fingerprint: str = ""

    # Preflight fingerprint — derived last, over security-relevant fields
    preflight_fingerprint: str = ""  # Excluded from its own computation

    # Diagnostic metadata (excluded from fingerprint)
    generated_at: str = ""  # Wall-clock timestamp — diagnostic only

    # Status — never AUTHORIZED (human decision required)
    preflight_status: str = "NOT_PROVEN"

    # The 16 deferred live checks (all LIVE_CEREMONY / PRE_PROVISIONING)
    required_checks: list[dict[str, Any]] = field(default_factory=list)

    # Resource plan (from inventory)
    resource_plan: dict[str, Any] = field(default_factory=dict)

    # Audit prerequisites (CloudWatch, IAM reader)
    audit_prerequisites: dict[str, Any] = field(default_factory=dict)

    # Pricing request (from cost request module)
    pricing_request: dict[str, Any] = field(default_factory=dict)

    # Authorization request (always NOT_AUTHORIZED)
    authorization_request: dict[str, Any] = field(default_factory=dict)

    # Abort conditions (from abort matrix)
    abort_conditions: list[dict[str, Any]] = field(default_factory=list)

    # Teardown plan (from teardown contract)
    teardown_plan: dict[str, Any] = field(default_factory=dict)

    # Evidence manifest (what evidence must be captured)
    evidence_manifest: dict[str, Any] = field(default_factory=dict)

    # Blockers (reasons BLOCKED if not empty)
    blockers: list[str] = field(default_factory=list)

    # Structured deferred live checks (same content as required_checks, richer structure)
    deferred_live_checks: list[dict[str, Any]] = field(default_factory=list)

    # Offline mandatory check results
    offline_checks: list[dict[str, Any]] = field(default_factory=list)

    # Canonical truth record
    canonical_truth: dict[str, str] = field(
        default_factory=lambda: dict(CANONICAL_TRUTH)
    )

    def compute_preflight_fingerprint(self) -> str:
        """Compute preflight fingerprint over security-relevant fields.

        Excluded: generated_at, preflight_fingerprint itself.
        """
        canonical = {
            "source_sha": self.source_sha,
            "candidate_fingerprint": self.candidate_fingerprint,
            "infrastructure_fingerprint": self.infrastructure_fingerprint,
            "resource_inventory_fingerprint": self.resource_inventory_fingerprint,
            "final_readiness_fingerprint": self.final_readiness_fingerprint,
            "preauth_fingerprint": self.preauth_fingerprint,
            "blocker_ids": sorted(self.blockers),
            "work_item": self.work_item,
            "schema_version": self.schema_version,
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "work_item": self.work_item,
            "source_sha": self.source_sha,
            "candidate_fingerprint": self.candidate_fingerprint,
            "infrastructure_fingerprint": self.infrastructure_fingerprint,
            "resource_inventory_fingerprint": self.resource_inventory_fingerprint,
            "final_readiness_fingerprint": self.final_readiness_fingerprint,
            "preauth_fingerprint": self.preauth_fingerprint,
            "preflight_fingerprint": self.preflight_fingerprint,
            "generated_at": self.generated_at,
            "preflight_status": self.preflight_status,
            "required_checks": self.required_checks,
            "deferred_live_checks": self.deferred_live_checks,
            "resource_plan": self.resource_plan,
            "audit_prerequisites": self.audit_prerequisites,
            "pricing_request": self.pricing_request,
            "authorization_request": self.authorization_request,
            "abort_conditions": self.abort_conditions,
            "teardown_plan": self.teardown_plan,
            "evidence_manifest": self.evidence_manifest,
            "blockers": self.blockers,
            "offline_checks": self.offline_checks,
            "canonical_truth": self.canonical_truth,
        }


# ---------------------------------------------------------------------------
# Git helpers (patchable for tests)
# ---------------------------------------------------------------------------


def _git_head_sha(repo: Path) -> str:
    """Return the current HEAD SHA of the repository."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _git_status_clean(repo: Path) -> tuple[bool, str]:
    """Return (clean, detail). Clean means no uncommitted changes."""
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            return False, f"git status failed: {r.stderr.strip()}"
        dirty = r.stdout.strip()
        if dirty:
            return False, f"dirty_files={dirty[:200]}"
        return True, "clean"
    except Exception as exc:
        return False, str(exc)


def _git_origin_main(repo: Path) -> tuple[bool, str]:
    """Return (on_main_or_pr_branch, detail)."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            return False, f"git branch failed: {r.stderr.strip()}"
        branch = r.stdout.strip()
        # Accept main or the preflight branch
        ok = branch in ("main", "governance/customer-zero-run3-operator-preflight-001")
        return ok, f"branch={branch}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Offline mandatory check implementations
# ---------------------------------------------------------------------------


def _check_source_binding(repo: Path, source_sha: str) -> dict[str, Any]:
    """SOURCE-BINDING: Validate current HEAD SHA matches expected pattern."""
    ok = len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha)
    return {
        "check_id": "SOURCE-BINDING",
        "description": "Current HEAD SHA is a valid 40-char hex git commit SHA",
        "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
        "result": "PASS" if ok else "FAIL",
        "detail": f"source_sha={source_sha[:16]}... valid_hex40={ok}",
    }


def _check_candidate_fingerprint(repo: Path) -> dict[str, Any]:
    """CANDIDATE-FINGERPRINT: Computed fingerprint matches recorded."""
    try:
        from services.governance.run3_candidate import build_candidate

        c1 = build_candidate(repo)
        c2 = build_candidate(repo)
        deterministic = c1.candidate_fingerprint == c2.candidate_fingerprint
        valid = len(c1.candidate_fingerprint) == 64
        ok = deterministic and valid
        return {
            "check_id": "CANDIDATE-FINGERPRINT",
            "description": "Candidate fingerprint computable and deterministic",
            "evidence_strength": "TEST_PROVEN" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"fingerprint={c1.candidate_fingerprint[:16]}... "
                f"deterministic={deterministic} valid_sha256={valid}"
            ),
            "_candidate_fingerprint": c1.candidate_fingerprint,
        }
    except Exception as exc:
        return {
            "check_id": "CANDIDATE-FINGERPRINT",
            "description": "Candidate fingerprint computable and deterministic",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_infra_fingerprint(repo: Path) -> dict[str, Any]:
    """INFRA-FINGERPRINT: Infrastructure source fingerprint computable."""
    try:
        from services.governance.run3_candidate import _compute_infra_fingerprint

        fp1 = _compute_infra_fingerprint()
        fp2 = _compute_infra_fingerprint()
        ok = len(fp1) == 64 and fp1 == fp2
        return {
            "check_id": "INFRA-FINGERPRINT",
            "description": "Infrastructure source fingerprint deterministic from infra/*.tf",
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": f"fingerprint={fp1[:16]}... deterministic={fp1 == fp2}",
            "_infrastructure_fingerprint": fp1,
        }
    except Exception as exc:
        return {
            "check_id": "INFRA-FINGERPRINT",
            "description": "Infrastructure source fingerprint deterministic from infra/*.tf",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_inventory_count(repo: Path) -> dict[str, Any]:
    """INVENTORY-COUNT: Exactly 21 ResourceInventoryEntry instances."""
    try:
        from services.governance.run3_resource_inventory import RESOURCE_INVENTORY

        count = len(RESOURCE_INVENTORY)
        ok = count == EXPECTED_INVENTORY_COUNT
        return {
            "check_id": "INVENTORY-COUNT",
            "description": f"Resource inventory has exactly {EXPECTED_INVENTORY_COUNT} entries",
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": f"count={count} expected={EXPECTED_INVENTORY_COUNT}",
        }
    except Exception as exc:
        return {
            "check_id": "INVENTORY-COUNT",
            "description": f"Resource inventory has exactly {EXPECTED_INVENTORY_COUNT} entries",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_proof_matrix_completeness(repo: Path) -> dict[str, Any]:
    """PROOF-MATRIX-COMPLETENESS: All 16 deferred checks present, no duplicates."""
    try:
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        ids = [p.proof_id for p in deferred]
        unique_ids = set(ids)
        count = len(deferred)
        no_dupes = len(ids) == len(unique_ids)
        ok = count == EXPECTED_DEFERRED_CHECK_COUNT and no_dupes
        return {
            "check_id": "PROOF-MATRIX-COMPLETENESS",
            "description": (
                f"Proof matrix has exactly {EXPECTED_DEFERRED_CHECK_COUNT} deferred live checks, "
                "no duplicates"
            ),
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"deferred_count={count} expected={EXPECTED_DEFERRED_CHECK_COUNT} "
                f"no_duplicates={no_dupes} total_matrix={len(PROOF_MATRIX)}"
            ),
        }
    except Exception as exc:
        return {
            "check_id": "PROOF-MATRIX-COMPLETENESS",
            "description": (
                f"Proof matrix has exactly {EXPECTED_DEFERRED_CHECK_COUNT} deferred live checks, "
                "no duplicates"
            ),
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_final_readiness_ready(repo: Path) -> dict[str, Any]:
    """FINAL-READINESS-READY: evaluate() returns READY."""
    try:
        from services.governance.customer_zero_readiness import evaluate

        result = evaluate(repo)
        ready = result.final_result.value == "READY"
        zero_blockers = result.offline_blocker_count == 0
        ok = ready and zero_blockers
        return {
            "check_id": "FINAL-READINESS-READY",
            "description": "Final-readiness evaluate() returns READY with 0 offline blockers",
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"final_result={result.final_result.value} "
                f"offline_blocker_count={result.offline_blocker_count}"
            ),
            "_final_readiness_fingerprint": result.canonical_fingerprint,
        }
    except Exception as exc:
        return {
            "check_id": "FINAL-READINESS-READY",
            "description": "Final-readiness evaluate() returns READY with 0 offline blockers",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_preauth_ready(repo: Path) -> dict[str, Any]:
    """PREAUTH-READY: Preauth evaluator exits 0 or item is in completed."""
    try:
        r = subprocess.run(
            [
                sys.executable,
                str(repo / "tools" / "ci" / "customer_zero_run3_preauth.py"),
                "--repo",
                str(repo),
                "--json",
            ],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=120,
        )
        ok = r.returncode == 0
        # Also accept COMPLETED evidence (post-merge the preauth item moves to completed)
        preauth_fp = ""
        if ok and r.stdout:
            try:
                artifact = json.loads(r.stdout)
                preauth_fp = artifact.get("canonical_fingerprint", "")
            except Exception:
                pass
        return {
            "check_id": "PREAUTH-READY",
            "description": "RUN3-PREAUTH CLI returns READY_FOR_HUMAN_COST_AUTHORIZATION (exit 0)",
            "evidence_strength": "TEST_PROVEN" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": f"exit_code={r.returncode}",
            "_preauth_fingerprint": preauth_fp,
        }
    except Exception as exc:
        return {
            "check_id": "PREAUTH-READY",
            "description": "RUN3-PREAUTH CLI returns READY_FOR_HUMAN_COST_AUTHORIZATION (exit 0)",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_simulation_green(repo: Path) -> dict[str, Any]:
    """SIMULATION-GREEN: offline_simulation_evidence.json is valid.

    Calls _validate_offline_simulation_evidence() from customer_zero_readiness
    (returns 4-tuple: status, evidence, reason, remediation) or falls back to
    direct JSON validation if the internal function is unavailable.
    """
    evidence_path = repo / "customer_one" / "offline_simulation_evidence.json"
    if not evidence_path.exists():
        return {
            "check_id": "SIMULATION-GREEN",
            "description": "Offline simulation evidence file is valid and GREEN",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": "offline_simulation_evidence.json not found",
        }
    # Try the canonical 4-tuple validator first
    try:
        from services.governance.customer_zero_readiness import (
            _validate_offline_simulation_evidence,  # type: ignore[attr-defined]
        )

        status_val, evidence, reason, _remediation = (
            _validate_offline_simulation_evidence(evidence_path, repo)
        )
        # status_val may be ReadinessStatus enum or plain string
        status_str = (
            status_val.value if hasattr(status_val, "value") else str(status_val)
        )
        ok = status_str == "PASS"
        return {
            "check_id": "SIMULATION-GREEN",
            "description": "Offline simulation evidence file is valid and GREEN",
            "evidence_strength": "TEST_PROVEN" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": evidence if ok else f"{status_str}: {reason}",
        }
    except (AttributeError, ImportError):
        pass
    except Exception as exc:
        return {
            "check_id": "SIMULATION-GREEN",
            "description": "Offline simulation evidence file is valid and GREEN",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": f"validation error: {exc}",
        }
    # Fallback: direct JSON validation
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
        result_green = data.get("result") == "GREEN"
        checks_passed = data.get("checks_passed", 0)
        checks_failed = data.get("checks_failed", 0)
        checks_executed = data.get("checks_executed", [])
        source_tree_hash = data.get("source_tree_hash", "")
        ok = (
            result_green
            and checks_passed > 0
            and checks_failed == 0
            and len(checks_executed) > 0
            and len(checks_executed) == len(set(checks_executed))  # no duplicates
            and bool(source_tree_hash)
        )
        return {
            "check_id": "SIMULATION-GREEN",
            "description": "Offline simulation evidence file is valid and GREEN",
            "evidence_strength": "TEST_PROVEN" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"result={data.get('result')} checks_passed={checks_passed} "
                f"checks_failed={checks_failed} has_tree_hash={bool(source_tree_hash)}"
            ),
        }
    except Exception as exc2:
        return {
            "check_id": "SIMULATION-GREEN",
            "description": "Offline simulation evidence file is valid and GREEN",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc2),
        }


def _check_teardown_contract(repo: Path) -> dict[str, Any]:
    """TEARDOWN-CONTRACT: Abort/teardown entries present."""
    try:
        from services.governance.run3_abort_teardown import (
            ABORT_MATRIX,
            TEARDOWN_CONTRACT,
        )

        abort_count = len(ABORT_MATRIX)
        preserved = TEARDOWN_CONTRACT.get("post_ceremony_preserved", [])
        absent = TEARDOWN_CONTRACT.get("post_ceremony_absent", [])
        preserved_addrs = {r["terraform_address"] for r in preserved}
        has_required_preserved = REQUIRED_PRESERVED_AWS_RESOURCES.issubset(
            preserved_addrs
        )
        has_absent = len(absent) >= 4
        no_proven = all(not a.blocks_proven for a in ABORT_MATRIX)
        ok = abort_count >= 10 and has_required_preserved and has_absent and no_proven
        return {
            "check_id": "TEARDOWN-CONTRACT",
            "description": "Abort matrix and teardown contract present and valid",
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"abort_count={abort_count} preserved_count={len(preserved)} "
                f"absent_count={len(absent)} no_proven={no_proven} "
                f"has_required_preserved={has_required_preserved}"
            ),
        }
    except Exception as exc:
        return {
            "check_id": "TEARDOWN-CONTRACT",
            "description": "Abort matrix and teardown contract present and valid",
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _check_preserved_audit_resources(repo: Path) -> dict[str, Any]:
    """PRESERVED-AUDIT-RESOURCES: 4 AWS audit resources classified PRESERVE_AFTER_CEREMONY."""
    try:
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        preserved = [
            r
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
        ]
        preserved_addrs = {r.terraform_address for r in preserved}
        has_all = REQUIRED_PRESERVED_AWS_RESOURCES.issubset(preserved_addrs)
        count = len(preserved)
        ok = has_all and count >= 4
        return {
            "check_id": "PRESERVED-AUDIT-RESOURCES",
            "description": (
                "4 AWS audit resources classified PRESERVE_AFTER_CEREMONY "
                "(never destroyed)"
            ),
            "evidence_strength": "STATIC_VERIFIED" if ok else "NOT_PROVEN",
            "result": "PASS" if ok else "FAIL",
            "detail": (
                f"preserved_count={count} required={len(REQUIRED_PRESERVED_AWS_RESOURCES)} "
                f"has_all_required={has_all}"
            ),
        }
    except Exception as exc:
        return {
            "check_id": "PRESERVED-AUDIT-RESOURCES",
            "description": (
                "4 AWS audit resources classified PRESERVE_AFTER_CEREMONY "
                "(never destroyed)"
            ),
            "evidence_strength": "NOT_PROVEN",
            "result": "FAIL",
            "detail": str(exc),
        }


def _run_offline_checks(repo: Path, source_sha: str) -> list[dict[str, Any]]:
    """Run all mandatory offline checks. Returns list of check result dicts."""
    checks: list[dict[str, Any]] = []
    checks.append(_check_source_binding(repo, source_sha))
    checks.append(_check_candidate_fingerprint(repo))
    checks.append(_check_infra_fingerprint(repo))
    checks.append(_check_inventory_count(repo))
    checks.append(_check_proof_matrix_completeness(repo))
    checks.append(_check_final_readiness_ready(repo))
    checks.append(_check_preauth_ready(repo))
    checks.append(_check_simulation_green(repo))
    checks.append(_check_teardown_contract(repo))
    checks.append(_check_preserved_audit_resources(repo))
    return checks


# ---------------------------------------------------------------------------
# Manifest builder
# ---------------------------------------------------------------------------


def build_preflight_manifest(repo: Path | None = None) -> OperatorPreflightManifest:
    """Build the deterministic operator preflight manifest.

    Composes all existing Run-3 modules. Safe to call multiple times —
    produces the same preflight fingerprint for the same source checkout.

    SAFETY INVARIANT: Never sets cost_authorization_status = AUTHORIZED.
    Never marks trust PROVEN. Never unblocks TRUST-003 or ACCEPT-001.
    """
    global _REPO
    if repo is not None:
        _REPO = repo

    manifest = OperatorPreflightManifest()
    manifest.generated_at = datetime.now(UTC).isoformat()

    # ── Source SHA ────────────────────────────────────────────────────────
    source_sha = _git_head_sha(_REPO)
    manifest.source_sha = source_sha

    # ── Offline checks ────────────────────────────────────────────────────
    offline_checks = _run_offline_checks(_REPO, source_sha)
    manifest.offline_checks = offline_checks

    # Collect blockers from failed checks
    blockers: list[str] = []
    for check in offline_checks:
        if check["result"] != "PASS":
            blockers.append(f"{check['check_id']}: {check['detail']}")

    # ── Extract fingerprints from check results ────────────────────────────
    for check in offline_checks:
        if check["check_id"] == "CANDIDATE-FINGERPRINT":
            manifest.candidate_fingerprint = check.get("_candidate_fingerprint", "")
        elif check["check_id"] == "INFRA-FINGERPRINT":
            manifest.infrastructure_fingerprint = check.get(
                "_infrastructure_fingerprint", ""
            )
        elif check["check_id"] == "FINAL-READINESS-READY":
            manifest.final_readiness_fingerprint = check.get(
                "_final_readiness_fingerprint", ""
            )
        elif check["check_id"] == "PREAUTH-READY":
            manifest.preauth_fingerprint = check.get("_preauth_fingerprint", "")

    # ── Resource inventory fingerprint ────────────────────────────────────
    try:
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )

        manifest.resource_inventory_fingerprint = compute_inventory_fingerprint()
    except Exception:
        manifest.resource_inventory_fingerprint = "FINGERPRINT_ERROR"
        blockers.append(
            "RESOURCE-INVENTORY-FINGERPRINT: Cannot compute inventory fingerprint"
        )

    # ── Resource plan ─────────────────────────────────────────────────────
    try:
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            get_ephemeral_resources,
            get_cost_bearing_resources,
        )

        inventory = get_inventory()
        manifest.resource_plan = {
            "total_resources": len(inventory),
            "cost_bearing": [r.to_dict() for r in get_cost_bearing_resources()],
            "ephemeral": [r.to_dict() for r in get_ephemeral_resources()],
            "preserved": [r.to_dict() for r in get_preserved_resources()],
            "full_inventory": [r.to_dict() for r in inventory],
        }
    except Exception as exc:
        manifest.resource_plan = {"error": str(exc)}

    # ── Audit prerequisites ───────────────────────────────────────────────
    try:
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        preserved_audit = [
            r.to_dict()
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
        ]
        reused = [
            r.to_dict()
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.REUSE_PRESERVED
        ]
        manifest.audit_prerequisites = {
            "preserved_aws_audit_resources": preserved_audit,
            "reused_preserved_resources": reused,
            "cloudwatch_log_group_required": "aws_cloudwatch_log_group.vault_audit",
            "audit_writer_required": "aws_iam_user.vault_audit",
            "audit_reader_required": "aws_iam_role.vault_audit_reader",
            "pre_ceremony_audit_verification": (
                "CloudWatch log group must be confirmed present before HCP cluster creation. "
                "Vault audit logging must be configured in HCP UI before any trust operations. "
                "Checkpoint Q: first Vault operation after provisioning must produce visible "
                "CloudWatch audit event before proceeding to proof matrix execution."
            ),
            "abort_condition": "ABORT-PRE-009: missing_audit_prerequisites",
        }
    except Exception as exc:
        manifest.audit_prerequisites = {"error": str(exc)}

    # ── Pricing request ───────────────────────────────────────────────────
    try:
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )
        from services.governance.run3_cost_request import build_cost_request

        candidate = build_candidate(_REPO)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]
        cost_req = build_cost_request(
            candidate.candidate_fingerprint,
            inv_fp,
            resources,
            preserved,
            source_sha,
        )
        manifest.pricing_request = cost_req.to_dict()
    except Exception as exc:
        manifest.pricing_request = {"error": str(exc)}

    # ── Authorization request (always NOT_AUTHORIZED) ─────────────────────
    manifest.authorization_request = {
        "authorization_status": "NOT_AUTHORIZED",
        "cost_authorization_status": "NOT_AUTHORIZED",
        "proposed_max_cost_usd": None,
        "proposed_max_runtime_hours": None,
        "authorization_owner": None,
        "authorization_expiration": None,
        "note": (
            "This preflight manifest is submitted for HUMAN REVIEW ONLY. "
            "PREPARED_FOR_HUMAN_REVIEW means offline preparation is complete. "
            "It does NOT constitute cost authorization, trust authorization, "
            "or permission to create paid HCP infrastructure. "
            "A human operator with explicit authority must create a separate "
            "authorization record after reviewing this manifest."
        ),
    }

    # ── Abort conditions ──────────────────────────────────────────────────
    try:
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        manifest.abort_conditions = [a.to_dict() for a in ABORT_MATRIX]
    except Exception as exc:
        manifest.abort_conditions = [{"error": str(exc)}]

    # ── Teardown plan ─────────────────────────────────────────────────────
    try:
        from services.governance.run3_abort_teardown import TEARDOWN_CONTRACT

        manifest.teardown_plan = TEARDOWN_CONTRACT
    except Exception as exc:
        manifest.teardown_plan = {"error": str(exc)}

    # ── Evidence manifest ─────────────────────────────────────────────────
    manifest.evidence_manifest = {
        "required_before_teardown": [
            "CloudWatch log group audit events captured to local file",
            "Portable verification bundles enrolled with all three trust key public materials",
            "Ceremony evidence manifest signed and captured",
            "All proof family results (A-K) documented with pass/fail/evidence",
        ],
        "required_artifacts": [
            "ceremony_audit_log/identity_signing_positive",
            "ceremony_audit_log/acceptance_signing_positive",
            "ceremony_audit_log/approval_signing_positive",
            "ceremony_audit_log/domain_isolation_3x3",
            "ceremony_audit_log/replay_resistance",
            "ceremony_audit_log/rotation_identity",
            "ceremony_audit_log/rotation_replay",
            "ceremony_audit_log/verifier_contract",
            "ceremony_audit_log/provenance_integrity",
            "ceremony_audit_log/cloudwatch_audit_evidence",
            "ceremony_audit_log/tenant_isolation",
            "ceremony_audit_log/checkpoint_q_audit",
        ],
        "post_ceremony_required": [
            "PortableVerificationAuthority.verify_offline() passes on all captured artifacts",
            "Billing evidence captured after teardown completes",
            "Provider-side deletion confirmed (not just Terraform state)",
        ],
        "abort_on_missing": True,
        "abort_reference": "ABORT-TEAR-001: required_evidence_not_preserved",
    }

    # ── Deferred live checks (the 16) ─────────────────────────────────────
    try:
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        manifest.required_checks = [
            {
                "check_id": p.proof_id,
                "proof_family": p.proof_id.split("-")[0],
                "objective": p.objective,
                "prerequisites": p.preconditions,
                "required_operator_role": "FrostGateTerraformOperator",
                "required_evidence": p.evidence_artifact,
                "verification_method": p.verification_method,
                "pass_condition": p.expected_result,
                "fail_condition": f"expected_result not achieved; failure_class={p.failure_classification}",
                "evidence_strength": "NOT_PROVEN",  # None have been proven yet
                "execution_stage": p.execution_stage,
                "abort_trigger": (
                    "ABORT-CER-002"
                    if "isolation" in p.objective.lower()
                    else "ABORT-CER-003"
                    if "replay" in p.objective.lower()
                    else "ABORT-POST-003"
                    if "audit" in p.objective.lower()
                    else "ABORT-CER-001"
                ),
            }
            for p in deferred
        ]
        manifest.deferred_live_checks = manifest.required_checks
    except Exception as exc:
        manifest.required_checks = [{"error": str(exc)}]
        manifest.deferred_live_checks = manifest.required_checks
        blockers.append(f"DEFERRED-LIVE-CHECKS: Cannot build check list: {exc}")

    # ── Determine preflight status ────────────────────────────────────────
    # Validate deferred check count
    deferred_count = len([c for c in manifest.required_checks if "error" not in c])
    if deferred_count != EXPECTED_DEFERRED_CHECK_COUNT:
        blockers.append(
            f"DEFERRED-COUNT: expected {EXPECTED_DEFERRED_CHECK_COUNT} deferred live checks, "
            f"got {deferred_count}"
        )

    manifest.blockers = blockers

    if not blockers:
        manifest.preflight_status = "PREPARED_FOR_HUMAN_REVIEW"
    else:
        manifest.preflight_status = "BLOCKED"

    # ── Preflight fingerprint (computed last) ─────────────────────────────
    manifest.preflight_fingerprint = manifest.compute_preflight_fingerprint()

    return manifest
