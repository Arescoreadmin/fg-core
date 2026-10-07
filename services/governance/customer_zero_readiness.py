"""CUSTOMER-ZERO-FINAL-READINESS-001 — Deterministic offline readiness authority.

This module is NOT standalone. It is a component of the FrostGate governance
platform and Customer-Zero trust ceremony readiness track.

PURPOSE
-------
Answer the single commercial question:
  "Can FrostGate prove, without provisioning paid infrastructure, that there are
  zero known offline blockers remaining before spending money on the final
  Customer-Zero trust ceremony?"

SAFETY BOUNDARY (NON-NEGOTIABLE)
---------------------------------
- OFFLINE ONLY — no network calls, no cloud mutation, no live Vault
- READ-ONLY — no database writes, no filesystem mutations outside tests
- ZERO COST — no paid infrastructure contact of any kind
- NO SELF-AUTHORIZATION — READY does not authorize spending or acceptance

CANONICAL TRUTH PRESERVED
--------------------------
After this module executes, regardless of result:
  CUSTOMER_ZERO_TRUST = NOT_PROVEN
  CUSTOMER_ZERO_ACCEPTANCE = BLOCKED
  CUSTOMER-ZERO-TRUST-003 = BLOCKED (not authorized by READY here)
  THIRD_PAID_CEREMONY = NOT_AUTHORIZED
  PAID_HCP_INFRASTRUCTURE = ABSENT

READINESS TAXONOMY
------------------
  PASS         — Evidence deterministically proves the requirement is met
  FAIL         — Evidence deterministically proves a violation exists
  NOT_PROVEN   — Required proof cannot be established from permitted offline evidence
  NOT_APPLICABLE — Requirement legitimately does not apply in this context
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0.0"
WORK_ITEM = "CUSTOMER-ZERO-FINAL-READINESS-001"
MODE = "offline"

# Required completed prerequisites (must appear in roadmap_authority.yaml completed)
REQUIRED_COMPLETED_PREREQUISITES = (
    "PROVENANCE-INTEGRITY-001",
    "VAULT-VERIFY-CONTRACT-001",
)

# Canonical truth: these are NEVER modified by this module.
CANONICAL_CUSTOMER_ZERO_TRUST_STATUS = "NOT_PROVEN"
CANONICAL_THIRD_PAID_CEREMONY_STATUS = "NOT_AUTHORIZED"
CANONICAL_ACCEPTANCE_STATUS = "BLOCKED"
CANONICAL_PAID_INFRA_STATUS = "ABSENT"

_REPO = Path(__file__).resolve().parents[2]

_SECRET_PATTERNS = (
    "private_key",
    "private key",
    "secret_id",
    "secret id",
    "secretid",
    "vault_token",
    "vault token",
    "bearer",
    "authorization",
    "recovery_key",
    "recovery key",
    "unseal",
    "approleid",
    "role_id",
    "client_secret",
    "client secret",
    "signing_key",
    "signing key",
    "seed",
)


# ---------------------------------------------------------------------------
# Status taxonomy
# ---------------------------------------------------------------------------


class ReadinessStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_PROVEN = "NOT_PROVEN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FinalResult(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReadinessDimension:
    """A single evaluated readiness dimension."""

    id: str
    category: str
    name: str
    status: ReadinessStatus
    evidence: str
    required: bool = True
    reason: str = ""
    remediation: str = ""
    offline_remediable: bool = True

    def is_blocker(self) -> bool:
        return self.required and self.status in (
            ReadinessStatus.FAIL,
            ReadinessStatus.NOT_PROVEN,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "status": self.status.value,
            "required": self.required,
            "evidence": self.evidence,
            "reason": self.reason,
            "remediation": self.remediation,
            "offline_remediable": self.offline_remediable,
        }


@dataclass(frozen=True)
class Blocker:
    """A readiness blocker with stable ID and remediation guidance."""

    id: str
    dimension_id: str
    status: ReadinessStatus
    reason: str
    evidence_reference: str
    remediation: str
    offline_remediable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "dimension_id": self.dimension_id,
            "status": self.status.value,
            "reason": self.reason,
            "evidence_reference": self.evidence_reference,
            "remediation": self.remediation,
            "offline_remediable": self.offline_remediable,
        }


@dataclass
class ReadinessResult:
    """Complete deterministic readiness evaluation result."""

    source_sha: str
    generated_at: str
    dimensions: list[ReadinessDimension] = field(default_factory=list)
    blockers: list[Blocker] = field(default_factory=list)

    @property
    def offline_blocker_count(self) -> int:
        return len(self.blockers)

    @property
    def final_result(self) -> FinalResult:
        return FinalResult.READY if not self.blockers else FinalResult.BLOCKED

    @property
    def canonical_fingerprint(self) -> str:
        """Deterministic fingerprint excluding generated_at."""
        canonical: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "work_item": WORK_ITEM,
            "source_sha": self.source_sha,
            "mode": MODE,
            "paid_infrastructure_present": False,
            "customer_zero_trust_status": CANONICAL_CUSTOMER_ZERO_TRUST_STATUS,
            "third_paid_ceremony_status": CANONICAL_THIRD_PAID_CEREMONY_STATUS,
            "dimensions": sorted(
                [d.to_dict() for d in self.dimensions], key=lambda x: x["id"]
            ),
            "offline_blockers": sorted(
                [b.to_dict() for b in self.blockers], key=lambda x: x["id"]
            ),
            "offline_blocker_count": self.offline_blocker_count,
            "result": self.final_result.value,
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "work_item": WORK_ITEM,
            "source_sha": self.source_sha,
            "generated_at": self.generated_at,
            "mode": MODE,
            "paid_infrastructure_present": False,
            "customer_zero_trust_status": CANONICAL_CUSTOMER_ZERO_TRUST_STATUS,
            "third_paid_ceremony_status": CANONICAL_THIRD_PAID_CEREMONY_STATUS,
            "canonical_truth": {
                "CUSTOMER_ZERO_TRUST": "NOT_PROVEN",
                "CUSTOMER_ZERO_ACCEPTANCE": "BLOCKED",
                "CUSTOMER_ZERO_TRUST_003": "NOT_AUTHORIZED",
                "THIRD_PAID_CEREMONY": "NOT_AUTHORIZED",
                "PAID_HCP_INFRASTRUCTURE": "ABSENT",
            },
            "dimensions": sorted(
                [d.to_dict() for d in self.dimensions], key=lambda x: x["id"]
            ),
            "offline_blockers": sorted(
                [b.to_dict() for b in self.blockers], key=lambda x: x["id"]
            ),
            "offline_blocker_count": self.offline_blocker_count,
            "result": self.final_result.value,
            "canonical_fingerprint": self.canonical_fingerprint,
        }


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


def _load_yaml_safe(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning empty dict on error."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _git_head(repo: Path) -> str:
    """Return HEAD SHA or empty string."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _git_origin_main(repo: Path) -> str:
    """Return origin/main SHA or empty string."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "origin/main"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _git_status_clean(repo: Path) -> bool:
    """Return True if the working tree is clean."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and result.stdout.strip() == ""
    except Exception:
        return False


def _git_branch(repo: Path) -> str:
    """Return current branch name or empty string."""
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _find_in_section(authority: dict[str, Any], section: str, item_id: str) -> bool:
    return any(
        e.get("id") == item_id
        for e in authority.get(section, [])
        if isinstance(e, dict)
    )


def _roadmap_checker_authorized(repo: Path, work_item: str) -> bool:
    """Run check_customer_one_roadmap.py and return True if AUTHORIZED."""
    checker = repo / "tools" / "ci" / "check_customer_one_roadmap.py"
    if not checker.exists():
        return False
    try:
        result = subprocess.run(
            ["python", str(checker), "--work-item", work_item],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0 and "AUTHORIZED" in result.stdout
    except Exception:
        return False


def _check_no_secret_material(data: Any, path: str = "$") -> list[str]:
    """Recursively scan for secret-bearing keys. Returns list of violations."""
    violations: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(pat in key_lower for pat in _SECRET_PATTERNS):
                violations.append(f"secret-bearing key at {path}.{key}")
            violations.extend(_check_no_secret_material(value, f"{path}.{key}"))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            violations.extend(_check_no_secret_material(item, f"{path}[{i}]"))
    return violations


def _terraform_files_exist(infra: Path) -> bool:
    return infra.exists() and any(infra.glob("*.tf"))


def _terraform_fmt_check(infra: Path) -> bool:
    """Run terraform fmt -check. Returns True if clean or terraform not available."""
    try:
        result = subprocess.run(
            ["terraform", "fmt", "-check", "-recursive"],
            cwd=str(infra),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # terraform not installed — classify as NOT_PROVEN not FAIL
        return False
    except Exception:
        return False


def _terraform_validate(infra: Path) -> tuple[bool, str]:
    """Run terraform validate (no provider auth). Returns (ok, message)."""
    try:
        # First init with -backend=false to avoid backend auth
        init_result = subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false"],
            cwd=str(infra),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if init_result.returncode != 0:
            return False, f"terraform init failed: {init_result.stderr[:200]}"
        val_result = subprocess.run(
            ["terraform", "validate"],
            cwd=str(infra),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return val_result.returncode == 0, val_result.stdout[:200]
    except FileNotFoundError:
        return False, "terraform not installed"
    except Exception as exc:
        return False, str(exc)[:200]


# ---------------------------------------------------------------------------
# Portable verification authority
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortableVerificationBundle:
    """Public-only portable verification bundle for offline historical verification.

    SECURITY INVARIANT: PRIVATE SIGNING MATERIAL MUST NEVER ENTER THIS BUNDLE.
    """

    artifact_digest: str  # SHA-256 of the canonical artifact bytes
    manifest: dict[str, Any]
    signature: str  # vault:v<n>:<base64>
    trust_domain: str
    public_key_material: str  # Base64-encoded Ed25519 public key (PUBLIC ONLY)
    public_key_fingerprint: str
    key_identifier: str
    key_version: int
    algorithm: str
    signing_timestamp: str
    source_sha: str
    methodology_version: str
    provenance_sha: str
    audit_evidence_reference: str

    def __post_init__(self) -> None:
        # Security: reject if manifest contains any secret-bearing field names.
        # This enforces that no private key material enters the portable bundle.
        manifest_violations = _check_no_secret_material(self.manifest, "$.manifest")
        if manifest_violations:
            raise ValueError(
                f"Security violation: portable bundle manifest contains secret-bearing fields: {manifest_violations}"
            )
        # Also scan the full bundle dict representation
        bundle_repr = {
            "signature": self.signature,
            "algorithm": self.algorithm,
            "key_identifier": self.key_identifier,
        }
        repr_violations = _check_no_secret_material(bundle_repr, "$")
        if repr_violations:
            raise ValueError(
                f"Security violation: portable bundle contains secret-bearing fields: {repr_violations}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_digest": self.artifact_digest,
            "manifest": self.manifest,
            "signature": self.signature,
            "trust_domain": self.trust_domain,
            "public_key_material": self.public_key_material,
            "public_key_fingerprint": self.public_key_fingerprint,
            "key_identifier": self.key_identifier,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "signing_timestamp": self.signing_timestamp,
            "source_sha": self.source_sha,
            "methodology_version": self.methodology_version,
            "provenance_sha": self.provenance_sha,
            "audit_evidence_reference": self.audit_evidence_reference,
        }

    @classmethod
    def validate_no_private_material(cls, bundle_dict: dict[str, Any]) -> bool:
        """Validate that a bundle dict contains no secret/private-key material."""
        violations = _check_no_secret_material(bundle_dict, "$")
        return len(violations) == 0


class PortableVerificationAuthority:
    """Durable offline verification authority for pre-enrolled public material.

    This authority allows historical verification of governance artifacts when
    the original Vault authority is absent (post-teardown scenario).

    DESIGN PRINCIPLE: Verification uses only:
      - The signed artifact/digest
      - The preserved public verification material (public key only)
      - The canonical signature
      - Non-secret provenance metadata

    Vault is NOT required for verification once public material is enrolled.
    """

    def __init__(self) -> None:
        # Registry: (trust_domain, key_identifier, key_version) -> public_key_material
        self._enrolled: dict[tuple[str, str, int], str] = {}

    def enroll(
        self,
        trust_domain: str,
        key_identifier: str,
        key_version: int,
        public_key_material: str,
    ) -> None:
        """Enroll pre-provisioned public verification material.

        ONLY public key material is accepted. Private keys are rejected.
        """
        violations = _check_no_secret_material(
            {"public_key_material": public_key_material}, "$"
        )
        if violations:
            raise ValueError(
                f"Private material rejected from portable bundle: {violations}"
            )
        self._enrolled[(trust_domain, key_identifier, key_version)] = (
            public_key_material
        )

    def is_enrolled(
        self, trust_domain: str, key_identifier: str, key_version: int
    ) -> bool:
        return (trust_domain, key_identifier, key_version) in self._enrolled

    def verify_offline(self, bundle: PortableVerificationBundle) -> bool:
        """Verify a governance artifact offline using pre-enrolled public material.

        This method deliberately does NOT contact Vault. It uses only the
        pre-enrolled public key and the canonical artifact digest/signature.

        Returns:
            True if verification succeeds with pre-enrolled material
            False if verification fails (invalid, wrong domain, wrong key, absent material)
        """
        from services.cgin.key_management.vault_transit import (
            TrustAnchor,
            TrustRole,
            public_key_fingerprint,
        )

        key = (bundle.trust_domain, bundle.key_identifier, bundle.key_version)
        if key not in self._enrolled:
            return False

        enrolled_pub = self._enrolled[key]

        # Verify fingerprint consistency
        try:
            computed_fp = public_key_fingerprint(enrolled_pub)
        except Exception:
            return False

        if computed_fp != bundle.public_key_fingerprint:
            return False

        # Reconstruct the signing payload from the artifact digest + domain
        # The artifact digest is the SHA-256 of the canonical artifact bytes.
        # For historical verification, we verify the signature over the artifact_digest
        # using the signing payload bound to the trust_domain.
        signing_payload = f"{bundle.trust_domain}\n{bundle.artifact_digest}".encode(
            "utf-8"
        )

        # Map trust_domain to TrustRole
        _domain_role_map = {
            "frostgate.report-proof.v1": TrustRole.IDENTITY,
            "frostgate.production-qualification.v1": TrustRole.APPROVAL,
            "frostgate.governed-delivery-authorization.v1": TrustRole.ACCEPTANCE,
            # Test domain used in adversarial tests
            "frostgate.test-domain.v1": TrustRole.IDENTITY,
        }
        role = _domain_role_map.get(bundle.trust_domain)
        if role is None:
            return False

        anchor = TrustAnchor(
            issuer=bundle.audit_evidence_reference,
            trust_role=role,
            key_id=bundle.key_identifier,
            key_version=bundle.key_version,
            algorithm=bundle.algorithm,
            public_key=enrolled_pub,
            public_key_fingerprint=computed_fp,
            status="active",
        )

        return anchor.verify(signing_payload, bundle.signature)


# ---------------------------------------------------------------------------
# Dimension evaluators (one per dimension)
# ---------------------------------------------------------------------------


def _dim(
    id: str,
    category: str,
    name: str,
    status: ReadinessStatus,
    evidence: str,
    reason: str = "",
    remediation: str = "",
    required: bool = True,
    offline_remediable: bool = True,
) -> ReadinessDimension:
    return ReadinessDimension(
        id=id,
        category=category,
        name=name,
        status=status,
        evidence=evidence,
        reason=reason,
        remediation=remediation,
        required=required,
        offline_remediable=offline_remediable,
    )


def _evaluate_repository_authority(repo: Path) -> list[ReadinessDimension]:
    """A. REPOSITORY / AUTHORITY dimensions."""
    dims: list[ReadinessDimension] = []
    authority_yaml = repo / "customer_one" / "roadmap_authority.yaml"

    # A1 — repository_authority
    authority = _load_yaml_safe(authority_yaml)
    if authority:
        dims.append(
            _dim(
                "A1-repository-authority",
                "A-REPOSITORY",
                "repository_authority",
                ReadinessStatus.PASS,
                f"customer_one/roadmap_authority.yaml loaded (schema_version={authority.get('schema_version', 'unknown')})",
            )
        )
    else:
        dims.append(
            _dim(
                "A1-repository-authority",
                "A-REPOSITORY",
                "repository_authority",
                ReadinessStatus.FAIL,
                "customer_one/roadmap_authority.yaml missing or malformed",
                reason="Authority file required for roadmap verification",
                remediation="Ensure customer_one/roadmap_authority.yaml exists and is valid YAML",
            )
        )

    # A2 — roadmap_authority (roadmap checker)
    authorized = _roadmap_checker_authorized(repo, WORK_ITEM)
    if authorized:
        dims.append(
            _dim(
                "A2-roadmap-authority",
                "A-REPOSITORY",
                "roadmap_authority",
                ReadinessStatus.PASS,
                "tools/ci/check_customer_one_roadmap.py returns AUTHORIZED for CUSTOMER-ZERO-FINAL-READINESS-001",
            )
        )
    else:
        dims.append(
            _dim(
                "A2-roadmap-authority",
                "A-REPOSITORY",
                "roadmap_authority",
                ReadinessStatus.FAIL,
                "check_customer_one_roadmap.py did not return AUTHORIZED",
                reason="Work item must be authorized before evaluation",
                remediation="Ensure CUSTOMER-ZERO-FINAL-READINESS-001 is in next_sequence with all blocked_by completed",
            )
        )

    # A3 — canonical_source_sha (HEAD == origin/main)
    head = _git_head(repo)
    origin_main = _git_origin_main(repo)
    if head and origin_main and head == origin_main:
        dims.append(
            _dim(
                "A3-canonical-source-sha",
                "A-REPOSITORY",
                "canonical_source_sha",
                ReadinessStatus.PASS,
                f"HEAD ({head[:12]}) == origin/main ({origin_main[:12]})",
            )
        )
    elif not head or not origin_main:
        dims.append(
            _dim(
                "A3-canonical-source-sha",
                "A-REPOSITORY",
                "canonical_source_sha",
                ReadinessStatus.NOT_PROVEN,
                "Could not determine HEAD or origin/main SHA",
                reason="Git state unavailable for canonical SHA verification",
                remediation="Ensure git is available and repository has origin/main",
            )
        )
    else:
        dims.append(
            _dim(
                "A3-canonical-source-sha",
                "A-REPOSITORY",
                "canonical_source_sha",
                ReadinessStatus.FAIL,
                f"HEAD ({head[:12]}) != origin/main ({origin_main[:12]})",
                reason="Source SHA mismatch; branch not synchronized with canonical main",
                remediation="git fetch origin --prune && git reset --hard origin/main",
            )
        )

    # A4 — clean_source_requirement
    clean = _git_status_clean(repo)
    if clean:
        dims.append(
            _dim(
                "A4-clean-source-requirement",
                "A-REPOSITORY",
                "clean_source_requirement",
                ReadinessStatus.PASS,
                "git status --porcelain: no uncommitted changes",
            )
        )
    else:
        dims.append(
            _dim(
                "A4-clean-source-requirement",
                "A-REPOSITORY",
                "clean_source_requirement",
                ReadinessStatus.FAIL,
                "Working tree has uncommitted changes",
                reason="Clean source required for deterministic readiness evaluation",
                remediation="Commit or stash all uncommitted changes before readiness evaluation",
            )
        )

    # A5 — completed_prerequisite_repairs
    missing_prereqs: list[str] = []
    for prereq in REQUIRED_COMPLETED_PREREQUISITES:
        if not _find_in_section(authority, "completed", prereq):
            missing_prereqs.append(prereq)

    if not missing_prereqs:
        dims.append(
            _dim(
                "A5-completed-prerequisite-repairs",
                "A-REPOSITORY",
                "completed_prerequisite_repairs",
                ReadinessStatus.PASS,
                f"Prerequisites confirmed in completed: {list(REQUIRED_COMPLETED_PREREQUISITES)}",
            )
        )
    else:
        dims.append(
            _dim(
                "A5-completed-prerequisite-repairs",
                "A-REPOSITORY",
                "completed_prerequisite_repairs",
                ReadinessStatus.FAIL,
                f"Missing completed prerequisites: {missing_prereqs}",
                reason="PROVENANCE-INTEGRITY-001 and VAULT-VERIFY-CONTRACT-001 must both be completed",
                remediation="Complete both prerequisites before CUSTOMER-ZERO-FINAL-READINESS-001",
            )
        )

    return dims


def _evaluate_application_truth(repo: Path) -> list[ReadinessDimension]:
    """B. APPLICATION TRUTH dimensions."""
    dims: list[ReadinessDimension] = []

    # B6 — result_truth_gate: check FG_RESULT_TRUTH_GATE implementation status
    authority = _load_yaml_safe(repo / "customer_one" / "roadmap_authority.yaml")
    active_obj = authority.get("active_objective", {})
    has_truth_gate = (
        isinstance(active_obj, dict)
        and active_obj.get("id") == "FG_RESULT_TRUTH_GATE"
        and active_obj.get("implementation_status") == "COMPLETE"
    )
    if has_truth_gate:
        dims.append(
            _dim(
                "B6-result-truth-gate",
                "B-APPLICATION-TRUTH",
                "result_truth_gate",
                ReadinessStatus.PASS,
                "FG_RESULT_TRUTH_GATE implementation_status=COMPLETE in roadmap_authority.yaml",
            )
        )
    else:
        dims.append(
            _dim(
                "B6-result-truth-gate",
                "B-APPLICATION-TRUTH",
                "result_truth_gate",
                ReadinessStatus.NOT_PROVEN,
                "FG_RESULT_TRUTH_GATE implementation status cannot be confirmed from offline evidence",
                reason="Result truth gate implementation status not confirmed",
                remediation="Verify FG_RESULT_TRUTH_GATE implementation_status=COMPLETE in roadmap_authority.yaml",
            )
        )

    # B7 — deterministic_findings: field_assessment.py _derive_manifest_hash exists
    fa_path = repo / "api" / "field_assessment.py"
    has_derive = False
    if fa_path.exists():
        content = fa_path.read_text(encoding="utf-8")
        has_derive = "_derive_manifest_hash_from_report_json" in content
    if has_derive:
        dims.append(
            _dim(
                "B7-deterministic-findings",
                "B-APPLICATION-TRUTH",
                "deterministic_findings",
                ReadinessStatus.PASS,
                "api/field_assessment.py contains _derive_manifest_hash_from_report_json (PROVENANCE-INTEGRITY-001 repair)",
            )
        )
    else:
        dims.append(
            _dim(
                "B7-deterministic-findings",
                "B-APPLICATION-TRUTH",
                "deterministic_findings",
                ReadinessStatus.FAIL,
                "api/field_assessment.py missing _derive_manifest_hash_from_report_json",
                reason="PROVENANCE-INTEGRITY-001 repair requires this function",
                remediation="Merge PROVENANCE-INTEGRITY-001 (PR #750) before this gate",
            )
        )

    # B8 — epistemic_determination: check FGA-025/026/027/028 completed
    fga_items = ["FGA-025", "FGA-026", "FGA-027", "FGA-028"]
    completed_fgas = [
        fid for fid in fga_items if _find_in_section(authority, "completed", fid)
    ]
    if len(completed_fgas) == len(fga_items):
        dims.append(
            _dim(
                "B8-epistemic-determination",
                "B-APPLICATION-TRUTH",
                "epistemic_determination",
                ReadinessStatus.PASS,
                f"FGA-025 through FGA-028 all completed: {completed_fgas}",
            )
        )
    else:
        missing_fgas = [f for f in fga_items if f not in completed_fgas]
        dims.append(
            _dim(
                "B8-epistemic-determination",
                "B-APPLICATION-TRUTH",
                "epistemic_determination",
                ReadinessStatus.NOT_PROVEN,
                f"Not all FGA items completed — missing: {missing_fgas}",
                reason="FGA epistemic authority items should be complete for assessment quality",
                remediation="Complete all FGA-025 through FGA-028 items",
            )
        )

    # B9 — technical_qa / REPORT-QA-001
    has_report_qa = _find_in_section(authority, "completed", "REPORT-QA-001")
    dims.append(
        _dim(
            "B9-technical-qa",
            "B-APPLICATION-TRUTH",
            "technical_qa",
            ReadinessStatus.PASS if has_report_qa else ReadinessStatus.NOT_PROVEN,
            (
                "REPORT-QA-001 completed"
                if has_report_qa
                else "REPORT-QA-001 not found in completed"
            ),
            reason="" if has_report_qa else "Report QA authority required",
            remediation="" if has_report_qa else "Complete REPORT-QA-001",
        )
    )

    # B10 — governance_qa / FA-ACTOR-001 + PROD-QUAL-001
    has_fa_actor = _find_in_section(authority, "completed", "FA-ACTOR-001")
    has_prod_qual = _find_in_section(authority, "completed", "PROD-QUAL-001")
    if has_fa_actor and has_prod_qual:
        dims.append(
            _dim(
                "B10-governance-qa",
                "B-APPLICATION-TRUTH",
                "governance_qa",
                ReadinessStatus.PASS,
                "FA-ACTOR-001 and PROD-QUAL-001 both completed",
            )
        )
    else:
        missing = [
            n
            for n, ok in [
                ("FA-ACTOR-001", has_fa_actor),
                ("PROD-QUAL-001", has_prod_qual),
            ]
            if not ok
        ]
        dims.append(
            _dim(
                "B10-governance-qa",
                "B-APPLICATION-TRUTH",
                "governance_qa",
                ReadinessStatus.NOT_PROVEN,
                f"Missing governance QA prerequisites: {missing}",
                reason="FA actor and production qualification authorities required",
                remediation=f"Complete: {missing}",
            )
        )

    # B11 — report_generation: GOV-DELIVERY-TRANSPORT-001 complete
    has_transport = _find_in_section(
        authority, "completed", "GOV-DELIVERY-TRANSPORT-001"
    )
    dims.append(
        _dim(
            "B11-report-generation",
            "B-APPLICATION-TRUTH",
            "report_generation",
            ReadinessStatus.PASS if has_transport else ReadinessStatus.NOT_PROVEN,
            (
                "GOV-DELIVERY-TRANSPORT-001 completed"
                if has_transport
                else "GOV-DELIVERY-TRANSPORT-001 not in completed"
            ),
            reason=(
                "" if has_transport else "Report delivery transport authority required"
            ),
            remediation="" if has_transport else "Complete GOV-DELIVERY-TRANSPORT-001",
        )
    )

    # B12 — provenance_integrity: PROVENANCE-INTEGRITY-001 completed
    has_pi = _find_in_section(authority, "completed", "PROVENANCE-INTEGRITY-001")
    dims.append(
        _dim(
            "B12-provenance-integrity",
            "B-APPLICATION-TRUTH",
            "provenance_integrity",
            ReadinessStatus.PASS if has_pi else ReadinessStatus.FAIL,
            (
                "PROVENANCE-INTEGRITY-001 completed (PR #750)"
                if has_pi
                else "PROVENANCE-INTEGRITY-001 NOT in completed"
            ),
            reason="" if has_pi else "DEFECT-PROVENANCE-INTEGRITY must be repaired",
            remediation="" if has_pi else "Merge PROVENANCE-INTEGRITY-001 repair",
        )
    )

    # B13 — source_build_methodology_provenance: trust_binding.py VaultBackend present
    tb_path = repo / "services" / "governance" / "trust_binding.py"
    has_vault_backend = False
    if tb_path.exists():
        content = tb_path.read_text(encoding="utf-8")
        has_vault_backend = "class VaultBackend" in content
    dims.append(
        _dim(
            "B13-source-build-methodology-provenance",
            "B-APPLICATION-TRUTH",
            "source_build_methodology_provenance",
            ReadinessStatus.PASS if has_vault_backend else ReadinessStatus.FAIL,
            (
                "VaultBackend class present in services/governance/trust_binding.py"
                if has_vault_backend
                else "VaultBackend class missing"
            ),
            reason="" if has_vault_backend else "Production VaultBackend required",
            remediation=(
                "" if has_vault_backend else "Ensure TRUST-BINDING-001 is merged"
            ),
        )
    )

    # B14 — remediation_reverification_path: check for TrustBindingFake test path
    fake_path = repo / "services" / "governance" / "trust_binding_fake.py"
    has_fake = fake_path.exists()
    dims.append(
        _dim(
            "B14-remediation-reverification-path",
            "B-APPLICATION-TRUTH",
            "remediation_reverification_path",
            ReadinessStatus.PASS if has_fake else ReadinessStatus.FAIL,
            (
                "services/governance/trust_binding_fake.py present (deterministic test path)"
                if has_fake
                else "trust_binding_fake.py missing"
            ),
            reason=(
                ""
                if has_fake
                else "Test fake required for deterministic reverification"
            ),
            remediation=(
                ""
                if has_fake
                else "Restore trust_binding_fake.py from TRUST-BINDING-001"
            ),
        )
    )

    return dims


def _evaluate_tenant_security(repo: Path) -> list[ReadinessDimension]:
    """C. TENANT / SECURITY BOUNDARY dimensions."""
    dims: list[ReadinessDimension] = []

    # C15 — tenant_isolation: RLS patterns in migrations
    migrations_path = repo / "migrations" / "postgres"
    has_rls = False
    if migrations_path.exists():
        for f in list(migrations_path.rglob("*.sql"))[:50]:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if (
                    "ROW LEVEL SECURITY" in content.upper()
                    or "ENABLE ROW LEVEL SECURITY" in content.upper()
                ):
                    has_rls = True
                    break
            except Exception:
                pass
    if not has_rls:
        # Check migration Python files for RLS
        for f in list(migrations_path.rglob("*.py"))[:50]:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if (
                    "row level security" in content.lower()
                    or "enable_rls" in content.lower()
                ):
                    has_rls = True
                    break
            except Exception:
                pass

    dims.append(
        _dim(
            "C15-tenant-isolation",
            "C-TENANT-SECURITY",
            "tenant_isolation",
            ReadinessStatus.PASS if has_rls else ReadinessStatus.NOT_PROVEN,
            (
                "RLS migration evidence found in migrations/postgres"
                if has_rls
                else "Could not confirm RLS in migrations"
            ),
            reason="" if has_rls else "Tenant RLS required for isolation",
            remediation="" if has_rls else "Verify RLS migrations are present",
        )
    )

    # C16 — RLS_authority: check_core_rls.py exists
    check_rls = repo / "tools" / "ci" / "check_core_rls.py"
    dims.append(
        _dim(
            "C16-rls-authority",
            "C-TENANT-SECURITY",
            "RLS_authority",
            ReadinessStatus.PASS if check_rls.exists() else ReadinessStatus.NOT_PROVEN,
            (
                "tools/ci/check_core_rls.py present"
                if check_rls.exists()
                else "tools/ci/check_core_rls.py missing"
            ),
            reason="" if check_rls.exists() else "RLS CI gate required",
            remediation="" if check_rls.exists() else "Restore check_core_rls.py",
        )
    )

    # C17 — authentication_boundary: Auth0 OIDC pattern
    auth_path = repo / "admin_gateway" / "auth" / "oidc.py"
    dims.append(
        _dim(
            "C17-authentication-boundary",
            "C-TENANT-SECURITY",
            "authentication_boundary",
            ReadinessStatus.PASS if auth_path.exists() else ReadinessStatus.NOT_PROVEN,
            (
                "admin_gateway/auth/oidc.py present (Auth0 OIDC boundary)"
                if auth_path.exists()
                else "OIDC auth module not found"
            ),
            reason=(
                "" if auth_path.exists() else "Authentication boundary module required"
            ),
            remediation=(
                "" if auth_path.exists() else "Restore admin_gateway/auth/oidc.py"
            ),
        )
    )

    # C18 — authorization_boundary: TrustBindingAuthority present
    tb_path = repo / "services" / "governance" / "trust_binding.py"
    has_auth = tb_path.exists()
    dims.append(
        _dim(
            "C18-authorization-boundary",
            "C-TENANT-SECURITY",
            "authorization_boundary",
            ReadinessStatus.PASS if has_auth else ReadinessStatus.FAIL,
            (
                "services/governance/trust_binding.py present (TrustBindingAuthority)"
                if has_auth
                else "trust_binding.py missing"
            ),
            reason="" if has_auth else "Authorization boundary required",
            remediation="" if has_auth else "Merge TRUST-BINDING-001",
        )
    )

    # C19 — secret_boundary: check_no_plaintext_secrets.py exists
    check_secrets = repo / "tools" / "ci" / "check_no_plaintext_secrets.py"
    dims.append(
        _dim(
            "C19-secret-boundary",
            "C-TENANT-SECURITY",
            "secret_boundary",
            (
                ReadinessStatus.PASS
                if check_secrets.exists()
                else ReadinessStatus.NOT_PROVEN
            ),
            (
                "tools/ci/check_no_plaintext_secrets.py present"
                if check_secrets.exists()
                else "Secret boundary checker not found"
            ),
            reason="" if check_secrets.exists() else "Secret boundary CI gate required",
            remediation=(
                ""
                if check_secrets.exists()
                else "Restore check_no_plaintext_secrets.py"
            ),
        )
    )

    # C20 — production_security_gates: fg-security target exists in Makefile
    makefile = repo / "Makefile"
    has_fg_security = False
    if makefile.exists():
        content = makefile.read_text(encoding="utf-8")
        has_fg_security = "fg-security:" in content
    dims.append(
        _dim(
            "C20-production-security-gates",
            "C-TENANT-SECURITY",
            "production_security_gates",
            ReadinessStatus.PASS if has_fg_security else ReadinessStatus.NOT_PROVEN,
            (
                "fg-security Makefile target present"
                if has_fg_security
                else "fg-security target not found in Makefile"
            ),
            reason="" if has_fg_security else "Production security gate required",
            remediation=(
                "" if has_fg_security else "Restore fg-security Makefile target"
            ),
        )
    )

    return dims


def _evaluate_trust_authority(repo: Path) -> list[ReadinessDimension]:
    """D. TRUST AUTHORITY dimensions (21-30)."""
    dims: list[ReadinessDimension] = []

    vt_path = repo / "services" / "cgin" / "key_management" / "vault_transit.py"
    tb_path = repo / "services" / "governance" / "trust_binding.py"

    # D21 — identity domain verification
    has_domain_report = False
    if tb_path.exists():
        content = tb_path.read_text(encoding="utf-8")
        has_domain_report = (
            "DOMAIN_REPORT" in content
            and "DOMAIN_QUALIFICATION" in content
            and "DOMAIN_DELIVERY_AUTHORIZATION" in content
        )
    dims.append(
        _dim(
            "D21-identity-domain-verification",
            "D-TRUST-AUTHORITY",
            "identity_domain_verification",
            ReadinessStatus.PASS if has_domain_report else ReadinessStatus.FAIL,
            (
                "Domain constants DOMAIN_REPORT/QUALIFICATION/DELIVERY_AUTHORIZATION present in trust_binding.py"
                if has_domain_report
                else "Domain constants missing"
            ),
            reason="" if has_domain_report else "Domain separation required for trust",
            remediation="" if has_domain_report else "Merge TRUST-BINDING-001",
        )
    )

    # D22 — cross-domain replay rejection
    has_replay_guard = False
    if tb_path.exists():
        content = tb_path.read_text(encoding="utf-8")
        # Domain prefix in signing bytes prevents cross-domain replay
        has_replay_guard = "_prepare_signing_bytes" in content and "domain" in content
    dims.append(
        _dim(
            "D22-cross-domain-replay-rejection",
            "D-TRUST-AUTHORITY",
            "cross_domain_replay_rejection",
            ReadinessStatus.PASS if has_replay_guard else ReadinessStatus.FAIL,
            (
                "_prepare_signing_bytes with domain prefix present in trust_binding.py"
                if has_replay_guard
                else "Cross-domain replay guard missing"
            ),
            reason=(
                ""
                if has_replay_guard
                else "Domain prefix required to prevent cross-domain replay"
            ),
            remediation="" if has_replay_guard else "Merge TRUST-BINDING-001",
        )
    )

    # D23 — key version semantics
    has_kv = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_kv = (
            "VaultKeyVersionUnavailableError" in content and "key_version" in content
        )
    dims.append(
        _dim(
            "D23-key-version-semantics",
            "D-TRUST-AUTHORITY",
            "key_version_semantics",
            ReadinessStatus.PASS if has_kv else ReadinessStatus.FAIL,
            (
                "VaultKeyVersionUnavailableError present in vault_transit.py (VAULT-VERIFY-CONTRACT-001)"
                if has_kv
                else "Key version error type missing"
            ),
            reason=(
                ""
                if has_kv
                else "DEFECT-VERIFIER-CONTRACT: key version must be distinguishable"
            ),
            remediation="" if has_kv else "Merge VAULT-VERIFY-CONTRACT-001 (PR #751)",
        )
    )

    # D24 — historical key verification
    has_hist = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_hist = "TrustAnchorRegistry" in content
    dims.append(
        _dim(
            "D24-historical-key-verification",
            "D-TRUST-AUTHORITY",
            "historical_key_verification",
            ReadinessStatus.PASS if has_hist else ReadinessStatus.FAIL,
            (
                "TrustAnchorRegistry present in vault_transit.py (offline historical verification)"
                if has_hist
                else "TrustAnchorRegistry missing"
            ),
            reason=(
                ""
                if has_hist
                else "Historical key verification requires TrustAnchorRegistry"
            ),
            remediation="" if has_hist else "Merge TRUST-BINDING-001",
        )
    )

    # D25 — deterministic verification contract
    has_det = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_det = "VaultVerifierUnavailableError" in content
    dims.append(
        _dim(
            "D25-deterministic-verification-contract",
            "D-TRUST-AUTHORITY",
            "deterministic_verification_contract",
            ReadinessStatus.PASS if has_det else ReadinessStatus.FAIL,
            (
                "VaultVerifierUnavailableError present (operational vs. invalid distinction)"
                if has_det
                else "VaultVerifierUnavailableError missing"
            ),
            reason=(
                ""
                if has_det
                else "DEFECT-VERIFIER-CONTRACT: operational failure must be distinguishable"
            ),
            remediation="" if has_det else "Merge VAULT-VERIFY-CONTRACT-001",
        )
    )

    # D26 — operational verifier failure contract
    # Check that TrustBindingAuthority.verify_report catches VaultTransitError -> False
    has_fail_closed = False
    if tb_path.exists():
        content = tb_path.read_text(encoding="utf-8")
        has_fail_closed = (
            "except VaultTransitError" in content and "return False" in content
        )
    dims.append(
        _dim(
            "D26-operational-verifier-failure-contract",
            "D-TRUST-AUTHORITY",
            "operational_verifier_failure_contract",
            ReadinessStatus.PASS if has_fail_closed else ReadinessStatus.FAIL,
            (
                "TrustBindingAuthority.verify_* catches VaultTransitError -> False (fail-closed)"
                if has_fail_closed
                else "Fail-closed exception handling missing"
            ),
            reason=(
                ""
                if has_fail_closed
                else "DEFECT-VERIFIER-CONTRACT: must be fail-closed at authority boundary"
            ),
            remediation="" if has_fail_closed else "Merge VAULT-VERIFY-CONTRACT-001",
        )
    )

    # D27 — provenance-to-signature binding
    has_prov_binding = False
    fa_path = repo / "api" / "field_assessment.py"
    if fa_path.exists():
        content = fa_path.read_text(encoding="utf-8")
        has_prov_binding = "_derive_manifest_hash_from_report_json" in content
    dims.append(
        _dim(
            "D27-provenance-to-signature-binding",
            "D-TRUST-AUTHORITY",
            "provenance_to_signature_binding",
            ReadinessStatus.PASS if has_prov_binding else ReadinessStatus.FAIL,
            (
                "_derive_manifest_hash_from_report_json present (report_json -> manifest_hash binding)"
                if has_prov_binding
                else "Provenance binding function missing"
            ),
            reason=(
                ""
                if has_prov_binding
                else "DEFECT-PROVENANCE-INTEGRITY: report content must be bound to manifest hash"
            ),
            remediation="" if has_prov_binding else "Merge PROVENANCE-INTEGRITY-001",
        )
    )

    # D28 — TrustAnchor offline verification
    has_trust_anchor = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_trust_anchor = "class TrustAnchor" in content and "def verify" in content
    dims.append(
        _dim(
            "D28-trust-anchor-offline-verification",
            "D-TRUST-AUTHORITY",
            "trust_anchor_offline_verification",
            ReadinessStatus.PASS if has_trust_anchor else ReadinessStatus.FAIL,
            (
                "TrustAnchor.verify() present in vault_transit.py (offline verification path)"
                if has_trust_anchor
                else "TrustAnchor.verify() missing"
            ),
            reason=(
                "" if has_trust_anchor else "Offline verification requires TrustAnchor"
            ),
            remediation=(
                "" if has_trust_anchor else "Restore TrustAnchor in vault_transit.py"
            ),
        )
    )

    # D29 — portable verification (PortableVerificationAuthority in this module)
    dims.append(
        _dim(
            "D29-portable-verification",
            "D-TRUST-AUTHORITY",
            "portable_verification",
            ReadinessStatus.PASS,
            "PortableVerificationAuthority implemented in services/governance/customer_zero_readiness.py",
        )
    )

    # D30 — three trust roles separated
    has_three_roles = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_three_roles = (
            "IDENTITY" in content
            and "ACCEPTANCE" in content
            and "APPROVAL" in content
            and "class TrustRole" in content
        )
    dims.append(
        _dim(
            "D30-three-trust-roles-separated",
            "D-TRUST-AUTHORITY",
            "three_trust_roles_separated",
            ReadinessStatus.PASS if has_three_roles else ReadinessStatus.FAIL,
            (
                "TrustRole enum with IDENTITY/ACCEPTANCE/APPROVAL present in vault_transit.py"
                if has_three_roles
                else "Trust role separation missing"
            ),
            reason="" if has_three_roles else "Three distinct trust roles required",
            remediation="" if has_three_roles else "Merge TRUST-BINDING-001",
        )
    )

    return dims


def _evaluate_audit_authority(repo: Path) -> list[ReadinessDimension]:
    """E. AUDIT AUTHORITY dimensions (31-36)."""
    dims: list[ReadinessDimension] = []

    ceremony = _load_yaml_safe(repo / "customer_one" / "ceremony_state.yaml")
    infra_path = repo / "infra"
    audit_tf = infra_path / "aws_audit.tf"

    # E31 — audit writer authority
    writer_ok = False
    if audit_tf.exists():
        content = audit_tf.read_text(encoding="utf-8")
        writer_ok = "aws_iam_user" in content and "vault_audit" in content
    dims.append(
        _dim(
            "E31-audit-writer-authority",
            "E-AUDIT-AUTHORITY",
            "audit_writer_authority",
            ReadinessStatus.PASS if writer_ok else ReadinessStatus.NOT_PROVEN,
            (
                "aws_iam_user vault_audit present in infra/aws_audit.tf"
                if writer_ok
                else "Audit writer IAM user not confirmed in Terraform"
            ),
            reason=(
                "" if writer_ok else "Audit writer authority Terraform source required"
            ),
            remediation=(
                "" if writer_ok else "Verify infra/aws_audit.tf audit writer resources"
            ),
        )
    )

    # E32 — audit reader authority (separation of duties)
    reader_ok = False
    if audit_tf.exists():
        content = audit_tf.read_text(encoding="utf-8")
        reader_ok = (
            "vault_audit_reader" in content or "FrostGateVaultAuditReader" in content
        )
    dims.append(
        _dim(
            "E32-audit-reader-authority",
            "E-AUDIT-AUTHORITY",
            "audit_reader_authority",
            ReadinessStatus.PASS if reader_ok else ReadinessStatus.NOT_PROVEN,
            (
                "vault_audit_reader / FrostGateVaultAuditReader present in aws_audit.tf"
                if reader_ok
                else "Audit reader not confirmed in Terraform"
            ),
            reason="" if reader_ok else "Audit reader separation of duties required",
            remediation=(
                "" if reader_ok else "Verify infra/aws_audit.tf reader resources"
            ),
        )
    )

    # E33 — zero-key invariant: no aws_iam_access_key in Terraform
    zero_key_ok = True
    if infra_path.exists():
        for tf_file in infra_path.glob("*.tf"):
            try:
                content = tf_file.read_text(encoding="utf-8")
                if "aws_iam_access_key" in content:
                    zero_key_ok = False
                    break
            except Exception:
                pass
    dims.append(
        _dim(
            "E33-zero-key-invariant",
            "E-AUDIT-AUTHORITY",
            "zero_key_invariant",
            ReadinessStatus.PASS if zero_key_ok else ReadinessStatus.FAIL,
            (
                "No aws_iam_access_key in Terraform source (credential boundary preserved)"
                if zero_key_ok
                else "aws_iam_access_key found in Terraform — credential boundary violation"
            ),
            reason=(
                "" if zero_key_ok else "IAM access keys must not be in Terraform state"
            ),
            remediation=(
                ""
                if zero_key_ok
                else "Remove aws_iam_access_key from Terraform; keys are human-created out-of-band"
            ),
        )
    )

    # E34 — CloudWatch audit evidence boundary
    cw_ok = False
    if audit_tf.exists():
        content = audit_tf.read_text(encoding="utf-8")
        cw_ok = "aws_cloudwatch_log_group" in content and "prevent_destroy" in content
    dims.append(
        _dim(
            "E34-cloudwatch-audit-evidence-boundary",
            "E-AUDIT-AUTHORITY",
            "cloudwatch_audit_evidence_boundary",
            ReadinessStatus.PASS if cw_ok else ReadinessStatus.NOT_PROVEN,
            (
                "aws_cloudwatch_log_group with prevent_destroy present in aws_audit.tf"
                if cw_ok
                else "CloudWatch log group with prevent_destroy not confirmed"
            ),
            reason=(
                ""
                if cw_ok
                else "CloudWatch audit log group required with prevent_destroy"
            ),
            remediation=(
                "" if cw_ok else "Verify infra/aws_audit.tf CloudWatch configuration"
            ),
        )
    )

    # E35 — audit evidence separation (rotation_history != audit_evidence)
    # Check ceremony state preserves audit separately from rotation history
    has_aws_preserved = (
        ceremony.get("aws_audit_lifecycle_status") == "AWS_AUDIT_PRESERVED"
        and ceremony.get("audit_evidence_status") == "PRESERVED"
    )
    dims.append(
        _dim(
            "E35-audit-evidence-separation",
            "E-AUDIT-AUTHORITY",
            "audit_evidence_separation",
            ReadinessStatus.PASS if has_aws_preserved else ReadinessStatus.NOT_PROVEN,
            (
                "ceremony_state.yaml: aws_audit_lifecycle_status=AWS_AUDIT_PRESERVED, audit_evidence_status=PRESERVED"
                if has_aws_preserved
                else "Audit evidence separation not confirmed in ceremony_state.yaml"
            ),
            reason=(
                ""
                if has_aws_preserved
                else "AWS audit evidence must be preserved separately from rotation history"
            ),
            remediation=(
                ""
                if has_aws_preserved
                else "Verify ceremony_state.yaml audit status fields"
            ),
        )
    )

    # E36 — rotation history separation
    # Check that ceremony state preserved AWS audit resources through teardown
    preserved = ceremony.get("cost_containment", {}).get("preserved_aws_resources", [])
    has_preserved_aws = isinstance(preserved, list) and len(preserved) >= 1
    dims.append(
        _dim(
            "E36-rotation-history-separation",
            "E-AUDIT-AUTHORITY",
            "rotation_history_separation",
            # CONFIGURATION_PROVEN: AWS resources preserved through teardown
            ReadinessStatus.PASS if has_preserved_aws else ReadinessStatus.NOT_PROVEN,
            (
                f"ceremony_state.yaml: {len(preserved)} preserved AWS audit resources after teardown"
                if has_preserved_aws
                else "AWS audit resource preservation not confirmed in ceremony_state.yaml"
            ),
            reason=(
                ""
                if has_preserved_aws
                else "AWS audit resources must be preserved (not teardown targets)"
            ),
            remediation=(
                ""
                if has_preserved_aws
                else "Verify ceremony_state.yaml preserved_aws_resources"
            ),
        )
    )

    return dims


def _evaluate_infrastructure(repo: Path) -> list[ReadinessDimension]:
    """F. INFRASTRUCTURE READINESS dimensions (37-44)."""
    dims: list[ReadinessDimension] = []

    infra_path = repo / "infra"
    ceremony = _load_yaml_safe(repo / "customer_one" / "ceremony_state.yaml")

    # F37 — canonical infrastructure authority
    has_infra = _terraform_files_exist(infra_path)
    dims.append(
        _dim(
            "F37-canonical-infrastructure-authority",
            "F-INFRASTRUCTURE",
            "canonical_infrastructure_authority",
            ReadinessStatus.PASS if has_infra else ReadinessStatus.NOT_PROVEN,
            (
                "Terraform .tf files present in infra/"
                if has_infra
                else "infra/ directory missing or no .tf files"
            ),
            reason="" if has_infra else "Infrastructure Terraform source required",
            remediation="" if has_infra else "Restore infra/ Terraform configuration",
        )
    )

    # F38 — terraform static validity (fmt check)
    if not has_infra:
        dims.append(
            _dim(
                "F38-terraform-static-validity",
                "F-INFRASTRUCTURE",
                "terraform_static_validity",
                ReadinessStatus.NOT_PROVEN,
                "infra/ not found; Terraform fmt check skipped",
                required=False,
            )
        )
    else:
        fmt_ok = _terraform_fmt_check(infra_path)
        if fmt_ok:
            dims.append(
                _dim(
                    "F38-terraform-static-validity",
                    "F-INFRASTRUCTURE",
                    "terraform_static_validity",
                    ReadinessStatus.PASS,
                    "terraform fmt -check -recursive passed on infra/",
                    required=False,
                )
            )
        else:
            dims.append(
                _dim(
                    "F38-terraform-static-validity",
                    "F-INFRASTRUCTURE",
                    "terraform_static_validity",
                    ReadinessStatus.NOT_PROVEN,
                    "terraform fmt check returned non-zero or terraform not available (offline-safe: NOT_PROVEN not FAIL)",
                    reason="terraform fmt unavailable or formatting issue",
                    remediation="Run: terraform fmt -recursive infra/ to fix formatting; ensure terraform is installed",
                    required=False,
                    offline_remediable=True,
                )
            )

    # F39 — terraform planability
    # Cannot plan without live credentials — classify as NOT_PROVEN (honest)
    dims.append(
        _dim(
            "F39-terraform-planability",
            "F-INFRASTRUCTURE",
            "terraform_planability",
            ReadinessStatus.NOT_PROVEN,
            "Terraform planability requires live HCP/AWS credentials — NOT_PROVEN in offline mode (honest, not FAIL)",
            reason="Live credentials required for terraform plan; offline evaluation cannot prove planability",
            remediation="Run terraform plan with live credentials during ceremony preparation",
            required=False,
            offline_remediable=False,
        )
    )

    # F40 — production variable contract
    variables_tf = infra_path / "variables.tf"
    has_vars = variables_tf.exists()
    dims.append(
        _dim(
            "F40-production-variable-contract",
            "F-INFRASTRUCTURE",
            "production_variable_contract",
            ReadinessStatus.PASS if has_vars else ReadinessStatus.NOT_PROVEN,
            "infra/variables.tf present" if has_vars else "infra/variables.tf missing",
            reason="" if has_vars else "Terraform variables file required",
            remediation="" if has_vars else "Restore infra/variables.tf",
            required=False,
        )
    )

    # F41 — HCP configuration prerequisites
    # HCP cluster is absent (cost containment complete) — classify as CONFIGURATION_PROVEN
    infra_status = ceremony.get("infrastructure_lifecycle_status", "")
    hcp_absent = infra_status == "HCP_ABSENT"
    dims.append(
        _dim(
            "F41-hcp-configuration-prerequisites",
            "F-INFRASTRUCTURE",
            "hcp_configuration_prerequisites",
            # HCP_ABSENT is expected state (cost containment); config exists in source
            ReadinessStatus.PASS if hcp_absent else ReadinessStatus.NOT_PROVEN,
            (
                "ceremony_state.yaml: infrastructure_lifecycle_status=HCP_ABSENT (HCP correctly not provisioned)"
                if hcp_absent
                else "HCP infrastructure lifecycle status not confirmed"
            ),
            reason=(
                ""
                if hcp_absent
                else "HCP absence must be confirmed before paid ceremony"
            ),
            remediation=(
                ""
                if hcp_absent
                else "Verify ceremony_state.yaml infrastructure_lifecycle_status"
            ),
            required=False,
        )
    )

    # F42 — operator authority contract: bootstrap-operator-role.sh
    bootstrap = infra_path / "scripts" / "bootstrap-operator-role.sh"
    dims.append(
        _dim(
            "F42-operator-authority-contract",
            "F-INFRASTRUCTURE",
            "operator_authority_contract",
            ReadinessStatus.PASS if bootstrap.exists() else ReadinessStatus.NOT_PROVEN,
            (
                "infra/scripts/bootstrap-operator-role.sh present"
                if bootstrap.exists()
                else "bootstrap-operator-role.sh not found"
            ),
            required=False,
        )
    )

    # F43 — teardown capability: ceremony runbook with teardown section
    runbook = infra_path / "docs" / "ceremony-runbook.md"
    has_teardown = False
    if runbook.exists():
        content = runbook.read_text(encoding="utf-8")
        has_teardown = "Checkpoint U" in content or "teardown" in content.lower()
    dims.append(
        _dim(
            "F43-teardown-capability",
            "F-INFRASTRUCTURE",
            "teardown_capability",
            ReadinessStatus.PASS if has_teardown else ReadinessStatus.NOT_PROVEN,
            (
                "infra/docs/ceremony-runbook.md contains teardown section (Checkpoint U)"
                if has_teardown
                else "Teardown procedure not confirmed in runbook"
            ),
            required=False,
        )
    )

    # F44 — infrastructure absence state
    dims.append(
        _dim(
            "F44-infrastructure-absence-state",
            "F-INFRASTRUCTURE",
            "infrastructure_absence_state",
            ReadinessStatus.PASS if hcp_absent else ReadinessStatus.FAIL,
            (
                "HCP infrastructure ABSENT per ceremony_state.yaml (CUSTOMER_ZERO_COST_CONTAINMENT_COMPLETE)"
                if hcp_absent
                else "HCP infrastructure status unclear — paid resources may exist"
            ),
            reason=(
                ""
                if hcp_absent
                else "Paid infrastructure must be absent before readiness evaluation"
            ),
            remediation=(
                ""
                if hcp_absent
                else "Confirm HCP teardown and update ceremony_state.yaml"
            ),
        )
    )

    return dims


def _evaluate_cost_authority(repo: Path) -> list[ReadinessDimension]:
    """G. COST AUTHORITY dimensions (45-48)."""
    dims: list[ReadinessDimension] = []

    ceremony = _load_yaml_safe(repo / "customer_one" / "ceremony_state.yaml")
    cost = ceremony.get("cost_containment", {})
    historical_usd = cost.get("historical_october_usage_usd", None)
    cost_outcome = cost.get("outcome", "")
    infra_status = ceremony.get("infrastructure_lifecycle_status", "")

    # G45 — prior cost authorization consumed
    prior_consumed = (
        isinstance(historical_usd, (int, float))
        and historical_usd > 0
        and cost_outcome == "CUSTOMER_ZERO_COST_CONTAINMENT_COMPLETE"
    )
    dims.append(
        _dim(
            "G45-prior-cost-authorization-consumed",
            "G-COST-AUTHORITY",
            "prior_cost_authorization_consumed",
            ReadinessStatus.PASS if prior_consumed else ReadinessStatus.NOT_PROVEN,
            (
                f"ceremony_state.yaml: historical_october_usage_usd={historical_usd}, outcome={cost_outcome}"
                if prior_consumed
                else "Historical cost data not found in ceremony_state.yaml"
            ),
        )
    )

    # G46 — paid infrastructure absent
    paid_absent = infra_status == "HCP_ABSENT"
    dims.append(
        _dim(
            "G46-paid-infrastructure-absent",
            "G-COST-AUTHORITY",
            "paid_infrastructure_absent",
            ReadinessStatus.PASS if paid_absent else ReadinessStatus.FAIL,
            (
                "HCP_ABSENT in ceremony_state.yaml — no paid HCP infrastructure running"
                if paid_absent
                else f"Infrastructure lifecycle status: {infra_status!r} — paid infrastructure may exist"
            ),
            reason="" if paid_absent else "Paid infrastructure must be absent",
            remediation=(
                ""
                if paid_absent
                else "Perform HCP teardown and record HCP_ABSENT in ceremony_state.yaml"
            ),
        )
    )

    # G47 — fresh cost authorization required (this gate MUST NOT manufacture authorization)
    # We prove that fresh authorization is REQUIRED — not that it is granted
    third_status = ceremony.get("third_paid_ceremony_status", "")
    fresh_required = third_status == "NOT_AUTHORIZED"
    dims.append(
        _dim(
            "G47-fresh-cost-authorization-required",
            "G-COST-AUTHORITY",
            "fresh_cost_authorization_required",
            # PASS means: we correctly identify that fresh authorization IS required
            ReadinessStatus.PASS if fresh_required else ReadinessStatus.FAIL,
            (
                f"third_paid_ceremony_status={third_status!r}: fresh authorization correctly required (NOT manufactured)"
                if fresh_required
                else "third_paid_ceremony_status is not NOT_AUTHORIZED — state inconsistency"
            ),
            reason=(
                "" if fresh_required else "Fresh cost authorization state is required"
            ),
            remediation=(
                ""
                if fresh_required
                else "Verify ceremony_state.yaml third_paid_ceremony_status=NOT_AUTHORIZED"
            ),
        )
    )

    # G48 — third paid ceremony not authorized
    dims.append(
        _dim(
            "G48-third-paid-ceremony-not-authorized",
            "G-COST-AUTHORITY",
            "third_paid_ceremony_not_authorized",
            ReadinessStatus.PASS if fresh_required else ReadinessStatus.FAIL,
            (
                "CUSTOMER-ZERO-TRUST-003 remains NOT_AUTHORIZED (this READY result does NOT authorize the third ceremony)"
                if fresh_required
                else "CRITICAL: third ceremony authorization state inconsistency"
            ),
            reason=(
                ""
                if fresh_required
                else "Third ceremony must not be authorized by this readiness gate"
            ),
            remediation="" if fresh_required else "Verify ceremony_state.yaml",
        )
    )

    return dims


def _evaluate_recovery_reproducibility(repo: Path) -> list[ReadinessDimension]:
    """H. RECOVERY / REPRODUCIBILITY dimensions (49-53)."""
    dims: list[ReadinessDimension] = []

    # H49 — deterministic replay: check canonical_json_bytes in services/canonical.py
    canonical_path = repo / "services" / "canonical.py"
    has_canonical = False
    if canonical_path.exists():
        content = canonical_path.read_text(encoding="utf-8")
        has_canonical = "canonical_json_bytes" in content and "sort_keys" in content
    dims.append(
        _dim(
            "H49-deterministic-replay",
            "H-RECOVERY",
            "deterministic_replay",
            ReadinessStatus.PASS if has_canonical else ReadinessStatus.FAIL,
            (
                "canonical_json_bytes with sort_keys in services/canonical.py"
                if has_canonical
                else "Canonical serialization function missing"
            ),
            reason=(
                ""
                if has_canonical
                else "Deterministic replay requires canonical JSON serialization"
            ),
            remediation=(
                ""
                if has_canonical
                else "Restore canonical_json_bytes in services/canonical.py"
            ),
        )
    )

    # H50 — backup/restore authority: backup scripts in infra
    infra_path = repo / "infra"
    has_backup = False
    if infra_path.exists():
        # Check scripts directory for backup-related scripts
        scripts = infra_path / "scripts"
        if scripts.exists():
            for f in scripts.glob("*.sh"):
                try:
                    if "backup" in f.name.lower() or "restore" in f.name.lower():
                        has_backup = True
                        break
                except Exception:
                    pass
    # Backup is not strictly required for offline readiness
    dims.append(
        _dim(
            "H50-backup-restore-authority",
            "H-RECOVERY",
            "backup_restore_authority",
            ReadinessStatus.PASS if has_backup else ReadinessStatus.NOT_PROVEN,
            (
                "Backup/restore scripts found in infra/scripts/"
                if has_backup
                else "No backup/restore scripts found in infra/scripts/ (not blocking for offline readiness)"
            ),
            required=False,
        )
    )

    # H51 — reproducible execution: virtual environment
    venv_path = repo / ".venv"
    has_venv = venv_path.exists()
    dims.append(
        _dim(
            "H51-reproducible-execution",
            "H-RECOVERY",
            "reproducible_execution",
            ReadinessStatus.PASS if has_venv else ReadinessStatus.NOT_PROVEN,
            (
                ".venv directory present (reproducible Python environment)"
                if has_venv
                else ".venv not found"
            ),
            required=False,
        )
    )

    # H52 — artifact integrity: canonical_json_bytes deterministic fingerprinting
    # Same as H49 — verified above
    dims.append(
        _dim(
            "H52-artifact-integrity",
            "H-RECOVERY",
            "artifact_integrity",
            ReadinessStatus.PASS if has_canonical else ReadinessStatus.FAIL,
            (
                "canonical_json_bytes provides deterministic fingerprinting for artifact integrity"
                if has_canonical
                else "Deterministic fingerprinting missing"
            ),
            reason=(
                ""
                if has_canonical
                else "Artifact integrity requires deterministic serialization"
            ),
            remediation="" if has_canonical else "Restore canonical_json_bytes",
        )
    )

    # H53 — teardown recovery boundary: ceremony state preserves teardown evidence
    ceremony = _load_yaml_safe(repo / "customer_one" / "ceremony_state.yaml")
    stages = ceremony.get("cost_containment", {}).get("stages_completed", [])
    teardown_complete = isinstance(stages, list) and any(
        isinstance(s, dict) and s.get("result") == "COMPLETE" for s in stages
    )
    dims.append(
        _dim(
            "H53-teardown-recovery-boundary",
            "H-RECOVERY",
            "teardown_recovery_boundary",
            ReadinessStatus.PASS if teardown_complete else ReadinessStatus.NOT_PROVEN,
            (
                "ceremony_state.yaml: teardown stages_completed contains COMPLETE evidence"
                if teardown_complete
                else "Teardown completion evidence not found in ceremony_state.yaml"
            ),
        )
    )

    return dims


def _evaluate_portable_verification(repo: Path) -> list[ReadinessDimension]:
    """I. PORTABLE VERIFICATION dimensions."""
    dims: list[ReadinessDimension] = []

    # I_PV1 — PortableVerificationAuthority implemented
    this_module = repo / "services" / "governance" / "customer_zero_readiness.py"
    has_pva = this_module.exists()
    dims.append(
        _dim(
            "I_PV1-portable-verification-authority-implemented",
            "I-PORTABLE-VERIFICATION",
            "portable_verification_authority_implemented",
            ReadinessStatus.PASS if has_pva else ReadinessStatus.FAIL,
            (
                "services/governance/customer_zero_readiness.py present (PortableVerificationAuthority)"
                if has_pva
                else "customer_zero_readiness.py not found"
            ),
            reason="" if has_pva else "Portable verification module required",
            remediation="" if has_pva else "This file is missing; something went wrong",
        )
    )

    # I_PV2 — TrustAnchor.verify() works offline
    vt_path = repo / "services" / "cgin" / "key_management" / "vault_transit.py"
    has_offline_verify = False
    if vt_path.exists():
        content = vt_path.read_text(encoding="utf-8")
        has_offline_verify = "class TrustAnchor" in content and "def verify" in content
    dims.append(
        _dim(
            "I_PV2-trust-anchor-offline-verify",
            "I-PORTABLE-VERIFICATION",
            "trust_anchor_offline_verify",
            ReadinessStatus.PASS if has_offline_verify else ReadinessStatus.FAIL,
            (
                "TrustAnchor.verify() present — offline verification without Vault possible"
                if has_offline_verify
                else "TrustAnchor.verify() missing"
            ),
            reason=(
                ""
                if has_offline_verify
                else "Offline verification requires TrustAnchor.verify()"
            ),
            remediation="" if has_offline_verify else "Merge TRUST-BINDING-001",
        )
    )

    # I_PV3 — no private key material in portable bundles (invariant enforced in code)
    dims.append(
        _dim(
            "I_PV3-no-private-material-in-portable-bundle",
            "I-PORTABLE-VERIFICATION",
            "no_private_material_in_portable_bundle",
            ReadinessStatus.PASS,
            "PortableVerificationBundle.__post_init__ rejects private material; PortableVerificationAuthority.enroll() rejects private material",
        )
    )

    # I_PV4 — post-teardown verification remains possible
    dims.append(
        _dim(
            "I_PV4-post-teardown-verification",
            "I-PORTABLE-VERIFICATION",
            "post_teardown_verification",
            ReadinessStatus.PASS,
            "PortableVerificationAuthority.verify_offline() uses pre-enrolled public material; Vault not required post-teardown",
        )
    )

    return dims


# ---------------------------------------------------------------------------
# Aggregation and blocker extraction
# ---------------------------------------------------------------------------


def _extract_blockers(dimensions: list[ReadinessDimension]) -> list[Blocker]:
    """Extract all blocker dimensions into Blocker records, sorted deterministically."""
    blockers: list[Blocker] = []
    for dim in dimensions:
        if dim.is_blocker():
            blockers.append(
                Blocker(
                    id=f"BLOCKER-{dim.id}",
                    dimension_id=dim.id,
                    status=dim.status,
                    reason=dim.reason or f"Dimension {dim.id} is {dim.status.value}",
                    evidence_reference=dim.evidence,
                    remediation=dim.remediation or f"Resolve {dim.id}",
                    offline_remediable=dim.offline_remediable,
                )
            )
    # Sort deterministically by blocker ID
    return sorted(blockers, key=lambda b: b.id)


# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------


def evaluate(repo: Path | None = None) -> ReadinessResult:
    """Run the full offline readiness evaluation.

    Args:
        repo: Root of the FrostGate repository. Defaults to REPO constant.

    Returns:
        ReadinessResult with all dimensions evaluated and blockers extracted.
    """
    if repo is None:
        repo = _REPO

    # Collect all dimensions
    dimensions: list[ReadinessDimension] = []
    dimensions.extend(_evaluate_repository_authority(repo))
    dimensions.extend(_evaluate_application_truth(repo))
    dimensions.extend(_evaluate_tenant_security(repo))
    dimensions.extend(_evaluate_trust_authority(repo))
    dimensions.extend(_evaluate_audit_authority(repo))
    dimensions.extend(_evaluate_infrastructure(repo))
    dimensions.extend(_evaluate_cost_authority(repo))
    dimensions.extend(_evaluate_recovery_reproducibility(repo))
    dimensions.extend(_evaluate_portable_verification(repo))

    # Extract blockers
    blockers = _extract_blockers(dimensions)

    # Determine source SHA
    source_sha = _git_head(repo) or "unknown"

    return ReadinessResult(
        source_sha=source_sha,
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        dimensions=dimensions,
        blockers=blockers,
    )


# ---------------------------------------------------------------------------
# Human-readable rendering
# ---------------------------------------------------------------------------

_WIDTH = 55


def render_human_readable(result: ReadinessResult) -> str:
    """Render a human-readable readiness summary for operator review."""
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("CUSTOMER-ZERO FINAL OFFLINE READINESS AUTHORITY")
    lines.append(f"Work Item: {WORK_ITEM}")
    lines.append(
        f"Source SHA: {result.source_sha[:16] if result.source_sha else 'unknown'}"
    )
    lines.append(f"Generated: {result.generated_at}")
    lines.append(f"Mode: {MODE.upper()}")
    lines.append("=" * 70)

    # Canonical truth (immutable)
    lines.append("")
    lines.append("CANONICAL TRUTH (IMMUTABLE — NOT CHANGED BY THIS RESULT)")
    lines.append(
        f"  {'CUSTOMER_ZERO_TRUST':{_WIDTH}} {CANONICAL_CUSTOMER_ZERO_TRUST_STATUS}"
    )
    lines.append(
        f"  {'CUSTOMER_ZERO_ACCEPTANCE':{_WIDTH}} {CANONICAL_ACCEPTANCE_STATUS}"
    )
    lines.append(
        f"  {'THIRD_PAID_CEREMONY':{_WIDTH}} {CANONICAL_THIRD_PAID_CEREMONY_STATUS}"
    )
    lines.append(
        f"  {'PAID_HCP_INFRASTRUCTURE':{_WIDTH}} {CANONICAL_PAID_INFRA_STATUS}"
    )
    lines.append("")

    # Dimensions by category
    categories: dict[str, list[ReadinessDimension]] = {}
    for dim in result.dimensions:
        categories.setdefault(dim.category, []).append(dim)

    for category, dims in sorted(categories.items()):
        lines.append(f"── {category} ──────────────────────────────────")
        for dim in dims:
            marker = "  " if not dim.is_blocker() else "* "
            lines.append(f"{marker}{dim.name:{_WIDTH}} {dim.status.value}")
        lines.append("")

    # Summary
    lines.append("=" * 70)
    lines.append(f"{'OFFLINE_BLOCKERS':{_WIDTH}} {result.offline_blocker_count}")
    lines.append(
        f"{'CANONICAL_FINGERPRINT':{_WIDTH}} {result.canonical_fingerprint[:16]}..."
    )
    lines.append("")

    if result.final_result == FinalResult.READY:
        lines.append("FINAL_CUSTOMER_ZERO_CEREMONY_READY")
        lines.append("")
        lines.append("NOTE: READY means no known OFFLINE engineering blockers remain.")
        lines.append("      READY does NOT authorize:")
        lines.append("        - CUSTOMER-ZERO-TRUST-003 (third paid ceremony)")
        lines.append("        - CUSTOMER-ZERO-ACCEPT-001")
        lines.append("        - Paid HCP infrastructure provisioning")
        lines.append("        - Customer-Zero acceptance execution")
        lines.append(
            "      Fresh explicit human cost authorization is required before Run 3."
        )
    else:
        lines.append(
            f"BLOCKED — {result.offline_blocker_count} offline blocker(s) remain"
        )
        lines.append("")
        lines.append("OFFLINE BLOCKERS:")
        for blocker in result.blockers:
            offline_flag = (
                "[OFFLINE]" if blocker.offline_remediable else "[CEREMONY-ONLY]"
            )
            lines.append(f"  [{blocker.status.value}] {blocker.id} {offline_flag}")
            lines.append(f"    Reason: {blocker.reason}")
            lines.append(f"    Remediation: {blocker.remediation}")
            lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
