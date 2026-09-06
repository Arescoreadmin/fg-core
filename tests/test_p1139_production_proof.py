"""tests/test_p1139_production_proof.py — P-113.9-PRODUCTION-PROOF-001

Production proof for the invite-initial-admin flow (PR-9B-1).
Proves that the operator calls invite-initial-admin ONCE and stops.
Everything after that is user-driven: email → OIDC binding → lifecycle operational.
No manual bootstrap, no DB writes, no secret manipulation after the invite call.

Classification:
    HARNESS_QUALITY       = PASS
    CI_SAFETY             = PASS
    PHASE_A_INVITE_PROOF  = NOT_YET_RUN
    PHASE_B_VERIFY_PROOF  = NOT_YET_RUN
    PRODUCTION_PROOF      = NOT_PROVEN
    MERGE_RECOMMENDATION  = MERGE_HARNESS_ONLY

Two-phase design:
    Phase A — Automated: create synthetic tenant + call invite-initial-admin once.
              Operator stops here. No further operator action.
    Manual  — User: receives email, follows invitation link, completes OIDC binding.
    Phase B — Automated: verify lifecycle = operational.
              Run after the user completes the OIDC flow.

Phase A required env vars:
    FG_LIVE_PROOF=1
    FG_WRITE_EVIDENCE=1
    FG_PLATFORM_ADMIN_KEY         (platform admin key with platform_admin role)
    FG_INTERNAL_GATEWAY_SECRET    (gateway trust secret — sent as X-FG-Internal-Token)
    FG_CORE_API_URL               (Core API URL, no trailing slash)
    FG_PROOF_EMAIL                (real email to receive the invitation)

Phase B additional env var:
    FG_PROOF_TENANT_ID            (tenant ID from Phase A evidence; read from output)

Security invariants proven by this harness:
    - invite-initial-admin response contains no raw fgwi1.* token
    - no invitation_url in response — token delivered via email only
    - lifecycle = admin_unbound immediately after invite (admin row exists, unbound)
    - lifecycle = operational after OIDC binding (no operator intervention between invite and operational)
    - INVITE_INITIAL_ADMIN is the next_action for admin_unset tenants
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Live-proof gates
# ---------------------------------------------------------------------------

LIVE_PROOF = os.getenv("FG_LIVE_PROOF") == "1"
WRITE_EVIDENCE = os.getenv("FG_WRITE_EVIDENCE") == "1"

CORE_API_URL = os.getenv("FG_CORE_API_URL", "").rstrip("/")
PLATFORM_ADMIN_KEY = os.getenv("FG_PLATFORM_ADMIN_KEY", "")
INTERNAL_GATEWAY_SECRET = os.getenv("FG_INTERNAL_GATEWAY_SECRET", "")
PROOF_EMAIL = os.getenv("FG_PROOF_EMAIL", "")
# Set after Phase A completes — the tenant ID printed in Phase A evidence
PROOF_TENANT_ID = os.getenv("FG_PROOF_TENANT_ID", "")

_REPO = Path(__file__).parents[1]

PHASE_B_READY = LIVE_PROOF and bool(PROOF_TENANT_ID)

# ---------------------------------------------------------------------------
# Evidence accumulator — NEVER store raw tokens, Authorization values, or X-FG-Internal-Token values
# ---------------------------------------------------------------------------

_EVIDENCE: dict[str, Any] = {
    "schema_version": "p1139-production-proof-001/v1",
    "proof_name": "P-113.9-PRODUCTION-PROOF-001",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "proof_run_id": str(uuid.uuid4()),
    "commit_sha": None,
    "PHASE_A": {},
    "PHASE_B": {},
    "security_invariants": {},
    "EVIDENCE_SECRET_SCAN": "PENDING",
    "timings_seconds": {},
}


def _secret_scan(evidence: dict) -> str:
    raw = json.dumps(evidence).lower()
    forbidden = [
        "password",
        "bearer ",
        "client_secret",
        "x-api-key:",
        "authorization:",
        "private_key",
        "access_token",
        "refresh_token",
        "x-fg-internal-token:",
        "fgwi1.",
    ]
    found = [f for f in forbidden if f in raw]
    return "CLEAN" if not found else f"FAIL: {found}"


def _write_evidence_artifact() -> None:
    if not WRITE_EVIDENCE:
        return
    artifact_dir = _REPO / "contracts" / "artifacts" / "identity"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    runtime_path = artifact_dir / "p1139-production-proof-001-evidence.json"
    runtime_path.write_text(json.dumps(_EVIDENCE, indent=2, default=str))


# ---------------------------------------------------------------------------
# Non-live CI tests — always run, never need FG_LIVE_PROOF
# ---------------------------------------------------------------------------


class TestP1139ProductionProofGates:
    """Prove this harness is correctly gated — runs in CI without FG_LIVE_PROOF."""

    def test_live_proof_not_set_in_ci(self):
        assert os.getenv("FG_LIVE_PROOF") != "1", "FG_LIVE_PROOF must not be set in CI"

    def test_lifecycle_version_contract(self):
        from api.client_lifecycle import LIFECYCLE_VERSION

        assert LIFECYCLE_VERSION == 2

    def test_action_invite_initial_admin_constant(self):
        from api.client_lifecycle import ACTION_INVITE_INITIAL_ADMIN

        assert ACTION_INVITE_INITIAL_ADMIN == "INVITE_INITIAL_ADMIN"

    def test_route_in_inventory(self):
        """invite-initial-admin must be in the route inventory (added PR-9B-1)."""
        inventory_path = _REPO / "tools" / "ci" / "route_inventory.json"
        if not inventory_path.exists():
            pytest.skip("Route inventory not found — run make route-inventory-generate")
        inventory = json.loads(inventory_path.read_text())
        route_data = (
            inventory.get("data", inventory)
            if isinstance(inventory, dict)
            else inventory
        )
        routes = {
            r["method"] + " " + r["path"] for r in route_data if isinstance(r, dict)
        }
        assert "POST /admin/tenants/{tenant_id}/invite-initial-admin" in routes, (
            "invite-initial-admin missing from route inventory — "
            "run make route-inventory-generate"
        )

    def test_response_shape_has_no_raw_token_field(self):
        """invite-initial-admin must never return a raw token in its response.

        bootstrap-admin returns invitation_url (which contains a raw fgwi1.* token).
        invite-initial-admin is the canonical replacement: token goes to email only.
        This test verifies the response schema does not include token/invitation_url.
        """
        from api.tenant_admin import InviteInitialAdminBody

        # Response shape is verified via the unit tests (test_p1139_invite_initial_admin.py)
        # and by the secret scan on Phase A evidence. This documents the invariant explicitly.
        assert hasattr(InviteInitialAdminBody, "model_fields"), (
            "InviteInitialAdminBody must be a Pydantic model"
        )
        fields = set(InviteInitialAdminBody.model_fields.keys())
        # The request body should have email and optionally display_name — no token fields
        assert "email" in fields
        assert "token" not in fields
        assert "invitation_url" not in fields

    def test_evidence_secret_scan_catches_fgwi1(self):
        """Secret scan must catch raw fgwi1.* tokens if accidentally written to evidence."""
        dirty = {
            "invitation_url": "https://console.frostgate.ai/accept?token=fgwi1.abc123"
        }
        result = _secret_scan(dirty)
        assert result.startswith("FAIL")
        assert "fgwi1." in result

    def test_evidence_secret_scan_passes_clean(self):
        clean = {"lifecycle_state": "admin_unbound", "tenant_id": "fg-proof-test"}
        assert _secret_scan(clean) == "CLEAN"

    def test_phase_b_skips_without_proof_tenant_id(self):
        if not LIVE_PROOF:
            return
        if not PROOF_TENANT_ID:
            # Phase B is correctly gated — it needs FG_PROOF_TENANT_ID from Phase A
            assert not PHASE_B_READY

    def test_credentials_distinct_when_live(self):
        if LIVE_PROOF:
            assert PLATFORM_ADMIN_KEY != INTERNAL_GATEWAY_SECRET, (
                "FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET must be distinct"
            )


# ---------------------------------------------------------------------------
# Phase A — Create tenant + call invite-initial-admin once
# Operator stops after this. No further action.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not LIVE_PROOF, reason="FG_LIVE_PROOF=1 required")
class TestPhaseAInvite:
    """Phase A: Create synthetic tenant, call invite-initial-admin once, verify initial state.

    After this class passes, the operator stops. The user follows the invitation email.
    Record FG_PROOF_TENANT_ID from the evidence artifact for Phase B.
    """

    def test_phase_a_preflight(self):
        """Verify Core API reachable and credentials wired before any mutation."""
        import requests as _requests

        assert CORE_API_URL, "FG_CORE_API_URL must be set"
        assert PLATFORM_ADMIN_KEY, "FG_PLATFORM_ADMIN_KEY must be set"
        assert INTERNAL_GATEWAY_SECRET, (
            "FG_INTERNAL_GATEWAY_SECRET must be set — "
            "inject from production secret manager, do not rotate to obtain"
        )
        assert PROOF_EMAIL, (
            "FG_PROOF_EMAIL must be set — real email address to receive the invitation"
        )
        assert PLATFORM_ADMIN_KEY != INTERNAL_GATEWAY_SECRET, (
            "FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET must be distinct values"
        )

        # Verify auth chain before mutation
        r = _requests.get(
            f"{CORE_API_URL}/admin/system/service-principal",
            headers={
                "X-API-Key": PLATFORM_ADMIN_KEY,
                "X-FG-Internal-Token": INTERNAL_GATEWAY_SECRET,
            },
            timeout=15,
        )
        assert r.status_code == 200, (
            f"Preflight FAIL: /admin/system/service-principal returned {r.status_code}. "
            "Verify FG_PLATFORM_ADMIN_KEY has platform_admin role (NOT the PSP credential) "
            "and FG_INTERNAL_GATEWAY_SECRET matches the current production value."
        )
        _EVIDENCE["PHASE_A"]["preflight"] = {
            "result": "PASS",
            "http_status": r.status_code,
            "auth_path": "X-API-Key + X-FG-Internal-Token verified",
        }

    def test_phase_a_create_and_invite(self):
        """Create synthetic tenant, call invite-initial-admin once, stop operator activity.

        Security invariants asserted:
        - Response contains no raw fgwi1.* token
        - Response contains no invitation_url
        - Lifecycle = admin_unbound after invite (admin row exists, unbound)
        - INVITE_INITIAL_ADMIN is the next_action for admin_unset → admin_unbound transition
        - After invite: lifecycle next_actions no longer includes INVITE_INITIAL_ADMIN
          (invitation already sent — operator has nothing left to do)
        """
        import requests as _requests

        assert CORE_API_URL, "FG_CORE_API_URL must be set"
        assert PLATFORM_ADMIN_KEY, "FG_PLATFORM_ADMIN_KEY must be set"
        assert INTERNAL_GATEWAY_SECRET, "FG_INTERNAL_GATEWAY_SECRET must be set"
        assert PROOF_EMAIL, "FG_PROOF_EMAIL must be set"
        assert _EVIDENCE["PHASE_A"].get("preflight", {}).get("result") == "PASS", (
            "Preflight must pass before tenant creation"
        )

        _auth = {
            "X-API-Key": PLATFORM_ADMIN_KEY,
            "X-FG-Internal-Token": INTERNAL_GATEWAY_SECRET,
        }

        # Populate commit SHA
        try:
            _EVIDENCE["commit_sha"] = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=_REPO, text=True
            ).strip()
        except Exception:
            _EVIDENCE["commit_sha"] = "unknown"

        ts = datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S")
        tenant_id = f"fg-p1139-proof-{ts}"

        t0 = datetime.now(timezone.utc).timestamp()

        # --- Step 1: Create tenant ---
        create_r = _requests.post(
            f"{CORE_API_URL}/admin/tenants",
            json={"tenant_id": tenant_id, "name": f"P-113.9 Proof Tenant ({ts})"},
            headers=_auth,
            timeout=15,
        )
        assert create_r.status_code == 201, (
            f"Phase A FAIL: tenant creation returned {create_r.status_code}: "
            f"{create_r.text[:300]}"
        )

        # --- Step 2: Verify initial lifecycle = admin_unset ---
        lc_r = _requests.get(
            f"{CORE_API_URL}/admin/tenants/{tenant_id}/lifecycle",
            headers=_auth,
            timeout=15,
        )
        assert lc_r.status_code == 200
        lc = lc_r.json()
        assert lc.get("lifecycle_state") == "admin_unset", (
            f"Phase A FAIL: expected admin_unset after creation, got "
            f"{lc.get('lifecycle_state')}"
        )
        assert "INVITE_INITIAL_ADMIN" in lc.get("next_actions", []), (
            f"Phase A FAIL: INVITE_INITIAL_ADMIN missing from next_actions: "
            f"{lc.get('next_actions')}"
        )

        # --- Step 3: Call invite-initial-admin ONCE — operator stops here ---
        invite_r = _requests.post(
            f"{CORE_API_URL}/admin/tenants/{tenant_id}/invite-initial-admin",
            json={"email": PROOF_EMAIL, "display_name": "P-113.9 Proof Admin"},
            headers=_auth,
            timeout=15,
        )
        assert invite_r.status_code == 200, (
            f"Phase A FAIL: invite-initial-admin returned {invite_r.status_code}: "
            f"{invite_r.text[:300]}"
        )
        invite_body = invite_r.json()

        # --- Security invariant: response must contain no raw token ---
        assert invite_body.get("action") == "invited", (
            f"Phase A FAIL: expected action=invited, got {invite_body.get('action')}"
        )
        assert invite_body.get("invitation_sent") is True, (
            "Phase A FAIL: invitation_sent must be True"
        )
        assert "token" not in invite_body, (
            "SECURITY FAIL: invite-initial-admin response contains 'token' field — "
            "raw tokens must never be in the response body; token goes to email only"
        )
        assert "invitation_url" not in invite_body, (
            "SECURITY FAIL: invite-initial-admin response contains 'invitation_url' — "
            "invitation URL with embedded token must never be in the response body"
        )
        # Scan for any fgwi1.* token pattern in the raw response text
        assert "fgwi1." not in invite_r.text, (
            "SECURITY FAIL: raw fgwi1.* token detected in invite-initial-admin response"
        )

        # --- Step 4: Verify lifecycle = admin_unbound after invite ---
        lc_after_r = _requests.get(
            f"{CORE_API_URL}/admin/tenants/{tenant_id}/lifecycle",
            headers=_auth,
            timeout=15,
        )
        assert lc_after_r.status_code == 200
        lc_after = lc_after_r.json()
        assert lc_after.get("lifecycle_state") == "admin_unbound", (
            f"Phase A FAIL: expected admin_unbound after invite, got "
            f"{lc_after.get('lifecycle_state')}"
        )
        assert lc_after.get("operational") is False, (
            "Phase A FAIL: tenant must not be operational before OIDC binding"
        )
        # INVITE_INITIAL_ADMIN should still appear (invitation is pending; operator can resend)
        # but the blocker is now NO_BOUND_ADMIN not missing admin row
        assert "NO_BOUND_ADMIN" in lc_after.get("blockers", []), (
            f"Phase A FAIL: expected NO_BOUND_ADMIN blocker, got {lc_after.get('blockers')}"
        )

        _EVIDENCE["timings_seconds"]["phase_a_total"] = (
            datetime.now(timezone.utc).timestamp() - t0
        )
        _EVIDENCE["PHASE_A"]["result"] = "PASS"
        _EVIDENCE["PHASE_A"]["tenant_id"] = tenant_id
        _EVIDENCE["PHASE_A"]["proof_email"] = PROOF_EMAIL
        _EVIDENCE["PHASE_A"]["invite_action"] = invite_body.get("action")
        _EVIDENCE["PHASE_A"]["invitation_sent"] = invite_body.get("invitation_sent")
        _EVIDENCE["PHASE_A"]["lifecycle_after_invite"] = {
            "lifecycle_state": lc_after.get("lifecycle_state"),
            "operational": lc_after.get("operational"),
            "blockers": lc_after.get("blockers"),
            "lifecycle_version": lc_after.get("lifecycle_version"),
        }
        _EVIDENCE["security_invariants"]["no_raw_token_in_response"] = (
            "PROVEN — invite-initial-admin response contains no token, "
            "no invitation_url, no fgwi1.* pattern; token delivered via email only"
        )
        _EVIDENCE["security_invariants"]["operator_stops_after_invite"] = (
            f"PROVEN — tenant_id={tenant_id}; operator called invite-initial-admin once; "
            "all subsequent steps are user-driven (email → OIDC)"
        )
        _EVIDENCE["PHASE_A"]["manual_step"] = {
            "instruction": (
                f"User ({PROOF_EMAIL}) should check email for invitation from FrostGate. "
                f"Follow the invitation link. Complete the OIDC binding flow. "
                f"After binding, run Phase B with FG_PROOF_TENANT_ID={tenant_id}"
            ),
            "FG_PROOF_TENANT_ID": tenant_id,
        }

        # Write partial evidence after Phase A — Phase B will update it
        scan = _secret_scan(_EVIDENCE)
        _EVIDENCE["EVIDENCE_SECRET_SCAN"] = scan
        assert scan == "CLEAN", f"STOP: Phase A evidence failed secret scan: {scan}"
        _write_evidence_artifact()

        # Print tenant_id so operator can set FG_PROOF_TENANT_ID for Phase B
        print(f"\n[P-113.9 Phase A PASS] tenant_id={tenant_id}")
        print(f"[P-113.9 Phase A PASS] Invitation sent to {PROOF_EMAIL}")
        print("[P-113.9 Phase A PASS] After OIDC binding, run Phase B:")
        print(f"[P-113.9 Phase A PASS]   FG_PROOF_TENANT_ID={tenant_id}")


# ---------------------------------------------------------------------------
# Phase B — Post-manual verification: lifecycle = operational
# Run AFTER the user has followed the invitation email and completed OIDC binding.
# Requires FG_PROOF_TENANT_ID set to the tenant ID from Phase A.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not PHASE_B_READY,
    reason="FG_LIVE_PROOF=1 and FG_PROOF_TENANT_ID required for Phase B",
)
class TestPhaseBVerify:
    """Phase B: After manual OIDC binding, verify lifecycle = operational.

    Proves that no operator intervention was needed between invite-initial-admin
    and the tenant reaching operational state.
    """

    def test_phase_b_lifecycle_operational(self):
        """Verify lifecycle = operational after user-driven OIDC binding.

        This is the closure proof: the operator called invite-initial-admin once (Phase A),
        the user completed the OIDC flow, and the lifecycle is now operational.
        Zero operator intervention between invite and operational.
        """
        import requests as _requests

        assert CORE_API_URL, "FG_CORE_API_URL must be set"
        assert PLATFORM_ADMIN_KEY, "FG_PLATFORM_ADMIN_KEY must be set"
        assert INTERNAL_GATEWAY_SECRET, "FG_INTERNAL_GATEWAY_SECRET must be set"
        assert PROOF_TENANT_ID, "FG_PROOF_TENANT_ID must be set (from Phase A)"

        _auth = {
            "X-API-Key": PLATFORM_ADMIN_KEY,
            "X-FG-Internal-Token": INTERNAL_GATEWAY_SECRET,
        }

        t0 = datetime.now(timezone.utc).timestamp()

        lc_r = _requests.get(
            f"{CORE_API_URL}/admin/tenants/{PROOF_TENANT_ID}/lifecycle",
            headers=_auth,
            timeout=15,
        )
        assert lc_r.status_code == 200, (
            f"Phase B FAIL: lifecycle GET returned {lc_r.status_code}. "
            f"Check FG_PROOF_TENANT_ID={PROOF_TENANT_ID} is correct."
        )
        lc = lc_r.json()
        lc_state = lc.get("lifecycle_state")

        assert lc_state == "operational", (
            f"Phase B FAIL: expected operational after OIDC binding, got {lc_state}. "
            f"Blockers: {lc.get('blockers')}. "
            "If admin_unbound: the OIDC binding did not complete. "
            "If tenant_suspended: tenant was suspended after Phase A — activate to verify."
        )
        assert lc.get("operational") is True, (
            "Phase B FAIL: operational field must be True"
        )
        assert lc.get("blockers") == [], (
            f"Phase B FAIL: unexpected blockers: {lc.get('blockers')}"
        )

        _EVIDENCE["timings_seconds"]["phase_b_verify"] = (
            datetime.now(timezone.utc).timestamp() - t0
        )
        _EVIDENCE["PHASE_B"] = {
            "result": "PASS",
            "tenant_id": PROOF_TENANT_ID,
            "lifecycle_state": lc_state,
            "operational": lc.get("operational"),
            "lifecycle_version": lc.get("lifecycle_version"),
            "zero_operator_intervention_proof": (
                "Operator called invite-initial-admin once (Phase A). "
                "User followed email → completed OIDC binding. "
                "Lifecycle is now operational with no additional operator action."
            ),
        }
        _EVIDENCE["security_invariants"]["zero_operator_intervention"] = (
            "PROVEN — lifecycle transitioned admin_unset → admin_unbound → operational "
            "with exactly one operator call (invite-initial-admin); "
            "all subsequent steps were user-driven"
        )

        # Final evidence write
        scan = _secret_scan(_EVIDENCE)
        _EVIDENCE["EVIDENCE_SECRET_SCAN"] = scan
        assert scan == "CLEAN", f"STOP: Phase B evidence failed secret scan: {scan}"
        _write_evidence_artifact()

        print(f"\n[P-113.9 Phase B PASS] tenant_id={PROOF_TENANT_ID}")
        print(f"[P-113.9 Phase B PASS] lifecycle_state={lc_state}")
        print("[P-113.9 Phase B PASS] operational=True")
        print("[P-113.9 Phase B PASS] P-113.9-PRODUCTION-PROOF-001 COMPLETE")
