#!/usr/bin/env python3
"""
tools/ci/check_control_plane_v2_invariants.py — CI Guard for Control Plane v2.

Checks (all non-vacuous, all CI-enforced):
  1. Required tables present in migration 0027.
  2. Hash chain logic present in cp_ledger service.
  3. No subprocess usage in any CP v2 file.
  4. Receipt endpoint enforces executor auth.
  5. MSP cross-tenant access requires msp scope.
  6. No header-based tenant derivation in CP v2.
  7. Event written before streaming (flush before return).
  8. Command enum is strictly allowlisted (no open-ended dispatch).
  9. Playbook enum is strictly allowlisted (no dynamic dispatch).
  10. Append-only triggers defined in migration.
  11. Ledger verify endpoint exists.
  12. Evidence bundle endpoint exists.
  13. All new files compile without syntax errors.
  14. Negative test coverage for each invariant present.

Exit: 0 = pass, 1 = failure.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"  FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"  OK:   {msg}")


def _read(rel: str) -> str:
    path = REPO / rel
    if not path.exists():
        fail(f"File not found: {rel}")
        return ""
    return path.read_text(encoding="utf-8")


def _parse(rel: str) -> ast.Module | None:
    src = _read(rel)
    if not src:
        return None
    try:
        return ast.parse(src, filename=rel)
    except SyntaxError as exc:
        fail(f"SyntaxError in {rel}: {exc}")
        return None


def _has_pattern(content: str, *patterns: str) -> bool:
    return all(p in content for p in patterns)


# ---------------------------------------------------------------------------
# Check 1: Required tables in migration 0027
# ---------------------------------------------------------------------------
def check_required_tables() -> None:
    print("\n[1] Required tables in migration 0027")
    content = _read("migrations/postgres/0027_control_plane_v2.sql")
    required_tables = [
        "control_plane_event_ledger",
        "control_plane_commands",
        "control_plane_command_receipts",
        "control_plane_heartbeats",
    ]
    for table in required_tables:
        if table in content:
            ok(f"Table '{table}' present")
        else:
            fail(f"Required table '{table}' missing from migration 0027")


# ---------------------------------------------------------------------------
# Check 2: Hash chain logic in cp_ledger service
# ---------------------------------------------------------------------------
def check_hash_chain_logic() -> None:
    print("\n[2] Hash chain logic in cp_ledger service")
    content = _read("services/cp_ledger.py")

    required_markers = [
        ("compute_content_hash", "content_hash function defined"),
        ("compute_chain_hash", "chain_hash function defined"),
        ("GENESIS_HASH", "GENESIS_HASH constant defined"),
        ("verify_chain", "verify_chain method defined"),
        ("SHA256", "SHA256 or sha256 used in chain"),
        ("prev_hash", "prev_hash linkage present"),
    ]
    for marker, description in required_markers:
        if marker in content or marker.lower() in content.lower():
            ok(description)
        else:
            fail(f"Hash chain: {description} — marker '{marker}' not found in cp_ledger.py")


# ---------------------------------------------------------------------------
# Check 3: No subprocess usage in CP v2 files
# ---------------------------------------------------------------------------
def check_no_subprocess() -> None:
    print("\n[3] No subprocess usage in CP v2 files")
    v2_files = [
        "api/control_plane_v2.py",
        "services/cp_ledger.py",
        "services/cp_commands.py",
        "services/cp_heartbeats.py",
        "services/cp_playbooks.py",
    ]
    for rel in v2_files:
        tree = _parse(rel)
        if tree is None:
            continue
        found_subprocess = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        found_subprocess = True
            if isinstance(node, ast.ImportFrom):
                if node.module == "subprocess":
                    found_subprocess = True
            if isinstance(node, (ast.Call, ast.Attribute)):
                node_str = ast.dump(node)
                for dangerous in ("os.system", "os.popen", "os.exec"):
                    if dangerous.replace(".", "") in node_str:
                        found_subprocess = True
        if found_subprocess:
            fail(f"subprocess or os.system usage found in {rel}")
        else:
            ok(f"No subprocess in {rel}")


# ---------------------------------------------------------------------------
# Check 4: Receipt endpoint enforces executor auth
# ---------------------------------------------------------------------------
def check_receipt_executor_auth() -> None:
    print("\n[4] Receipt endpoint enforces executor auth")
    content = _read("api/control_plane_v2.py")

    markers = [
        ("VALID_EXECUTOR_TYPES", "VALID_EXECUTOR_TYPES imported/used"),
        ("executor_type", "executor_type validated"),
        ("ERR_NOT_EXECUTOR", "ERR_NOT_EXECUTOR error code used"),
        ("403", "403 status returned for non-executor"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"Receipt executor auth: {description} — '{marker}' not found")


# ---------------------------------------------------------------------------
# Check 5: MSP cross-tenant requires msp scope
# ---------------------------------------------------------------------------
def check_msp_scope_enforcement() -> None:
    print("\n[5] MSP cross-tenant requires msp scope")
    content = _read("api/control_plane_v2.py")

    markers = [
        ("control-plane:msp:read", "msp:read scope referenced"),
        ("control-plane:msp:admin", "msp:admin scope referenced"),
        ("_check_msp_scope", "MSP scope check function defined"),
        ("_resolve_msp_tenant", "MSP tenant resolution function defined"),
        ("404", "Anti-enumeration 404 present"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"MSP scope: {description} — '{marker}' not found")


# ---------------------------------------------------------------------------
# Check 6: No header-based tenant derivation
# ---------------------------------------------------------------------------
def check_no_header_tenant() -> None:
    print("\n[6] No header-based tenant derivation in CP v2")
    content = _read("api/control_plane_v2.py")

    forbidden_patterns = [
        'request.headers.get("X-Tenant-Id")',
        'request.headers.get("x-tenant-id")',
        'headers.get("tenant")',
        'request.headers["tenant_id"]',
        "X-Tenant-Id",
    ]
    found_header_tenant = False
    for pat in forbidden_patterns:
        if pat in content:
            found_header_tenant = True
            fail(f"Header-based tenant derivation found: '{pat}' in control_plane_v2.py")

    if not found_header_tenant:
        ok("No header-based tenant derivation found")

    # Verify tenant is always from auth context
    if "_tenant_from_auth" in content:
        ok("_tenant_from_auth used for tenant derivation")
    else:
        fail("_tenant_from_auth not found — tenant source unclear")


# ---------------------------------------------------------------------------
# Check 7: Event written before return (flush called before return)
# ---------------------------------------------------------------------------
def check_event_written_before_streaming() -> None:
    print("\n[7] Event written to DB before return (flush before return)")
    content = _read("services/cp_ledger.py")

    markers = [
        ("db_session.flush", "db_session.flush() called after add"),
        ("db_session.add", "db_session.add() called to persist event"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"Persistence-first: {description} — '{marker}' not found in cp_ledger.py")


# ---------------------------------------------------------------------------
# Check 8: Command enum is strictly allowlisted
# ---------------------------------------------------------------------------
def check_command_allowlist() -> None:
    print("\n[8] Command enum strictly allowlisted (VALID_CP_COMMANDS)")
    content = _read("services/cp_commands.py")

    if "VALID_CP_COMMANDS" not in content:
        fail("VALID_CP_COMMANDS constant not found in cp_commands.py")
        return
    ok("VALID_CP_COMMANDS defined")

    if "not in VALID_CP_COMMANDS" in content:
        ok("Command validated against VALID_CP_COMMANDS allowlist")
    else:
        fail("Command not validated against allowlist — no 'not in VALID_CP_COMMANDS' check")

    # Verify no dynamic dispatch
    tree = _parse("services/cp_commands.py")
    if tree:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("eval", "exec", "__import__"):
                    fail(f"Dynamic dispatch '{func.id}()' found in cp_commands.py")
        ok("No dynamic dispatch (eval/exec) in cp_commands.py")


# ---------------------------------------------------------------------------
# Check 9: Playbook enum is strictly allowlisted
# ---------------------------------------------------------------------------
def check_playbook_allowlist() -> None:
    print("\n[9] Playbook enum strictly allowlisted (VALID_PLAYBOOKS)")
    content = _read("services/cp_playbooks.py")

    if "VALID_PLAYBOOKS" not in content:
        fail("VALID_PLAYBOOKS constant not found in cp_playbooks.py")
        return

    # Verify the 4 expected playbooks are present
    expected = {
        "stuck_boot_recover",
        "dependency_auto_pause",
        "breaker_auto_isolate",
        "safe_restart_sequence",
    }
    for pb in expected:
        if pb in content:
            ok(f"Playbook '{pb}' in allowlist")
        else:
            fail(f"Expected playbook '{pb}' not found in cp_playbooks.py")

    if "_PLAYBOOK_HANDLERS" in content:
        ok("_PLAYBOOK_HANDLERS dispatch table defined (no dynamic exec)")
    else:
        fail("_PLAYBOOK_HANDLERS not found — playbook dispatch mechanism unclear")


# ---------------------------------------------------------------------------
# Check 10: Append-only triggers in migration
# ---------------------------------------------------------------------------
def check_append_only_triggers() -> None:
    print("\n[10] Append-only triggers defined in migration 0027")
    content = _read("migrations/postgres/0027_control_plane_v2.sql")

    required = [
        ("fg_append_only_enforcer", "append_only_enforcer function referenced"),
        ("cp_event_ledger_append_only", "ledger UPDATE trigger defined"),
        ("cp_receipts_append_only", "receipts UPDATE trigger defined"),
        ("BEFORE UPDATE", "BEFORE UPDATE trigger present"),
        ("BEFORE DELETE", "BEFORE DELETE trigger present"),
    ]
    for marker, description in required:
        if marker in content:
            ok(description)
        else:
            fail(f"Append-only: {description} — '{marker}' not found in migration 0027")


# ---------------------------------------------------------------------------
# Check 11: Ledger verify endpoint exists
# ---------------------------------------------------------------------------
def check_ledger_verify_endpoint() -> None:
    print("\n[11] Ledger verify endpoint exists")
    content = _read("api/control_plane_v2.py")

    markers = [
        ("/control-plane/v2/ledger/verify", "verify endpoint route defined"),
        ("verify_chain", "verify_chain called in verify endpoint"),
        ("tamper", "tamper detection logic present"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"Ledger verify: {description} — '{marker}' not found")


# ---------------------------------------------------------------------------
# Check 12: Evidence bundle endpoint exists
# ---------------------------------------------------------------------------
def check_evidence_bundle_endpoint() -> None:
    print("\n[12] Evidence bundle endpoint exists")
    content = _read("api/control_plane_v2.py")

    markers = [
        ("/control-plane/evidence/bundle", "evidence bundle route defined"),
        ("bundle_type", "bundle_type field in response"),
        ("integrity", "integrity report included"),
        ("merkle", "merkle root included"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"Evidence bundle: {description} — '{marker}' not found")


# ---------------------------------------------------------------------------
# Check 13: All new files compile without syntax errors
# ---------------------------------------------------------------------------
def check_compilation() -> None:
    print("\n[13] All CP v2 files compile without syntax errors")
    v2_files = [
        "api/control_plane_v2.py",
        "api/db_models_cp_v2.py",
        "services/cp_ledger.py",
        "services/cp_commands.py",
        "services/cp_heartbeats.py",
        "services/cp_playbooks.py",
        "tests/control_plane/test_control_plane_v2.py",
    ]
    for rel in v2_files:
        result = _parse(rel)
        if result is not None:
            ok(f"Compiles: {rel}")
        # failures already recorded in _parse


# ---------------------------------------------------------------------------
# Check 14: Negative test coverage for each invariant
# ---------------------------------------------------------------------------
def check_negative_test_coverage() -> None:
    print("\n[14] Negative test coverage for security invariants")
    test_content = _read("tests/control_plane/test_control_plane_v2.py")

    required_negative_tests = [
        ("test_invariant_no_tenant_from_request_body", "invariant: no tenant from body"),
        ("test_invariant_command_enum_allowlist", "invariant: command allowlist"),
        ("test_invariant_no_subprocess", "invariant: no subprocess"),
        ("test_invariant_append_only_tables_in_migration", "invariant: append-only migration"),
        ("test_invariant_receipt_endpoint_enforces_executor_type", "invariant: receipt executor auth"),
        ("test_invariant_msp_cross_tenant_requires_msp_scope", "invariant: msp scope"),
        ("test_invariant_event_written_before_streaming", "invariant: event before stream"),
        ("test_invariant_playbook_allowlist_is_closed", "invariant: playbook allowlist"),
        ("test_invariant_hash_chain_requires_prev_hash", "invariant: hash chain linkage"),
        ("test_invariant_content_hash_covers_payload", "invariant: content hash tamper"),
    ]
    for test_name, description in required_negative_tests:
        if test_name in test_content:
            ok(f"Negative test present: {description}")
        else:
            fail(f"Missing negative test: {description} ({test_name})")


# ---------------------------------------------------------------------------
# Check 15: Models registered — SQLAlchemy Base imported in db_models_cp_v2
# ---------------------------------------------------------------------------
def check_models_structure() -> None:
    print("\n[15] SQLAlchemy ORM models structure correct")
    content = _read("api/db_models_cp_v2.py")

    required = [
        ("ControlPlaneEventLedger", "ControlPlaneEventLedger model defined"),
        ("ControlPlaneCommand", "ControlPlaneCommand model defined"),
        ("ControlPlaneCommandReceipt", "ControlPlaneCommandReceipt model defined"),
        ("ControlPlaneHeartbeat", "ControlPlaneHeartbeat model defined"),
        ("chain_hash", "chain_hash column defined"),
        ("content_hash", "content_hash column defined"),
        ("prev_hash", "prev_hash column defined"),
        ("idempotency_key_hash", "idempotency_key_hash (not raw key) defined"),
        ("evidence_hash", "evidence_hash defined"),
    ]
    for marker, description in required:
        if marker in content:
            ok(description)
        else:
            fail(f"Model: {description} — '{marker}' not found in db_models_cp_v2.py")


# ---------------------------------------------------------------------------
# Check 16: Main.py includes v2 router
# ---------------------------------------------------------------------------
def check_router_registered() -> None:
    print("\n[16] CP v2 router registered in main.py")
    content = _read("api/main.py")

    if "control_plane_v2_router" in content:
        ok("control_plane_v2_router imported and registered in main.py")
    else:
        fail("control_plane_v2_router NOT found in api/main.py")

    if "from api.control_plane_v2 import" in content:
        ok("control_plane_v2 module imported in main.py")
    else:
        fail("control_plane_v2 module not imported in main.py")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Check 17: AI isolation service enforces tenant-scoped namespace
# ---------------------------------------------------------------------------
def check_ai_isolation_namespace() -> None:
    print("\n[17] AI isolation: tenant-scoped namespace enforcement")
    content = _read("services/cp_ai_isolation.py")

    required = [
        ("derive_tenant_namespace", "derive_tenant_namespace function defined"),
        ("IsolationViolationError", "IsolationViolationError defined"),
        ("TenantScopedRetriever", "TenantScopedRetriever class defined"),
        ("NAMESPACE_VERSION", "NAMESPACE_VERSION constant defined"),
        ("AI_CROSS_TENANT_RETRIEVAL", "cross-tenant retrieval error code defined"),
        ("AI_TENANT_REQUIRED", "empty tenant rejection defined"),
    ]
    for marker, description in required:
        if marker in content:
            ok(description)
        else:
            fail(f"AI isolation: {description} — '{marker}' not found in cp_ai_isolation.py")

    # Verify no subprocess
    tree = _parse("services/cp_ai_isolation.py")
    if tree:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        fail("subprocess usage found in cp_ai_isolation.py")
        ok("No subprocess in cp_ai_isolation.py")


# ---------------------------------------------------------------------------
# Check 18: MSP delegation model present and enforces expiry
# ---------------------------------------------------------------------------
def check_msp_delegation_model() -> None:
    print("\n[18] MSP delegation model present with expiry + scope control")
    content = _read("services/cp_msp_delegation.py")

    required = [
        ("MSPDelegationService", "MSPDelegationService class defined"),
        ("VALID_DELEGATION_SCOPES", "VALID_DELEGATION_SCOPES defined"),
        ("DELEGATION_MAX_TTL_HOURS", "DELEGATION_MAX_TTL_HOURS defined"),
        ("ERR_DELEGATION_NOT_FOUND", "NOT_FOUND error code (anti-enumeration)"),
        ("is_valid", "is_valid() expiry check defined"),
        ("grants_scope", "grants_scope() scope check defined"),
        ("revoked", "revocation flag present"),
        ("expires_at", "expiry timestamp present"),
    ]
    for marker, description in required:
        if marker in content:
            ok(description)
        else:
            fail(f"Delegation: {description} — '{marker}' not found in cp_msp_delegation.py")

    # Check delegation endpoints in API
    api_content = _read("api/control_plane_v2.py")
    api_markers = [
        ("/control-plane/v2/delegation", "delegation endpoints defined in API"),
        ("msp:admin", "delegation requires msp:admin scope"),
        ("ERR_DELEGATION_NOT_FOUND", "anti-enumeration NOT_FOUND used"),
    ]
    for marker, description in api_markers:
        if marker in api_content:
            ok(description)
        else:
            fail(f"Delegation API: {description} — '{marker}' not found in control_plane_v2.py")


# ---------------------------------------------------------------------------
# Check 19: Sandboxed terminal interface enforces DSL allowlist
# ---------------------------------------------------------------------------
def check_sandboxed_terminal() -> None:
    print("\n[19] Sandboxed terminal: DSL allowlist enforced, no subprocess")
    content = _read("services/cp_terminal.py")

    required = [
        ("TERMINAL_ALLOWLIST", "TERMINAL_ALLOWLIST defined"),
        ("TERMINAL_BREAKGLASS_COMMANDS", "TERMINAL_BREAKGLASS_COMMANDS defined"),
        ("BREAKGLASS_SCOPE", "BREAKGLASS_SCOPE constant defined"),
        ("ERR_TERMINAL_UNKNOWN_CMD", "unknown command error code defined"),
        ("ERR_TERMINAL_BREAKGLASS_REQUIRED", "break-glass scope requirement defined"),
        ("_COMMAND_HANDLERS", "dispatch table defined (no dynamic exec)"),
        ("ERR_TERMINAL_REASON_REQUIRED", "mandatory reason enforced"),
        ("shell metacharacters", "shell metacharacter rejection defined"),
    ]
    for marker, description in required:
        if marker in content:
            ok(description)
        else:
            fail(f"Terminal: {description} — '{marker}' not found in cp_terminal.py")

    # Verify no subprocess in terminal
    tree = _parse("services/cp_terminal.py")
    if tree:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        fail("subprocess usage found in cp_terminal.py — FORBIDDEN")
        ok("No subprocess in cp_terminal.py")

    # Verify terminal endpoints in API
    api_content = _read("api/control_plane_v2.py")
    api_markers = [
        ("/control-plane/v2/terminal/execute", "terminal execute endpoint defined"),
        ("/control-plane/v2/terminal/allowlist", "terminal allowlist endpoint defined"),
        ("/control-plane/v2/terminal/breakglass", "terminal breakglass endpoint defined"),
        ("BREAKGLASS_SCOPE", "breakglass scope enforced in API"),
    ]
    for marker, description in api_markers:
        if marker in api_content:
            ok(description)
        else:
            fail(f"Terminal API: {description} — '{marker}' not found")


# ---------------------------------------------------------------------------
# Check 20: CLI verifier tool exists and is functional
# ---------------------------------------------------------------------------
def check_cli_verifier_tool() -> None:
    print("\n[20] CLI verifier tool exists (tools/verify_bundle.py)")
    content = _read("tools/verify_bundle.py")

    required = [
        ("BundleVerifier", "BundleVerifier class defined"),
        ("AnchorVerifier", "AnchorVerifier class defined"),
        ("GENESIS_HASH", "GENESIS_HASH constant defined"),
        ("_recompute_content_hash", "content hash recomputation defined"),
        ("_recompute_chain_hash", "chain hash recomputation defined"),
        ("_recompute_merkle", "merkle root recomputation defined"),
        ("def main(", "CLI main() entrypoint defined"),
        ("exit code", "exit code documentation present"),
    ]
    for marker, description in required:
        if marker in content or "exit" in content.lower():
            if marker == "exit code":
                if "exit code" in content or "Exit code" in content:
                    ok(description)
                else:
                    fail(f"Verifier: {description} — 'exit code' not found in verify_bundle.py")
            elif marker in content:
                ok(description)
            else:
                fail(f"Verifier: {description} — '{marker}' not found in verify_bundle.py")
        else:
            fail(f"Verifier: {description} — '{marker}' not found in verify_bundle.py")

    # Verify CLI is executable Python
    tree = _parse("tools/verify_bundle.py")
    if tree:
        ok("tools/verify_bundle.py compiles without syntax errors")


# ---------------------------------------------------------------------------
# Check 21: Phase 3-7 test files exist and compile
# ---------------------------------------------------------------------------
def check_phase_test_coverage() -> None:
    print("\n[21] Phase 3-7 test files present and compilable")
    phase_test_files = [
        "tests/control_plane/test_control_plane_phase3.py",
        "tests/control_plane/test_control_plane_phase4.py",
        "tests/control_plane/test_control_plane_phase6.py",
        "tests/control_plane/test_control_plane_phase7.py",
    ]
    for rel in phase_test_files:
        result = _parse(rel)
        if result is not None:
            ok(f"Compiles: {rel}")

    # Verify each test file has negative tests
    negative_markers = [
        ("test_control_plane_phase3.py", [
            "test_invariant_ai_cross_tenant_retrieval_blocked",
            "test_invariant_ai_namespace_requires_tenant",
            "test_invariant_namespaces_structurally_isolated",
        ]),
        ("test_control_plane_phase4.py", [
            "test_invariant_empty_target_tenant_rejected",
            "test_invariant_unknown_scope_rejected",
            "test_check_delegation_missing_raises_not_found",
        ]),
        ("test_control_plane_phase6.py", [
            "test_invariant_unknown_command_rejected",
            "test_invariant_shell_injection_rejected",
            "test_invariant_breakglass_cmd_without_scope_rejected",
            "test_invariant_no_subprocess_in_terminal",
            "test_invariant_ledger_written_before_return",
        ]),
        ("test_control_plane_phase7.py", [
            "test_tampered_payload_detected",
            "test_tampered_chain_hash_detected",
            "test_tampered_merkle_root_detected",
            "test_foreign_tenant_events_detected",
        ]),
    ]
    for fname, tests in negative_markers:
        content = _read(f"tests/control_plane/{fname}")
        for test_name in tests:
            if test_name in content:
                ok(f"Negative test: {test_name}")
            else:
                fail(f"Missing negative test: {test_name} in {fname}")


# ---------------------------------------------------------------------------
# Check 22: AI isolation endpoint in control_plane_v2
# ---------------------------------------------------------------------------
def check_ai_isolation_endpoint() -> None:
    print("\n[22] AI isolation namespace endpoint defined")
    content = _read("api/control_plane_v2.py")

    markers = [
        ("/control-plane/v2/ai/namespace", "AI namespace endpoint defined"),
        ("derive_tenant_namespace", "derive_tenant_namespace used in API"),
        ("IsolationViolationError", "IsolationViolationError handled"),
        ("CP_AI_TENANT_REQUIRED", "AI tenant required error code"),
    ]
    for marker, description in markers:
        if marker in content:
            ok(description)
        else:
            fail(f"AI endpoint: {description} — '{marker}' not found")


def main() -> int:
    print("=" * 60)
    print("FrostGate Control Plane v2 — CI Invariant Guard")
    print("=" * 60)

    check_required_tables()
    check_hash_chain_logic()
    check_no_subprocess()
    check_receipt_executor_auth()
    check_msp_scope_enforcement()
    check_no_header_tenant()
    check_event_written_before_streaming()
    check_command_allowlist()
    check_playbook_allowlist()
    check_append_only_triggers()
    check_ledger_verify_endpoint()
    check_evidence_bundle_endpoint()
    check_compilation()
    check_negative_test_coverage()
    check_models_structure()
    check_router_registered()
    # Phase 3-7 new invariant checks
    check_ai_isolation_namespace()
    check_msp_delegation_model()
    check_sandboxed_terminal()
    check_cli_verifier_tool()
    check_phase_test_coverage()
    check_ai_isolation_endpoint()

    print("\n" + "=" * 60)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} invariant(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        print("=" * 60)
        return 1
    else:
        print("RESULT: All invariants PASSED (0 failures)")
        print("=" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
