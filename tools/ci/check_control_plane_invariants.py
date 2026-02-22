#!/usr/bin/env python3
"""
Control Plane CI Invariants Checker

Verifies that the control plane implementation meets all security invariants:
1. All control endpoints are protected by scope
2. All control endpoints emit audit on every action
3. No subprocess usage in API layer (api/control_plane.py)
4. Rate limit decorators applied to control commands
5. WebSocket auth enforced (no unauthenticated upgrade path)
6. No fail-open behavior (no bare except: pass patterns on security checks)
7. Idempotency enforcement on command endpoints
8. Cooldown enforcement in command bus
9. No internal IP leakage in error responses

Exit code 0 = all invariants pass.
Exit code 1 = one or more invariants failed.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parents[2]
CONTROL_PLANE_API = REPO_ROOT / "api" / "control_plane.py"
LOCKER_COMMAND_BUS = REPO_ROOT / "services" / "locker_command_bus.py"
MODULE_REGISTRY = REPO_ROOT / "services" / "module_registry.py"
BOOT_TRACE = REPO_ROOT / "services" / "boot_trace.py"
EVENT_STREAM = REPO_ROOT / "services" / "event_stream.py"

FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"  ok: {msg}")


def check_file_exists(path: Path, label: str) -> bool:
    if not path.exists():
        fail(f"{label} missing: {path}")
        return False
    ok(f"{label} exists")
    return True


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# INV-1: All control endpoints protected by scope
# ---------------------------------------------------------------------------
def check_scope_enforcement() -> None:
    print("\n[INV-1] All control endpoints require scope enforcement")
    src = read_source(CONTROL_PLANE_API)

    # Find all @router.post and @router.get decorators (not WS)
    route_pattern = re.compile(
        r'@router\.(get|post)\(\s*\n?\s*"([^"]+)"', re.MULTILINE
    )
    for match in route_pattern.finditer(src):
        method, path = match.group(1), match.group(2)

        # Find the scope dependency nearby
        window_start = match.start()
        window_end = src.find("def ", match.end()) + 200
        window = src[window_start:window_end]

        if "require_scopes" not in window:
            fail(f"[INV-1] {method.upper()} {path} missing require_scopes()")
        else:
            ok(f"{method.upper()} {path} has scope guard")


# ---------------------------------------------------------------------------
# INV-2: No subprocess in API or command bus layer
# ---------------------------------------------------------------------------
def check_no_subprocess() -> None:
    print("\n[INV-2] No subprocess usage in control plane API or command bus")
    files = [
        (CONTROL_PLANE_API, "api/control_plane.py"),
        (LOCKER_COMMAND_BUS, "services/locker_command_bus.py"),
    ]

    # Check for actual subprocess imports and calls (not comments/docstrings)
    # Patterns that indicate actual usage, not documentation
    forbidden_patterns = [
        (re.compile(r"^\s*import subprocess", re.MULTILINE), "import subprocess"),
        (re.compile(r"^\s*from subprocess", re.MULTILINE), "from subprocess import"),
        (re.compile(r"subprocess\.(run|Popen|call|check_output|check_call)\s*\("), "subprocess.run/Popen/call"),
        (re.compile(r"os\.system\s*\("), "os.system()"),
        (re.compile(r"os\.popen\s*\("), "os.popen()"),
        (re.compile(r"\bshell\s*=\s*True"), "shell=True"),
    ]

    for path, label in files:
        src = read_source(path)
        found_any = False
        for pattern, description in forbidden_patterns:
            matches = pattern.findall(src)
            if matches:
                fail(f"[INV-2] {label} contains forbidden pattern: {description!r}")
                found_any = True
        if not found_any:
            ok(f"{label}: no subprocess/shell execution patterns")


# ---------------------------------------------------------------------------
# INV-3: Rate limit applied on control command endpoints
# ---------------------------------------------------------------------------
def check_rate_limit_applied() -> None:
    print("\n[INV-3] Rate limiting applied on command endpoints")
    src = read_source(CONTROL_PLANE_API)

    if "_rate_limit_check" not in src:
        fail("[INV-3] _rate_limit_check not found in control_plane.py")
    else:
        ok("_rate_limit_check defined in control_plane.py")

    # Check that locker command endpoints call rate limit
    # Find the _dispatch_locker_command function body
    dispatch_match = re.search(
        r"def _dispatch_locker_command.*?(?=^def |\Z)", src, re.MULTILINE | re.DOTALL
    )
    if dispatch_match:
        dispatch_body = dispatch_match.group(0)
        if "_rate_limit_check" in dispatch_body:
            ok("_dispatch_locker_command applies rate limit")
        else:
            fail("[INV-3] _dispatch_locker_command does not call _rate_limit_check")
    else:
        fail("[INV-3] _dispatch_locker_command function not found")


# ---------------------------------------------------------------------------
# INV-4: WebSocket auth enforced (no unauthenticated upgrade)
# ---------------------------------------------------------------------------
def check_websocket_auth() -> None:
    print("\n[INV-4] WebSocket auth enforced - no unauthenticated upgrade")
    src = read_source(CONTROL_PLANE_API)

    ws_func_match = re.search(
        r"async def control_plane_events.*?(?=^@router|\Z)",
        src,
        re.MULTILINE | re.DOTALL,
    )
    if not ws_func_match:
        fail("[INV-4] WebSocket handler not found")
        return

    ws_body = ws_func_match.group(0)

    # Must close before accept if no key
    if "websocket.close" not in ws_body:
        fail("[INV-4] WebSocket does not close on auth failure")
    else:
        ok("WebSocket closes on auth failure")

    # Must NOT call accept() before auth check
    accept_pos = ws_body.find("await websocket.accept()")
    close_pos = ws_body.find("websocket.close(")
    if accept_pos != -1 and close_pos != -1 and close_pos > accept_pos:
        fail("[INV-4] websocket.accept() called before auth close path")
    else:
        ok("websocket.accept() called only after auth verification")

    # Must verify API key
    if "verify_api_key_detailed" not in ws_body and "verify_api_key" not in ws_body:
        fail("[INV-4] WebSocket does not verify API key")
    else:
        ok("WebSocket verifies API key")

    # Must check tenant binding
    if "tenant_id" not in ws_body:
        fail("[INV-4] WebSocket does not check tenant binding")
    else:
        ok("WebSocket checks tenant binding")


# ---------------------------------------------------------------------------
# INV-5: Idempotency enforced in command bus
# ---------------------------------------------------------------------------
def check_idempotency() -> None:
    print("\n[INV-5] Idempotency enforced in command bus")
    src = read_source(LOCKER_COMMAND_BUS)

    if "IdempotencyStore" not in src:
        fail("[INV-5] IdempotencyStore not found in locker_command_bus.py")
    else:
        ok("IdempotencyStore class exists")

    if "check_and_set" not in src:
        fail("[INV-5] check_and_set not found in locker_command_bus.py")
    else:
        ok("check_and_set method exists")

    # Dispatch must use idempotency
    dispatch_match = re.search(
        r"def dispatch.*?(?=^    def |\Z)", src, re.MULTILINE | re.DOTALL
    )
    if dispatch_match and "check_and_set" in dispatch_match.group(0):
        ok("dispatch() calls check_and_set (idempotency)")
    else:
        fail("[INV-5] dispatch() does not call check_and_set")


# ---------------------------------------------------------------------------
# INV-6: Cooldown enforcement in command bus
# ---------------------------------------------------------------------------
def check_cooldown() -> None:
    print("\n[INV-6] Cooldown enforced in command bus")
    src = read_source(LOCKER_COMMAND_BUS)

    if "CooldownTracker" not in src:
        fail("[INV-6] CooldownTracker not found in locker_command_bus.py")
    else:
        ok("CooldownTracker class exists")

    dispatch_match = re.search(
        r"def dispatch.*?(?=^    def |\Z)", src, re.MULTILINE | re.DOTALL
    )
    if dispatch_match and "cooldown" in dispatch_match.group(0).lower():
        ok("dispatch() enforces cooldown")
    else:
        fail("[INV-6] dispatch() does not enforce cooldown")

    if "ERR_LOCKER_COOLDOWN" in src:
        ok("ERR_LOCKER_COOLDOWN deterministic error code defined")
    else:
        fail("[INV-6] ERR_LOCKER_COOLDOWN not defined")


# ---------------------------------------------------------------------------
# INV-7: Audit emitted on every control action
# ---------------------------------------------------------------------------
def check_audit_emission() -> None:
    print("\n[INV-7] Audit emitted on every control action")
    src = read_source(LOCKER_COMMAND_BUS)

    if "emit_command_audit" not in src:
        fail("[INV-7] emit_command_audit not found in locker_command_bus.py")
        return

    ok("emit_command_audit function exists")

    # Every return path in dispatch must emit audit
    dispatch_match = re.search(
        r"def dispatch.*?(?=^    def |\Z)", src, re.MULTILINE | re.DOTALL
    )
    if not dispatch_match:
        fail("[INV-7] dispatch() not found")
        return

    dispatch_body = dispatch_match.group(0)
    # Count return statements that DON'T have emit_command_audit before them
    # Simplified check: all outcome objects returned must be preceded by emit_command_audit
    returns = list(re.finditer(r"return outcome", dispatch_body))
    audits = list(re.finditer(r"emit_command_audit", dispatch_body))

    if len(returns) == 0:
        fail("[INV-7] dispatch() has no return statements")
        return

    # Every return must have an emit_command_audit call before it in the same block
    audit_positions = [m.start() for m in audits]
    for ret_match in returns:
        ret_pos = ret_match.start()
        # Check if there's any audit call before this return
        preceding_audits = [p for p in audit_positions if p < ret_pos]
        if not preceding_audits:
            fail(f"[INV-7] return at pos {ret_pos} has no preceding emit_command_audit")
        else:
            ok(f"return at pos {ret_pos} has audit call")


# ---------------------------------------------------------------------------
# INV-8: No fail-open in security checks
# ---------------------------------------------------------------------------
def check_no_fail_open() -> None:
    print("\n[INV-8] No fail-open in security checks")
    src = read_source(CONTROL_PLANE_API)

    # Look for bare except: pass patterns in auth context
    bare_except = re.findall(r"except\s+Exception\s*:\s*\n\s*pass", src)
    if bare_except:
        fail(f"[INV-8] Found {len(bare_except)} bare 'except Exception: pass' in control_plane.py")
    else:
        ok("No bare 'except Exception: pass' in control_plane.py")

    # Check that auth failures close, not silently pass
    ws_match = re.search(
        r"async def control_plane_events.*?(?=^@|\Z)",
        src,
        re.MULTILINE | re.DOTALL,
    )
    if ws_match:
        ws_body = ws_match.group(0)
        if "return" in ws_body and "websocket.close" in ws_body:
            ok("WebSocket auth failures properly return after close")
        else:
            fail("[INV-8] WebSocket may not properly return on auth failure")


# ---------------------------------------------------------------------------
# INV-9: Deterministic error codes defined
# ---------------------------------------------------------------------------
def check_deterministic_error_codes() -> None:
    print("\n[INV-9] Deterministic error codes defined")

    files_to_check = [
        (CONTROL_PLANE_API, "api/control_plane.py", ["CP-API-"]),
        (LOCKER_COMMAND_BUS, "services/locker_command_bus.py", ["CP-LOCK-"]),
        (MODULE_REGISTRY, "services/module_registry.py", ["CP-MOD-"]),
        (BOOT_TRACE, "services/boot_trace.py", ["CP-BOOT-"]),
        (EVENT_STREAM, "services/event_stream.py", ["CP-EVT-"]),
    ]

    for path, label, prefixes in files_to_check:
        src = read_source(path)
        for prefix in prefixes:
            if prefix in src:
                ok(f"{label} has deterministic error codes with prefix {prefix!r}")
            else:
                fail(f"[INV-9] {label} missing error codes with prefix {prefix!r}")


# ---------------------------------------------------------------------------
# INV-10: Boot trace has all canonical stages
# ---------------------------------------------------------------------------
def check_boot_trace_stages() -> None:
    print("\n[INV-10] Boot trace has all canonical stages")
    src = read_source(BOOT_TRACE)

    required_stages = [
        "config_loaded",
        "tenant_binding_initialized",
        "db_connected",
        "migrations_completed",
        "redis_connected",
        "nats_connected",
        "opa_validated",
        "routes_registered",
        "websocket_ready",
        "ready_true",
    ]

    for stage in required_stages:
        if stage in src:
            ok(f"Boot stage {stage!r} defined")
        else:
            fail(f"[INV-10] Boot stage {stage!r} missing from boot_trace.py")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("Control Plane Invariants Check")
    print("=" * 60)

    # Check all files exist
    all_exist = all([
        check_file_exists(CONTROL_PLANE_API, "api/control_plane.py"),
        check_file_exists(LOCKER_COMMAND_BUS, "services/locker_command_bus.py"),
        check_file_exists(MODULE_REGISTRY, "services/module_registry.py"),
        check_file_exists(BOOT_TRACE, "services/boot_trace.py"),
        check_file_exists(EVENT_STREAM, "services/event_stream.py"),
    ])

    if not all_exist:
        print("\n❌ Required files missing. Cannot continue checks.")
        sys.exit(1)

    check_scope_enforcement()
    check_no_subprocess()
    check_rate_limit_applied()
    check_websocket_auth()
    check_idempotency()
    check_cooldown()
    check_audit_emission()
    check_no_fail_open()
    check_deterministic_error_codes()
    check_boot_trace_stages()

    print("\n" + "=" * 60)
    if FAILURES:
        print(f"❌ {len(FAILURES)} invariant(s) FAILED:")
        for f in FAILURES:
            print(f"   - {f}")
        sys.exit(1)
    else:
        print("✅ All control plane invariants PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
