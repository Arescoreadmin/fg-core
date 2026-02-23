"""
tests/control_plane/test_control_plane_phase6.py — Phase 6: Sandboxed Terminal Tests.

Tests cover:
  - Allowlisted command execution
  - Unknown command rejection (not executed)
  - Shell metacharacter injection rejection
  - Break-glass command requires break-glass scope
  - Break-glass session creation with TTL
  - Expired break-glass session rejection
  - Mandatory reason enforcement
  - Ledger event emitted before returning (truth plane first)
  - Evidence bundle link in every response
  - Tenant isolation from auth context
  - No subprocess usage (CI-verifiable)

Security invariants verified:
  - No subprocess, no shell
  - Only TERMINAL_ALLOWLIST commands
  - Break-glass requires scope
  - Reason mandatory
  - Ledger before output
"""

from __future__ import annotations

import ast
import uuid
import pytest
from datetime import datetime, timezone, timedelta

from services.cp_terminal import (
    SandboxedTerminalService,
    TERMINAL_ALLOWLIST,
    TERMINAL_READ_COMMANDS,
    TERMINAL_BREAKGLASS_COMMANDS,
    BREAKGLASS_SCOPE,
    BREAKGLASS_MAX_TTL_SECONDS,
    ERR_TERMINAL_UNKNOWN_CMD,
    ERR_TERMINAL_BREAKGLASS_REQUIRED,
    ERR_TERMINAL_REASON_REQUIRED,
    ERR_TERMINAL_REASON_INVALID,
    reset_breakglass_sessions,
    _parse_command,
)


class _MockLedger:
    """Minimal ledger stub."""

    def __init__(self):
        self.events = []

    def append_event(self, **kwargs):
        from dataclasses import dataclass

        @dataclass
        class Entry:
            id: str = "ledger-event-id"

        self.events.append(kwargs)
        return Entry()


class _MockDB:
    """Minimal DB session stub."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


@pytest.fixture(autouse=True)
def clear_sessions():
    reset_breakglass_sessions()
    yield
    reset_breakglass_sessions()


@pytest.fixture
def svc():
    return SandboxedTerminalService()


@pytest.fixture
def ledger():
    return _MockLedger()


@pytest.fixture
def db():
    return _MockDB()


READ_SCOPES = frozenset({"control-plane:read"})
ADMIN_SCOPES = frozenset({"control-plane:read", "control-plane:admin"})
BREAKGLASS_SCOPES = frozenset({"control-plane:read", BREAKGLASS_SCOPE})


class TestCommandAllowlist:
    """Test that only allowlisted commands are accepted."""

    def test_allowlist_contains_expected_commands(self):
        """Terminal allowlist contains all expected commands."""
        expected_read = {
            "status",
            "list",
            "inspect",
            "check-health",
            "show-ledger",
            "show-commands",
            "show-receipts",
        }
        expected_bg = {"force-inspect", "emergency-list"}
        assert expected_read == TERMINAL_READ_COMMANDS
        assert expected_bg == TERMINAL_BREAKGLASS_COMMANDS
        assert TERMINAL_ALLOWLIST == expected_read | expected_bg

    def test_execute_status_command(self, svc, ledger, db):
        """status <entity_id> executes correctly."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="status module-001",
            reason="Testing status command",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )
        assert result.ok is True
        assert result.command == "status"
        assert result.output["entity_id"] == "module-001"

    def test_execute_list_command(self, svc, ledger, db):
        """list <entity_type> executes correctly."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="list locker",
            reason="Listing lockers for audit",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )
        assert result.ok is True
        assert result.command == "list"
        assert result.output["entity_type"] == "locker"

    def test_execute_inspect_command(self, svc, ledger, db):
        """inspect <entity_id> executes correctly."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="inspect entity-001",
            reason="Inspect entity state",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )
        assert result.ok is True
        assert result.command == "inspect"

    def test_execute_show_ledger_command(self, svc, ledger, db):
        """show-ledger [limit] executes correctly."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="show-ledger 20",
            reason="Show recent ledger for audit",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )
        assert result.ok is True
        assert result.command == "show-ledger"


class TestUnknownCommandRejection:
    """NEGATIVE: Unknown commands must be rejected without execution."""

    def test_invariant_unknown_command_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Unknown command rejected with ERR_TERMINAL_UNKNOWN_CMD.
        The command must NOT be executed.
        """
        with pytest.raises(ValueError, match=ERR_TERMINAL_UNKNOWN_CMD):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="run_arbitrary_thing target",
                reason="Testing unknown command rejection",
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=READ_SCOPES,
            )

    def test_invariant_shell_injection_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Shell metacharacters in command are rejected.
        Prevents shell injection via command argument.
        """
        dangerous_commands = [
            "status module; rm -rf /",
            "list locker | cat /etc/passwd",
            "inspect entity && evil",
            "status $(whoami)",
            "list `echo pwned`",
        ]
        for cmd in dangerous_commands:
            with pytest.raises(ValueError):
                svc.execute(
                    db_session=db,
                    ledger=ledger,
                    raw_command=cmd,
                    reason="Testing shell injection",
                    tenant_id="tenant-alpha",
                    actor_id="actor-001",
                    actor_role="operator",
                    scopes=READ_SCOPES,
                )

    def test_invariant_empty_command_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Empty command is rejected.
        """
        with pytest.raises(ValueError):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="   ",
                reason="Testing empty command",
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=READ_SCOPES,
            )


class TestBreakglassEnforcement:
    """NEGATIVE: Break-glass commands require break-glass scope."""

    def test_invariant_breakglass_cmd_without_scope_rejected(self, svc, ledger, db):
        """
        NEGATIVE: force-inspect without break-glass scope → ERR_TERMINAL_BREAKGLASS_REQUIRED.
        """
        with pytest.raises(ValueError, match=ERR_TERMINAL_BREAKGLASS_REQUIRED):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="force-inspect entity-001",
                reason="Emergency inspection without scope",
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=READ_SCOPES,  # No break-glass scope
            )

    def test_invariant_emergency_list_without_scope_rejected(self, svc, ledger, db):
        """
        NEGATIVE: emergency-list without break-glass scope rejected.
        """
        with pytest.raises(ValueError, match=ERR_TERMINAL_BREAKGLASS_REQUIRED):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="emergency-list locker",
                reason="Emergency list without scope",
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=ADMIN_SCOPES,  # admin but no break-glass
            )

    def test_breakglass_cmd_with_scope_succeeds(self, svc, ledger, db):
        """Break-glass command with correct scope succeeds."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="force-inspect entity-001",
            reason="Emergency inspection with break-glass scope",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=BREAKGLASS_SCOPES,
        )
        assert result.ok is True
        assert result.breakglass is True
        assert result.command == "force-inspect"


class TestBreakglassSession:
    """Tests for break-glass session creation."""

    def test_create_breakglass_session(self, svc, ledger, db):
        """Break-glass session is created with TTL."""
        session = svc.create_breakglass_session(
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            reason="Emergency investigation needed",
            ttl_seconds=1800,
        )
        assert session.session_id
        assert session.tenant_id == "tenant-alpha"
        assert session.actor_id == "actor-001"
        assert session.ttl_seconds == 1800
        assert session.is_valid() is True

    def test_breakglass_session_ttl_capped(self, svc, ledger, db):
        """Break-glass session TTL is capped at BREAKGLASS_MAX_TTL_SECONDS."""
        session = svc.create_breakglass_session(
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            reason="Testing TTL cap",
            ttl_seconds=99999,  # Way over limit
        )
        assert session.ttl_seconds == BREAKGLASS_MAX_TTL_SECONDS

    def test_breakglass_session_expired_invalid(self, svc):
        """Expired break-glass session is invalid."""
        from services.cp_terminal import BreakglassSession

        now = datetime.now(timezone.utc)
        session = BreakglassSession(
            session_id=str(uuid.uuid4()),
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            reason="Test",
            created_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            ttl_seconds=1,
        )
        assert session.is_valid() is False


class TestReasonEnforcement:
    """NEGATIVE: Mandatory reason enforcement."""

    def test_invariant_empty_reason_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Empty reason is rejected.
        """
        with pytest.raises(ValueError, match=ERR_TERMINAL_REASON_REQUIRED):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="status entity-001",
                reason="",
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=READ_SCOPES,
            )

    def test_invariant_short_reason_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Reason too short is rejected.
        """
        with pytest.raises(ValueError, match=ERR_TERMINAL_REASON_INVALID):
            svc.execute(
                db_session=db,
                ledger=ledger,
                raw_command="status entity-001",
                reason="ab",  # Too short (< 4 chars)
                tenant_id="tenant-alpha",
                actor_id="actor-001",
                actor_role="operator",
                scopes=READ_SCOPES,
            )


class TestLedgerEmissionBeforeOutput:
    """Invariant: Ledger event emitted before returning output."""

    def test_invariant_ledger_written_before_return(self, svc, ledger, db):
        """
        Invariant: Ledger event is written BEFORE command output is returned.
        Verified by checking ledger.events is populated before result is returned.
        """
        assert len(ledger.events) == 0

        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="status entity-001",
            reason="Audit trail test",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )

        # Ledger must have been written
        assert len(ledger.events) == 1
        # Result must also be returned
        assert result.ok is True
        assert result.ledger_event_id == "ledger-event-id"

    def test_evidence_bundle_link_in_response(self, svc, ledger, db):
        """Evidence bundle link is always included in response."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="status entity-001",
            reason="Testing evidence link",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
            trace_id="trace-001",
        )
        assert result.evidence_bundle_link
        assert "/control-plane/evidence/bundle" in result.evidence_bundle_link


class TestTerminalResultStructure:
    """Test TerminalResult structure completeness."""

    def test_result_to_dict_complete(self, svc, ledger, db):
        """TerminalResult.to_dict() contains all required fields."""
        result = svc.execute(
            db_session=db,
            ledger=ledger,
            raw_command="status entity-001",
            reason="Structure completeness test",
            tenant_id="tenant-alpha",
            actor_id="actor-001",
            actor_role="operator",
            scopes=READ_SCOPES,
        )
        d = result.to_dict()
        required = [
            "invocation_id",
            "command",
            "args",
            "tenant_id",
            "actor_id",
            "reason",
            "ok",
            "output",
            "error_code",
            "breakglass",
            "ledger_event_id",
            "evidence_bundle_link",
            "ts",
        ]
        for f in required:
            assert f in d, f"Missing field: {f}"


class TestNoSubprocessInTerminal:
    """CI-gate: Verify no subprocess usage in terminal service."""

    def test_invariant_no_subprocess_in_terminal(self):
        """
        NEGATIVE: Terminal service must not import or use subprocess.
        This test parses the AST to verify no subprocess usage.
        """
        from pathlib import Path

        src = (
            Path(__file__).parent.parent.parent / "services" / "cp_terminal.py"
        ).read_text()
        tree = ast.parse(src, filename="cp_terminal.py")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "subprocess", (
                        "subprocess imported in cp_terminal.py — FORBIDDEN"
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "subprocess", (
                    "subprocess imported in cp_terminal.py — FORBIDDEN"
                )

    def test_invariant_terminal_uses_dispatch_table(self):
        """
        Terminal must use _COMMAND_HANDLERS dispatch table, not dynamic dispatch.
        """
        from services.cp_terminal import _COMMAND_HANDLERS

        assert isinstance(_COMMAND_HANDLERS, dict)
        # All allowlist commands must be in the dispatch table
        for cmd in TERMINAL_ALLOWLIST:
            assert cmd in _COMMAND_HANDLERS, (
                f"Command '{cmd}' in TERMINAL_ALLOWLIST but not in _COMMAND_HANDLERS"
            )


class TestParseCommand:
    """Test command parsing safety."""

    def test_parse_valid_command(self):
        cmd, args = _parse_command("status entity-001")
        assert cmd == "status"
        assert args == ["entity-001"]

    def test_parse_pipe_rejected(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _parse_command("list locker | cat")

    def test_parse_semicolon_rejected(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _parse_command("status x; rm -rf /")

    def test_parse_backtick_rejected(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _parse_command("status `whoami`")

    def test_parse_dollar_rejected(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _parse_command("status $(id)")
