"""Regression tests for the codex_gates.sh basic-secret-scan gate.

Reproduces the rg + grep -vE pipeline so changes to either the detector
pattern or the safe-ref filter are caught before the gate runs in CI.

SYNC: keep _DETECT and _SAFE_REF aligned with codex_gates.sh.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

_DETECT = (
    r"(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY"
    r"|BEGIN( RSA)? PRIVATE KEY|xox[baprs]-|-----BEGIN PRIVATE KEY-----)"
)
_SAFE_REF = (
    r"\$\{\{[^}]*\}\}"          # GitHub Actions ${{ secrets.FOO }}
    r"|-z\s"                     # shell presence test: -z "$VAR"
    r"|=\.\.\.(\s|$)"            # doc placeholder: VAR=...
    r"|=<[^>]*>"                 # doc placeholder: VAR=<value>
    r"|`[A-Z_]+`"                # markdown backtick name span
    r"|process\.env\."           # JS/Node env access: process.env.VAR
    r"|:[0-9]+:\s*#"             # rg output line whose content is a comment
)


def _scan(content: str) -> list[str]:
    """Run the gate pipeline on *content*; return non-filtered matching lines."""
    with tempfile.TemporaryDirectory() as d:
        probe = Path(d) / "probe.txt"
        probe.write_text(content)
        rg = subprocess.run(
            ["rg", "-n", "--no-heading", "--with-filename", _DETECT, str(probe)],
            capture_output=True,
            text=True,
        )
        if not rg.stdout:
            return []
        grep = subprocess.run(
            ["grep", "-vE", _SAFE_REF],
            input=rg.stdout,
            capture_output=True,
            text=True,
        )
        return [line for line in grep.stdout.splitlines() if line]


# ── Should detect (real secret values) ───────────────────────────────────────


def test_detects_aws_secret_assignment() -> None:
    assert _scan("export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")


def test_detects_openai_key_assignment() -> None:
    assert _scan("OPENAI_API_KEY=sk-proj-abc123realkey\n")


def test_detects_pem_begin_marker() -> None:
    assert _scan("-----BEGIN PRIVATE KEY-----\n")


def test_detects_pem_rsa_marker() -> None:
    assert _scan("-----BEGIN RSA PRIVATE KEY-----\n")


def test_detects_slack_bot_token() -> None:
    assert _scan("token = xoxb-12345678-secret\n")


def test_detects_aws_secret_without_export() -> None:
    assert _scan("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")


# ── Should ignore (safe reference contexts) ───────────────────────────────────


def test_ignores_github_actions_secret_ref() -> None:
    line = "      AWS_SECRET_ACCESS_KEY: ${{ secrets.FG_BACKUP_R2_SECRET_ACCESS_KEY }}\n"
    assert not _scan(line)


def test_ignores_github_actions_secret_ref_openai() -> None:
    line = "      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
    assert not _scan(line)


def test_ignores_shell_presence_test_double_quote() -> None:
    assert not _scan('[[ -z "$AWS_SECRET_ACCESS_KEY" ]] && echo missing\n')


def test_ignores_shell_presence_test_brace_default() -> None:
    assert not _scan('[[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]]\n')


def test_ignores_shell_presence_test_inline() -> None:
    line = "if [[ -z \"$bucket\" || -z \"${AWS_SECRET_ACCESS_KEY:-}\" ]]; then\n"
    assert not _scan(line)


def test_ignores_doc_placeholder_ellipsis() -> None:
    assert not _scan("export AWS_SECRET_ACCESS_KEY=...\n")


def test_ignores_doc_placeholder_angle_bracket() -> None:
    assert not _scan("export AWS_SECRET_ACCESS_KEY=<your-secret-key>\n")


def test_ignores_doc_placeholder_angle_secret() -> None:
    assert not _scan("export OPENAI_API_KEY=<secret>\n")


def test_ignores_markdown_backtick_name() -> None:
    line = "| Populate `AWS_SECRET_ACCESS_KEY` or set `FG_BACKUP_OFFSITE_PROVIDER=local` |\n"
    assert not _scan(line)


def test_ignores_js_process_env_access() -> None:
    assert not _scan("const key = process.env.OPENAI_API_KEY;\n")


def test_ignores_comment_line_name_reference() -> None:
    assert not _scan("#   AWS_SECRET_ACCESS_KEY     the S3 secret key\n")


def test_ignores_comment_line_with_parenthetical() -> None:
    assert not _scan("#   AWS_SECRET_ACCESS_KEY (or a working rclone remote).\n")
