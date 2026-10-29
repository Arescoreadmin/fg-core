"""Regression tests for the codex_gates.sh basic-secret-scan gate.

Reproduces the rg + grep -vE pipeline so changes to either the detector
pattern or the safe-ref filter are caught before the gate runs in CI.

SYNC: keep _DETECT and _SAFE_REF aligned with codex_gates.sh.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

# Env-var names require '=' so name-only references (comments, shell tests,
# GH Actions env blocks, markdown, process.env access) are eliminated at
# detection time rather than by a post-filter that could hide real secrets.
_DETECT = (
    r"(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)="
    r"|(BEGIN( RSA)? PRIVATE KEY|xox[baprs]-|-----BEGIN PRIVATE KEY-----)"
)
# Post-filter handles only the residual safe forms that still contain '=':
# placeholder values and GitHub Actions inline injection.
_SAFE_REF = r"=\.\.\.(\s|$)|=<[^>]*>|\$\{\{[^}]*\}\}"


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


def test_detects_aws_secret_without_export() -> None:
    assert _scan("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")


def test_detects_openai_key_assignment() -> None:
    assert _scan("OPENAI_API_KEY=sk-proj-abc123realkey\n")


def test_detects_pem_begin_marker() -> None:
    assert _scan("-----BEGIN PRIVATE KEY-----\n")


def test_detects_pem_rsa_marker() -> None:
    assert _scan("-----BEGIN RSA PRIVATE KEY-----\n")


def test_detects_slack_bot_token() -> None:
    assert _scan("token = xoxb-12345678-secret\n")


def test_detects_aws_secret_in_comment() -> None:
    """Credentials committed in comments must not be silently dropped."""
    assert _scan("# export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")


# ── Should ignore (safe reference contexts) ───────────────────────────────────
# The tighter detector (VAR=) means most name-only forms never reach rg output.
# These tests document the intended behaviour regardless of which layer handles it.


def test_ignores_github_actions_colon_form() -> None:
    """YAML env block uses ':' not '=' — name-only, not matched by detector."""
    line = (
        "      AWS_SECRET_ACCESS_KEY: ${{ secrets.FG_BACKUP_R2_SECRET_ACCESS_KEY }}\n"
    )
    assert not _scan(line)


def test_ignores_github_actions_inline_equals() -> None:
    """Inline shell assignment with GH Actions injection — filtered by ${{ }}."""
    line = (
        "export AWS_SECRET_ACCESS_KEY=${{ secrets.FG_BACKUP_R2_SECRET_ACCESS_KEY }}\n"
    )
    assert not _scan(line)


def test_ignores_shell_presence_test_double_quote() -> None:
    assert not _scan('[[ -z "$AWS_SECRET_ACCESS_KEY" ]] && echo missing\n')


def test_ignores_shell_presence_test_brace_default() -> None:
    assert not _scan('[[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]]\n')


def test_ignores_shell_presence_test_inline() -> None:
    line = 'if [[ -z "$bucket" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then\n'
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


def test_ignores_comment_line_name_only() -> None:
    """Name reference in a comment without '=' — not matched by detector."""
    assert not _scan("#   AWS_SECRET_ACCESS_KEY     the S3 secret key\n")


def test_ignores_comment_line_with_parenthetical() -> None:
    assert not _scan("#   AWS_SECRET_ACCESS_KEY (or a working rclone remote).\n")


def test_ignores_error_string_containing_name() -> None:
    """String literal error message using the var name — no '=' after the name."""
    line = "return NextResponse.json({ error: 'OPENAI_API_KEY is not configured' })\n"
    assert not _scan(line)


def test_detects_pem_begin_private_key_in_value() -> None:
    """PEM private key block as a dict value must be detected by the scanner."""
    assert _scan('key = "-----BEGIN PRIVATE KEY-----\\nABCDEF"\n')


def test_detects_aws_secret_in_python_print() -> None:
    """print() constructing an AWS_SECRET_ACCESS_KEY assignment must be detected."""
    assert _scan("print('export AWS_SECRET_ACCESS_KEY=' + creds['SecretAccessKey'])\n")


def test_detects_slack_token_in_string_literal() -> None:
    """Slack bot token prefix in a string literal must be detected."""
    assert _scan('token = "xoxb-12345-secret"\n')


def test_ignores_split_detection_string_adjacent_literals() -> None:
    """Adjacent-literal split of a PEM marker is a safe reference in test fixtures."""
    # This test documents that adjacent literals in Python source break the scanner
    # pattern while preserving runtime string identity — used in deny-list fixtures.
    # The scanner does not see the complete detection pattern in split form.
    assert not _scan('"-----BEGIN P" "RIVATE KEY-----"\n')


def test_scanner_is_deterministic() -> None:
    """Running the scanner twice on the same content produces identical results."""
    # Strip the temp-path prefix (varies per call) before comparing — only the
    # line number and matched text must be identical across runs.
    content = "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    strip = lambda lines: [line.split(":", 1)[1] for line in lines]  # noqa: E731
    assert strip(_scan(content)) == strip(_scan(content))


# ── Bare PEM marker strings (false-positive source in test fixtures) ──────────
# Tests that assert PEM markers are ABSENT from evidence files use strings like
# "BEGIN PRIVATE KEY" as detection patterns.  The scanner correctly flags them
# (the pattern is intentionally broad).  codex_gates.sh excludes such test files
# from the scan; these tests document that the scanner DOES detect the bare form.


def test_detects_bare_pem_begin_private_key() -> None:
    """Bare 'BEGIN PRIVATE KEY' string (no dashes) is detected by the scanner.

    This is the pattern present in test_offline_simulation_evidence_lifecycle.py
    as an assertion-literal, which is why that file is excluded from the scan.
    """
    assert _scan('"BEGIN PRIVATE KEY",\n')


def test_detects_bare_pem_begin_rsa_private_key() -> None:
    """Bare 'BEGIN RSA PRIVATE KEY' string is detected by the scanner."""
    assert _scan('"BEGIN RSA PRIVATE KEY",\n')


def test_scanner_excludes_offline_simulation_lifecycle_file() -> None:
    """codex_gates.sh excludes test_offline_simulation_evidence_lifecycle.py.

    That file uses 'BEGIN PRIVATE KEY' / 'BEGIN RSA PRIVATE KEY' as assertion
    literals (checking that evidence files do NOT contain private key material).
    Without the exclusion, codex_gates.sh would false-positive on those lines.
    """
    gates = (
        __file__.split("tests")[0].rstrip("/") if "tests" in __file__ else "."
    ) + "/codex_gates.sh"
    from pathlib import Path

    gates_text = Path(gates).read_text()
    assert "test_offline_simulation_evidence_lifecycle.py" in gates_text, (
        "codex_gates.sh must exclude test_offline_simulation_evidence_lifecycle.py "
        "to avoid false-positive on PEM marker assertion literals"
    )
