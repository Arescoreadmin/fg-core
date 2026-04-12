"""
tools/ci/check_no_plaintext_secrets.py

Secret-scanning gate: ensures that env/prod.env (and any env/*.env file)
only contains CHANGE_ME_* placeholder values for known-secret variables.

Rules enforced
--------------
1. Any variable whose name matches SECRET_VAR_RE must have a value that is
   either empty or a CHANGE_ME_* placeholder (possibly embedded inside a
   URL — the credential segment is extracted and checked independently).
2. A hard blocklist of known-leaked raw values is also checked across ALL
   lines in every env file, regardless of variable name.

Exit codes
----------
  0  no violations found
  1  one or more violations found (details printed to stderr)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Variable-name patterns that hold secrets.
SECRET_VAR_RE = re.compile(
    r"""
    (PASSWORD | SECRET | _TOKEN | _KEY | _PEPPER | _SALT |
     _AUTH_SECRET | _SIGNING | _ENCRYPTION | _JWT | _SESSION |
     _WEBHOOK | _INTERNAL | _API_KEY | _AGENT_KEY | _AGENT_API)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# A value is an acceptable placeholder if it is:
#   - empty
#   - exactly  CHANGE_ME_<UPPER_SNAKE>
#   - a URL whose credential segment matches CHANGE_ME_<UPPER_SNAKE>
PLACEHOLDER_RE = re.compile(r"^CHANGE_ME_[A-Z0-9_]+$")

# Pattern to extract credentials from a URL: scheme://[user:]password@host
# We look for the segment between the last ":" before "@" and the "@".
URL_CRED_RE = re.compile(r"://(?:[^:@/]*:)?([^@/]+)@")

# Hard-blocked literal substrings — add known-leaked values here.
# This list is intentionally short; the placeholder rule catches the rest.
BLOCKED_LITERALS: list[str] = [
    "VD_6zx6nD4JJg3APEhNVAIBPSlqlGQao",  # postgres password leaked in git history
]

# Files to scan (glob relative to repo root).
ENV_GLOB = "env/*.env"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_acceptable(value: str) -> bool:
    """Return True if *value* is an empty string or an approved placeholder."""
    if not value:
        return True
    # Plain placeholder
    if PLACEHOLDER_RE.match(value):
        return True
    # URL with placeholder credentials, e.g.
    #   postgresql+psycopg://fg_user:CHANGE_ME_X@postgres:5432/frostgate
    #   redis://:CHANGE_ME_X@redis:6379/0
    #   nats://CHANGE_ME_X@nats:4222
    if "://" in value:
        match = URL_CRED_RE.search(value)
        if match:
            cred = match.group(1)
            return PLACEHOLDER_RE.match(cred) is not None
        # URL with no credential segment — nothing to check
        return True
    return False


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation strings for *path*."""
    violations: list[str] = []
    text = path.read_text(encoding="utf-8")

    # Hard-blocklist check (whole-file scan).
    for bad in BLOCKED_LITERALS:
        if bad in text:
            violations.append(
                f"{path}: contains blocked literal (a previously-leaked credential)"
            )

    # Per-line secret-variable check.
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Strip surrounding quotes if present.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]

        if not SECRET_VAR_RE.search(key):
            continue

        if not _is_acceptable(value):
            violations.append(
                f"{path}:{lineno}: secret variable {key!r} contains a non-placeholder "
                f"value — replace with CHANGE_ME_{key} and rotate externally"
            )

    return violations


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    env_files = sorted(repo_root.glob(ENV_GLOB))

    if not env_files:
        print(f"check_no_plaintext_secrets: no files matched {ENV_GLOB!r} — nothing to scan")
        return 0

    all_violations: list[str] = []
    for env_file in env_files:
        all_violations.extend(_scan_file(env_file))

    if all_violations:
        print("FAIL: plaintext secrets detected in env files:", file=sys.stderr)
        for v in all_violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nRemediation:\n"
            "  1. Replace each flagged value with CHANGE_ME_<VAR_NAME>\n"
            "  2. Rotate the real credential externally (Vault / AWS SSM / etc.)\n"
            "  3. Inject the rotated value at deploy time via your secrets manager",
            file=sys.stderr,
        )
        return 1

    scanned = ", ".join(str(f.relative_to(repo_root)) for f in env_files)
    print(f"check_no_plaintext_secrets: OK ({scanned})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
