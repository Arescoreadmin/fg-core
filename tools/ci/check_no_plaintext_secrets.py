"""
tools/ci/check_no_plaintext_secrets.py

Secret-scanning gate: ensures that env files tracked in this repository only
contain CHANGE_ME_* placeholder values (or shell-reference forms) for all
known-secret variables.  Fail-closed: any unrecognised value in a secret-class
variable is a hard failure.

Rules enforced
--------------
1. Any variable whose name matches SECRET_VAR_RE must have a value that is
   either empty, a CHANGE_ME_* placeholder, a ${VAR} shell reference, or
   (for URL values) has a credential segment that satisfies one of the above.
2. A hard blocklist of known-leaked raw values is checked across ALL lines in
   every scanned file, regardless of variable name.

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
# Secret variable-name detection
# ---------------------------------------------------------------------------
# Matches any variable whose name contains a known secret-class suffix/token.
# Anchored tokens (ending with $) prevent matching config booleans such as
# FG_AUTH_ALLOW_FALLBACK or FG_AUTH_ENABLED.
_SECRET_SUFFIXES = re.compile(
    r"""(?x)
    (?:
        PASSWORD          # *_PASSWORD
      | SECRET            # *_SECRET
      | _TOKEN(?:$|\b)    # *_TOKEN (not TOKENIZE etc.)
      | _KEY(?:$|\b)      # *_KEY
      | _CREDENTIAL       # *_CREDENTIAL
      | _PEPPER           # *_PEPPER
      | _SALT(?:$|\b)     # *_SALT
      | _SIGNING          # *_SIGNING
      | _ENCRYPTION       # *_ENCRYPTION
      | _JWT(?:$|\b)      # *_JWT
      | _SESSION(?:$|\b)  # *_SESSION
      | _WEBHOOK          # *_WEBHOOK
      | _INTERNAL         # *_INTERNAL (covers FG_INTERNAL_AUTH_SECRET)
      | _API_KEY          # *_API_KEY
      | _AGENT_KEY        # *_AGENT_KEY
      | _AGENT_API        # *_AGENT_API
    )
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Acceptable placeholder patterns
# ---------------------------------------------------------------------------

# Plain CHANGE_ME_* sentinel
_CHANGE_ME_RE = re.compile(r"^CHANGE_ME_[A-Z0-9_]+$")

# Shell variable reference: ${VAR}, ${VAR:-default}, ${VAR:?error}, $VAR
_SHELL_REF_RE = re.compile(r"^\$\{[A-Z_][A-Z0-9_]*(?::[?!-][^}]*)?\}$|^\$[A-Z_][A-Z0-9_]*$")

# Extract credential segment from a URL (the token between : and @ ).
# Handles:
#   scheme://user:PASSWORD@host
#   scheme://:PASSWORD@host          (redis style — no user)
#   scheme://PASSWORD@host           (nats style — token only)
_URL_CRED_RE = re.compile(r"://(?:[^:@/]*:)?([^@/]+)@")

# ---------------------------------------------------------------------------
# Hard-blocked literal substrings
# Add every previously-leaked raw credential here.  The list must be kept
# short; the placeholder rule catches all future secrets by name.
# ---------------------------------------------------------------------------
BLOCKED_LITERALS: list[str] = [
    "VD_6zx6nD4JJg3APEhNVAIBPSlqlGQao",  # postgres password — leaked in git history
]

# ---------------------------------------------------------------------------
# Scan surface: globs relative to repo root
# Only globs for which there is repo evidence are included.
# ---------------------------------------------------------------------------
ENV_GLOBS: list[str] = [
    "env/*.env",
    ".env.example",
    "agent/.env.example",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_acceptable(value: str) -> bool:
    """Return True if *value* is empty or an approved template form."""
    if not value:
        return True
    if _CHANGE_ME_RE.match(value):
        return True
    if _SHELL_REF_RE.match(value):
        return True
    if "://" in value:
        match = _URL_CRED_RE.search(value)
        if match:
            cred = match.group(1)
            return bool(_CHANGE_ME_RE.match(cred) or _SHELL_REF_RE.match(cred))
        # URL with no embedded credential — nothing to check.
        return True
    return False


def _is_secret_var(key: str) -> bool:
    return bool(_SECRET_SUFFIXES.search(key))


def _scan_file(path: Path) -> list[str]:
    """Return a list of human-readable violation strings for *path*."""
    violations: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        violations.append(f"{path}: cannot read file — {exc}")
        return violations

    # Hard-blocklist check (whole-file scan, independent of var name).
    for bad in BLOCKED_LITERALS:
        if bad in text:
            violations.append(
                f"{path}: contains a known-leaked credential literal — "
                "rotate immediately and remove from file"
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

        # Strip balanced surrounding quotes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]

        if not _is_secret_var(key):
            continue

        if not _is_acceptable(value):
            violations.append(
                f"{path}:{lineno}: {key!r} has a non-placeholder value — "
                f"replace with CHANGE_ME_{key} and rotate the real secret externally"
            )

    return violations


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]

    scanned: list[Path] = []
    for glob in ENV_GLOBS:
        scanned.extend(sorted(repo_root.glob(glob)))

    if not scanned:
        print(
            f"check_no_plaintext_secrets: no env files found "
            f"(globs: {ENV_GLOBS}) — nothing to scan"
        )
        return 0

    all_violations: list[str] = []
    for env_file in scanned:
        all_violations.extend(_scan_file(env_file))

    if all_violations:
        print("FAIL: plaintext secrets detected in env files:", file=sys.stderr)
        for v in all_violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nRemediation:\n"
            "  1. Replace each flagged value with CHANGE_ME_<VAR_NAME>\n"
            "  2. Rotate the real credential externally (Vault / AWS SSM / etc.)\n"
            "  3. Inject the rotated value at deploy time — never commit it",
            file=sys.stderr,
        )
        return 1

    names = ", ".join(str(f.relative_to(repo_root)) for f in scanned)
    print(f"check_no_plaintext_secrets: OK ({names})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
