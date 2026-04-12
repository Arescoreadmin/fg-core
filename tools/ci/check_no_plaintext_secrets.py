"""
tools/ci/check_no_plaintext_secrets.py

Secret-scanning gate: ensures that env files tracked in this repository only
contain CHANGE_ME_* placeholder values (or shell-reference forms) for all
known-secret variables, AND that no URL-embedded credential is plaintext
regardless of the variable name.

Rules enforced
--------------
1. Every assignment whose value is a URL with userinfo is checked for
   plaintext credentials — independent of whether the key name looks secret.
   This catches DATABASE_URL, FG_DB_URL, FG_REDIS_URL, etc.
2. Any variable whose name matches _SECRET_SUFFIXES must have a direct value
   that is either empty, a CHANGE_ME_* placeholder, or a ${VAR} shell ref.
3. A hard blocklist of known-leaked raw values is checked across ALL lines in
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
# Secret variable-name detection (Check B — direct value check only)
# ---------------------------------------------------------------------------
# Anchored tokens prevent false-positives on config booleans such as
# FG_AUTH_ALLOW_FALLBACK or FG_AUTH_ENABLED.
_SECRET_SUFFIXES = re.compile(
    r"""(?x)
    (?:
        PASSWORD          # *_PASSWORD
      | SECRET            # *_SECRET
      | _TOKEN(?:$|\b)    # *_TOKEN  (not TOKENIZE etc.)
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

# Plain CHANGE_ME_* sentinel.
_CHANGE_ME_RE = re.compile(r"^CHANGE_ME_[A-Z0-9_]+$")

# Shell variable reference: ${VAR}, ${VAR:-default}, ${VAR:?error}, $VAR
_SHELL_REF_RE = re.compile(
    r"^\$\{[A-Z_][A-Z0-9_]*(?::[?!-][^}]*)?\}$|^\$[A-Z_][A-Z0-9_]*$"
)

# Extract the credential (password/token) from a URL's userinfo component.
# Handles:
#   scheme://user:PASSWORD@host      → group(1) = PASSWORD
#   scheme://:PASSWORD@host          → group(1) = PASSWORD  (redis style)
#   scheme://PASSWORD@host           → group(1) = PASSWORD  (nats token style)
_URL_CRED_RE = re.compile(r"://(?:[^:@/]*:)?([^@/]+)@")

# ---------------------------------------------------------------------------
# Hard-blocked literal substrings
# Add every previously-leaked raw credential here.  The list must be kept
# short; the name-pattern rule catches all future secrets.
# ---------------------------------------------------------------------------
BLOCKED_LITERALS: list[str] = [
    "VD_6zx6nD4JJg3APEhNVAIBPSlqlGQao",  # postgres password — leaked in git history
]

# ---------------------------------------------------------------------------
# Scan surface: globs relative to repo root.
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

def _is_secret_var(key: str) -> bool:
    return bool(_SECRET_SUFFIXES.search(key))


def _is_cred_acceptable(cred: str) -> bool:
    """Return True if a URL credential segment is an approved placeholder."""
    return bool(_CHANGE_ME_RE.match(cred) or _SHELL_REF_RE.match(cred))


def _extract_url_cred(value: str) -> str | None:
    """Return the credential segment embedded in *value* as a URL, or None."""
    match = _URL_CRED_RE.search(value)
    return match.group(1) if match else None


def _is_acceptable(value: str) -> bool:
    """Return True if *value* is empty or an approved template form.

    For URL values the credential segment is extracted and checked; the rest
    of the URL is not evaluated.
    """
    if not value:
        return True
    if _CHANGE_ME_RE.match(value):
        return True
    if _SHELL_REF_RE.match(value):
        return True
    if "://" in value:
        cred = _extract_url_cred(value)
        if cred is None:
            return True  # URL with no embedded credential
        return _is_cred_acceptable(cred)
    return False


def _scan_file(path: Path) -> list[str]:
    """Return a list of human-readable violation strings for *path*."""
    violations: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        violations.append(f"{path}: cannot read file — {exc}")
        return violations

    # --- Hard-blocklist check (whole-file, independent of var name) ---------
    for bad in BLOCKED_LITERALS:
        if bad in text:
            violations.append(
                f"{path}: contains a known-leaked credential literal — "
                "rotate immediately and remove from file"
            )

    # --- Per-line checks ----------------------------------------------------
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

        url_violation_reported = False

        # --- Check A: URL credential scan — runs for EVERY line -------------
        # Catches DATABASE_URL, FG_DB_URL, FG_REDIS_URL, FG_NATS_URL, etc.
        # regardless of whether the key name matches a secret suffix.
        if "://" in value:
            cred = _extract_url_cred(value)
            if cred is not None and not _is_cred_acceptable(cred):
                violations.append(
                    f"{path}:{lineno}: {key!r} URL contains a non-placeholder "
                    f"credential — replace the embedded password with "
                    f"CHANGE_ME_{key} and rotate externally"
                )
                url_violation_reported = True

        # --- Check B: Secret-class direct value -----------------------------
        # Only for variables whose name matches a known secret suffix.
        # Suppressed when Check A already flagged this line (avoids duplicate
        # reports for URL-valued secret-class variables).
        if not url_violation_reported and _is_secret_var(key):
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
